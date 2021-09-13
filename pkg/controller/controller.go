package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync/atomic"

	machinehandlerpkg "github.com/openshift/cluster-machine-approver/pkg/machinehandler"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	certificatesv1client "k8s.io/client-go/kubernetes/typed/certificates/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	configNamespace    = "openshift-config-managed"
	kubeletCAConfigMap = "csr-controller-ca"
)

// MachineApproverReconciler reconciles a machine-approver  object
type CertificateApprover struct {
	NodeClient  client.Client
	NodeRestCfg *rest.Config

	MachineClient  client.Client
	MachineRestCfg *rest.Config

	Config   ClusterMachineApproverConfig
	APIGroup string
}

func (m *CertificateApprover) SetupWithManager(mgr ctrl.Manager, options controller.Options) error {
	return m.buildWithManager(mgr, options, m)
}

func (m *CertificateApprover) buildWithManager(mgr ctrl.Manager, options controller.Options, c reconcile.Reconciler) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(options).
		For(&certificatesv1.CertificateSigningRequest{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return pendingCertFilter(e.Object) },
			UpdateFunc:  func(e event.UpdateEvent) bool { return pendingCertFilter(e.ObjectNew) },
			GenericFunc: func(e event.GenericEvent) bool { return pendingCertFilter(e.Object) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return false },
		})).
		Watches(
			&source.Kind{Type: &corev1.ConfigMap{}},
			handler.EnqueueRequestsFromMapFunc(m.toCSRs),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(e event.CreateEvent) bool { return caConfigMapFilter(e.Object, nil) },
				UpdateFunc:  func(e event.UpdateEvent) bool { return caConfigMapFilter(e.ObjectOld, e.ObjectNew) },
				GenericFunc: func(e event.GenericEvent) bool { return caConfigMapFilter(e.Object, nil) },
				DeleteFunc:  func(e event.DeleteEvent) bool { return false },
			})).Complete(c)
}

func pendingCertFilter(obj runtime.Object) bool {
	cert, ok := obj.(*certificatesv1.CertificateSigningRequest)
	return ok && !isApproved(*cert)
}

func (m *CertificateApprover) toCSRs(client.Object) []reconcile.Request {
	requests := []reconcile.Request{}
	list := &certificatesv1.CertificateSigningRequestList{}
	err := m.NodeClient.List(context.Background(), list)
	if err != nil {
		klog.Errorf("Unable to list pending CSRs: %v", err)
		return nil
	}
	for _, csr := range list.Items {
		if isApproved(csr) {
			continue
		}
		requests = append(requests, reconcile.Request{
			NamespacedName: client.ObjectKey{Name: csr.Name},
		})
	}

	return requests
}

func caConfigMapFilter(obj runtime.Object, new runtime.Object) bool {
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok || cm.Name != kubeletCAConfigMap || cm.Namespace != configNamespace {
		return false
	}
	cmData, foundDataOld := cm.Data["ca-bundle.crt"]
	if new == nil {
		return cm.Name == kubeletCAConfigMap &&
			cm.Namespace == configNamespace &&
			foundDataOld
	}
	cmNew, ok := new.(*corev1.ConfigMap)
	cmDataNew, foundDataNew := cmNew.Data["ca-bundle.crt"]
	return ok &&
		cm.Name == kubeletCAConfigMap &&
		cm.Namespace == configNamespace &&
		foundDataNew &&
		cmData != cmDataNew
}

func (m *CertificateApprover) Reconcile(ctx context.Context, req ctrl.Request) (reconcile.Result, error) {
	csrs := &certificatesv1.CertificateSigningRequestList{}
	klog.Infof("Reconciling CSR: %v", req.Name)
	if err := m.NodeClient.List(ctx, csrs); err != nil {
		klog.Errorf("%v: Failed to list CSRs: %v", req.Name, err)
		return reconcile.Result{}, fmt.Errorf("Failed to get CSRs: %w", err)
	}

	machineHandler := &machinehandlerpkg.MachineHandler{
		Client:   m.MachineClient,
		Config:   m.MachineRestCfg,
		Ctx:      ctx,
		APIGroup: m.APIGroup,
	}

	machines, err := machineHandler.ListMachines()
	if err != nil {
		klog.Errorf("%v: Failed to list machines: %v", req.Name, err)
		return reconcile.Result{}, fmt.Errorf("Failed to list machines: %w", err)
	}

	if offLimits := reconcileLimits(req.Name, machines, csrs); offLimits {
		// Stop all reconciliation
		return reconcile.Result{}, nil
	}

	for _, csr := range csrs.Items {
		if csr.Name == req.Name {
			return reconcile.Result{}, m.reconcileCSR(csr, machines)
		}
	}

	klog.Errorf("Failed to find CSR: %v", req)

	return reconcile.Result{}, nil
}

// reconcileLimits will short circut logic if number of pending CSRs is exceeding limit
func reconcileLimits(csrName string, machines []machinehandlerpkg.Machine, csrs *certificatesv1.CertificateSigningRequestList) bool {
	maxPending := getMaxPending(machines)
	atomic.StoreUint32(&MaxPendingCSRs, uint32(maxPending))
	pending := recentlyPendingCSRs(csrs.Items)
	atomic.StoreUint32(&PendingCSRs, uint32(pending))
	if pending > maxPending {
		klog.Errorf("%v: Pending CSRs: %d; Max pending allowed: %d. Difference between pending CSRs and machines > %v. Ignoring all CSRs as too many recent pending CSRs seen", csrName, pending, maxPending, maxDiffBetweenPendingCSRsAndMachinesCount)
		return true
	}

	return false
}

func (m *CertificateApprover) reconcileCSR(csr certificatesv1.CertificateSigningRequest, machines []machinehandlerpkg.Machine) error {
	parsedCSR, err := parseCSR(&csr)
	if err != nil {
		klog.Errorf("%v: Failed to parse csr: %v", csr.Name, err)
		return fmt.Errorf("error parsing request CSR: %v", err)
	}

	kubeletCA := m.getKubeletCA()
	if kubeletCA == nil {
		// This is not a fatal error.  The renewal authorization flow
		// depending on the existing serving cert will be skipped.
		klog.Errorf("failed to get kubelet CA")
	}

	if authorize, err := authorizeCSR(m.NodeClient, m.Config, machines, &csr, parsedCSR, kubeletCA); !authorize {
		// Don't deny since it might be someone else's CSR
		klog.Infof("%s: CSR not authorized", csr.Name)
		return err
	}

	if err := approve(m.NodeRestCfg, &csr); err != nil {
		return fmt.Errorf("Unable to approve CSR %s: %w", csr.Name, err)
	}
	klog.Infof("CSR %s approved", csr.Name)

	return nil
}

// getKubeletCA fetches the kubelet CA from the ConfigMap in the
// openshift-config-managed namespace.
func (m *CertificateApprover) getKubeletCA() *x509.CertPool {
	configMap := &corev1.ConfigMap{}
	key := client.ObjectKey{
		Namespace: configNamespace,
		Name:      kubeletCAConfigMap,
	}
	if err := m.NodeClient.Get(context.Background(), key, configMap); err != nil {
		klog.Errorf("failed to get kubelet CA: %v", err)
		return nil
	}

	caBundle, ok := configMap.Data["ca-bundle.crt"]
	if !ok {
		klog.Errorf("no ca-bundle.crt in %s", kubeletCAConfigMap)
		return nil
	}

	certPool := x509.NewCertPool()

	if ok := certPool.AppendCertsFromPEM([]byte(caBundle)); !ok {
		klog.Errorf("failed to parse ca-bundle.crt in %s", kubeletCAConfigMap)
		return nil
	}

	return certPool
}

func approve(rest *rest.Config, csr *certificatesv1.CertificateSigningRequest) error {
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:           certificatesv1.CertificateApproved,
		Reason:         "NodeCSRApprove",
		Message:        "This CSR was approved by the Node CSR Approver",
		LastUpdateTime: metav1.Now(),
		Status:         "True",
	})
	certClient, err := certificatesv1client.NewForConfig(rest)
	if err != nil {
		return err
	}
	if _, err := certClient.CertificateSigningRequests().
		UpdateApproval(context.Background(), csr.Name, csr, metav1.UpdateOptions{}); err != nil {
		return err
	}
	return nil
}

// parseCSR extracts the CSR from the API object and decodes it.
func parseCSR(obj *certificatesv1.CertificateSigningRequest) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(obj.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func getMaxPending(machines []machinehandlerpkg.Machine) int {
	return len(machines) + maxDiffBetweenPendingCSRsAndMachinesCount
}
