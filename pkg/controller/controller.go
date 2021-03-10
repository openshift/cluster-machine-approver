package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync/atomic"

	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	certificatesv1 "k8s.io/api/certificates/v1beta1"
	certificatesv1beta1 "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

	clusterMachineApproverAnnotationKey = "cluster-machine-approver.openshift.io/"
	rejectionAnnotationKey              = clusterMachineApproverAnnotationKey + "rejection-reason"
	errorAnnotationKey                  = clusterMachineApproverAnnotationKey + "error"
)

// MachineApproverReconciler reconciles a machine-approver  object
type CertificateApprover struct {
	client.Client
	RestCfg *rest.Config
	Config  ClusterMachineApproverConfig
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
	err := m.List(context.Background(), list)
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
	if err := m.List(ctx, csrs); err != nil {
		return reconcile.Result{}, fmt.Errorf("Failed to get CSRs: %w", err)
	}

	machines := &machinev1.MachineList{}
	if err := m.List(ctx, machines); err != nil {
		return reconcile.Result{}, fmt.Errorf("Failed to list machines: %w", err)
	}

	if offLimits := reconcileLimits(machines, csrs); offLimits {
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
func reconcileLimits(machines *machinev1.MachineList, csrs *certificatesv1.CertificateSigningRequestList) bool {
	maxPending := getMaxPending(machines.Items)
	atomic.StoreUint32(&MaxPendingCSRs, uint32(maxPending))
	pending := recentlyPendingCSRs(csrs.Items)
	atomic.StoreUint32(&PendingCSRs, uint32(pending))
	if pending > maxPending {
		klog.Errorf("Pending CSRs: %d; Max pending allowed: %d. Difference between pending CSRs and machines > %v. Ignoring all CSRs as too many recent pending CSRs seen", pending, maxPending, maxDiffBetweenPendingCSRsAndMachinesCount)
		return true
	}

	return false
}

func (m *CertificateApprover) reconcileCSR(csr certificatesv1.CertificateSigningRequest, machines *machinev1.MachineList) error {
	parsedCSR, err := parseCSR(&csr)
	if err != nil {
		formattedError := fmt.Errorf("error parsing request CSR: %v", err)
		m.addCsrAnnotation(&csr, errorAnnotationKey, formattedError.Error())
		return formattedError
	}

	kubeletCA := m.getKubeletCA()
	if kubeletCA == nil {
		// This is not a fatal error.  The renewal authorization flow
		// depending on the existing serving cert will be skipped.
		klog.Errorf("failed to get kubelet CA")
	}

	if err := authorizeCSR(m, m.Config, machines.Items, &csr, parsedCSR, kubeletCA); err != nil {
		// Don't deny since it might be someone else's CSR
		m.addCsrAnnotation(&csr, rejectionAnnotationKey, fmt.Errorf("Not authorized: %v", err).Error())
		return fmt.Errorf("CSR %s not authorized: %v", csr.Name, err)
	}

	if err := approve(m.RestCfg, &csr); err != nil {
		m.addCsrAnnotation(&csr, errorAnnotationKey, fmt.Errorf("Unable to approve: %v", csr.Name, err).Error())
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
	if err := m.Get(context.Background(), key, configMap); err != nil {
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

func (m *CertificateApprover) addCsrAnnotation(csr *certificatesv1.CertificateSigningRequest, key string, value string) error {
	baseToPatch := client.MergeFrom(csr.DeepCopy())
	if csr.Annotations == nil {
		csr.Annotations = map[string]string{}
	}
	csr.Annotations[key] = value
	if err := m.Client.Patch(context.Background(), csr, baseToPatch); err != nil {
		klog.Errorf("Failed to add annotation for %s: %v", csr.Name, err)
		return err
	}
	return nil
}

func approve(rest *rest.Config, csr *certificatesv1.CertificateSigningRequest) error {
	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
		Type:           certificatesv1.CertificateApproved,
		Reason:         "NodeCSRApprove",
		Message:        "This CSR was approved by the Node CSR Approver",
		LastUpdateTime: metav1.Now(),
	})
	certClient, err := certificatesv1beta1.NewForConfig(rest)
	if err != nil {
		return err
	}
	if _, err := certClient.CertificateSigningRequests().
		UpdateApproval(context.Background(), csr, metav1.UpdateOptions{}); err != nil {
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

func getMaxPending(machines []machinev1.Machine) int {
	return len(machines) + maxDiffBetweenPendingCSRsAndMachinesCount
}
