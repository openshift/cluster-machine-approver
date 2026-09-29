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
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
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
)

const (
	configNamespace            = "openshift-config-managed"
	kubeletCAConfigMap         = "csr-controller-ca"
	csrConditionApproveMessage = "This CSR was approved by the Node CSR Approver (cluster-machine-approver)"
)

// MachineApproverReconciler reconciles a machine-approver  object
type CertificateApprover struct {
	WorkloadClient client.Client
	NodeRestCfg    *rest.Config

	ManagementClient client.Client
	MachineRestCfg   *rest.Config
	MachineNamespace string

	Config           ClusterMachineApproverConfig
	APIGroupVersions []schema.GroupVersion
}

func (m *CertificateApprover) SetupWithManager(mgr ctrl.Manager, options controller.Options) error {
	return m.buildWithManager(mgr, options, m)
}

func (m *CertificateApprover) buildWithManager(mgr ctrl.Manager, options controller.Options, c reconcile.Reconciler) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(options).
		For(&certificatesv1.CertificateSigningRequest{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return pendingNodeCertFilter(e.Object) },
			UpdateFunc:  func(e event.UpdateEvent) bool { return pendingNodeCertFilter(e.ObjectNew) },
			GenericFunc: func(e event.GenericEvent) bool { return pendingNodeCertFilter(e.Object) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return false },
		})).
		Watches(
			&corev1.ConfigMap{},
			handler.EnqueueRequestsFromMapFunc(m.toCSRs),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(e event.CreateEvent) bool { return caConfigMapFilter(e.Object, nil) },
				UpdateFunc:  func(e event.UpdateEvent) bool { return caConfigMapFilter(e.ObjectOld, e.ObjectNew) },
				GenericFunc: func(e event.GenericEvent) bool { return caConfigMapFilter(e.Object, nil) },
				DeleteFunc:  func(e event.DeleteEvent) bool { return false },
			})).Complete(c)
}

// pendingNodeCertFilter filters CSRs that need to be reconciled
func pendingNodeCertFilter(obj runtime.Object) bool {
	cert, ok := obj.(*certificatesv1.CertificateSigningRequest)
	// Reconcile unapproved or approved by another controller to update our metrics
	reconcileRequired := ok && (!isApproved(*cert) || (isRecentlyApproved(*cert) && !isApprovedByCMA(*cert)))

	if !reconcileRequired {
		return false
	}

	switch cert.Spec.SignerName {
	case certificatesv1.KubeletServingSignerName:
		groupSet := sets.NewString(cert.Spec.Groups...)
		// Reconcile kubernetes.io/kubelet-serving when it has the system:nodes group
		if !groupSet.Has(nodeGroup) {
			klog.V(3).Infof("%s: Ignoring csr because it does not have the system:nodes group", cert.Name)
			return false
		}
	case certificatesv1.KubeAPIServerClientKubeletSignerName:
		// Reconcile kubernetes.io/kube-apiserver-client-kubelet when it is created by the node bootstrapper
		if cert.Spec.Username != nodeBootstrapperUsername {
			klog.V(3).Infof("%s: Ignoring csr because it is not from the node bootstrapper", cert.Name)
			return false
		}
	default:
		// Ignore all other CSRs
		klog.V(3).Infof("%s: Ignoring csr because of unsupported signerName: %s", cert.Name, cert.Spec.SignerName)
		return false
	}

	return true
}

func (m *CertificateApprover) toCSRs(ctx context.Context, obj client.Object) []reconcile.Request {
	requests := []reconcile.Request{}
	csrs, err := listNodeCSRs(ctx, m.WorkloadClient)
	if err != nil {
		klog.Errorf("Unable to list CSRs: %v", err)
		return nil
	}

	for _, csr := range csrs {
		// Only reconcile pending or recently approved by another controller
		if pendingNodeCertFilter(&csr) {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKey{Name: csr.Name},
			})
		}
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

func listNodeCSRs(ctx context.Context, ctrlClient client.Client) ([]certificatesv1.CertificateSigningRequest, error) {
	csrList := &certificatesv1.CertificateSigningRequestList{}
	csrs := []certificatesv1.CertificateSigningRequest{}

	if err := ctrlClient.List(ctx, csrList, &client.ListOptions{FieldSelector: fields.OneTermEqualSelector(signerNameField, certificatesv1.KubeAPIServerClientKubeletSignerName)}); err != nil {
		return nil, fmt.Errorf("failed to get CSRs: %w", err)
	}
	csrs = append(csrs, csrList.Items...)

	if err := ctrlClient.List(ctx, csrList, &client.ListOptions{FieldSelector: fields.OneTermEqualSelector(signerNameField, certificatesv1.KubeletServingSignerName)}); err != nil {
		return nil, fmt.Errorf("failed to get CSRs: %w", err)
	}
	csrs = append(csrs, csrList.Items...)

	return csrs, nil
}

func (m *CertificateApprover) Reconcile(ctx context.Context, req ctrl.Request) (reconcile.Result, error) {
	klog.Infof("Reconciling CSR: %v", req.Name)

	csrs, err := listNodeCSRs(ctx, m.WorkloadClient)
	if err != nil {
		klog.Errorf("%v: failed to list CSRs: %v", req.Name, err)
		return reconcile.Result{}, fmt.Errorf("%v: failed to list CSRs: %w", req.Name, err)
	}

	machineHandler := &machinehandlerpkg.MachineHandler{
		Client:    m.ManagementClient,
		Config:    m.MachineRestCfg,
		Ctx:       ctx,
		Namespace: m.MachineNamespace,
	}

	var machines []machinehandlerpkg.Machine

	for _, apiGroupVersion := range m.APIGroupVersions {
		newMachines, err := machineHandler.ListMachines(apiGroupVersion)
		if err != nil {
			klog.Errorf("%v: Failed to list machines in API group %v: %v", req.Name, apiGroupVersion, err)
			return reconcile.Result{}, fmt.Errorf("Failed to list machines: %w", err)
		}
		machines = append(machines, newMachines...)
	}

	nodes := &corev1.NodeList{}
	if err := m.WorkloadClient.List(ctx, nodes); err != nil {
		klog.Errorf("%v: Failed to list Nodes: %v", req.Name, err)
		return reconcile.Result{}, fmt.Errorf("Failed to get Nodes: %w", err)
	}

	if offLimits := reconcileLimits(req.Name, machines, nodes, csrs); offLimits {
		// Stop all reconciliation
		return reconcile.Result{}, nil
	}

	for _, csr := range csrs {
		if csr.Name == req.Name {
			if err := m.reconcileCSR(csr, machines); err != nil {
				return reconcile.Result{}, fmt.Errorf("could not reconcile CSR: %v", err)
			}

			// Reconcile the limits at the end of a reconcile so that the currently
			// pending CSRs metric has an up to date value if we approved a CSR.
			// When an error occurs, we requeue and so update the limits on the
			// next reconcile.
			// Don't use a cached client here else we may not have up to date CSRs.
			return reconcile.Result{}, reconcileLimitsUncached(m.NodeRestCfg, csr.Name, machines, nodes)
		}
	}

	klog.Errorf("Failed to find CSR: %v", req)

	return reconcile.Result{}, nil
}

// reconcileLimits will short circut logic if number of pending CSRs is exceeding limit
func reconcileLimits(csrName string, machines []machinehandlerpkg.Machine, nodes *corev1.NodeList, csrs []certificatesv1.CertificateSigningRequest) bool {
	maxPending := getMaxPending(machines, nodes)
	atomic.StoreUint32(&MaxPendingCSRs, uint32(maxPending))
	pending := recentlyPendingNodeCSRs(csrs)
	atomic.StoreUint32(&PendingCSRs, uint32(pending))
	if pending > maxPending {
		klog.Errorf("%v: Pending CSRs: %d; Max pending allowed: %d. Difference between pending CSRs and machines > %v. Ignoring all CSRs as too many recent pending CSRs seen", csrName, pending, maxPending, maxDiffBetweenPendingCSRsAndMachinesCount)
		return true
	}

	return false
}

// reconcileLimitsUncached is used to update the limits using an uncached certificates list.
// This is used at the end of the approval process to ensure that the limits (and therefore)
// the metrics are always up to date.
func reconcileLimitsUncached(cfg *rest.Config, csrName string, machines []machinehandlerpkg.Machine, nodes *corev1.NodeList) error {
	certClient, err := certificatesv1client.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("could not initialise certificates client: %v", err)
	}

	clientCertificates, err := certClient.CertificateSigningRequests().List(context.Background(), metav1.ListOptions{FieldSelector: clientKubeletFieldSelector})
	if err != nil {
		return fmt.Errorf("could not list CSRs: %v", err)
	}

	servingCertificates, err := certClient.CertificateSigningRequests().List(context.Background(), metav1.ListOptions{FieldSelector: kubeletServingFieldSelector})
	if err != nil {
		return fmt.Errorf("could not list CSRs: %v", err)
	}

	csrs := clientCertificates.Items
	csrs = append(csrs, servingCertificates.Items...)
	reconcileLimits(csrName, machines, nodes, csrs)
	return nil
}

func (m *CertificateApprover) reconcileCSR(csr certificatesv1.CertificateSigningRequest, machines []machinehandlerpkg.Machine) error {
	// If a CSR is approved after being added to the queue, but before we reconcile it,
	// it may have already been approved. If it has already been approved, trying to
	// approve it again will result in an error and cause a loop.
	// Return early if the CSR has been approved externally.
	if isApproved(csr) {
		klog.Infof("%v: CSR is already approved", csr.Name)
		return nil
	}

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

	if authorize, err := authorizeCSR(m.WorkloadClient, m.Config, machines, &csr, parsedCSR, kubeletCA); !authorize {
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
	if err := m.WorkloadClient.Get(context.Background(), key, configMap); err != nil {
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
	needsupdate := false
	now := metav1.Now()
	condition := certificatesv1.CertificateSigningRequestCondition{
		Type:               certificatesv1.CertificateApproved,
		Reason:             "NodeCSRApprove",
		Message:            csrConditionApproveMessage,
		LastUpdateTime:     now,
		LastTransitionTime: now,
		Status:             "True",
	}

	// Check if the new condition already exists, and change it only if there is a status
	// transition (otherwise we should preserve the current last transition time).
	exists := false
	for i := range csr.Status.Conditions {
		existingCondition := csr.Status.Conditions[i]
		if existingCondition.Type == condition.Type {
			exists = true
			if !hasSameState(existingCondition, condition) {
				csr.Status.Conditions[i] = condition
				needsupdate = true
			}
			break
		}
	}

	// If the condition does not exist, set the last transition time and add it.
	if !exists {
		csr.Status.Conditions = append(csr.Status.Conditions, condition)
		needsupdate = true
	}

	if needsupdate {
		certClient, err := certificatesv1client.NewForConfig(rest)
		if err != nil {
			return err
		}
		if _, err := certClient.CertificateSigningRequests().
			UpdateApproval(context.Background(), csr.Name, csr, metav1.UpdateOptions{}); err != nil {
			return err
		}
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

func getMaxPending(machines []machinehandlerpkg.Machine, nodes *corev1.NodeList) int {
	return max(len(machines), len(nodes.Items)) + maxDiffBetweenPendingCSRsAndMachinesCount
}

func max(x, y int) int {
	if x < y {
		return y
	}
	return x
}

// hasSameState returns true if a condition has the same state of another; state is defined
// by the union of following fields: Type, Status, Reason, Severity and Message (it excludes LastTransitionTime).
func hasSameState(i, j certificatesv1.CertificateSigningRequestCondition) bool {
	return i.Type == j.Type &&
		i.Status == j.Status &&
		i.Reason == j.Reason &&
		i.Message == j.Message
}
