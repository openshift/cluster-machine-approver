package status

import (
	"context"
	"fmt"
	"os"

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"

	certificatesv1 "k8s.io/api/certificates/v1beta1"

	"github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
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
	clusterOperatorName           = "machine-approver"
	clusterOperatorNamespace      = "openshift-cluster-machine-approver"
	unknownVersionValue           = "unknown"
	operatorVersionKey            = "operator"
	reasonAsExpected              = "AsExpected"
	releaseVersionEnvVariableName = "RELEASE_VERSION"
)

var relatedObjects = []configv1.ObjectReference{
	{
		Group:    "",
		Resource: "namespaces",
		Name:     clusterOperatorNamespace,
	},
	{
		Group:    "certificates.k8s.io",
		Resource: "certificatesigningrequests",
		Name:     "",
	},
}

type StatusController struct {
	client.Client
}

func (c *StatusController) SetupWithManager(mgr ctrl.Manager, options controller.Options) error {
	return buildWithManager(mgr, options, c)
}

func buildWithManager(mgr ctrl.Manager, options controller.Options, c reconcile.Reconciler) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(options).
		For(&configv1.ClusterOperator{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return clusterOperatorFilter(e.Object) },
			UpdateFunc:  func(e event.UpdateEvent) bool { return clusterOperatorFilter(e.ObjectNew) },
			DeleteFunc:  func(e event.DeleteEvent) bool { return clusterOperatorFilter(e.Object) },
			GenericFunc: func(e event.GenericEvent) bool { return clusterOperatorFilter(e.Object) },
		})).
		// Watch CSR changes
		Watches(
			&source.Kind{Type: &certificatesv1.CertificateSigningRequest{}},
			&handler.EnqueueRequestsFromMapFunc{ToRequests: handler.ToRequestsFunc(toClusterOperator)},
			builder.WithPredicates(predicate.Funcs{
				CreateFunc:  func(e event.CreateEvent) bool { return csrFilter(e.Object) },
				UpdateFunc:  func(e event.UpdateEvent) bool { return csrFilter(e.ObjectNew) },
				GenericFunc: func(e event.GenericEvent) bool { return csrFilter(e.Object) },
				DeleteFunc:  func(e event.DeleteEvent) bool { return false },
			})).Complete(c)
}

func clusterOperatorFilter(obj runtime.Object) bool {
	approverCO, ok := obj.(*configv1.ClusterOperator)
	return ok && approverCO.Name == clusterOperatorName
}

func csrFilter(obj runtime.Object) bool {
	_, ok := obj.(*certificatesv1.CertificateSigningRequest)
	return ok
}

func toClusterOperator(handler.MapObject) []reconcile.Request {
	return []reconcile.Request{{
		NamespacedName: client.ObjectKey{
			Name: clusterOperatorName,
		},
	}}
}

func (c *StatusController) Reconcile(req ctrl.Request) (reconcile.Result, error) {
	return ctrl.Result{}, c.reconcileStatus()
}

// reconcileStatus sets the Available condition to True, with the given reason
// and message, and sets both the Progressing and Degraded conditions to False.
func (c *StatusController) reconcileStatus() error {
	co, err := c.getOrCreateClusterOperator()
	if err != nil {
		return err
	}

	conds := []configv1.ClusterOperatorStatusCondition{
		{
			Type:               configv1.OperatorAvailable,
			Status:             configv1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             reasonAsExpected,
			Message:            fmt.Sprintf("Cluster Machine Approver is available at %s", getReleaseVersion()),
		},
		{
			Type:               configv1.OperatorDegraded,
			Status:             configv1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             reasonAsExpected,
			Message:            "",
		},
		{
			Type:               configv1.OperatorProgressing,
			Status:             configv1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             reasonAsExpected,
			Message:            "",
		},
		{
			Type:               configv1.OperatorUpgradeable,
			Status:             configv1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             reasonAsExpected,
			Message:            "",
		},
	}

	co.Status.Versions = []configv1.OperandVersion{{Name: operatorVersionKey, Version: getReleaseVersion()}}
	return c.syncStatus(co, conds)
}

func (c *StatusController) getOrCreateClusterOperator() (*configv1.ClusterOperator, error) {
	co := &configv1.ClusterOperator{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: clusterOperatorName}, co); apierrors.IsNotFound(err) {
		klog.Infof("ClusterOperator does not exist, creating a new one.")
		co = &configv1.ClusterOperator{
			ObjectMeta: metav1.ObjectMeta{
				Name: clusterOperatorName,
			},
			Status: configv1.ClusterOperatorStatus{},
		}

		err = c.Create(context.Background(), co)
		if err != nil {
			return nil, fmt.Errorf("failed to create cluster operator: %v", err)
		}
		return co, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get clusterOperator %q: %v", clusterOperatorName, err)
	}
	return co, nil
}

//syncStatus applies the new condition to the mao ClusterOperator object.
func (c *StatusController) syncStatus(co *configv1.ClusterOperator, conds []configv1.ClusterOperatorStatusCondition) error {
	for _, c := range conds {
		v1helpers.SetStatusCondition(&co.Status.Conditions, c)
	}

	if !equality.Semantic.DeepEqual(co.Status.RelatedObjects, relatedObjects) {
		co.Status.RelatedObjects = relatedObjects
	}

	return c.Status().Update(context.Background(), co)
}

func getReleaseVersion() string {
	releaseVersion := os.Getenv(releaseVersionEnvVariableName)
	if len(releaseVersion) == 0 {
		releaseVersion = unknownVersionValue
		klog.Infof("%s environment variable is missing, defaulting to %q", releaseVersionEnvVariableName, unknownVersionValue)
	}
	return releaseVersion
}
