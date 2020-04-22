package main

import (
	"context"
	"fmt"
	"os"
	"time"

	osconfigv1 "github.com/openshift/api/config/v1"
	osclientset "github.com/openshift/client-go/config/clientset/versioned"
	osv1client "github.com/openshift/client-go/config/clientset/versioned/typed/config/v1"
	"github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
	"github.com/openshift/library-go/pkg/operator/status"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const (
	clusterOperatorName           = "machine-approver"
	clusterOperatorNamespace      = "openshift-cluster-machine-approver"
	unknownVersionValue           = "unknown"
	queueKey                      = "trigger"
	operatorVersionKey            = "operator"
	releaseVersionEnvVariableName = "RELEASE_VERSION"
)

var relatedObjects = []osconfigv1.ObjectReference{
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

type statusController struct {
	queue                   workqueue.RateLimitingInterface
	clusterOperators        osv1client.ClusterOperatorInterface
	versionGetter           status.VersionGetter
	versionCh               <-chan struct{}
	clusterOperatorInformer cache.Controller
}

func NewStatusController(config *restclient.Config) *statusController {
	// Run a controller to handle the clusterOperator status
	osClient, err := osclientset.NewForConfig(config)
	if err != nil {
		klog.Fatal(err)
	}

	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	versionGetter := status.NewVersionGetter()

	coListWatcher := cache.NewListWatchFromClient(osClient.ConfigV1().RESTClient(), "clusteroperators",
		v1.NamespaceAll, fields.OneTermEqualSelector("metadata.name", clusterOperatorName))

	_, informer := cache.NewIndexerInformer(coListWatcher, &osconfigv1.ClusterOperator{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { queue.Add(queueKey) },
		UpdateFunc: func(old, new interface{}) { queue.Add(queueKey) },
		DeleteFunc: func(obj interface{}) { queue.Add(queueKey) },
	}, cache.Indexers{})

	return &statusController{
		clusterOperators:        osClient.ConfigV1().ClusterOperators(),
		queue:                   queue,
		versionGetter:           versionGetter,
		versionCh:               versionGetter.VersionChangedChannel(),
		clusterOperatorInformer: informer,
	}
}

func (c *statusController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *statusController) Run(threadiness int, stopCh chan struct{}) {
	defer utilruntime.HandleCrash()

	// Let the workers stop when we are done
	defer c.queue.ShutDown()
	klog.Info("Starting cluster operator status controller")

	go c.clusterOperatorInformer.Run(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(stopCh, c.clusterOperatorInformer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	go c.watchVersionGetter(stopCh)

	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

// watchVersionGetter adds to the queue anything from c.versionCh
// c.versionCh emits something every time c.versionGetter.SetVersion is called.
func (c *statusController) watchVersionGetter(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()

	// Always trigger at least once.
	c.queue.Add(queueKey)

	for {
		select {
		case <-stopCh:
			return
		case <-c.versionCh:
			klog.V(3).Infof("Triggered watchVersionGetter")
			c.queue.Add(queueKey)
		}
	}
}

func (c *statusController) processNextItem() bool {
	// Wait until there is a new item in the working queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	// TODO(alberto): consider smarter logic.
	// e.g degraded when recentlyPendingCSRs(c.indexer); pending > maxPending
	err := c.statusAvailable()

	// Handle the error if something went wrong during the execution of the business logic
	c.handleErr(err, key)
	return true
}

func (c *statusController) handleErr(err error, key interface{}) {
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		c.queue.Forget(key)
		return
	}

	// This controller retries 30 times if something goes wrong. After that, it stops trying.
	if c.queue.NumRequeues(key) < 30 {
		klog.Infof("Error syncing status %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		c.queue.AddRateLimited(key)
		return
	}

	c.queue.Forget(key)
	// Report to an external entity that, even after several retries, we could not successfully process this key
	utilruntime.HandleError(err)
	klog.Infof("Dropping key %q out of the queue: %v", key, err)
}

// statusAvailable sets the Available condition to True, with the given reason
// and message, and sets both the Progressing and Degraded conditions to False.
func (c *statusController) statusAvailable() error {
	co, err := c.getOrCreateClusterOperator()
	if err != nil {
		return err
	}

	conds := []osconfigv1.ClusterOperatorStatusCondition{
		{
			Type:               osconfigv1.OperatorAvailable,
			Status:             osconfigv1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "",
			Message:            fmt.Sprintf("Cluster Machine Approver is available at %s", c.versionGetter.GetVersions()["operator"]),
		},
		{
			Type:               osconfigv1.OperatorDegraded,
			Status:             osconfigv1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             "",
			Message:            "",
		},
		{
			Type:               osconfigv1.OperatorProgressing,
			Status:             osconfigv1.ConditionFalse,
			LastTransitionTime: metav1.Now(),
			Reason:             "",
			Message:            "",
		},
		{
			Type:               osconfigv1.OperatorUpgradeable,
			Status:             osconfigv1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "",
			Message:            "",
		},
	}

	co.Status.Versions = []osconfigv1.OperandVersion{{Name: "operator", Version: getReleaseVersion()}}
	return c.syncStatus(co, conds)
}

func (c *statusController) getOrCreateClusterOperator() (*osconfigv1.ClusterOperator, error) {
	var co *osconfigv1.ClusterOperator

	co, err := c.clusterOperators.Get(context.Background(), clusterOperatorName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		klog.Infof("ClusterOperator does not exist, creating a new one.")
		co = &osconfigv1.ClusterOperator{
			ObjectMeta: metav1.ObjectMeta{
				Name: clusterOperatorName,
			},
			Status: osconfigv1.ClusterOperatorStatus{},
		}

		co, err = c.clusterOperators.Create(context.Background(), co, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to create cluster operator: %v", err)
		}
		return co, nil
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get clusterOperator %q: %v", clusterOperatorName, err)
	}
	return co, nil
}

//syncStatus applies the new condition to the mao ClusterOperator object.
func (c *statusController) syncStatus(co *osconfigv1.ClusterOperator, conds []osconfigv1.ClusterOperatorStatusCondition) error {
	for _, c := range conds {
		v1helpers.SetStatusCondition(&co.Status.Conditions, c)
	}

	if !equality.Semantic.DeepEqual(co.Status.RelatedObjects, relatedObjects) {
		co.Status.RelatedObjects = relatedObjects
	}

	_, err := c.clusterOperators.UpdateStatus(context.Background(), co, metav1.UpdateOptions{})
	return err
}

func getReleaseVersion() string {
	releaseVersion := os.Getenv(releaseVersionEnvVariableName)
	if len(releaseVersion) == 0 {
		releaseVersion = unknownVersionValue
		klog.Infof("%s environment variable is missing, defaulting to %q", releaseVersionEnvVariableName, unknownVersionValue)
	}
	return releaseVersion
}
