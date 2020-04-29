/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/openshift/machine-api-operator/pkg/apis/machine/v1beta1"
	mapiclient "github.com/openshift/machine-api-operator/pkg/generated/clientset/versioned"
	machinev1beta1client "github.com/openshift/machine-api-operator/pkg/generated/clientset/versioned/typed/machine/v1beta1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	certificatesv1beta1client "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog"
)

const (
	// defaultMetricsPort is the default port to expose metrics.
	defaultMetricsPort  = 9191
	configNamespace     = "openshift-config-managed"
	kubeletCAConfigMap  = "csr-controller-ca"
	machineAPINamespace = "openshift-machine-api"
)

type Controller struct {
	config ClusterMachineApproverConfig

	client *kubernetes.Clientset

	csrs     certificatesv1beta1client.CertificateSigningRequestInterface
	nodes    corev1client.NodeInterface
	machines machinev1beta1client.MachineInterface

	indexer  cache.Indexer
	queue    workqueue.RateLimitingInterface
	informer cache.Controller
}

func NewController(config ClusterMachineApproverConfig, clientset *kubernetes.Clientset, machineClientset *mapiclient.Clientset, queue workqueue.RateLimitingInterface, indexer cache.Indexer, informer cache.Controller) *Controller {
	return &Controller{
		config: config,

		client: clientset,

		csrs:     clientset.CertificatesV1beta1().CertificateSigningRequests(),
		nodes:    clientset.CoreV1().Nodes(),
		machines: machineClientset.MachineV1beta1().Machines(machineAPINamespace),

		indexer:  indexer,
		queue:    queue,
		informer: informer,
	}
}

// getKubeletCA fetches the kubelet CA from the ConfigMap in the
// openshift-config-managed namespace.
func (c *Controller) getKubeletCA() (*x509.CertPool, error) {
	configMap, err := c.client.CoreV1().ConfigMaps(configNamespace).
		Get(context.Background(), kubeletCAConfigMap, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	caBundle, ok := configMap.Data["ca-bundle.crt"]
	if !ok {
		return nil, fmt.Errorf("no ca-bundle.crt in %s", kubeletCAConfigMap)
	}

	certPool := x509.NewCertPool()

	if ok := certPool.AppendCertsFromPEM([]byte(caBundle)); !ok {
		return nil, fmt.Errorf("failed to parse ca-bundle.crt in %s", kubeletCAConfigMap)
	}

	return certPool, nil
}

func (c *Controller) processNextItem() bool {
	// Wait until there is a new item in the working queue
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	// Tell the queue that we are done with processing this key. This unblocks the key for other workers
	// This allows safe parallel processing because two csrs with the same key are never processed in
	// parallel.
	defer c.queue.Done(key)

	// handle new CSR
	err := c.handleNewCSR(key.(string))
	// Handle the error if something went wrong during the execution of the business logic
	c.handleErr(err, key)
	return true
}

func (c *Controller) handleNewCSR(key string) error {
	obj, exists, err := c.indexer.GetByKey(key)
	if err != nil {
		klog.Errorf("Fetching object with key %s from store failed with %v", key, err)
		return err
	}

	if !exists {
		// Below we will warm up our cache with a CSR, so that we will see a delete for one csr
		klog.Infof("CSR %s does not exist anymore", key)
		return nil
	}

	// do not mutate informer cache
	csr := obj.(*certificatesv1beta1.CertificateSigningRequest).DeepCopy()
	// Note that you also have to check the uid if you have a local controlled resource, which
	// is dependent on the actual instance, to detect that a CSR was recreated with the same name
	klog.Infof("CSR %s added", csr.Name)

	if isApproved(csr) {
		klog.Infof("CSR %s is already approved", csr.Name)
		return nil
	}

	machines, err := c.machines.List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list machines: %v", err)
	}
	maxPending := getMaxPending(machines.Items)
	atomic.StoreUint32(&maxPendingCSRs, uint32(maxPending))
	if pending := recentlyPendingCSRs(c.indexer); pending > maxPending {
		klog.Errorf("Pending CSRs: %d; Max pending allowed: %d. Difference between pending CSRs and machines > %v. Ignoring all CSRs as too many recent pending CSRs seen", pending, maxPending, maxDiffBetweenPendingCSRsAndMachinesCount)
		return nil
	}

	parsedCSR, err := parseCSR(csr)
	if err != nil {
		klog.Infof("error parsing request CSR: %v", err)
		return nil
	}

	// TODO(bison): This is a quick hack, we should watch this and
	// reload it on change rather than fetching it for each CSR.
	kubeletCA, err := c.getKubeletCA()
	if err != nil {
		// This is not a fatal error.  The renewal authorization flow
		// depending on the existing serving cert will be skipped.
		klog.Errorf("failed to get kubelet CA: %v", err)
	}

	if err := authorizeCSR(c.config, machines.Items, c.nodes, csr, parsedCSR, kubeletCA); err != nil {
		// Don't deny since it might be someone else's CSR
		klog.Infof("CSR %s not authorized: %v", csr.Name, err)
		return err
	}

	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1beta1.CertificateSigningRequestCondition{
		Type:           certificatesv1beta1.CertificateApproved,
		Reason:         "NodeCSRApprove",
		Message:        "This CSR was approved by the Node CSR Approver",
		LastUpdateTime: metav1.Now(),
	})

	if _, err := c.csrs.UpdateApproval(context.Background(), csr, metav1.UpdateOptions{}); err != nil {
		return err
	}

	klog.Infof("CSR %s approved", csr.Name)

	return nil
}

func getMaxPending(machines []v1beta1.Machine) int {
	return len(machines) + maxDiffBetweenPendingCSRsAndMachinesCount
}

// handleErr checks if an error happened and makes sure we will retry later.
func (c *Controller) handleErr(err error, key interface{}) {
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		c.queue.Forget(key)
		return
	}

	// This controller retries 30 times if something goes wrong. After that, it stops trying.
	if c.queue.NumRequeues(key) < 30 {
		klog.Infof("Error syncing csr %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		c.queue.AddRateLimited(key)
		return
	}

	c.queue.Forget(key)
	// Report to an external entity that, even after several retries, we could not successfully process this key
	utilruntime.HandleError(err)
	klog.Infof("Dropping CSR %q out of the queue: %v", key, err)
}

func (c *Controller) Run(threadiness int, stopCh chan struct{}) {
	defer utilruntime.HandleCrash()

	// Let the workers stop when we are done
	defer c.queue.ShutDown()
	klog.Info("Starting Machine Approver")

	go c.informer.Run(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) runWorker() {
	for c.processNextItem() {
	}
}

func main() {
	var (
		kubeconfig string
		master     string
		cliConfig  string
	)

	klog.InitFlags(nil)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.StringVar(&cliConfig, "config", "", "CLI config")
	flag.Parse()

	// creates the connection
	config, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		klog.Fatal(err)
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		klog.Fatal(err)
	}

	machineClient, err := mapiclient.NewForConfig(config)
	if err != nil {
		klog.Fatal(err)
	}

	// create the csr watcher
	csrListWatcher := cache.NewListWatchFromClient(client.CertificatesV1beta1().RESTClient(), "certificatesigningrequests", v1.NamespaceAll, fields.Everything())

	// create the workqueue
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	// Bind the workqueue to a cache with the help of an informer. This way we make sure that
	// whenever the cache is updated, the csr key is added to the workqueue.
	// Note that when we finally process the item from the workqueue, we might see a newer version
	// of the CSR than the version which was responsible for triggering the update.
	indexer, informer := cache.NewIndexerInformer(csrListWatcher, &certificatesv1beta1.CertificateSigningRequest{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
	}, cache.Indexers{})

	controller := NewController(loadConfig(cliConfig), client, machineClient, queue, indexer, informer)

	// Now let's start the controller
	stop := make(chan struct{})
	defer close(stop)
	startMetricsCollectionAndServer(indexer)
	go controller.Run(1, stop)

	statusController := NewStatusController(config)
	go statusController.Run(1, stop)
	statusController.versionGetter.SetVersion(operatorVersionKey, getReleaseVersion())

	// Wait forever
	select {}
}

func startMetricsCollectionAndServer(indexer cache.Indexer) {
	metricsCollector := NewMetricsCollector(indexer)
	prometheus.MustRegister(metricsCollector)
	metricsPort := defaultMetricsPort
	if port, ok := os.LookupEnv("METRICS_PORT"); ok {
		v, err := strconv.Atoi(port)
		if err != nil {
			klog.Fatalf("Error parsing METRICS_PORT (%q) environment variable: %v", port, err)
		}
		metricsPort = v
	}
	klog.V(4).Info("Starting server to serve prometheus metrics")
	go startHTTPMetricServer(fmt.Sprintf("127.0.0.1:%d", metricsPort))
}

func startHTTPMetricServer(metricsPort string) {
	mux := http.NewServeMux()
	//TODO(vikasc): Use promhttp package for handler. This is Deprecated
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    metricsPort,
		Handler: mux,
	}
	klog.Fatal(server.ListenAndServe())
}

// parseCSR extracts the CSR from the API object and decodes it.
func parseCSR(obj *certificatesv1beta1.CertificateSigningRequest) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(obj.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}
