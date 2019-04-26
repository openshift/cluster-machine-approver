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
	"flag"
	"fmt"
	"time"

	"github.com/golang/glog"

	//"sigs.k8s.io/controller-runtime/pkg/client/config"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	csrclient "k8s.io/client-go/util/certificate/csr"
	"k8s.io/client-go/util/workqueue"

	mapiclient "github.com/openshift/cluster-api/pkg/client/clientset_generated/clientset"
)

const machineAPINamespace = "openshift-machine-api"

type Controller struct {
	clientset     *kubernetes.Clientset
	machineClient *mapiclient.Clientset
	indexer       cache.Indexer
	queue         workqueue.RateLimitingInterface
	informer      cache.Controller
}

func NewController(clientset *kubernetes.Clientset, machineClientset *mapiclient.Clientset, queue workqueue.RateLimitingInterface, indexer cache.Indexer, informer cache.Controller) *Controller {
	return &Controller{
		clientset:     clientset,
		machineClient: machineClientset,
		informer:      informer,
		indexer:       indexer,
		queue:         queue,
	}
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
		glog.Errorf("Fetching object with key %s from store failed with %v", key, err)
		return err
	}

	if !exists {
		// Below we will warm up our cache with a CSR, so that we will see a delete for one csr
		glog.Infof("CSR %s does not exist anymore\n", key)
		return nil
	}

	csr := obj.(*certificatesv1beta1.CertificateSigningRequest).DeepCopy()
	// Note that you also have to check the uid if you have a local controlled resource, which
	// is dependent on the actual instance, to detect that a CSR was recreated with the same name
	glog.Infof("CSR %s added\n", csr.GetName())

	var alreadyApproved bool
	for _, c := range csr.Status.Conditions {
		if c.Type == certificatesv1beta1.CertificateApproved {
			alreadyApproved = true
			break
		}
	}
	if alreadyApproved {
		glog.Infof("CSR %s is already approved\n", csr.GetName())
		return nil
	}

	parsedCSR, err := csrclient.ParseCSR(csr)
	if err != nil {
		glog.Infof("error parsing request CSR: %v", err)
		return nil
	}

	approvalMsg := "This CSR was approved by the Node CSR Approver"
	machineList, err := c.machineClient.MachineV1beta1().Machines(machineAPINamespace).List(metav1.ListOptions{})
	if err == nil {
		err := authorizeCSR(machineList, csr, parsedCSR)
		if err != nil {
			// Don't deny since it might be someone else's CSR
			glog.Infof("CSR %s not authorized: %v", csr.GetName(), err)
			return err
		}
	}
	if err != nil {
		glog.Infof("machine api not available: %v", err)
		// Validate the CSR for the bootstrapping phase without a SAN check.
		_, err := validateCSRContents(csr, parsedCSR)
		if err != nil {
			glog.Infof("CSR %s not valid: %v", csr.GetName(), err)
			return err
		}
		approvalMsg += " (no SAN validation)"
	}

	csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1beta1.CertificateSigningRequestCondition{
		Type:           certificatesv1beta1.CertificateApproved,
		Reason:         "NodeCSRApprove",
		Message:        approvalMsg,
		LastUpdateTime: metav1.Now(),
	})

	if _, err := c.clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(csr); err != nil {
		return err
	}

	glog.Infof("CSR %s approved\n", csr.GetName())

	return nil
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

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if c.queue.NumRequeues(key) < 5 {
		glog.Infof("Error syncing csr %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		c.queue.AddRateLimited(key)
		return
	}

	c.queue.Forget(key)
	// Report to an external entity that, even after several retries, we could not successfully process this key
	utilruntime.HandleError(err)
	glog.Infof("Dropping CSR %q out of the queue: %v", key, err)
}

func (c *Controller) Run(threadiness int, stopCh chan struct{}) {
	defer utilruntime.HandleCrash()

	// Let the workers stop when we are done
	defer c.queue.ShutDown()
	glog.Info("Starting Machine Approver")

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
	var kubeconfig string
	var master string

	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.Parse()

	// creates the connection
	config, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		glog.Fatal(err)
	}

	// creates the clientset
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		glog.Fatal(err)
	}

	machineClient, err := mapiclient.NewForConfig(config)
	if err != nil {
		glog.Fatal(err)
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

	controller := NewController(client, machineClient, queue, indexer, informer)

	// Now let's start the controller
	stop := make(chan struct{})
	defer close(stop)
	go controller.Run(1, stop)

	// Wait forever
	select {}
}
