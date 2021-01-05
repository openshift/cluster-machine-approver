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
	"net/http"
	"os"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	configv1 "github.com/openshift/api/config/v1"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"github.com/openshift/cluster-machine-approver/pkg/controller"
	control "sigs.k8s.io/controller-runtime"
	ctrl "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	// defaultMetricsPort is the default port to expose metrics.
	defaultMetricsPort  = 9191
	configNamespace     = "openshift-config-managed"
	kubeletCAConfigMap  = "csr-controller-ca"
	machineAPINamespace = "openshift-machine-api"
)

func main() {
	var (
		kubeconfig string
		master     string
		cliConfig  string
	)

	flagSet := flag.NewFlagSet("cluster-machine-approver", flag.ExitOnError)

	klog.InitFlags(flagSet)

	flagSet.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flagSet.StringVar(&master, "master", "", "master url")
	flagSet.StringVar(&cliConfig, "config", "", "CLI config")
	flagSet.Parse(os.Args[1:])

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

	// Now let's start the controller
	stop := make(chan struct{})
	defer close(stop)

	startMetricsCollectionAndServer(indexer)

	// Create a new Cmd to provide shared dependencies and start components
	klog.Info("setting up manager")
	mgr, err := manager.New(control.GetConfigOrDie(), manager.Options{
		MetricsBindAddress: defaultMetricsPort,
	})
	if err != nil {
		klog.Fatalf("unable to set up overall controller manager: %v", err)
	}

	klog.Info("registering components")

	klog.Info("setting up scheme")
	if err := configv1.Install(mgr.GetScheme()); err != nil {
		klog.Fatal(err)
	}

	if err := machinev1.AddToScheme(mgr.GetScheme()); err != nil {
		klog.Fatal("unable to add Machines to scheme")
	}

	// Setup all Controllers
	klog.Info("setting up controllers")
	if err = (&controller.CertificateApprover{
		Client:  mgr.GetClient(),
		RestCfg: mgr.GetConfig(),
		Config:  controller.LoadConfig(cliConfig),
	}).SetupWithManager(mgr, ctrl.Options{}); err != nil {
		klog.Fatalf("unable to create CSR controller: %v", err)
	}

	statusController := NewStatusController(config)
	go statusController.Run(1, stop)
	statusController.versionGetter.SetVersion(operatorVersionKey, getReleaseVersion())

	// Start the Cmd
	klog.Info("starting the cmd")
	if err := mgr.Start(control.SetupSignalHandler()); err != nil {
		klog.Fatalf("unable to run the manager: %v", err)
	}
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
