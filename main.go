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
	"os"
	"strconv"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/cluster-machine-approver/pkg/controller"
	"github.com/openshift/cluster-machine-approver/pkg/metrics"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	control "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	capiGroup = "cluster.x-k8s.io"
	mapiGroup = "machine.openshift.io"
)

func main() {
	var cliConfig string
	var APIGroup string
	var managementKubeConfigPath string
	var workloadKubeConfigPath string

	flagSet := flag.NewFlagSet("cluster-machine-approver", flag.ExitOnError)

	klog.InitFlags(flagSet)
	flagSet.StringVar(&cliConfig, "config", "", "CLI config")
	flagSet.StringVar(&APIGroup, "apigroup", "machine.openshift.io", "API group for machines, defaults to machine.openshift.io")
	flagSet.StringVar(&managementKubeConfigPath, "management-cluster-kubeconfig", "", "management kubeconfig path,")
	flagSet.StringVar(&workloadKubeConfigPath, "workload-cluster-kubeconfig", "", "workload kubeconfig path")

	flagSet.Parse(os.Args[1:])

	if err := validateAPIGroup(APIGroup); err != nil {
		klog.Fatalf(err.Error())
	}

	// Now let's start the controller
	stop := make(chan struct{})
	defer close(stop)

	metricsPort := metrics.DefaultMetricsPort
	if port, ok := os.LookupEnv("METRICS_PORT"); ok {
		v, err := strconv.Atoi(port)
		if err != nil {
			klog.Fatalf("Error parsing METRICS_PORT (%q) environment variable: %v", port, err)
		}
		metricsPort = fmt.Sprintf(":%d", v)
	}

	managementConfig, workloadConfig, err := createClientConfigs(managementKubeConfigPath, workloadKubeConfigPath)
	if err != nil {
		klog.Fatalf("Can't set client configs: %v", err)
	}

	managementClient, workloadClient, err := createClients(managementConfig, workloadConfig)
	if err != nil {
		klog.Fatalf("Can't create clients: %v", err)
	}

	// Create a new Cmd to provide shared dependencies and start components
	klog.Info("setting up manager")
	mgr, err := manager.New(workloadConfig, manager.Options{
		MetricsBindAddress: metricsPort,
	})
	if err != nil {
		klog.Fatalf("unable to set up overall controller manager: %v", err)
	}

	klog.Info("registering components")

	klog.Info("setting up scheme")
	if err := configv1.Install(mgr.GetScheme()); err != nil {
		klog.Fatal(err)
	}

	// Prevent the controller from caching node and machine objects.
	// Stale nodes and machines can cause the approver to not approve certificates
	// within a timely manner, leading to failed node bootstraps.
	uncachedManagementClient, err := client.NewDelegatingClient(client.NewDelegatingClientInput{
		Client:      *managementClient,
		CacheReader: mgr.GetClient(),
		// CacheUnstructured should be false because we manipulate with unstructured machines
		CacheUnstructured: false,
	})
	if err != nil {
		klog.Fatalf("unable to set up delegating client: %v", err)
	}

	uncachedWorkloadClient, err := client.NewDelegatingClient(client.NewDelegatingClientInput{
		Client:      *workloadClient,
		CacheReader: mgr.GetClient(),
		UncachedObjects: []client.Object{
			&corev1.Node{},
		},
	})
	if err != nil {
		klog.Fatalf("unable to set up delegating client: %v", err)
	}

	// Setup all Controllers
	klog.Info("setting up controllers")
	if err = (&controller.CertificateApprover{
		MachineClient:  uncachedManagementClient,
		MachineRestCfg: managementConfig,
		NodeClient:     uncachedWorkloadClient,
		NodeRestCfg:    workloadConfig,
		Config:         controller.LoadConfig(cliConfig),
		APIGroup:       APIGroup,
	}).SetupWithManager(mgr, ctrl.Options{}); err != nil {
		klog.Fatalf("unable to create CSR controller: %v", err)
	}

	statusController := NewStatusController(mgr.GetConfig())
	go statusController.Run(1, stop)
	statusController.versionGetter.SetVersion(operatorVersionKey, getReleaseVersion())

	// Start the Cmd
	klog.Info("starting the cmd")
	if err := mgr.Start(control.SetupSignalHandler()); err != nil {
		klog.Fatalf("unable to run the manager: %v", err)
	}
}

// createClientConfigs allow users to provide second config using management-kubeconfig, if specified
// try to build it from provided path. First returned value is management config used for Machines,
// second is workload config used for Node/CSRs.
func createClientConfigs(managementKubeConfigPath, workloadKubeConfigPath string) (*rest.Config, *rest.Config, error) {
	managementConfig, err := clientcmd.BuildConfigFromFlags("", managementKubeConfigPath)
	if err != nil {
		return nil, nil, err
	}

	workloadConfig, err := clientcmd.BuildConfigFromFlags("", workloadKubeConfigPath)
	if err != nil {
		return nil, nil, err
	}

	return managementConfig, workloadConfig, nil
}

// createClients creates 2 API clients, First returned value is management client used for Machines,
// second is workload client used for Node/CSRs.
func createClients(managementConfig, workloadConfig *rest.Config) (*client.Client, *client.Client, error) {
	managementClient, err := client.New(managementConfig, client.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client: %v", err)
	}

	workloadClient, err := client.New(workloadConfig, client.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client: %v", err)
	}

	return &managementClient, &workloadClient, nil
}

func validateAPIGroup(apiGroup string) error {
	if apiGroup != capiGroup && apiGroup != mapiGroup {
		return fmt.Errorf("unsupported APIGroup %s, allowed values %s, %s", apiGroup, capiGroup, mapiGroup)
	}

	return nil
}
