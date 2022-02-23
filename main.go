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
	"time"

	configv1 "github.com/openshift/api/config/v1"
	networkv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/cluster-machine-approver/pkg/controller"
	"github.com/openshift/cluster-machine-approver/pkg/metrics"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
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
	var apiGroup string
	var apiVersion string
	var managementKubeConfigPath string
	var machineNamespace string
	var workloadKubeConfigPath string
	var disableStatusController bool
	var leaderElect bool
	var leaderElectLeaseDuration time.Duration
	var leaderElectRenewDeadline time.Duration
	var leaderElectRetryPeriod time.Duration
	var leaderElectResourceName string
	var leaderElectResourceNamespace string

	flagSet := flag.NewFlagSet("cluster-machine-approver", flag.ExitOnError)

	klog.InitFlags(flagSet)
	flagSet.StringVar(&cliConfig, "config", "", "CLI config")
	flagSet.StringVar(&apiGroup, "apigroup", "machine.openshift.io", "API group for machines, defaults to machine.openshift.io")
	flagSet.StringVar(&apiVersion, "apiversion", "", "API version for machines, will default to the server preferred version if not set")
	flagSet.StringVar(&managementKubeConfigPath, "management-cluster-kubeconfig", "", "management kubeconfig path,")
	flagSet.StringVar(&machineNamespace, "machine-namespace", "", "restrict machine operations to a specific namespace, if not set, all machines will be observed in approval decisions")
	flagSet.StringVar(&workloadKubeConfigPath, "workload-cluster-kubeconfig", "", "workload kubeconfig path")
	flagSet.BoolVar(&disableStatusController, "disable-status-controller", false, "disable status controller that will update the machine-approver clusteroperator status")

	flagSet.BoolVar(&leaderElect, "leader-elect", true, "use leader election when starting the manager.")
	flagSet.DurationVar(&leaderElectLeaseDuration, "leader-elect-lease-duration", 137*time.Second, "the duration that non-leader candidates will wait to force acquire leadership.")
	flagSet.DurationVar(&leaderElectRenewDeadline, "leader-elect-renew-deadline", 107*time.Second, "the duration that the acting controlplane will retry refreshing leadership before giving up.")
	flagSet.DurationVar(&leaderElectRetryPeriod, "leader-elect-retry-period", 26*time.Second, "the duration the LeaderElector clients should wait between tries of actions.")
	flagSet.StringVar(&leaderElectResourceName, "leader-elect-resource-name", "cluster-machine-approver-leader", "the name of the resource that leader election will use for holding the leader lock.")
	flagSet.StringVar(&leaderElectResourceNamespace, "leader-elect-resource-namespace", "openshift-cluster-machine-approver", "the namespace in which the leader election resource will be created.")
	flagSet.Parse(os.Args[1:])

	if err := validateapiGroup(apiGroup); err != nil {
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
		MetricsBindAddress:            metricsPort,
		LeaderElectionNamespace:       leaderElectResourceNamespace,
		LeaderElection:                leaderElect,
		LeaseDuration:                 &leaderElectLeaseDuration,
		LeaderElectionID:              leaderElectResourceName,
		LeaderElectionResourceLock:    resourcelock.LeasesResourceLock,
		LeaderElectionReleaseOnCancel: true,
		RetryPeriod:                   &leaderElectRetryPeriod,
		RenewDeadline:                 &leaderElectRenewDeadline,
	})
	if err != nil {
		klog.Fatalf("unable to set up overall controller manager: %v", err)
	}

	klog.Info("registering components")

	klog.Info("setting up scheme")
	if err := configv1.Install(mgr.GetScheme()); err != nil {
		klog.Fatal(err)
	}
	if err := networkv1.Install(mgr.GetScheme()); err != nil {
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
			&configv1.Network{},
			&networkv1.HostSubnet{},
		},
	})
	if err != nil {
		klog.Fatalf("unable to set up delegating client: %v", err)
	}

	// Setup all Controllers
	klog.Info("setting up controllers")
	if err = (&controller.CertificateApprover{
		MachineClient:    uncachedManagementClient,
		MachineRestCfg:   managementConfig,
		MachineNamespace: machineNamespace,
		NodeClient:       uncachedWorkloadClient,
		NodeRestCfg:      workloadConfig,
		Config:           controller.LoadConfig(cliConfig),
		APIGroup:         apiGroup,
		APIVersion:       apiVersion,
	}).SetupWithManager(mgr, ctrl.Options{}); err != nil {
		klog.Fatalf("unable to create CSR controller: %v", err)
	}

	if !disableStatusController {
		statusController := NewStatusController(mgr.GetConfig())
		go func() {
			<-mgr.Elected()
			statusController.Run(1, stop)
		}()
		statusController.versionGetter.SetVersion(operatorVersionKey, getReleaseVersion())
	}

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

func validateapiGroup(apiGroup string) error {
	if apiGroup != capiGroup && apiGroup != mapiGroup {
		return fmt.Errorf("unsupported apiGroup %s, allowed values %s, %s", apiGroup, capiGroup, mapiGroup)
	}

	return nil
}
