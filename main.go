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
	"crypto/tls"
	goflag "flag"
	"fmt"
	"os"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	networkv1 "github.com/openshift/api/network/v1"
	"github.com/openshift/cluster-machine-approver/pkg/controller"
	"github.com/openshift/cluster-machine-approver/pkg/metrics"
	utiltls "github.com/openshift/library-go/pkg/controllerruntime/tls"
	flag "github.com/spf13/pflag"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	control "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

const (
	capiGroup = "cluster.x-k8s.io"
	mapiGroup = "machine.openshift.io"
)

func main() {
	var cliConfig string
	var apiGroupVersions []string
	var apiGroup string // deprecated
	var managementKubeConfigPath string
	var machineNamespace string
	var workloadKubeConfigPath string
	var disableStatusController bool
	var maxConcurrentReconciles int

	var leaderElect bool
	var leaderElectLeaseDuration time.Duration
	var leaderElectRenewDeadline time.Duration
	var leaderElectRetryPeriod time.Duration
	var leaderElectResourceName string
	var leaderElectResourceNamespace string
	var metricsBindAddress string

	flagSet := flag.NewFlagSet("cluster-machine-approver", flag.ExitOnError)

	// Set logger for controller-runtime
	control.SetLogger(klog.NewKlogr())

	scheme := runtime.NewScheme()
	if err := configv1.AddToScheme(scheme); err != nil {
		klog.Fatalf("unable to add configv1 to scheme: %v", err)
	}

	klog.InitFlags(nil)
	flagSet.AddGoFlagSet(goflag.CommandLine)

	flagSet.StringVar(&cliConfig, "config", "", "CLI config")
	flagSet.StringSliceVar(&apiGroupVersions, "api-group-version", nil, "API group and version for machines in format '<group>/<version' or just '<group>'. If version is omitted, it will be set to the latest registered version in the cluster. Defaults to 'machine.openshift.io'. This option can be given multiple times.")
	flagSet.StringVar(&managementKubeConfigPath, "management-cluster-kubeconfig", "", "management kubeconfig path,")
	flagSet.StringVar(&machineNamespace, "machine-namespace", "", "restrict machine operations to a specific namespace, if not set, all machines will be observed in approval decisions")
	flagSet.StringVar(&workloadKubeConfigPath, "workload-cluster-kubeconfig", "", "workload kubeconfig path")
	flagSet.BoolVar(&disableStatusController, "disable-status-controller", false, "disable status controller that will update the machine-approver clusteroperator status")
	flagSet.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", 1, "maximum number concurrent reconciles for the CSR approving controller")

	flagSet.BoolVar(&leaderElect, "leader-elect", true, "use leader election when starting the manager.")
	flagSet.DurationVar(&leaderElectLeaseDuration, "leader-elect-lease-duration", 137*time.Second, "the duration that non-leader candidates will wait to force acquire leadership.")
	flagSet.DurationVar(&leaderElectRenewDeadline, "leader-elect-renew-deadline", 107*time.Second, "the duration that the acting controlplane will retry refreshing leadership before giving up.")
	flagSet.DurationVar(&leaderElectRetryPeriod, "leader-elect-retry-period", 26*time.Second, "the duration the LeaderElector clients should wait between tries of actions.")
	flagSet.StringVar(&leaderElectResourceName, "leader-elect-resource-name", "cluster-machine-approver-leader", "the name of the resource that leader election will use for holding the leader lock.")
	flagSet.StringVar(&leaderElectResourceNamespace, "leader-elect-resource-namespace", "openshift-cluster-machine-approver", "the namespace in which the leader election resource will be created.")
	flagSet.StringVar(&metricsBindAddress, "metrics-bind-address", metrics.DefaultMetricsBindAddress, "the address the metrics endpoint binds to.")

	// Deprecated options
	flagSet.StringVar(&apiGroup, "apigroup", "", "API group for machines")
	flagSet.MarkDeprecated("apigroup", "apigroup has been deprecated in favor of api-group-version option")

	flagSet.Parse(os.Args[1:])

	if apiGroup != "" && len(apiGroupVersions) > 0 {
		klog.Fatal("Cannot set both --apigroup and --api-group-version options together.")
	}

	var parsedAPIGroupVersions []schema.GroupVersion

	if len(apiGroupVersions) > 0 {
		// Parsing API Group Versions
		for _, apiGroupVersion := range apiGroupVersions {
			parsedAPIGroupVersion, err := parseGroupVersion(apiGroupVersion)
			if err != nil {
				klog.Fatalf("Invalid API Group Version value: %s", apiGroupVersion)
			}
			parsedAPIGroupVersions = append(parsedAPIGroupVersions, parsedAPIGroupVersion)
		}
	} else {
		// Setting the default
		parsedAPIGroupVersions = []schema.GroupVersion{
			{Group: mapiGroup},
		}
	}

	if apiGroup != "" {
		// For backward compatibility with --apigroup option
		parsedAPIGroupVersions = []schema.GroupVersion{
			{Group: apiGroup},
		}
	}

	for _, parsedAPIGroupVersion := range parsedAPIGroupVersions {
		if err := validateAPIGroup(parsedAPIGroupVersion.Group); err != nil {
			klog.Fatalf("%s", err.Error())
		}
	}

	// Now let's start the controller
	stop := make(chan struct{})
	defer close(stop)

	managementConfig, workloadConfig, err := createClientConfigs(managementKubeConfigPath, workloadKubeConfigPath)
	if err != nil {
		klog.Fatalf("Can't set client configs: %v", err)
	}

	k8sClient, err := client.New(managementConfig, client.Options{Scheme: scheme})
	if err != nil {
		klog.Fatalf("unable to create Kubernetes client: %v", err)
	}

	// Fetch the TLS profile from the APIServer resource.
	tlsSecurityProfileSpec, err := utiltls.FetchAPIServerTLSProfile(context.Background(), k8sClient)
	if err != nil {
		klog.Fatalf("unable to get TLS profile from API server: %v", err)
	}

	// Create the TLS configuration function for the server endpoints.
	tlsConfig, unsupportedCiphers := utiltls.NewTLSConfigFromProfile(tlsSecurityProfileSpec)
	if len(unsupportedCiphers) > 0 {
		klog.Infof("TLS configuration contains unsupported ciphers that will be ignored: %v", unsupportedCiphers)
	}

	// Create a context that can be cancelled when there is a need to shut down the manager	.
	ctx, cancel := context.WithCancel(control.SetupSignalHandler())
	// Ensure the context is cancelled when the program exits.
	defer cancel()

	// Create a new Cmd to provide shared dependencies and start components
	klog.Info("setting up manager")
	mgr, err := manager.New(workloadConfig, manager.Options{
		Metrics: server.Options{
			BindAddress:   metricsBindAddress,
			SecureServing: true,
			TLSOpts:       []func(*tls.Config){tlsConfig},
		},
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

	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &certificatesv1.CertificateSigningRequest{}, "spec.signerName", func(rawObj client.Object) []string {
		csr := rawObj.(*certificatesv1.CertificateSigningRequest)
		return []string{csr.Spec.SignerName}
	}); err != nil {
		klog.Fatalf("failed to index field spec.signerName: %v", err)
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
	uncachedManagementClient, err := client.New(managementConfig, client.Options{
		Cache: &client.CacheOptions{
			Reader: mgr.GetClient(),
			// Unstructured should be false because we manipulate with unstructured machines
			Unstructured: false,
		},
	})
	if err != nil {
		klog.Fatalf("unable to set up delegating client: %v", err)
	}

	uncachedWorkloadClient, err := client.New(workloadConfig, client.Options{
		Cache: &client.CacheOptions{
			Reader:       mgr.GetClient(),
			Unstructured: false,
			DisableFor: []client.Object{
				&corev1.Node{},
				&configv1.Network{},
				&networkv1.HostSubnet{},
			},
		},
	})
	if err != nil {
		klog.Fatalf("unable to set up delegating client: %v", err)
	}

	// Setup all Controllers
	klog.Info("setting up controllers")
	if err = (&controller.CertificateApprover{
		ManagementClient: uncachedManagementClient,
		MachineRestCfg:   managementConfig,
		MachineNamespace: machineNamespace,
		WorkloadClient:   uncachedWorkloadClient,
		NodeRestCfg:      workloadConfig,
		Config:           controller.LoadConfig(cliConfig),
		APIGroupVersions: parsedAPIGroupVersions,
	}).SetupWithManager(mgr, ctrl.Options{
		MaxConcurrentReconciles: maxConcurrentReconciles,
	}); err != nil {
		klog.Fatalf("unable to create CSR controller: %v", err)
	}

	if !disableStatusController {
		mgrClock := clock.RealClock{}
		statusController := NewStatusController(mgr.GetConfig(), mgrClock)
		go func() {
			<-mgr.Elected()
			statusController.Run(1, stop)
		}()
		statusController.versionGetter.SetVersion(operatorVersionKey, getReleaseVersion())
	}

	// Set up the TLS security profile watcher controller.
	// This will trigger a graceful shutdown when the TLS profile changes.
	if err := (&utiltls.TLSSecurityProfileWatcher{
		Client:                mgr.GetClient(),
		InitialTLSProfileSpec: tlsSecurityProfileSpec,
		Shutdown:              cancel,
	}).SetupWithManager(mgr); err != nil {
		klog.Fatalf("unable to create TLS security profile watcher controller: %v", err)
	}

	// Start the Cmd
	klog.Info("starting the cmd")
	if err := mgr.Start(ctx); err != nil {
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

// parseGroupVersion turns "group/version" string into a GroupVersion struct. It reports error
// if it cannot parse the string.
func parseGroupVersion(gv string) (schema.GroupVersion, error) {
	if (len(gv) == 0) || (gv == "/") {
		return schema.GroupVersion{}, nil
	}

	switch strings.Count(gv, "/") {
	case 0:
		return schema.GroupVersion{Group: gv}, nil
	case 1:
		i := strings.Index(gv, "/")
		return schema.GroupVersion{Group: gv[:i], Version: gv[i+1:]}, nil
	default:
		return schema.GroupVersion{}, fmt.Errorf("unexpected GroupVersion string: %v", gv)
	}
}
