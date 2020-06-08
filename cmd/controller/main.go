/*
Copyright 2020 The Kubernetes Authors.

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
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"github.com/openshift/cluster-machine-approver/pkg/controller"
	"github.com/openshift/cluster-machine-approver/pkg/metrics"
	"github.com/openshift/cluster-machine-approver/pkg/status"
	"k8s.io/klog/v2"
	control "sigs.k8s.io/controller-runtime"
	ctrl "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

func main() {
	klog.InitFlags(nil)
	cliConfig := flag.String("config", "", "CLI config")
	flag.Parse()

	metricsPort := metrics.DefaultMetricsPort
	if port, ok := os.LookupEnv("METRICS_PORT"); ok {
		v, err := strconv.Atoi(port)
		if err != nil {
			klog.Fatalf("Error parsing METRICS_PORT (%q) environment variable: %v", port, err)
		}
		metricsPort = fmt.Sprintf(":%d", v)
	}

	// Create a new Cmd to provide shared dependencies and start components
	klog.Info("setting up manager")
	mgr, err := manager.New(control.GetConfigOrDie(), manager.Options{
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

	if err := machinev1.AddToScheme(mgr.GetScheme()); err != nil {
		klog.Fatal("unable to add Machines to scheme")
	}

	// Setup all Controllers
	klog.Info("setting up controllers")
	if err = (&controller.CertificateApprover{
		Client:  mgr.GetClient(),
		RestCfg: mgr.GetConfig(),
		Config:  controller.LoadConfig(*cliConfig),
	}).SetupWithManager(mgr, ctrl.Options{}); err != nil {
		klog.Fatalf("unable to create CSR controller: %v", err)
	}

	if err = (&status.StatusController{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr, ctrl.Options{}); err != nil {
		klog.Fatalf("unable to create Cluster Operator controller: %v", err)
	}

	// Start the Cmd
	klog.Info("starting the cmd")
	if err := mgr.Start(control.SetupSignalHandler()); err != nil {
		klog.Fatalf("unable to run the manager: %v", err)
	}
}
