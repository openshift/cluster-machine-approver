/*
Copyright 2018 The Kubernetes Authors.

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

package controller

import (
	"context"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func init() {
	klog.InitFlags(nil)
	klog.SetOutput(GinkgoWriter)
}

var (
	c      client.Client
	env    *envtest.Environment
	config *rest.Config
	mgr    manager.Manager
	done   chan struct{}
)

func TestMachinesetController(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Cluster Operator status controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	Expect(machinev1.AddToScheme(scheme.Scheme)).To(Succeed())
	Expect(appsv1.AddToScheme(scheme.Scheme)).To(Succeed())
})

func setupEnv() {
	env = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("machine.openshift.io_machines.yaml")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	config, err = env.Start()
	Expect(err).To(Succeed())
	Expect(config).ToNot(BeNil())

	c, err = client.New(config, client.Options{Scheme: scheme.Scheme})
	Expect(err).To(Succeed())
	Expect(c).ToNot(BeNil())

	ns := &v1.Namespace{}
	ns.SetName(configNamespace)
	Expect(c.Create(context.Background(), ns)).To(Succeed())
}

func setupMgr(reconciler reconcile.Reconciler) {
	var err error
	setupEnv()
	mgr, err = manager.New(config, manager.Options{
		MetricsBindAddress: "0",
		Scheme:             scheme.Scheme,
	})
	Expect(err).To(Succeed())
	Expect(mgr).ToNot(BeNil())

	approver := &CertificateApprover{
		Client: c,
	}
	Expect(approver.buildWithManager(mgr, controller.Options{}, reconciler)).To(Succeed())
	c = mgr.GetClient()
	done = make(chan struct{})
	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(done)).To(Succeed())
	}()
}

var _ = BeforeEach(func() {
	env, config, mgr, c = nil, nil, nil, nil
})

var _ = AfterEach(func() {
	if env != nil {
		Expect(env.Stop()).To(Succeed())
	}
})
