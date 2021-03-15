package controller

import (
	"context"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"path/filepath"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	"testing"
)

func init() {
	klog.InitFlags(nil)
	klog.SetOutput(GinkgoWriter)
}

var (
	c      client.Client
	env    *envtest.Environment
	config *rest.Config
)

func TestMachinesetController(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Machine Approver controller test suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	var err error

	env = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("testing", "machine_crd.yaml")},
		ErrorIfCRDPathMissing: true,
	}

	config, err = env.Start()
	Expect(err).To(Succeed())
	Expect(config).ToNot(BeNil())

	c, err = client.New(config, client.Options{Scheme: scheme.Scheme})
	Expect(err).To(Succeed())
	Expect(c).ToNot(BeNil())

	Expect(machinev1.AddToScheme(scheme.Scheme)).To(Succeed())
	Expect(appsv1.AddToScheme(scheme.Scheme)).To(Succeed())

	ns := &v1.Namespace{}
	ns.SetName(configNamespace)
	Expect(c.Create(context.Background(), ns)).To(Succeed())

	Expect(machinev1.AddToScheme(scheme.Scheme)).To(Succeed())
	Expect(appsv1.AddToScheme(scheme.Scheme)).To(Succeed())
})

var _ = AfterSuite(func() {
	if env != nil {
		Expect(env.Stop()).To(Succeed())
	}
})
