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

package status

import (
	"context"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	configv1 "github.com/openshift/api/config/v1"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"github.com/openshift/library-go/pkg/config/clusteroperator/v1helpers"
	appsv1 "k8s.io/api/apps/v1"
	certificatesv1 "k8s.io/api/certificates/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	timeout   = time.Second * 10
	forPeriod = time.Second * 3
)

// Mocked copy of clientWrongCN certificate
const csrData = `-----BEGIN CERTIFICATE REQUEST-----
MIICczCCAVsCAQAwLjEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRUwEwYDVQQDEwxz
eXN0ZW06bm9kZTowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/m0SP
zooyqB2raVHz183M2oUklhQCRP3DVqBFtt0kC5BB6zzfWdnk5clsu3yyA/vGNFo3
f+jNCrtP9/LVjXrbfiQrWfoyMW10gBOsSO7ovSuMhwPd7/8vEoUs+eOnYqp2khZ5
5KvJLMa7e59WZvzsqBWMMRWp9sCVXFpDwHbq8bAWoDZYhxyLR8f3d8sYH6oncj9m
lbn3NAPakTvSnSJwPepSby3bUykgCP7SuU7P4PrlAXf55kTX/+DV5ZG3TO/cdVhl
7F1rwQ6vetzp1bb36sbWtYv0oDMw9+tNpmiUfDr/9bOf/6zNTUij6ZRylYleo1I1
OKdI21OBRFAhhyVvAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAW5cOsaSYnURz
wnMRVpr7B821+DZu1G8Mv1lUzEvU+ZaVIaIL6Dv0BfDb9QLOYHzfceCYzJmavSOl
SdZLoLkL1SYUp77tGDcbwWQyngWY5G7upZudBMEYOHvG/4YnNPb+5BkIgsREJl/+
jVK2u+yuAkzkDdODM2NwRP9TGhPCbcqFeE2ozdJzluIGYafsQFPFr7kb8liiOV2O
u1xKRHq7Bb54+3sRt1PsmuYhIl4l1Sh1epKIhUGzBxyzJUAKsbsPk6s64euMhCxz
VoJUoVggIY3WxIVV+rpqlC7ThIgdYkq7fZeAeYAnbwB8eM208w5NUgxYTsZN7VDo
rj/Dkdwyag==
-----END CERTIFICATE REQUEST-----`

var _ = Describe("Cluster Operator status controller", func() {
	var operator *configv1.ClusterOperator
	var statusController *StatusController

	BeforeEach(func() {
		statusController = &StatusController{Client: cl}
		operator = &configv1.ClusterOperator{}
		operator.SetName(clusterOperatorName)
	})

	AfterEach(func() {
		os.Unsetenv(releaseVersionEnvVariableName)
		err := cl.Get(context.Background(), client.ObjectKey{Name: clusterOperatorName}, &configv1.ClusterOperator{})
		if err == nil || !apierrors.IsNotFound(err) {
			Expect(cl.Delete(context.Background(), operator)).To(Succeed())
		}
		Expect(apierrors.IsNotFound(cl.Get(context.Background(), client.ObjectKey{Name: clusterOperatorName}, &configv1.ClusterOperator{}))).To(BeTrue())
	})

	type testCase struct {
		releaseVersionEnvVariableValue string
		// Use a function so that runtime information can be populated (eg UID)
		existingCO *configv1.ClusterOperator
	}

	DescribeTable("should ensure Cluster Operator status is present",
		func(tc testCase) {
			By("Running test case")
			expectedVersion := unknownVersionValue
			if tc.releaseVersionEnvVariableValue != "" {
				expectedVersion = tc.releaseVersionEnvVariableValue
				Expect(os.Setenv(releaseVersionEnvVariableName, tc.releaseVersionEnvVariableValue)).To(Succeed())
			}

			if tc.existingCO != nil {
				err := cl.Create(context.Background(), tc.existingCO)
				Expect(err).To(Succeed())
			}

			Expect(statusController.reconcileStatus()).To(Succeed())

			getOp := &configv1.ClusterOperator{}
			Eventually(func() (bool, error) {
				var err error
				err = cl.Get(context.Background(), client.ObjectKey{Name: clusterOperatorName}, getOp)
				if err != nil {
					return false, err
				}
				// Successful sync means CO exists and the status is not empty
				return getOp != nil && len(getOp.Status.Versions) > 0, nil
			}, timeout).Should(BeTrue())

			// check version.
			Expect(getOp.Status.Versions).To(HaveLen(1))
			Expect(getOp.Status.Versions[0].Name).To(Equal(operatorVersionKey))
			Expect(getOp.Status.Versions[0].Version).To(Equal(expectedVersion))

			// check conditions.
			Expect(v1helpers.IsStatusConditionTrue(getOp.Status.Conditions, configv1.OperatorAvailable)).To(BeTrue())
			Expect(v1helpers.FindStatusCondition(getOp.Status.Conditions, configv1.OperatorAvailable).Reason).To(Equal(reasonAsExpected))
			Expect(v1helpers.IsStatusConditionTrue(getOp.Status.Conditions, configv1.OperatorUpgradeable)).To(BeTrue())
			Expect(v1helpers.FindStatusCondition(getOp.Status.Conditions, configv1.OperatorUpgradeable).Reason).To(Equal(reasonAsExpected))
			Expect(v1helpers.IsStatusConditionFalse(getOp.Status.Conditions, configv1.OperatorDegraded)).To(BeTrue())
			Expect(v1helpers.FindStatusCondition(getOp.Status.Conditions, configv1.OperatorDegraded).Reason).To(Equal(reasonAsExpected))
			Expect(v1helpers.IsStatusConditionFalse(getOp.Status.Conditions, configv1.OperatorProgressing)).To(BeTrue())
			Expect(v1helpers.FindStatusCondition(getOp.Status.Conditions, configv1.OperatorProgressing).Reason).To(Equal(reasonAsExpected))

			// check related objects.
			Expect(getOp.Status.RelatedObjects).To(Equal(relatedObjects))
		},
		Entry("when there's no existing cluster operator nor release version", testCase{
			releaseVersionEnvVariableValue: "",
			existingCO:                     nil,
		}),
		Entry("when there's no existing cluster operator but there's release version", testCase{
			releaseVersionEnvVariableValue: "a_cvo_given_version",
			existingCO:                     nil,
		}),
		Entry("when there's an existing cluster operator and a release version", testCase{
			releaseVersionEnvVariableValue: "another_cvo_given_version",
			existingCO: &configv1.ClusterOperator{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterOperatorName,
				},
				Status: configv1.ClusterOperatorStatus{
					Conditions: []configv1.ClusterOperatorStatusCondition{
						{
							Type:               configv1.OperatorAvailable,
							Status:             configv1.ConditionFalse,
							LastTransitionTime: metav1.Now(),
							Reason:             "",
							Message:            "",
						},
						{
							Type:               configv1.OperatorDegraded,
							Status:             configv1.ConditionTrue,
							LastTransitionTime: metav1.Now(),
							Reason:             "",
							Message:            "",
						},
						{
							Type:               configv1.OperatorProgressing,
							Status:             configv1.ConditionTrue,
							LastTransitionTime: metav1.Now(),
							Reason:             "",
							Message:            "",
						},
						{
							Type:               configv1.OperatorUpgradeable,
							Status:             configv1.ConditionFalse,
							LastTransitionTime: metav1.Now(),
							Reason:             "",
							Message:            "",
						},
					},
					Versions: []configv1.OperandVersion{
						{
							Name:    "anything",
							Version: "anything",
						},
					},
					RelatedObjects: []configv1.ObjectReference{
						{
							Group:    "",
							Resource: "anything",
							Name:     "anything",
						},
					},
				},
			},
		}),
	)
})

var _ = Describe("Filters are exclusive", func() {
	It("Should allow only 'machine-approver' clusterOperators", func() {
		operator := &configv1.ClusterOperator{}
		operator.SetName(clusterOperatorName)
		Expect(clusterOperatorFilter(operator)).To(BeTrue())
		operator.SetName("unknown")
		Expect(clusterOperatorFilter(operator)).To(BeFalse())
		Expect(clusterOperatorFilter(nil)).To(BeFalse())
	})

	It("Should allow only CSR objects", func() {
		Expect(csrFilter(&certificatesv1.CertificateSigningRequest{})).To(BeTrue())
		Expect(csrFilter(&machinev1.Machine{})).To(BeFalse())
	})
})

var _ = Describe("toClusterOperator mapping is targeting requests to 'machine-approver' clusterOperator", func() {
	It("Should map reconciles to 'machine-approver' CO", func() {
		object := certificatesv1.CertificateSigningRequest{}
		mapObject := handler.MapObject{
			Meta:   object.GetObjectMeta(),
			Object: &object,
		}
		requests := []reconcile.Request{{
			NamespacedName: client.ObjectKey{
				Name: clusterOperatorName,
			},
		}}
		Expect(toClusterOperator(mapObject)).To(Equal(requests))
	})
})

var _ = Describe("Reconcile triggers", func() {
	var operator *configv1.ClusterOperator
	var csr *certificatesv1.CertificateSigningRequest
	var env *envtest.Environment
	var c client.Client
	var done chan struct{}
	var reconciled chan struct{}

	BeforeEach(func() {
		reconciled = make(chan struct{})
		done = make(chan struct{})
		operator = &configv1.ClusterOperator{}
		operator.SetName(clusterOperatorName)

		csr = &certificatesv1.CertificateSigningRequest{
			Spec: certificatesv1.CertificateSigningRequestSpec{
				Request: []byte(csrData),
			},
		}
		csr.SetName("csrtest")

		By("Setting up test environment")
		env = &envtest.Environment{
			CRDDirectoryPaths: []string{filepath.Join("clusteroperator.crd.yaml")},
		}

		Expect(configv1.Install(scheme.Scheme)).To(Succeed())
		Expect(appsv1.AddToScheme(scheme.Scheme)).To(Succeed())

		config, err := env.Start()
		Expect(err).To(Succeed())
		Expect(config).ToNot(BeNil())
		mgr, err := manager.New(config, manager.Options{
			MetricsBindAddress: "0",
			Scheme:             scheme.Scheme,
		})
		Expect(err).To(Succeed())
		Expect(mgr).ToNot(BeNil())
		c = mgr.GetClient()
		Expect(c).ToNot(BeNil())

		Expect(buildWithManager(mgr, controller.Options{}, reconcile.Func(func(req reconcile.Request) (reconcile.Result, error) {
			Expect(req.Name).To(Equal(clusterOperatorName))
			Expect(req.Namespace).To(BeEmpty())
			reconciled <- struct{}{}
			return reconcile.Result{}, nil
		}))).To(Succeed())

		go func() {
			defer GinkgoRecover()
			Expect(mgr.Start(done)).To(Succeed())
		}()
	})

	AfterEach(func() {
		close(reconciled)
		close(done)
		Expect(env.Stop()).NotTo(HaveOccurred())
	})

	It("Should reconcile on CSR create and update, but not delete", func() {
		Expect(c.Create(context.Background(), csr)).To(Succeed())
		Eventually(reconciled, timeout).Should(Receive())

		csr.Status.Certificate = []byte(csrData)
		Expect(c.Status().Update(context.Background(), csr)).To(Succeed())
		Eventually(reconciled, timeout).Should(Receive())

		Expect(c.Delete(context.Background(), csr)).To(Succeed())
		Consistently(reconciled, forPeriod).ShouldNot(Receive())
	})

	It("Should reconcile on ClusterOperator create, update and delete", func() {
		Expect(c.Create(context.Background(), operator)).To(Succeed())
		Eventually(reconciled, timeout).Should(Receive())

		Expect(c.Status().Update(context.Background(), operator)).To(Succeed())
		Eventually(reconciled, timeout).Should(Receive())

		Expect(c.Delete(context.Background(), operator)).To(Succeed())
		Eventually(reconciled, timeout).Should(Receive())
	})

	It("Should not reconcile on ClusterOperator create, update and delete other than 'machine-approver'", func() {
		operator.SetName("nottheone")

		Expect(c.Create(context.Background(), operator)).To(Succeed())
		Consistently(reconciled, forPeriod).ShouldNot(Receive())

		Expect(c.Status().Update(context.Background(), operator)).To(Succeed())
		Consistently(reconciled, forPeriod).ShouldNot(Receive())

		Expect(c.Delete(context.Background(), operator)).To(Succeed())
		Consistently(reconciled, forPeriod).ShouldNot(Receive())
	})
})
