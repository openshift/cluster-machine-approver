// Copyright 2026 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	// Deliberately not dot-importing gomega to avoid accidentally using bare
	// async functions against the default Gomega instance. If there's a way to
	// just dot-import the matchers that would be welcome.
	"github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// componentReadinessPrefix is registered in openshift-eng/ci-test-mapping to map to the Cluster Machine Approver component.
	// DO NOT CHANGE THIS VALUE.
	componentReadinessPrefix = "[sig-cluster-lifecycle] Cluster Machine Approver "

	// controllerActionTimeout is a suitable timeout when waiting for a controller to act on a change.
	controllerActionTimeout = 2 * time.Minute
	// controllerPollingInterval is a suitable interval when polling for a controller to act on a change.
	controllerPollingInterval = 500 * time.Millisecond
	// nodeReadySettlement is how long a Node must have been continuously Ready before we consider it settled.
	nodeReadySettlement = time.Minute
	// servingCSRWorkTimeout bounds all work within a single spec, across all attempted Nodes.
	servingCSRWorkTimeout = 10 * time.Minute
	// servingCSRCleanupTimeout bounds cleanup retries during DeferCleanup, which
	// otherwise inherit only the long-lived suite context.
	servingCSRCleanupTimeout = time.Minute
)

type servingCSRNodeRole string

const (
	servingCSRWorker       servingCSRNodeRole = "worker"
	servingCSRControlPlane servingCSRNodeRole = "control-plane"
)

var _ = Describe(componentReadinessPrefix+"Kubelet serving CSR approval", Label("Parallel"), func() {
	var (
		client kubernetes.Interface
		g      = gomega.Default
	)

	BeforeEach(func(ctx SpecContext) {
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		g.Expect(err).NotTo(gomega.HaveOccurred(), "failed to load Kubernetes client configuration")

		client, err = kubernetes.NewForConfig(config)
		g.Expect(err).NotTo(gomega.HaveOccurred(), "failed to create Kubernetes client")

		if isMicroShift(ctx, g, client) {
			Skip("kubelet serving CSR approval is not supported on MicroShift")
		}
	})

	It("approves a renewed kubelet serving CSR on a worker node", func(ctx SpecContext) {
		runServingCSRDisruption(g, ctx, client, servingCSRWorker)
	})

	It("approves a renewed kubelet serving CSR on a control-plane node", func(ctx SpecContext) {
		runServingCSRDisruption(g, ctx, client, servingCSRControlPlane)
	})
})

// runServingCSRDisruption retries failed attempts only if their Node is no longer stable.
func runServingCSRDisruption(g gomega.Gomega, ctx context.Context, client kubernetes.Interface, role servingCSRNodeRole) {
	GinkgoHelper()

	ctx, cancel := context.WithTimeout(ctx, servingCSRWorkTimeout)
	defer cancel()

	var nodes *corev1.NodeList
	g.Eventually(ctx, func(pollCtx context.Context) error {
		var err error
		nodes, err = client.CoreV1().Nodes().List(pollCtx, metav1.ListOptions{})
		return err
	}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(gomega.Succeed())

	// Filter the nodes to only include those with the desired role.
	var roleNodes []*corev1.Node
	for _, node := range nodes.Items {
		if nodeMatchesRole(&node, role) {
			roleNodes = append(roleNodes, &node)
		}
	}

	// If there are no nodes with the desired role, skip the test.
	//
	// Note that we intentionally haven't filtered for usable Nodes yet. The
	// intended use case of this skip is topologies which don't have nodes of a
	// particular role. If Nodes are present but none are usable that's still an
	// error.
	if len(roleNodes) == 0 {
		Skip(fmt.Sprintf("no nodes with the %s role were found", role))
	}

	// Shuffle the nodes to avoid bias towards the first node in the list.
	rand.Shuffle(len(roleNodes), func(i, j int) { roleNodes[i], roleNodes[j] = roleNodes[j], roleNodes[i] })

	// Attempt to force a CSR renewal on each node in turn until we either
	// succeed or run out of Nodes.
	//
	// We need to consider that Nodes may be added and removed by the parallel
	// suite, so it's possible we will try to use an unsuitable Node. We deal
	// with that in 2 ways:
	// 1. We skip any Node which does not meet the stable criteria before
	//    starting.
	// 2. If the test fails, we check again to see if the Node still meets the
	//    stable criteria. We ignore the failure and try the next Node if it does
	//    not.

	for _, node := range roleNodes {
		// Get a fresh copy of the node to avoid stale data
		freshNode := getFreshNode(g, ctx, client, node)

		// Skip this Node if it was removed, replaced, or it is not settled
		if freshNode == nil || freshNode.UID != node.UID || !nodeIsSettled(freshNode, time.Now()) {
			continue
		}

		marker := newServingCSRMarker(freshNode.Status.Addresses)
		DeferCleanup(func(cleanupCtx context.Context) {
			ctx, cancel := context.WithTimeout(cleanupCtx, servingCSRCleanupTimeout)
			defer cancel()
			g.Eventually(ctx, func() error {
				return updateNodeMarker(ctx, client, node, marker, false)
			}).WithPolling(controllerPollingInterval).Should(gomega.Succeed(), "failed to remove temporary marker from node")
		})

		singleNodeErr := runWithGomega(func(nodeG gomega.Gomega) {
			// Fetch the baseline CSRs before forcing an invalid CSR
			baselineCSRs := fetchBaselineCSRs(nodeG, ctx, client)

			var invalidCSR *certificatesv1.CertificateSigningRequest
			By("Updating node with temporary marker and waiting for temporary CSR", func() {
				invalidCSR = forceInvalidCSR(nodeG, ctx, client, node, marker, baselineCSRs)
			})
			DeferCleanup(func(cleanupCtx context.Context) {
				ctx, cancel := context.WithTimeout(cleanupCtx, servingCSRCleanupTimeout)
				defer cancel()
				g.Eventually(ctx, func(pollCtx context.Context) error {
					err := client.CertificatesV1().CertificateSigningRequests().Delete(pollCtx, invalidCSR.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &invalidCSR.UID}})
					if apierrors.IsNotFound(err) {
						return nil
					}
					return err
				}).WithPolling(controllerPollingInterval).Should(gomega.Succeed(), "failed to delete invalid CSR")
			})

			By("Removing invalid marker from node", func() {
				nodeG.Eventually(ctx, func(pollCtx context.Context) error {
					return updateNodeMarker(pollCtx, client, node, marker, false)
				}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(gomega.Succeed(), "failed to remove invalid marker from node")
			})

			// Re-fetch the baseline CSRs before denying the invalid CSR
			baselineCSRs = fetchBaselineCSRs(nodeG, ctx, client)

			By("Denying invalid CSR", func() {
				denyInvalidCSR(nodeG, ctx, client, invalidCSR)
			})

			var renewalCSR *certificatesv1.CertificateSigningRequest
			By("Waiting for renewal CSR", func() {
				renewalCSR = waitForRenewalCSR(nodeG, ctx, client, node, baselineCSRs, marker)
			})

			By("Waiting for approval", func() {
				waitForCSRApproval(nodeG, ctx, client, renewalCSR)
			})
		})

		// We're finished if the validation attempt succeeded
		if singleNodeErr == nil {
			return
		}

		freshNode = getFreshNode(g, ctx, client, node)
		if freshNode == nil || freshNode.UID != node.UID || !nodeIsSettled(freshNode, time.Now()) {
			By(fmt.Sprintf("ignoring failure on node %q which is no longer stable: %v", node.Name, singleNodeErr))
			continue
		}

		Fail(fmt.Sprintf("failed to validate CSR renewal on node %q: %v", node.Name, singleNodeErr))
	}

	Fail("failed to validate CSR renewal on any node")
}

// runWithGomega executes fn with a new Gomega instance. It returns Gomega
// assertion failures as an error without panicking.
func runWithGomega(fn func(g gomega.Gomega)) (err error) {
	type gomegaAssertionError string

	failHandler := func(message string, _ ...int) {
		panic(gomegaAssertionError(message))
	}

	defer func() {
		if r := recover(); r != nil {
			if failure, ok := r.(gomegaAssertionError); ok {
				err = errors.New(string(failure))
			} else {
				panic(r)
			}
		}
	}()

	g := gomega.NewGomega(failHandler)
	fn(g)

	return nil
}

// isMicroShift returns true if the cluster is running MicroShift.
// It uses the same marker as the CAPI e2e tests.
func isMicroShift(ctx context.Context, g gomega.Gomega, client kubernetes.Interface) bool {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	isMicroShift := false
	g.Eventually(timeoutCtx, func(pollCtx context.Context) error {
		_, err := client.CoreV1().ConfigMaps("kube-public").Get(pollCtx, "microshift-version", metav1.GetOptions{})
		switch {
		case err == nil:
			isMicroShift = true
			return nil
		case apierrors.IsNotFound(err):
			return nil
		default:
			return err
		}
	}).Should(gomega.Succeed(), "failed to detect MicroShift from ConfigMap kube-public/microshift-version")

	return isMicroShift
}

func getFreshNode(g gomega.Gomega, ctx context.Context, client kubernetes.Interface, node *corev1.Node) *corev1.Node {
	var freshNode *corev1.Node
	g.Eventually(ctx, func(pollCtx context.Context) error {
		var err error
		freshNode, err = client.CoreV1().Nodes().Get(pollCtx, node.Name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(gomega.Succeed(), fmt.Sprintf("failed to get fresh node %q", node.Name))
	return freshNode
}

func fetchBaselineCSRs(g gomega.Gomega, ctx context.Context, client kubernetes.Interface) map[types.UID]struct{} {
	var csrs *certificatesv1.CertificateSigningRequestList
	By("Fetching pre-existing CSRs", func() {
		g.Eventually(ctx, func(pollCtx context.Context) error {
			var err error
			csrs, err = client.CertificatesV1().CertificateSigningRequests().List(pollCtx, metav1.ListOptions{})
			return err
		}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(gomega.Succeed(), "failed to list baseline CSRs")
	})

	baselineCSRs := make(map[types.UID]struct{})
	for _, csr := range csrs.Items {
		baselineCSRs[csr.UID] = struct{}{}
	}

	return baselineCSRs
}

func forceInvalidCSR(g gomega.Gomega, ctx context.Context, client kubernetes.Interface, node *corev1.Node, marker string, baselineCSRs map[types.UID]struct{}) *certificatesv1.CertificateSigningRequest {
	GinkgoHelper()

	var temporaryCSR certificatesv1.CertificateSigningRequest
	g.Eventually(ctx, func(pollCtx context.Context) ([]certificatesv1.CertificateSigningRequest, error) {
		err := updateNodeMarker(pollCtx, client, node, marker, true)
		if err != nil {
			return nil, err
		}

		csrs, err := client.CertificatesV1().CertificateSigningRequests().List(pollCtx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}

		return csrs.Items, nil
	}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(gomega.ContainElement(gomega.SatisfyAll(
		beFreshServingCSR(node.Name, baselineCSRs),
		gomega.HaveField("Status.Certificate", gomega.BeEmpty()),
		gomega.HaveField("Status.Conditions", gomega.Not(gomega.ContainElement(gomega.HaveField("Type", gomega.BeElementOf(
			certificatesv1.CertificateApproved, certificatesv1.CertificateDenied, certificatesv1.CertificateFailed,
		))))),
		gomega.HaveField("Spec.Request", gomega.WithTransform(csrRequestSANs, gomega.HaveField("DNSNames", gomega.ContainElement(marker)))),
	), &temporaryCSR))

	return &temporaryCSR
}

func denyInvalidCSR(g gomega.Gomega, ctx context.Context, client kubernetes.Interface, invalidCSR *certificatesv1.CertificateSigningRequest) {
	g.Eventually(ctx, func(pollCtx context.Context) error {
		freshCSR, err := client.CertificatesV1().CertificateSigningRequests().Get(pollCtx, invalidCSR.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if freshCSR.UID != invalidCSR.UID || len(freshCSR.Status.Certificate) > 0 || csrHasCondition(freshCSR, certificatesv1.CertificateApproved) || csrHasCondition(freshCSR, certificatesv1.CertificateFailed) {
			return gomega.StopTrying(fmt.Sprintf("temporary CSR %q changed, was unexpectedly approved, issued or failed", freshCSR.Name))
		}

		if csrHasCondition(freshCSR, certificatesv1.CertificateDenied) {
			return nil // A previous UpdateApproval may have succeeded despite a client error.
		}
		freshCSR.Status.Conditions = append(freshCSR.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
			Type:           certificatesv1.CertificateDenied,
			Status:         corev1.ConditionTrue,
			Reason:         "TemporaryNodeHostname",
			Message:        "Denied by serving CSR renewal test after removing the temporary node hostname",
			LastUpdateTime: metav1.Now(),
		})

		csrs := client.CertificatesV1().CertificateSigningRequests()
		_, err = csrs.UpdateApproval(pollCtx, freshCSR.Name, freshCSR, metav1.UpdateOptions{})
		return err
	}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(gomega.Succeed(), "failed to deny invalid CSR")
}

func waitForRenewalCSR(g gomega.Gomega, ctx context.Context, client kubernetes.Interface, node *corev1.Node, baselineCSRs map[types.UID]struct{}, marker string) *certificatesv1.CertificateSigningRequest {
	var freshCSR certificatesv1.CertificateSigningRequest
	g.Eventually(ctx, func(pollCtx context.Context) ([]certificatesv1.CertificateSigningRequest, error) {
		list, err := client.CertificatesV1().CertificateSigningRequests().List(pollCtx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return list.Items, nil
	}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(gomega.ContainElement(gomega.SatisfyAll(
		beFreshServingCSR(node.Name, baselineCSRs),
		gomega.HaveField("Spec.Request", gomega.WithTransform(csrRequestSANs, gomega.HaveField("DNSNames", gomega.Not(gomega.ContainElement(marker))))),
	), &freshCSR), "did not find fresh CSR")
	return &freshCSR
}

func waitForCSRApproval(g gomega.Gomega, ctx context.Context, client kubernetes.Interface, csr *certificatesv1.CertificateSigningRequest) {
	g.Eventually(ctx, func(pollCtx context.Context) (*certificatesv1.CertificateSigningRequest, error) {
		freshCSR, err := client.CertificatesV1().CertificateSigningRequests().Get(pollCtx, csr.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if csr.UID != freshCSR.UID || csrHasCondition(freshCSR, certificatesv1.CertificateDenied) || csrHasCondition(freshCSR, certificatesv1.CertificateFailed) {
			return nil, gomega.StopTrying("corrected CSR changed or reached a terminal state")
		}
		return freshCSR, nil
	}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(gomega.HaveField("Status.Conditions", gomega.ContainElement(gomega.SatisfyAll(
		gomega.HaveField("Type", gomega.Equal(certificatesv1.CertificateApproved)),
		gomega.HaveField("Status", gomega.Equal(corev1.ConditionTrue)),
	))), "fresh CSR should be approved")
}

func nodeMatchesRole(node *corev1.Node, role servingCSRNodeRole) bool {
	_, worker := node.Labels["node-role.kubernetes.io/worker"]
	_, controlPlane := node.Labels["node-role.kubernetes.io/control-plane"]
	_, master := node.Labels["node-role.kubernetes.io/master"]
	switch role {
	case servingCSRWorker:
		return worker && !controlPlane && !master
	case servingCSRControlPlane:
		return controlPlane || master // Includes dual-role nodes; worker selection does not.
	}
	return false
}

func nodeIsSettled(node *corev1.Node, now time.Time) bool {
	if node.DeletionTimestamp != nil {
		return false
	}
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue && !condition.LastTransitionTime.IsZero() && now.Sub(condition.LastTransitionTime.Time) >= nodeReadySettlement
		}
	}
	return false
}

func newServingCSRMarker(addresses []corev1.NodeAddress) string {
	for {
		marker := fmt.Sprintf("serving-csr-%s.invalid", uuid.NewUUID())
		if !slices.ContainsFunc(addresses, func(address corev1.NodeAddress) bool { return address.Address == marker }) {
			return marker
		}
	}
}

// updateNodeMarker makes exactly one optimistic-locking attempt against the
// CURRENT Node addresses. It must only ever use Update (UpdateStatus) with the
// object fetched in this same call, so its ResourceVersion is sent to the API
// server: a concurrent address change by another actor (kubelet, cloud
// provider) then surfaces as a conflict error, which callers retry with
// Eventually. Never patch Node address lists — a patch that doesn't pass the
// fetched resource version would silently overwrite concurrent changes.
func updateNodeMarker(ctx context.Context, client kubernetes.Interface, selected *corev1.Node, marker string, add bool) error {
	node, err := client.CoreV1().Nodes().Get(ctx, selected.Name, metav1.GetOptions{})
	if !add && (apierrors.IsNotFound(err) || err == nil && node.UID != selected.UID) {
		return nil // Nothing to restore; never mutate a replacement UID.
	}
	if err != nil {
		return err
	}

	if node.UID != selected.UID || add && !nodeIsSettled(node, time.Now()) {
		return gomega.StopTrying(fmt.Sprintf("node %q changed UID or is no longer stable", node.Name))
	}

	address := corev1.NodeAddress{Type: corev1.NodeHostName, Address: marker}
	addresses := slices.Clone(node.Status.Addresses)
	if add && !slices.Contains(addresses, address) {
		addresses = append(addresses, address)
	} else if !add {
		addresses = slices.DeleteFunc(addresses, func(current corev1.NodeAddress) bool { return current == address })
	}

	if slices.Equal(addresses, node.Status.Addresses) {
		return nil
	}

	node.Status.Addresses = addresses
	_, err = client.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
	return err
}

func csrHasCondition(csr *certificatesv1.CertificateSigningRequest, conditionType certificatesv1.RequestConditionType) bool {
	return slices.ContainsFunc(csr.Status.Conditions, func(condition certificatesv1.CertificateSigningRequestCondition) bool {
		return condition.Type == conditionType
	})
}

func beFreshServingCSR(nodeName string, baseline map[types.UID]struct{}) gomegatypes.GomegaMatcher {
	return gomega.SatisfyAll(
		gomega.HaveField("UID", gomega.Not(gomega.BeKeyOf(baseline))),
		gomega.HaveField("Spec.SignerName", gomega.Equal(certificatesv1.KubeletServingSignerName)),
		gomega.HaveField("Spec.Username", gomega.Equal("system:node:"+nodeName)),
	)
}

type servingSANs struct {
	DNSNames    []string
	IPAddresses []string
}

func csrRequestSANs(requestPEM []byte) (servingSANs, error) {
	block, _ := pem.Decode(requestPEM)
	if block == nil {
		return servingSANs{}, fmt.Errorf("request does not contain a PEM block")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return servingSANs{}, fmt.Errorf("failed to parse certificate request: %w", err)
	}
	sans := servingSANs{DNSNames: slices.Clone(request.DNSNames)}
	for _, ip := range request.IPAddresses {
		sans.IPAddresses = append(sans.IPAddresses, ip.String())
	}
	return normalizedServingSANs(sans), nil
}

func normalizedServingSANs(sans servingSANs) servingSANs {
	slices.Sort(sans.DNSNames)
	slices.Sort(sans.IPAddresses)
	sans.DNSNames = slices.Compact(sans.DNSNames)
	sans.IPAddresses = slices.Compact(sans.IPAddresses)
	return sans
}
