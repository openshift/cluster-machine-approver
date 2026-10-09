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
	"fmt"
	"math/rand/v2"
	"net"
	"slices"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	"github.com/onsi/gomega"
	. "github.com/onsi/gomega"
	gomegatypes "github.com/onsi/gomega/types"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// componentReadinessPrefix is registered in openshift-eng/ci-test-mapping to map to the Cluster Machine Approver component.
	componentReadinessPrefix = "[sig-cluster-lifecycle] Cluster Machine Approver "

	// controllerActionTimeout is a suitable timeout when waiting for a controller to act on a change.
	controllerActionTimeout = 60 * time.Second

	// controllerPollingInterval is a suitable interval when polling for a controller to act on a change.
	controllerPollingInterval = 500 * time.Millisecond
)

type servingCSRNodeRole string

const (
	servingCSRWorker       servingCSRNodeRole = "worker"
	servingCSRControlPlane servingCSRNodeRole = "control-plane"
)

var _ = Describe(componentReadinessPrefix+"Kubelet serving CSR approval", Label("Serial"), func() {
	var client kubernetes.Interface

	BeforeEach(func(ctx SpecContext) {
		config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		Expect(err).NotTo(HaveOccurred(), "failed to load Kubernetes client configuration")

		client, err = kubernetes.NewForConfig(config)
		Expect(err).NotTo(HaveOccurred(), "failed to create Kubernetes client")

		if isMicroShift(ctx, gomega.Default, client) {
			Skip("kubelet serving CSR approval is not supported on MicroShift")
		}
	})

	It("approves a renewed kubelet serving CSR on a worker node", Serial, func(ctx SpecContext) {
		runServingCSRDisruption(ctx, client, servingCSRWorker)
	})

	It("approves a renewed kubelet serving CSR on a control-plane node", Serial, func(ctx SpecContext) {
		runServingCSRDisruption(ctx, client, servingCSRControlPlane)
	})
})

// runServingCSRDisruption tests that a renewed serving CSR is automatically approved.
func runServingCSRDisruption(ctx context.Context, client kubernetes.Interface, role servingCSRNodeRole) {
	GinkgoHelper()

	node, err := selectReadyNode(ctx, client, role)
	Expect(err).NotTo(HaveOccurred(), "failed to select a Ready node")
	if node == nil {
		Skip(fmt.Sprintf("no nodes with the %s role were found", role))
	}

	csr := forceKubeletServingCSRRenewal(ctx, client, node, role)

	By(fmt.Sprintf("Waiting for new kubelet serving CSR %q to be approved", csr.Name), func() {
		csrs := client.CertificatesV1().CertificateSigningRequests()

		Eventually(ctx, func(pollCtx context.Context) (*certificatesv1.CertificateSigningRequest, error) {
			return csrs.Get(pollCtx, csr.Name, metav1.GetOptions{})
		}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(
			HaveField("Status.Conditions", ContainElement(SatisfyAll(
				HaveField("Type", Equal(certificatesv1.CertificateApproved)),
				HaveField("Status", Equal(corev1.ConditionTrue)),
			))), fmt.Sprintf("renewed kubelet serving CSR %q was not approved", csr.Name))
	})
}

// isMicroShift returns true if the cluster is running MicroShift.
// It uses the presence of the ConfigMap kube-public/microshift-version as a
// marker, which is the same check used in the CAPI e2e tests.
func isMicroShift(ctx context.Context, g gomega.Gomega, client kubernetes.Interface) bool {
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	isMicroShift := false
	g.Eventually(func(pollCtx context.Context) error {
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
	}).WithContext(timeoutCtx).Should(Succeed(), "failed to detect MicroShift from ConfigMap kube-public/microshift-version")

	return isMicroShift
}

// forceKubeletServingCSRRenewal forces the kubelet on the given node to request
// a new serving certificate. kubelet does not provide a simple way to force
// renewal of a valid serving certificate. To achieve an immediate renewal, we:
// - Temporarily replace one of the node's InternalIPs with an invalid test IP
// - Wait for kubelet to create a corresponding CSR for a new serving certificate
// - Restore the node's addresses
// - Explicitly deny the invalid CSR
//
// Denying the invalid CSR causes kubelet to create a replacement CSR. This new
// CSR is correct because we restored the node's addresses, so it should be
// automatically approved by CMA.
func forceKubeletServingCSRRenewal(ctx context.Context, client kubernetes.Interface, node *corev1.Node, role servingCSRNodeRole) *certificatesv1.CertificateSigningRequest {
	GinkgoHelper()

	savedAddresses := slices.Clone(node.Status.Addresses)
	internalIPIndex, originalInternalIP, err := firstNodeInternalIP(savedAddresses)
	Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to find the original InternalIP on node %q", node.Name))
	badInternalIP, err := selectBadNodeInternalIP(savedAddresses)
	Expect(err).NotTo(HaveOccurred(), "failed to select a temporary InternalIP distinct from the node's existing addresses")

	// We don't need to restore addresses on cleanup if we restored them
	// successfully during the test.
	restoreAddressesOnce := sync.Once{}

	restoreAddresses := func(ctx context.Context) {
		restoreAddressesOnce.Do(func() {
			By(fmt.Sprintf("Restoring saved addresses on node %q", node.Name), func() {
				Eventually(ctx, func(pollCtx context.Context) (*corev1.Node, error) {
					return updateNodeAddresses(pollCtx, client, node.Name, savedAddresses)
				}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(
					HaveField("Status.Addresses", Equal(savedAddresses)), fmt.Sprintf("failed to restore saved addresses on node %q", node.Name))
			})
		})
	}
	DeferCleanup(restoreAddresses, NodeTimeout(controllerActionTimeout))

	baseline, err := listCSRUIDs(ctx, client)
	Expect(err).NotTo(HaveOccurred(), "failed to record baseline CSR UIDs before disruption")
	freshServingCSR := beFreshServingCSR(node.Name, baseline)
	csrs := client.CertificatesV1().CertificateSigningRequests()

	badAddresses := slices.Clone(savedAddresses)
	badAddresses[internalIPIndex].Address = badInternalIP
	var badCSR certificatesv1.CertificateSigningRequest
	By(fmt.Sprintf("Waiting for kubelet on %s node %q to request a serving certificate with temporary IP %s", role, node.Name, badInternalIP), func() {
		// Kubelet may overwrite the temporary addresses, so reapply them while waiting.
		Eventually(ctx, func(g Gomega, pollCtx context.Context) (*certificatesv1.CertificateSigningRequestList, error) {
			g.Expect(updateNodeAddresses(pollCtx, client, node.Name, badAddresses)).To(
				HaveField("Status.Addresses", Equal(badAddresses)), fmt.Sprintf("failed to apply temporary addresses on node %q", node.Name))
			return csrs.List(pollCtx, metav1.ListOptions{})
		}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(
			HaveField("Items", ContainElement(SatisfyAll(
				freshServingCSR,
				HaveField("Spec.Request", WithTransform(csrRequestIPAddresses, ContainElement(badInternalIP))),
			), &badCSR)), fmt.Sprintf("kubelet on node %q did not request a fresh serving CSR with temporary IP %s", node.Name, badInternalIP))
	})

	// Ensure we clean up the temporary-IP serving CSR after the test.
	DeferCleanup(func(cleanupCtx context.Context) {
		By(fmt.Sprintf("Deleting temporary-IP serving CSR %q", badCSR.Name), func() {
			Expect(csrs.Delete(cleanupCtx, badCSR.Name, metav1.DeleteOptions{})).To(Succeed(), "failed to delete temporary-IP serving CSR")
		})
	})

	// Restore addresses before denying the temporary-IP serving CSR so the
	// kubelet's replacement CSR will be correct.
	restoreAddresses(ctx)

	By(fmt.Sprintf("Denying pending temporary-IP serving CSR %q", badCSR.Name), func() {
		Eventually(ctx, func(g Gomega, pollCtx context.Context) {
			csr, err := csrs.Get(pollCtx, badCSR.Name, metav1.GetOptions{})
			g.Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to get temporary-IP serving CSR %q before denial", badCSR.Name))
			g.Expect(csr.UID).To(Equal(badCSR.UID), "temporary-IP serving CSR UID changed before denial")
			g.Expect(csr).To(bePendingCSR(), "temporary-IP serving CSR must remain pending before denial")

			// Replace any existing Denied condition rather than adding a duplicate.
			csr.Status.Conditions = slices.DeleteFunc(csr.Status.Conditions, func(condition certificatesv1.CertificateSigningRequestCondition) bool {
				return condition.Type == certificatesv1.CertificateDenied
			})
			csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{
				Type:           certificatesv1.CertificateDenied,
				Status:         corev1.ConditionTrue,
				Reason:         "TemporaryNodeInternalIP",
				Message:        "Denied by serving CSR renewal test after restoring the node InternalIP",
				LastUpdateTime: metav1.Now(),
			})
			_, err = csrs.UpdateApproval(pollCtx, csr.Name, csr, metav1.UpdateOptions{})
			g.Expect(err).NotTo(HaveOccurred(), fmt.Sprintf("failed to deny temporary-IP serving CSR %q", badCSR.Name))
		}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(Succeed(), "failed to deny the pending temporary-IP serving CSR")
	})

	var correctedCSR certificatesv1.CertificateSigningRequest
	By(fmt.Sprintf("Waiting for kubelet on node %q to request a corrected serving CSR", node.Name), func() {
		Eventually(ctx, func(pollCtx context.Context) (*certificatesv1.CertificateSigningRequestList, error) {
			return csrs.List(pollCtx, metav1.ListOptions{})
		}).WithTimeout(controllerActionTimeout).WithPolling(controllerPollingInterval).Should(
			HaveField("Items", ContainElement(SatisfyAll(
				freshServingCSR,
				HaveField("UID", Not(Equal(badCSR.UID))),
				HaveField("Spec.Request", WithTransform(csrRequestIPAddresses, SatisfyAll(
					ContainElement(net.ParseIP(originalInternalIP).String()),
					Not(ContainElement(badInternalIP)),
				))),
			), &correctedCSR)), fmt.Sprintf("kubelet on node %q did not request a fresh corrected serving CSR with original IP %s and without temporary IP %s", node.Name, originalInternalIP, badInternalIP))
	})

	return &correctedCSR
}

func selectReadyNode(ctx context.Context, client kubernetes.Interface, role servingCSRNodeRole) (*corev1.Node, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	Expect(err).NotTo(HaveOccurred(), "failed to list nodes")

	return selectReadyNodeFromList(nodes.Items, role)
}

// selectReadyNodeFromList returns nil without an error when no nodes match the role.
func selectReadyNodeFromList(nodes []corev1.Node, role servingCSRNodeRole) (*corev1.Node, error) {
	GinkgoHelper()

	if role != servingCSRWorker && role != servingCSRControlPlane {
		return nil, fmt.Errorf("unsupported node role %q", role)
	}

	var candidates []corev1.Node
	haveMatchingNode := false
	for i := range nodes {
		node := nodes[i]
		_, worker := node.Labels["node-role.kubernetes.io/worker"]
		_, controlPlane := node.Labels["node-role.kubernetes.io/control-plane"]
		_, master := node.Labels["node-role.kubernetes.io/master"]

		matchesRole := false
		switch role {
		case servingCSRWorker:
			// We only match workers with no other role
			matchesRole = worker && !controlPlane && !master
		case servingCSRControlPlane:
			// We deliberately match control-plane nodes which are also workers
			matchesRole = controlPlane || master
		}
		if matchesRole {
			haveMatchingNode = true
			if nodeIsReady(&node) {
				candidates = append(candidates, node)
			}
		}
	}

	// If we found no nodes with the desired role, skip the test.
	// This handles topologies with no
	if !haveMatchingNode {
		return nil, nil
	}

	// If we found nodes with the desired role but none are Ready, fail the test.
	if len(candidates) == 0 {
		return nil, fmt.Errorf("found %d nodes with the %s role but none are Ready", len(candidates), role)
	}

	// Select a random node from the candidates to prevent bias towards the first node in the list.
	return &candidates[rand.IntN(len(candidates))], nil
}

func nodeIsReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func firstNodeInternalIP(addresses []corev1.NodeAddress) (int, string, error) {
	for i, address := range addresses {
		if address.Type != corev1.NodeInternalIP {
			continue
		}
		if net.ParseIP(address.Address) == nil {
			return -1, "", fmt.Errorf("first NodeInternalIP %q is not a valid IP address", address.Address)
		}
		return i, address.Address, nil
	}
	return -1, "", fmt.Errorf("node has no NodeInternalIP address")
}

// selectBadNodeInternalIP returns an IP address we don't expect to see on a
// node which will not be approved by CMA.
func selectBadNodeInternalIP(addresses []corev1.NodeAddress) (string, error) {
	// The loopback address is a valid but non-node IP; RFC 5737 documentation-only addresses are fallbacks.
	for _, candidate := range []string{"127.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1"} {
		if !slices.ContainsFunc(addresses, func(address corev1.NodeAddress) bool {
			return address.Address == candidate
		}) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("all false test IP candidates are already present in the node addresses")
}

func beFreshServingCSR(nodeName string, baseline map[types.UID]struct{}) gomegatypes.GomegaMatcher {
	return SatisfyAll(
		HaveField("UID", Not(BeKeyOf(baseline))),
		HaveField("Spec.SignerName", Equal(certificatesv1.KubeletServingSignerName)),
		HaveField("Spec.Username", Equal("system:node:"+nodeName)),
	)
}

func bePendingCSR() gomegatypes.GomegaMatcher {
	return SatisfyAll(
		HaveField("Status.Certificate", BeEmpty()),
		HaveField("Status.Conditions", Not(ContainElement(SatisfyAll(
			HaveField("Type", BeElementOf(certificatesv1.CertificateApproved, certificatesv1.CertificateDenied)),
			HaveField("Status", Equal(corev1.ConditionTrue)),
		)))),
	)
}

func csrRequestIPAddresses(requestPEM []byte) ([]string, error) {
	block, _ := pem.Decode(requestPEM)
	if block == nil {
		return nil, fmt.Errorf("request does not contain a PEM block")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	addresses := make([]string, len(request.IPAddresses))
	for i, ip := range request.IPAddresses {
		addresses[i] = ip.String()
	}
	return addresses, nil
}

func listCSRUIDs(ctx context.Context, client kubernetes.Interface) (map[types.UID]struct{}, error) {
	csrs, err := client.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	baseline := make(map[types.UID]struct{}, len(csrs.Items))
	for i := range csrs.Items {
		baseline[csrs.Items[i].UID] = struct{}{}
	}
	return baseline, nil
}

// updateNodeAddresses makes a single attempt; callers use Eventually to retry conflicts.
func updateNodeAddresses(ctx context.Context, client kubernetes.Interface, nodeName string, addresses []corev1.NodeAddress) (*corev1.Node, error) {
	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	if slices.Equal(node.Status.Addresses, addresses) {
		return node, nil
	}
	node.Status.Addresses = slices.Clone(addresses)
	return client.CoreV1().Nodes().UpdateStatus(ctx, node, metav1.UpdateOptions{})
}
