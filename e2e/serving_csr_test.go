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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	typedcertificatesv1 "k8s.io/client-go/kubernetes/typed/certificates/v1"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	clienttesting "k8s.io/client-go/testing"
)

// boundedPollCtx bounds a function whose internal Eventually uses the
// production controller timeouts, so a regression fails fast instead of
// blocking for minutes.
func boundedPollCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestNodeMatchesRole(t *testing.T) {
	for _, tt := range []struct {
		name   string
		labels []string
		role   servingCSRNodeRole
		want   bool
	}{
		{"worker", []string{"worker"}, servingCSRWorker, true},
		{"worker excludes control-plane", []string{"worker", "control-plane"}, servingCSRWorker, false},
		{"worker excludes master", []string{"worker", "master"}, servingCSRWorker, false},
		{"control-plane", []string{"control-plane"}, servingCSRControlPlane, true},
		{"legacy master", []string{"master"}, servingCSRControlPlane, true},
		{"combined worker and control-plane", []string{"worker", "control-plane"}, servingCSRControlPlane, true},
		{"combined worker and master", []string{"worker", "master"}, servingCSRControlPlane, true},
		{"control-plane excludes worker-only", []string{"worker"}, servingCSRControlPlane, false},
		{"worker excludes unlabeled", nil, servingCSRWorker, false},
		{"control-plane excludes unlabeled", nil, servingCSRControlPlane, false},
		{"unknown role", []string{"worker"}, servingCSRNodeRole("bogus"), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			g.Expect(nodeMatchesRole(readyNode("node", nodeRoleLabels(tt.labels...)), tt.role)).To(Equal(tt.want))
		})
	}
}

func TestNodeIsSettled(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name        string
		status      corev1.ConditionStatus
		transition  time.Time
		terminating bool
		want        bool
	}{
		{name: "missing Ready"},
		{name: "not Ready", status: corev1.ConditionFalse, transition: now.Add(-time.Hour)},
		{name: "unknown Ready", status: corev1.ConditionUnknown, transition: now.Add(-time.Hour)},
		{name: "zero transition", status: corev1.ConditionTrue},
		{name: "recent transition", status: corev1.ConditionTrue, transition: now.Add(-nodeReadySettlement + time.Second)},
		{name: "future transition", status: corev1.ConditionTrue, transition: now.Add(time.Hour)},
		{name: "at settlement threshold", status: corev1.ConditionTrue, transition: now.Add(-nodeReadySettlement), want: true},
		{name: "settled", status: corev1.ConditionTrue, transition: now.Add(-2 * nodeReadySettlement), want: true},
		{name: "terminating", status: corev1.ConditionTrue, transition: now.Add(-time.Hour), terminating: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			node := readyNode("node", nil)
			node.Status.Conditions = nil
			if tt.status != "" {
				node.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: tt.status, LastTransitionTime: metav1.NewTime(tt.transition)}}
			}
			if tt.terminating {
				node.DeletionTimestamp = &metav1.Time{Time: now}
			}
			g.Expect(nodeIsSettled(node, now)).To(Equal(tt.want))
		})
	}
}

func TestNewServingCSRMarker(t *testing.T) {
	g := NewWithT(t)
	addresses := []corev1.NodeAddress{
		{Type: corev1.NodeHostName, Address: "worker"},
		{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
	}
	marker := newServingCSRMarker(addresses)
	g.Expect(validation.IsDNS1123Subdomain(marker)).To(BeEmpty())
	g.Expect(net.ParseIP(marker)).To(BeNil())
	g.Expect(marker).To(HavePrefix("serving-csr-"))
	g.Expect(marker).To(HaveSuffix(".invalid"))
	for range 100 {
		other := newServingCSRMarker(addresses)
		g.Expect(other).NotTo(Equal(marker))
		g.Expect(slices.ContainsFunc(addresses, func(address corev1.NodeAddress) bool { return address.Address == other })).To(BeFalse())
	}
}

func TestCSRRequestSANs(t *testing.T) {
	for _, tt := range []struct {
		name    string
		sans    []string
		wantDNS []string
		wantIPs []string
	}{
		{"no SANs", nil, nil, nil},
		{"DNS names", []string{"worker", "worker.internal"}, []string{"worker", "worker.internal"}, nil},
		{"IPv4", []string{"10.0.0.1"}, nil, []string{"10.0.0.1"}},
		{"IPv6 canonicalized", []string{"2001:db8:0:0::10"}, nil, []string{"2001:db8::10"}},
		{"duplicates removed", []string{"worker", "worker", "10.0.0.1", "10.0.0.1"}, []string{"worker"}, []string{"10.0.0.1"}},
		{"sorted", []string{"z.example", "a.example"}, []string{"a.example", "z.example"}, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			csr := testServingCSR(g, "csr", "system:node:worker", certificatesv1.KubeletServingSignerName, nil, tt.sans...)
			sans, err := csrRequestSANs(csr.Spec.Request)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(sans.DNSNames).To(Equal(tt.wantDNS))
			g.Expect(sans.IPAddresses).To(Equal(tt.wantIPs))
		})
	}
}

func TestCSRRequestSANsRejectsMalformedRequests(t *testing.T) {
	for _, tt := range []struct {
		name    string
		request []byte
	}{
		{"no PEM block", []byte("not a PEM document")},
		{"non-CSR PEM block", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})},
		{"malformed DER", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("junk")})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := csrRequestSANs(tt.request)
			g.Expect(err).To(HaveOccurred())
		})
	}
}

func TestBeFreshServingCSR(t *testing.T) {
	g := NewWithT(t)
	baseline := map[types.UID]struct{}{types.UID("old"): {}}
	fresh := testServingCSR(g, "fresh", "system:node:worker", certificatesv1.KubeletServingSignerName, nil, "worker")
	g.Expect(&fresh).To(beFreshServingCSR("worker", baseline))
	for _, tt := range []struct {
		name   string
		mutate func(*certificatesv1.CertificateSigningRequest)
	}{
		{"baseline UID", func(csr *certificatesv1.CertificateSigningRequest) { csr.UID = "old" }},
		{"other node", func(csr *certificatesv1.CertificateSigningRequest) { csr.Spec.Username = "system:node:other" }},
		{"other signer", func(csr *certificatesv1.CertificateSigningRequest) {
			csr.Spec.SignerName = certificatesv1.KubeAPIServerClientKubeletSignerName
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			other := fresh.DeepCopy()
			tt.mutate(other)
			g.Expect(other).NotTo(beFreshServingCSR("worker", baseline))
		})
	}
}

func TestRunWithGomega(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(runWithGomega(func(g Gomega) {
			g.Expect(true).To(BeTrue())
		})).NotTo(HaveOccurred())
	})
	t.Run("assertion failure becomes an error", func(t *testing.T) {
		g := NewWithT(t)
		err := runWithGomega(func(g Gomega) {
			g.Expect(2).To(Equal(1), "the number is wrong")
		})
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("the number is wrong"))
	})
	t.Run("eventually failure becomes an error", func(t *testing.T) {
		g := NewWithT(t)
		err := runWithGomega(func(g Gomega) {
			g.Eventually(func() error { return errors.New("nope") }).WithTimeout(10 * time.Millisecond).Should(Succeed())
		})
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("nope"))
	})
	t.Run("foreign panics propagate", func(t *testing.T) {
		g := NewWithT(t)
		g.Expect(func() {
			_ = runWithGomega(func(g Gomega) {
				panic("not a gomega failure")
			})
		}).To(PanicWith("not a gomega failure"))
	})
}

func TestGetFreshNode(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		g := NewWithT(t)
		node := readyNode("worker", nodeRoleLabels("worker"))
		client := newServingCSRTrackedClient(g, node)
		g.Expect(getFreshNode(g, boundedPollCtx(t, 5*time.Second), client, node)).To(HaveField("Name", Equal("worker")))
	})
	t.Run("missing", func(t *testing.T) {
		g := NewWithT(t)
		node := readyNode("worker", nodeRoleLabels("worker"))
		client := newServingCSRTrackedClient(g)
		g.Expect(getFreshNode(g, boundedPollCtx(t, 5*time.Second), client, node)).To(BeNil())
	})
	t.Run("transient errors retried", func(t *testing.T) {
		g := NewWithT(t)
		node := readyNode("worker", nodeRoleLabels("worker"))
		client := newServingCSRTrackedClient(g, node)
		calls := 0
		client.PrependReactor("get", "nodes", func(action clienttesting.Action) (bool, runtime.Object, error) {
			calls++
			if calls == 1 {
				return true, nil, apierrors.NewServerTimeout(schema.GroupResource{Resource: "nodes"}, "get", 1)
			}
			return false, nil, nil
		})
		g.Expect(getFreshNode(g, boundedPollCtx(t, 5*time.Second), client, node)).To(HaveField("Name", Equal("worker")))
		g.Expect(calls).To(Equal(2))
	})
}

func TestIsMicroShift(t *testing.T) {
	for _, tt := range []struct {
		name      string
		lookupErr error
		want      bool
	}{
		{name: "marker found", want: true},
		{name: "marker absent", lookupErr: apierrors.NewNotFound(schema.GroupResource{Resource: "configmaps"}, "microshift-version")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			calls := 0
			client := &servingCSRTestClient{getConfigMap: func(ctx context.Context, namespace, name string, _ metav1.GetOptions) (*corev1.ConfigMap, error) {
				g.Expect(namespace).To(Equal("kube-public"))
				g.Expect(name).To(Equal("microshift-version"))
				_, bounded := ctx.Deadline()
				g.Expect(bounded).To(BeTrue())
				calls++
				return &corev1.ConfigMap{}, tt.lookupErr
			}}
			g.Expect(isMicroShift(t.Context(), g, client)).To(Equal(tt.want))
			g.Expect(calls).To(Equal(1))
		})
	}
	t.Run("transient errors retried", func(t *testing.T) {
		g := NewWithT(t)
		calls := 0
		client := &servingCSRTestClient{getConfigMap: func(ctx context.Context, namespace, name string, _ metav1.GetOptions) (*corev1.ConfigMap, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("transient")
			}
			return &corev1.ConfigMap{}, nil
		}}
		g.Expect(isMicroShift(t.Context(), g, client)).To(BeTrue())
		g.Expect(calls).To(Equal(2))
	})
}

func TestUpdateNodeMarkerGuardsNodeIdentityAndTermination(t *testing.T) {
	for _, tt := range []struct {
		name        string
		replacement bool
		terminating bool
		missing     bool
	}{
		{name: "replacement", replacement: true},
		{name: "terminating", terminating: true},
		{name: "missing", missing: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			selected := readyNode("worker", nodeRoleLabels("worker"))
			current := selected.DeepCopy()
			const marker = "serving-csr-test.invalid"
			current.Status.Addresses = append(current.Status.Addresses, corev1.NodeAddress{Type: corev1.NodeHostName, Address: marker})
			if tt.replacement {
				current.UID = "replacement"
			}
			if tt.terminating {
				current.DeletionTimestamp = &metav1.Time{Time: time.Now()}
			}
			client := newServingCSRTrackedClient(g)
			if !tt.missing {
				g.Expect(client.Tracker().Create(corev1.SchemeGroupVersion.WithResource("nodes"), current, "")).To(Succeed())
			}
			err := updateNodeMarker(t.Context(), client, selected, marker, true)
			g.Expect(err).To(HaveOccurred())
			if tt.terminating {
				fresh, err := client.CoreV1().Nodes().Get(t.Context(), selected.Name, metav1.GetOptions{})
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(nodeIsSettled(fresh, time.Now())).To(BeFalse(), "the guard must align with the settled criteria used to select nodes")
			}
			err = updateNodeMarker(t.Context(), client, selected, marker, false)
			g.Expect(err).NotTo(HaveOccurred())
			updated, err := client.CoreV1().Nodes().Get(t.Context(), selected.Name, metav1.GetOptions{})
			if tt.terminating {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(updated.Status.Addresses).To(Equal(selected.Status.Addresses))
			} else if tt.missing {
				g.Expect(apierrors.IsNotFound(err)).To(BeTrue(), "the node must remain missing")
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(updated.Status.Addresses).To(ContainElement(corev1.NodeAddress{Type: corev1.NodeHostName, Address: marker}), "a replacement node must never be modified")
			}
			if !tt.terminating {
				for _, action := range client.Actions() {
					g.Expect(action.GetVerb()).To(Equal("get"))
				}
			}
		})
	}
}

func TestDenyInvalidCSR(t *testing.T) {
	newCSR := func(g *WithT) certificatesv1.CertificateSigningRequest {
		return testServingCSR(g, "csr", "system:node:worker", certificatesv1.KubeletServingSignerName, nil, "worker")
	}

	t.Run("denies a pending CSR", func(t *testing.T) {
		g := NewWithT(t)
		csr := newCSR(g)
		client := newServingCSRTrackedClient(g, &csr)
		denyInvalidCSR(g, boundedPollCtx(t, 5*time.Second), client, &csr)
		updated, err := client.CertificatesV1().CertificateSigningRequests().Get(t.Context(), csr.Name, metav1.GetOptions{})
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(updated.Status.Conditions).To(ContainElement(SatisfyAll(
			HaveField("Type", Equal(certificatesv1.CertificateDenied)),
			HaveField("Status", Equal(corev1.ConditionTrue)),
			HaveField("Reason", Equal("TemporaryNodeHostname")),
		)))
		g.Expect(client.Actions()).To(ContainElement(SatisfyAll(
			HaveField("Verb", Equal("update")),
			HaveField("Resource.Resource", Equal("certificatesigningrequests")),
			HaveField("Subresource", Equal("approval")),
		)))
	})

	t.Run("already denied is idempotent", func(t *testing.T) {
		g := NewWithT(t)
		csr := testServingCSR(g, "csr", "system:node:worker", certificatesv1.KubeletServingSignerName, []certificatesv1.CertificateSigningRequestCondition{
			{Type: certificatesv1.CertificateDenied, Status: corev1.ConditionTrue},
		})
		client := newServingCSRTrackedClient(g, &csr)
		denyInvalidCSR(g, boundedPollCtx(t, 5*time.Second), client, &csr)
		g.Expect(client.Actions()).To(HaveLen(1), "a previously successful denial must not be repeated")
		g.Expect(client.Actions()[0].GetVerb()).To(Equal("get"))
	})

	// The table cases all assert the same guard: the stored CSR no longer
	// matches the one the test selected, in a way that makes denying it wrong
	// or pointless. Each case mutates the stored copy ("current") while the
	// test keeps its original selection, so the mismatch must be detected,
	// reported as a terminal error, and the denial never attempted.
	for _, tt := range []struct {
		name   string
		mutate func(*certificatesv1.CertificateSigningRequest)
	}{
		{"replaced", func(csr *certificatesv1.CertificateSigningRequest) { csr.UID = "replacement" }},
		{"approved", func(csr *certificatesv1.CertificateSigningRequest) {
			csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue})
		}},
		{"issued", func(csr *certificatesv1.CertificateSigningRequest) { csr.Status.Certificate = []byte("issued") }},
		{"failed", func(csr *certificatesv1.CertificateSigningRequest) {
			csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{Type: certificatesv1.CertificateFailed, Status: corev1.ConditionTrue})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			selected := newCSR(g)
			current := selected.DeepCopy()
			tt.mutate(current)
			client := newServingCSRTrackedClient(g, current)
			err := runWithGomega(func(g Gomega) {
				denyInvalidCSR(g, boundedPollCtx(t, 5*time.Second), client, &selected)
			})
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring("unexpectedly approved, issued or failed"))
			g.Expect(client.Actions()).To(HaveLen(1), "a changed CSR must not be denied")
			g.Expect(client.Actions()[0].GetVerb()).To(Equal("get"))
		})
	}
}

// TestForceInvalidCSR exercises forceInvalidCSR's matcher chain in situ:
// adding the marker hostname to the Node must make it capture the one CSR
// that is genuinely the kubelet's invalid request — fresh (not in the
// baseline), for this node, kubelet-serving signer, still pending, and
// carrying the marker among its DNS SANs. Selecting anything else here
// would make the e2e test deny an unrelated CSR.
//
// Method: a node-status update reactor stands in for the kubelet — when it
// sees the marker address written, it populates the fake client's tracker
// with the target CSR plus decoys that each fail exactly one clause of the
// matcher (baseline UID, already approved/denied, already issued, other
// node, other signer, no marker SAN). The test asserts only "target" is
// captured and that its parsed request still contains the marker.
func TestForceInvalidCSR(t *testing.T) {
	g := NewWithT(t)
	node := readyNode("worker", nodeRoleLabels("worker"))
	client := newServingCSRTrackedClient(g, node)
	const marker = "serving-csr-test.invalid"
	username := "system:node:worker"
	signer := certificatesv1.KubeletServingSignerName
	baseline := testServingCSR(g, "baseline", username, signer, nil, "worker")
	baselineCSRs := map[types.UID]struct{}{baseline.UID: {}}
	target := testServingCSR(g, "target", username, signer, nil, "worker", marker)
	approved := testServingCSR(g, "approved", username, signer, []certificatesv1.CertificateSigningRequestCondition{
		{Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue},
	}, "worker", marker)
	denied := testServingCSR(g, "denied", username, signer, []certificatesv1.CertificateSigningRequestCondition{
		{Type: certificatesv1.CertificateDenied, Status: corev1.ConditionTrue},
	}, "worker", marker)
	issued := testServingCSR(g, "issued", username, signer, nil, "worker", marker)
	issued.Status.Certificate = []byte("issued")
	otherNode := testServingCSR(g, "other-node", "system:node:other", signer, nil, "worker", marker)
	otherSigner := testServingCSR(g, "other-signer", username, certificatesv1.KubeAPIServerClientKubeletSignerName, nil, "worker", marker)
	noMarker := testServingCSR(g, "no-marker", username, signer, nil, "worker")

	created := false
	client.PrependReactor("update", "nodes", func(action clienttesting.Action) (bool, runtime.Object, error) {
		updated := action.(clienttesting.UpdateAction).GetObject().(*corev1.Node)
		if !created && slices.Contains(updated.Status.Addresses, corev1.NodeAddress{Type: corev1.NodeHostName, Address: marker}) {
			created = true
			for _, csr := range []*certificatesv1.CertificateSigningRequest{&baseline, &target, &approved, &denied, &issued, &otherNode, &otherSigner, &noMarker} {
				g.Expect(client.Tracker().Add(csr)).To(Succeed())
			}
		}
		return false, nil, nil
	})

	got := forceInvalidCSR(g, boundedPollCtx(t, 5*time.Second), client, node, marker, baselineCSRs)
	g.Expect(got.Name).To(Equal("target"))
	sans, err := csrRequestSANs(got.Spec.Request)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(sans.DNSNames).To(ContainElement(marker))
}

// TestWaitForRenewalCSR exercises waitForRenewalCSR's matcher chain in situ:
// after the invalid CSR is denied and the marker hostname removed, the
// kubelet re-issues its serving certificate request, and the e2e test must
// capture that genuine renewal — fresh (not in the baseline), for this node,
// kubelet-serving signer, and without the marker SAN. Capturing the wrong
// CSR here would make the e2e test wait for the approval of the wrong
// request.
//
// Method: the fake client's tracker is pre-populated with the renewal CSR
// plus decoys that each fail one clause of the matcher: the invalid CSR,
// which is still fresh but carries the marker SAN, and a baseline CSR from
// before the disruption. The test asserts only "renewal" is captured and
// that its parsed request does not contain the marker.
func TestWaitForRenewalCSR(t *testing.T) {
	g := NewWithT(t)
	node := readyNode("worker", nodeRoleLabels("worker"))
	client := newServingCSRTrackedClient(g)
	const marker = "serving-csr-test.invalid"
	username := "system:node:worker"
	signer := certificatesv1.KubeletServingSignerName
	baseline := testServingCSR(g, "baseline", username, signer, nil, "worker")
	baselineCSRs := map[types.UID]struct{}{baseline.UID: {}}
	invalid := testServingCSR(g, "invalid", username, signer, nil, "worker", marker)
	renewal := testServingCSR(g, "renewal", username, signer, nil, "worker")
	for _, csr := range []*certificatesv1.CertificateSigningRequest{&baseline, &invalid, &renewal} {
		g.Expect(client.Tracker().Add(csr)).To(Succeed())
	}
	got := waitForRenewalCSR(g, boundedPollCtx(t, 5*time.Second), client, node, baselineCSRs, marker)
	g.Expect(got.Name).To(Equal("renewal"))
	sans, err := csrRequestSANs(got.Spec.Request)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(sans.DNSNames).NotTo(ContainElement(marker))
}

func TestWaitForCSRApproval(t *testing.T) {
	newCSR := func(g *WithT) certificatesv1.CertificateSigningRequest {
		return testServingCSR(g, "csr", "system:node:worker", certificatesv1.KubeletServingSignerName, nil, "worker")
	}

	t.Run("approved", func(t *testing.T) {
		g := NewWithT(t)
		csr := testServingCSR(g, "csr", "system:node:worker", certificatesv1.KubeletServingSignerName, []certificatesv1.CertificateSigningRequestCondition{
			{Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue},
		})
		client := newServingCSRTrackedClient(g, &csr)
		waitForCSRApproval(g, boundedPollCtx(t, 5*time.Second), client, &csr)
	})

	// The table cases all assert the same guard: the stored CSR has reached a
	// state where waiting for approval is pointless — it was replaced under
	// the test's feet, or was denied or failed by another actor. Each case
	// mutates the stored copy ("current") while the test keeps its original
	// selection, so the wait must stop immediately with a terminal error
	// instead of blocking until the timeout.
	for _, tt := range []struct {
		name   string
		mutate func(*certificatesv1.CertificateSigningRequest)
	}{
		{"replaced", func(csr *certificatesv1.CertificateSigningRequest) { csr.UID = "replacement" }},
		{"denied", func(csr *certificatesv1.CertificateSigningRequest) {
			csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{Type: certificatesv1.CertificateDenied, Status: corev1.ConditionTrue})
		}},
		{"failed", func(csr *certificatesv1.CertificateSigningRequest) {
			csr.Status.Conditions = append(csr.Status.Conditions, certificatesv1.CertificateSigningRequestCondition{Type: certificatesv1.CertificateFailed, Status: corev1.ConditionTrue})
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			selected := newCSR(g)
			current := selected.DeepCopy()
			tt.mutate(current)
			client := newServingCSRTrackedClient(g, current)
			err := runWithGomega(func(g Gomega) {
				waitForCSRApproval(g, boundedPollCtx(t, 5*time.Second), client, &selected)
			})
			g.Expect(err).To(HaveOccurred())
			g.Expect(err.Error()).To(ContainSubstring("terminal state"))
		})
	}

	// The table cases construct a CSR that stays unchanged but never becomes
	// approved: either it has no conditions at all, or it carries an Approved
	// condition whose status is not True (the matcher requires ConditionTrue,
	// not merely the condition's presence). Waiting must fail on timeout; the
	// bounded context keeps that failure fast.
	for _, tt := range []struct {
		name       string
		conditions []certificatesv1.CertificateSigningRequestCondition
	}{
		{"pending", nil},
		{"approved condition not true", []certificatesv1.CertificateSigningRequestCondition{{Type: certificatesv1.CertificateApproved, Status: corev1.ConditionFalse}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			csr := testServingCSR(g, "csr", "system:node:worker", certificatesv1.KubeletServingSignerName, tt.conditions)
			client := newServingCSRTrackedClient(g, &csr)
			err := runWithGomega(func(g Gomega) {
				waitForCSRApproval(g, boundedPollCtx(t, 50*time.Millisecond), client, &csr)
			})
			g.Expect(err).To(HaveOccurred())
		})
	}
}

// A small typed facade keeps the standard fake tracker/reactors without
// vendoring generated fake clients for every Kubernetes API.
type servingCSRTrackedClient struct {
	kubernetes.Interface
	clienttesting.Fake
	tracker clienttesting.ObjectTracker
}

func newServingCSRTrackedClient(g *WithT, objects ...runtime.Object) *servingCSRTrackedClient {
	g.THelper()
	c := &servingCSRTrackedClient{tracker: clienttesting.NewObjectTracker(scheme.Scheme, scheme.Codecs.UniversalDecoder())}
	for _, object := range objects {
		g.Expect(c.tracker.Add(object)).To(Succeed())
	}
	c.AddReactor("*", "*", clienttesting.ObjectReaction(c.tracker))
	return c
}

func (c *servingCSRTrackedClient) Tracker() clienttesting.ObjectTracker { return c.tracker }

func (c *servingCSRTrackedClient) CoreV1() typedcorev1.CoreV1Interface {
	return &servingCSRTrackedCore{client: c}
}

func (c *servingCSRTrackedClient) CertificatesV1() typedcertificatesv1.CertificatesV1Interface {
	return &servingCSRTrackedCertificates{client: c}
}

type servingCSRTrackedCore struct {
	typedcorev1.CoreV1Interface
	client *servingCSRTrackedClient
}

func (c *servingCSRTrackedCore) Nodes() typedcorev1.NodeInterface {
	return &servingCSRTrackedNodes{client: c.client}
}

type servingCSRTrackedNodes struct {
	typedcorev1.NodeInterface
	client *servingCSRTrackedClient
}

func (c *servingCSRTrackedNodes) Get(_ context.Context, name string, options metav1.GetOptions) (*corev1.Node, error) {
	object, err := c.client.Invokes(clienttesting.NewRootGetActionWithOptions(corev1.SchemeGroupVersion.WithResource("nodes"), name, options), &corev1.Node{})
	node, _ := object.(*corev1.Node)
	return node, err
}

func (c *servingCSRTrackedNodes) UpdateStatus(_ context.Context, node *corev1.Node, options metav1.UpdateOptions) (*corev1.Node, error) {
	object, err := c.client.Invokes(clienttesting.NewRootUpdateSubresourceActionWithOptions(corev1.SchemeGroupVersion.WithResource("nodes"), "status", node, options), &corev1.Node{})
	updated, _ := object.(*corev1.Node)
	return updated, err
}

func (c *servingCSRTrackedNodes) Delete(_ context.Context, name string, options metav1.DeleteOptions) error {
	_, err := c.client.Invokes(clienttesting.NewRootDeleteActionWithOptions(corev1.SchemeGroupVersion.WithResource("nodes"), name, options), &corev1.Node{})
	return err
}

type servingCSRTrackedCertificates struct {
	typedcertificatesv1.CertificatesV1Interface
	client *servingCSRTrackedClient
}

func (c *servingCSRTrackedCertificates) CertificateSigningRequests() typedcertificatesv1.CertificateSigningRequestInterface {
	return &servingCSRTrackedRequests{client: c.client}
}

type servingCSRTrackedRequests struct {
	typedcertificatesv1.CertificateSigningRequestInterface
	client *servingCSRTrackedClient
}

func (c *servingCSRTrackedRequests) Get(_ context.Context, name string, options metav1.GetOptions) (*certificatesv1.CertificateSigningRequest, error) {
	object, err := c.client.Invokes(clienttesting.NewRootGetActionWithOptions(certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"), name, options), &certificatesv1.CertificateSigningRequest{})
	csr, _ := object.(*certificatesv1.CertificateSigningRequest)
	return csr, err
}

func (c *servingCSRTrackedRequests) List(_ context.Context, options metav1.ListOptions) (*certificatesv1.CertificateSigningRequestList, error) {
	object, err := c.client.Invokes(clienttesting.NewRootListActionWithOptions(certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"), certificatesv1.SchemeGroupVersion.WithKind("CertificateSigningRequest"), options), &certificatesv1.CertificateSigningRequestList{})
	csrs, _ := object.(*certificatesv1.CertificateSigningRequestList)
	return csrs, err
}

func (c *servingCSRTrackedRequests) UpdateApproval(_ context.Context, _ string, csr *certificatesv1.CertificateSigningRequest, options metav1.UpdateOptions) (*certificatesv1.CertificateSigningRequest, error) {
	object, err := c.client.Invokes(clienttesting.NewRootUpdateSubresourceActionWithOptions(certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"), "approval", csr, options), &certificatesv1.CertificateSigningRequest{})
	updated, _ := object.(*certificatesv1.CertificateSigningRequest)
	return updated, err
}

func (c *servingCSRTrackedRequests) Delete(_ context.Context, name string, options metav1.DeleteOptions) error {
	_, err := c.client.Invokes(clienttesting.NewRootDeleteActionWithOptions(certificatesv1.SchemeGroupVersion.WithResource("certificatesigningrequests"), name, options), &certificatesv1.CertificateSigningRequest{})
	return err
}

// MicroShift detection uses a single ConfigMap lookup.
type servingCSRTestClient struct {
	kubernetes.Interface
	typedcorev1.CoreV1Interface
	getConfigMap func(context.Context, string, string, metav1.GetOptions) (*corev1.ConfigMap, error)
}

func (c *servingCSRTestClient) CoreV1() typedcorev1.CoreV1Interface { return c }

func (c *servingCSRTestClient) ConfigMaps(namespace string) typedcorev1.ConfigMapInterface {
	return &servingCSRTestConfigMaps{namespace: namespace, get: c.getConfigMap}
}

type servingCSRTestConfigMaps struct {
	typedcorev1.ConfigMapInterface
	namespace string
	get       func(context.Context, string, string, metav1.GetOptions) (*corev1.ConfigMap, error)
}

func (c *servingCSRTestConfigMaps) Get(ctx context.Context, name string, options metav1.GetOptions) (*corev1.ConfigMap, error) {
	return c.get(ctx, c.namespace, name, options)
}

func testServingCSR(g *WithT, uid types.UID, username, signerName string, conditions []certificatesv1.CertificateSigningRequestCondition, addresses ...string) certificatesv1.CertificateSigningRequest {
	g.THelper()
	request := &x509.CertificateRequest{}
	for _, address := range addresses {
		if ip := net.ParseIP(address); ip != nil {
			request.IPAddresses = append(request.IPAddresses, ip)
		} else {
			request.DNSNames = append(request.DNSNames, address)
		}
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	g.Expect(err).NotTo(HaveOccurred(), "generate CSR key")
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, request, privateKey)
	g.Expect(err).NotTo(HaveOccurred(), "create CSR request")
	return certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: string(uid), UID: uid},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			SignerName: signerName,
			Username:   username,
			Request:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}),
		},
		Status: certificatesv1.CertificateSigningRequestStatus{Conditions: conditions},
	}
}

func nodeRoleLabels(roles ...string) map[string]string {
	labels := make(map[string]string, len(roles))
	for _, role := range roles {
		labels["node-role.kubernetes.io/"+role] = ""
	}
	return labels
}

func readyNode(name string, labels map[string]string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name), ResourceVersion: "1", Labels: labels},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{{Type: corev1.NodeHostName, Address: name}, {Type: corev1.NodeInternalIP, Address: "10.0.0.1"}},
			Conditions: []corev1.NodeCondition{{
				Type: corev1.NodeReady, Status: corev1.ConditionTrue, LastTransitionTime: metav1.NewTime(time.Now().Add(-2 * nodeReadySettlement)),
			}},
		},
	}
}
