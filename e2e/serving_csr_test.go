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
	"net"
	"testing"

	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

func TestSelectReadyNodeFromList(t *testing.T) {
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			labels := nodeRoleLabels(tt.labels...)
			notReady := readyNode("not-ready", labels)
			notReady.Status.Conditions[0].Status = corev1.ConditionFalse
			nodes := []corev1.Node{*readyNode("eligible", labels), *notReady}

			got, err := selectReadyNodeFromList(nodes, tt.role)
			g.Expect(err).NotTo(HaveOccurred())
			if tt.want {
				g.Expect(got).NotTo(BeNil())
				if got != nil {
					g.Expect(got.Name).To(Equal("eligible"))
				}
			} else {
				g.Expect(got).To(BeNil())
			}
		})
	}
}

func TestSelectReadyNodeFromListMissingOrUnreadyRoles(t *testing.T) {
	for _, role := range []servingCSRNodeRole{servingCSRWorker, servingCSRControlPlane} {
		t.Run(string(role), func(t *testing.T) {
			g := NewWithT(t)
			for _, nodes := range [][]corev1.Node{nil, {*readyNode("unlabeled", nil)}} {
				got, err := selectReadyNodeFromList(nodes, role)
				g.Expect(got).To(BeNil())
				g.Expect(err).NotTo(HaveOccurred())
			}
			for _, conditions := range [][]corev1.NodeCondition{
				nil,
				{{Type: corev1.NodeReady, Status: corev1.ConditionFalse}},
				{{Type: corev1.NodeReady, Status: corev1.ConditionUnknown}},
			} {
				node := readyNode("not-ready", nodeRoleLabels(string(role)))
				node.Status.Conditions = conditions
				got, err := selectReadyNodeFromList([]corev1.Node{*node, *readyNode("unlabeled", nil)}, role)
				g.Expect(got).To(BeNil())
				g.Expect(err).To(HaveOccurred())
				g.Expect(err).To(MatchError(ContainSubstring("none are Ready")))
			}
		})
	}
}

func TestSelectReadyNodeFromListRejectsUnsupportedRole(t *testing.T) {
	g := NewWithT(t)
	for _, nodes := range [][]corev1.Node{nil, {*readyNode("node", nodeRoleLabels("worker"))}} {
		_, err := selectReadyNodeFromList(nodes, "unknown")
		g.Expect(err).To(HaveOccurred())
	}
}

func TestSelectReadyNodeFromListChoosesReadyMatch(t *testing.T) {
	g := NewWithT(t)
	nodes := []corev1.Node{
		*readyNode("control-plane", nodeRoleLabels("control-plane")),
		*readyNode("worker-0", nodeRoleLabels("worker")),
		*readyNode("worker-1", nodeRoleLabels("worker")),
	}
	for range 20 {
		got, err := selectReadyNodeFromList(nodes, servingCSRWorker)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(got).NotTo(BeNil())
		if got != nil {
			g.Expect(got.Name).To(BeElementOf("worker-0", "worker-1"))
		}
	}
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
}

func TestFirstNodeInternalIP(t *testing.T) {
	for _, tt := range []struct {
		name      string
		addresses []corev1.NodeAddress
		wantIP    string
		wantIndex int
	}{
		{
			name:      "IPv4",
			addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}},
			wantIP:    "10.0.0.1",
		},
		{
			name:      "IPv6",
			addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "2001:db8::10"}},
			wantIP:    "2001:db8::10",
		},
		{
			name: "dual-stack IPv4 first",
			addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeInternalIP, Address: "2001:db8::10"},
			},
			wantIP: "10.0.0.1",
		},
		{
			name: "dual-stack IPv6 first",
			addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "2001:db8::10"},
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			},
			wantIP: "2001:db8::10",
		},
		{
			name: "skip non-internal address",
			addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "192.0.2.1"},
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			},
			wantIP:    "10.0.0.1",
			wantIndex: 1,
		},
		{name: "missing"},
		{
			name:      "invalid",
			addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "not-an-ip"}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			index, address, err := firstNodeInternalIP(tt.addresses)
			if tt.wantIP == "" {
				g.Expect(err).To(HaveOccurred())
				return
			}
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(index).To(Equal(tt.wantIndex))
			g.Expect(address).To(Equal(tt.wantIP))
			if index >= 0 && index < len(tt.addresses) {
				g.Expect(tt.addresses[index].Type).To(Equal(corev1.NodeInternalIP))
			}
		})
	}
}

func TestSelectBadNodeInternalIPAvoidsExistingAddresses(t *testing.T) {
	for _, tt := range []struct {
		name      string
		addresses []corev1.NodeAddress
		want      string
	}{
		{
			name:      "loopback is available",
			addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.1"}},
			want:      "127.0.0.1",
		},
		{
			name: "skip existing internal and external addresses",
			addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "192.0.2.1"},
				{Type: corev1.NodeExternalIP, Address: "127.0.0.1"},
				{Type: corev1.NodeExternalIP, Address: "198.51.100.1"},
			},
			want: "203.0.113.1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			got, err := selectBadNodeInternalIP(tt.addresses)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestBeFreshServingCSR(t *testing.T) {
	const nodeName = "worker-0"
	oldUID := types.UID("old")
	baseline := map[types.UID]struct{}{oldUID: {}}
	for _, tt := range []struct {
		name, username, signer string
		uid                    types.UID
		want                   bool
	}{
		{"fresh serving CSR", "system:node:" + nodeName, certificatesv1.KubeletServingSignerName, "fresh", true},
		{"baseline UID", "system:node:" + nodeName, certificatesv1.KubeletServingSignerName, oldUID, false},
		{"wrong signer", "system:node:" + nodeName, certificatesv1.KubeAPIServerClientKubeletSignerName, "fresh", false},
		{"wrong node", "system:node:worker-1", certificatesv1.KubeletServingSignerName, "fresh", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			csr := &certificatesv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{UID: tt.uid},
				Spec:       certificatesv1.CertificateSigningRequestSpec{SignerName: tt.signer, Username: tt.username},
			}
			matched, err := beFreshServingCSR(nodeName, baseline).Match(csr)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(matched).To(Equal(tt.want))
		})
	}
}

func TestServingCSRMatcherChecksSANs(t *testing.T) {
	const nodeName = "worker-0"
	for _, tt := range []struct {
		name, requiredIP string
		ips              []string
		want             bool
	}{
		{"IPv4", "10.0.0.1", []string{"10.0.0.1"}, true},
		{"IPv6", "2001:db8::10", []string{"2001:db8::10"}, true},
		{"dual-stack", "2001:db8::10", []string{"10.0.0.1", "2001:db8::10"}, true},
		{"temporary IP remains in SANs", "10.0.0.1", []string{"10.0.0.1", "127.0.0.1"}, false},
		{"required IP is absent", "10.0.0.1", []string{"192.0.2.1"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			csr := testServingCSR(g, types.UID(tt.name), "system:node:"+nodeName, certificatesv1.KubeletServingSignerName, tt.ips...)
			matcher := HaveField("Spec.Request", WithTransform(csrRequestIPAddresses, SatisfyAll(
				ContainElement(tt.requiredIP),
				Not(ContainElement("127.0.0.1")),
			)))
			if tt.want {
				g.Expect(&csr).To(matcher)
			} else {
				g.Expect(&csr).NotTo(matcher)
			}
		})
	}
}

func TestPendingCSRMatcherRejectsTerminalStates(t *testing.T) {
	for _, tt := range []struct {
		name        string
		conditions  []certificatesv1.CertificateSigningRequestCondition
		certificate []byte
		wantPending bool
	}{
		{name: "pending", wantPending: true},
		{
			name: "approved",
			conditions: []certificatesv1.CertificateSigningRequestCondition{{
				Type: certificatesv1.CertificateApproved, Status: corev1.ConditionTrue,
			}},
		},
		{
			name: "denied",
			conditions: []certificatesv1.CertificateSigningRequestCondition{{
				Type: certificatesv1.CertificateDenied, Status: corev1.ConditionTrue,
			}},
		},
		{name: "issued certificate", certificate: []byte("issued")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			csr := &certificatesv1.CertificateSigningRequest{
				Status: certificatesv1.CertificateSigningRequestStatus{
					Conditions:  tt.conditions,
					Certificate: tt.certificate,
				},
			}
			g.Expect(bePendingCSR().Match(csr)).To(Equal(tt.wantPending))
		})
	}
}

type servingCSRTestClient struct {
	kubernetes.Interface
	typedcorev1.CoreV1Interface
	getConfigMap func(context.Context, string, string, metav1.GetOptions) (*corev1.ConfigMap, error)
	listNodes    func(context.Context, metav1.ListOptions) (*corev1.NodeList, error)
}

func (c *servingCSRTestClient) CoreV1() typedcorev1.CoreV1Interface {
	return c
}

func (c *servingCSRTestClient) ConfigMaps(namespace string) typedcorev1.ConfigMapInterface {
	return &servingCSRTestConfigMaps{namespace: namespace, get: c.getConfigMap}
}

func (c *servingCSRTestClient) Nodes() typedcorev1.NodeInterface {
	return &servingCSRTestNodes{list: c.listNodes}
}

type servingCSRTestConfigMaps struct {
	typedcorev1.ConfigMapInterface
	namespace string
	get       func(context.Context, string, string, metav1.GetOptions) (*corev1.ConfigMap, error)
}

func (c *servingCSRTestConfigMaps) Get(ctx context.Context, name string, options metav1.GetOptions) (*corev1.ConfigMap, error) {
	return c.get(ctx, c.namespace, name, options)
}

type servingCSRTestNodes struct {
	typedcorev1.NodeInterface
	list func(context.Context, metav1.ListOptions) (*corev1.NodeList, error)
}

func (c *servingCSRTestNodes) List(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error) {
	return c.list(ctx, options)
}

func testServingCSR(g *WithT, uid types.UID, username, signerName string, addresses ...string) certificatesv1.CertificateSigningRequest {
	g.THelper()

	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ip := net.ParseIP(address)
		g.Expect(ip).NotTo(BeNil(), "test address %q is not a valid IP", address)
		ips = append(ips, ip)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	g.Expect(err).NotTo(HaveOccurred(), "generate CSR key")
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{IPAddresses: ips}, privateKey)
	g.Expect(err).NotTo(HaveOccurred(), "create CSR request")
	request := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER})
	return certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: string(uid), UID: uid},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			SignerName: signerName,
			Username:   username,
			Request:    request,
		},
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
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Status: corev1.NodeStatus{Conditions: []corev1.NodeCondition{{
			Type: corev1.NodeReady, Status: corev1.ConditionTrue,
		}}},
	}
}
