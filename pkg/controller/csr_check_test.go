package controller

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	testcerts "github.com/openshift/cluster-machine-approver/pkg/controller/testing"
)

var baseTime = time.Date(2020, 11, 19, 0, 0, 0, 0, time.UTC)

func init() {
	now = clock.NewFakePassiveClock(baseTime).Now
}

func Test_authorizeCSR(t *testing.T) {
	defaultPort := int32(25435)
	defaultAddr := "127.0.0.1"
	defaultNode := func() *corev1.Node {
		return &corev1.Node{
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: defaultAddr},
				},
				DaemonEndpoints: corev1.NodeDaemonEndpoints{
					KubeletEndpoint: corev1.DaemonEndpoint{
						Port: defaultPort,
					},
				},
			},
		}
	}

	withName := func(name string, node *corev1.Node) *corev1.Node {
		node.Name = name
		return node
	}
	withPort := func(port int32, node *corev1.Node) *corev1.Node {
		node.Status.DaemonEndpoints.KubeletEndpoint.Port = port
		return node
	}

	type args struct {
		config        ClusterMachineApproverConfig
		machines      []machinev1.Machine
		node          *corev1.Node
		kubeletServer net.Listener
		req           *certificatesv1.CertificateSigningRequest
		csr           string
		ca            []*x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "ok",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "",
		},
		{
			name: "bad-csr",
			args: args{
				csr: testcerts.EmptyCSR,
				req: &certificatesv1.CertificateSigningRequest{},
			},
			wantErr: "PEM block type must be CERTIFICATE REQUEST",
		},
		{
			name: "no-node-prefix",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "\"test\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "only-node-prefix",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "Empty name",
		},
		{
			name: "no-machine-status-ref",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "No target machine for node \"test\"",
		},
		{
			name: "missing-groups-1",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "Too few groups",
		},
		{
			name: "missing-groups-2",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "Too few groups",
		},
		{
			name: "extra-group",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
							"foo-bar",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "",
		},
		{
			name: "wrong-group",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:foo-bar",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "map[\"system:authenticated\":{} \"system:foo-bar\":{}] not in \"system:authenticated\" and \"system:nodes\"",
		},
		{
			name: "usages-missing",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "Too few usages",
		},
		{
			name: "usages-missing",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: `map["client auth":{} "digital signature":{} "key encipherment":{}] is missing usages`,
		},
		{
			name: "usages-missing-1",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "Too few usages",
		},
		{
			name: "usage-missing-2",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "Too few usages",
		},
		{
			name: "usage-extra",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
							certificatesv1.UsageSigning,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "Too few usages",
		},
		{
			name: "csr-cn",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.OtherName,
			},
			wantErr: "Mismatched CommonName system:node:foobar != system:node:test",
		},
		{
			name: "csr-cn-2",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.NoNamePrefix,
			},
			wantErr: "Mismatched CommonName test != system:node:test",
		},
		{
			name: "csr-no-o",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.NoGroup,
			},
			wantErr: "Organization [] doesn't include system:nodes",
		},
		{
			name: "csr-extra-addr",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.ExtraAddr,
			},
			wantErr: "IP address '99.0.1.1' not in machine addresses: 127.0.0.1 10.0.0.1",
		},
		{
			name: "csr-san-ip-mismatch",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.2",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "IP address '10.0.0.1' not in machine addresses: 127.0.0.1 10.0.0.2",
		},
		{
			name: "csr-san-dns-mismatch",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node2",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
			},
			wantErr: "DNS name 'node1' not in machine names: node1.local node2",
		},
		{
			name: "client good",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "",
		},
		{
			name: "client extra O",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "bear",
								},
							},
						},
					},
				},
				node: withName("bear", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientExtraO,
			},
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client with DNS",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "monkey",
								},
							},
						},
					},
				},
				node: withName("monkey", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientWithDNS,
			},
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but extra usage",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but wrong usage",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but missing usage",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but wrong CN",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "zebra",
								},
							},
						},
					},
				},
				node: withName("zebra", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientWrongCN,
			},
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but wrong user",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "green"},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper-not",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "CSR green for node client cert has wrong user system:serviceaccount:openshift-machine-config-operator:node-bootstrapper-not or groups map[system:authenticated:{} system:serviceaccounts:{} system:serviceaccounts:openshift-machine-config-operator:{}]",
		},
		{
			name: "client good but wrong user group",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "blue"},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
							"extra-group",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "CSR blue for node client cert has wrong user system:serviceaccount:openshift-machine-config-operator:node-bootstrapper or groups map[extra-group:{} system:authenticated:{} system:serviceaccounts:{} system:serviceaccounts:openshift-machine-config-operator:{}]",
		},
		{
			name: "client good but empty name",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "yellow"},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientEmptyName,
			},
			wantErr: "CSR yellow has empty node name",
		},
		{
			name: "client good but node exists",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "node panda already exists or other error: <nil>",
		},
		{
			name: "client good but missing machine",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeExternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "failed to find machine for node panda",
		},
		{
			name: "client good but machine has node ref",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{Name: "other"},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "machine for node panda already has node ref",
		},
		{
			name: "client good but auto approval is disabled",
			args: args{
				config: ClusterMachineApproverConfig{
					NodeClientCert: NodeClientCert{
						Disabled: true,
					},
				},
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "orange"},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "CSR orange for node client cert rejected as the flow is disabled",
		},
		{
			name: "client good with proper timing",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							CreationTimestamp: creationTimestamp(2 * time.Minute),
						},
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "pink",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "",
		},
		{
			name: "client good with proper timing 2",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							CreationTimestamp: creationTimestamp(3 * time.Minute),
						},
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "pink",
						CreationTimestamp: creationTimestamp(2*time.Minute + 51*time.Second),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "",
		},
		{
			name: "client good but CSR too early",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							CreationTimestamp: creationTimestamp(3 * time.Minute),
						},
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "purple",
						CreationTimestamp: creationTimestamp(2 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "CSR purple creation time 2020-11-19 00:02:00 +0000 UTC not in range (2020-11-19 00:02:50 +0000 UTC, 2020-11-19 02:03:00 +0000 UTC)",
		},
		{
			name: "client good but CSR too late",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						ObjectMeta: metav1.ObjectMeta{
							CreationTimestamp: creationTimestamp(3 * time.Minute),
						},
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "red",
						CreationTimestamp: creationTimestamp(25 * time.Hour),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
						},
						Username: "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper",
						Groups: []string{
							"system:authenticated",
							"system:serviceaccounts:openshift-machine-config-operator",
							"system:serviceaccounts",
						},
					},
				},
				csr: testcerts.ClientGood,
			},
			wantErr: "CSR red creation time 2020-11-20 01:00:00 +0000 UTC not in range (2020-11-19 00:02:50 +0000 UTC, 2020-11-19 02:03:00 +0000 UTC)",
		},
		{
			name: "successfull renew flow",
			args: args{
				node: withName("test", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "renew",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
				ca:  []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			},
		},
		{
			name: "successfull fallback to fresh approval",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							NodeRef: &corev1.ObjectReference{
								Name: "test",
							},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalIP,
									Address: "127.0.0.1",
								},
								{
									Type:    corev1.NodeExternalIP,
									Address: "10.0.0.1",
								},
								{
									Type:    corev1.NodeInternalDNS,
									Address: "node1.local",
								},
								{
									Type:    corev1.NodeExternalDNS,
									Address: "node1",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "renew",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: testcerts.GoodCSR,
				ca:  []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			},
		},
		{
			name: "successfull fallback to fresh approval from incorrect server cert",
			args: args{
				node: withPort(defaultPort+1, withName("test", defaultNode())),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "renew",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr:           testcerts.GoodCSR,
				ca:            []*x509.Certificate{parseCert(t, testcerts.DifferentCert)},
				kubeletServer: fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort+1), testcerts.DifferentCert, testcerts.DifferentKey),
			},
			wantErr: `No target machine for node "test"`,
		},
	}

	server := fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort), testcerts.ServerCertGood, testcerts.ServerKeyGood)
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kubeletServer := server
			if tt.args.kubeletServer != nil {
				kubeletServer = tt.args.kubeletServer
				defer kubeletServer.Close()
			}

			nodes := []runtime.Object{}
			if tt.args.node != nil {
				nodes = []runtime.Object{tt.args.node}
			}
			cl := fake.NewFakeClient(nodes...)
			tt.args.req.Spec.Request = []byte(tt.args.csr)
			parsedCSR, err := parseCSR(tt.args.req)
			if err != nil {
				if errString(err) != tt.wantErr {
					t.Errorf("parseCSR() error = %v, wantErr %s", err, tt.wantErr)
				}
				return
			}

			var ca *x509.CertPool
			if len(tt.args.ca) > 0 {
				// Start renewal flow
				ca = x509.NewCertPool()
				for _, cert := range tt.args.ca {
					ca.AddCert(cert)
				}
				go respond(kubeletServer)
			}
			if err := authorizeCSR(cl, tt.args.config, tt.args.machines, tt.args.req, parsedCSR, ca); errString(err) != tt.wantErr {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, tt.wantErr)
			}
		})

		t.Run("Invalid call", func(t *testing.T) {
			if err := authorizeCSR(nil, tt.args.config, tt.args.machines, nil, nil, nil); errString(err) != "Invalid request" {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, "Invalid request")
			}
		})
	}
}

func TestAuthorizeServingRenewal(t *testing.T) {
	presetTimeCorrect := time.Date(2020, 11, 19, 0, 0, 0, 0, time.UTC)
	presetTimeExpired := time.Date(2020, 11, 18, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		nodeName    string
		csr         *x509.CertificateRequest
		currentCert *x509.Certificate
		ca          []*x509.Certificate
		time        time.Time
		wantErr     string
	}{
		{
			name:     "missing args",
			nodeName: "panda",
			wantErr:  "CSR, serving cert, or CA not provided",
		},
		{
			name:        "all good",
			nodeName:    "test",
			csr:         parseCR(t, testcerts.GoodCSR),
			currentCert: parseCert(t, testcerts.ServerCertGood),
			ca:          []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			time:        presetTimeCorrect,
		},
		{
			name:        "reject expired",
			nodeName:    "test",
			csr:         parseCR(t, testcerts.GoodCSR),
			currentCert: parseCert(t, testcerts.ServerCertGood),
			ca:          []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			time:        presetTimeExpired,
			wantErr:     "x509: certificate has expired or is not yet valid: current time 2020-11-18T00:00:00Z is before 2020-11-18T20:12:00Z",
		},
		{
			name:        "SAN list differs",
			nodeName:    "test",
			csr:         parseCR(t, testcerts.ExtraAddr),
			currentCert: parseCert(t, testcerts.ServerCertGood),
			ca:          []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "CSR Subject Alternate Name values do not match current certificate",
		},
		{
			name:        "No certificate match",
			nodeName:    "test",
			csr:         parseCR(t, testcerts.GoodCSR),
			currentCert: parseCert(t, testcerts.ServerCertGood),
			ca:          []*x509.Certificate{},
			time:        presetTimeCorrect,
			wantErr:     "x509: certificate signed by unknown authority",
		},
		{
			name:        "Request from different node",
			nodeName:    "test",
			csr:         parseCR(t, testcerts.OtherName),
			currentCert: parseCert(t, testcerts.ServerCertGood),
			ca:          []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "current serving cert and CSR common name mismatch",
		},
		{
			name:        "Unexpected CN",
			nodeName:    "panda",
			csr:         parseCR(t, testcerts.GoodCSR),
			currentCert: parseCert(t, testcerts.ServerCertGood),
			ca:          []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "current serving cert has bad common name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPool := x509.NewCertPool()
			for _, cert := range tt.ca {
				certPool.AddCert(cert)
			}
			err := authorizeServingRenewal(
				tt.nodeName,
				tt.csr,
				tt.currentCert,
				x509.VerifyOptions{Roots: certPool, CurrentTime: tt.time},
			)

			if errString(err) != tt.wantErr {
				t.Errorf("got: %v, want: %s", err, tt.wantErr)
			}
		})
	}
}

func TestGetServingCert(t *testing.T) {
	defaultPort := int32(25535)
	defaultAddr := "127.0.0.1"
	defaultNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: defaultAddr},
			},
			DaemonEndpoints: corev1.NodeDaemonEndpoints{
				KubeletEndpoint: corev1.DaemonEndpoint{
					Port: defaultPort,
				},
			},
		},
	}

	wrongAddr := defaultNode.DeepCopy()
	wrongAddr.Status.DaemonEndpoints.KubeletEndpoint.Port = int32(25544)

	uninitialized := defaultNode.DeepCopy()
	uninitialized.Status = corev1.NodeStatus{}

	tests := []struct {
		name      string
		nodeName  string
		node      *corev1.Node
		rootCerts []*x509.Certificate
		wantErr   string
	}{
		{
			name:      "all good",
			nodeName:  "test",
			node:      defaultNode,
			rootCerts: []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
		},
		{
			name:      "unknown certificate",
			nodeName:  "test",
			node:      defaultNode,
			rootCerts: []*x509.Certificate{parseCert(t, testcerts.DifferentCert)},
			wantErr:   "x509: certificate signed by unknown authority",
		},
		{
			name:      "node not found",
			nodeName:  "test",
			rootCerts: []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			wantErr:   "nodes \"test\" not found",
		},
		{
			name:      "wrong address",
			nodeName:  "test",
			node:      wrongAddr,
			rootCerts: []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			wantErr:   "dial tcp 127.0.0.1:25544: connect: connection refused",
		},
		{
			name:     "no pool provided",
			nodeName: "test",
			node:     defaultNode,
			wantErr:  "no CA found: will not retrieve serving cert",
		},
		{
			name:      "node with no addr",
			nodeName:  "test",
			node:      uninitialized,
			rootCerts: []*x509.Certificate{parseCert(t, testcerts.RootCertGood)},
			wantErr:   "node test has no internal addresses",
		},
	}

	server := fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort), testcerts.ServerCertGood, testcerts.ServerKeyGood)
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var certPool *x509.CertPool
			if len(tt.rootCerts) > 0 {
				certPool = x509.NewCertPool()
				for _, cert := range tt.rootCerts {
					certPool.AddCert(cert)
				}
			}

			objects := []runtime.Object{}
			if tt.node != nil {
				objects = append(objects, tt.node)
			}
			cl := fake.NewFakeClient(objects...)

			go respond(server)
			serverCert, err := getServingCert(cl, tt.nodeName, certPool)
			if errString(err) != tt.wantErr {
				t.Fatalf("got: %v, want: %s", err, tt.wantErr)
			}
			if err == nil && !serverCert.Equal(parseCert(t, testcerts.ServerCertGood)) {
				t.Fatal("Expected server certificate match on success")
			}
		})
	}
}

func TestRecentlyPendingCSRs(t *testing.T) {
	approvedCSR := certificatesv1.CertificateSigningRequest{
		Status: certificatesv1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1.CertificateSigningRequestCondition{{
				Type: certificatesv1.CertificateApproved,
			}},
		},
	}
	pendingCSR := certificatesv1.CertificateSigningRequest{}
	pendingTime := baseTime.Add(time.Second)
	pastApprovalTime := baseTime.Add(-maxPendingDelta)
	preApprovalTime := baseTime.Add(10 * time.Second)

	createdAt := func(time time.Time, csr certificatesv1.CertificateSigningRequest) certificatesv1.CertificateSigningRequest {
		csr.CreationTimestamp.Time = time
		return csr
	}

	tests := []struct {
		name          string
		csrs          []certificatesv1.CertificateSigningRequest
		expectPending int
	}{
		{
			name:          "recently pending csr",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, pendingCSR)},
			expectPending: 1,
		},
		{
			name:          "recently approved csr",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, approvedCSR)},
			expectPending: 0,
		},
		{
			name:          "pending past approval time",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pastApprovalTime, pendingCSR)},
			expectPending: 0,
		},
		{
			name:          "pending before approval time",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(preApprovalTime, pendingCSR)},
			expectPending: 0,
		},
		{
			name: "multiple different csrs",
			csrs: []certificatesv1.CertificateSigningRequest{
				createdAt(pendingTime, pendingCSR),
				createdAt(pendingTime, pendingCSR),

				createdAt(pendingTime, approvedCSR),
				createdAt(preApprovalTime, approvedCSR),
				createdAt(pastApprovalTime, approvedCSR),
				createdAt(preApprovalTime, pendingCSR),
				createdAt(pastApprovalTime, pendingCSR),
			},
			expectPending: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if pending := recentlyPendingCSRs(tt.csrs); pending != tt.expectPending {
				t.Errorf("Expected %v pending CSRs, got: %v", tt.expectPending, pending)
			}
		})
	}
}

func TestNodeInternalIP(t *testing.T) {
	tests := []struct {
		name    string
		node    *corev1.Node
		wantIP  string
		wantErr string
	}{
		{
			name: "no addresses",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "no-addresses",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{},
				},
			},
			wantErr: "node no-addresses has no internal addresses",
		},
		{
			name: "no internal ip",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "no-internal-ip",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeHostName, Address: "host.example.com"},
					},
				},
			},
			wantErr: "node no-internal-ip has no internal addresses",
		},
		{
			name: "has internal ip",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "has-internal-ip",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			wantIP: "10.0.0.1",
		},
		{
			name: "has ipv6 address",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "has-ipv6-address",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "2600:1f18:4254:5100:ef8a:7b65:7782:9248"},
					},
				},
			},
			wantIP: "2600:1f18:4254:5100:ef8a:7b65:7782:9248",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := nodeInternalIP(tt.node)

			if errString(err) != tt.wantErr {
				t.Errorf("got: %v, want: %s", err, tt.wantErr)
			}

			if ip != tt.wantIP {
				t.Errorf("got: %v, want: %s", err, tt.wantIP)
			}
		})
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	errStr := err.Error()
	if len(errStr) == 0 {
		panic("invalid error")
	}
	return errStr
}

func creationTimestamp(delta time.Duration) metav1.Time {
	return metav1.NewTime(baseTime.Add(delta))
}

func TestGetMaxPending(t *testing.T) {
	ml := []machinev1.Machine{
		{
			Status: machinev1.MachineStatus{},
		},
		{
			Status: machinev1.MachineStatus{},
		},
	}

	res := getMaxPending(ml)
	expected := len(ml) + maxDiffBetweenPendingCSRsAndMachinesCount
	if res != expected {
		t.Errorf("getMaxPending returned incorrect value: %v, expect: %v", res, expected)
	}
}

func TestEqualStrings(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "both empty",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "equal",
			a:        []string{"a", "b"},
			b:        []string{"a", "b"},
			expected: true,
		},
		{
			name:     "different order",
			a:        []string{"b", "a"},
			b:        []string{"a", "b"},
			expected: true,
		},
		{
			name:     "not equal",
			a:        []string{"a"},
			b:        []string{"a", "b"},
			expected: false,
		},
		{
			name:     "duplicates",
			a:        []string{"a", "a"},
			b:        []string{"a", "b"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertNoChange(t, tt.a, tt.b, func(t *testing.T) {
				if equal := equalStrings(tt.a, tt.b); equal != tt.expected {
					t.Errorf("%v == %v :: wanted %v, got %v",
						tt.a, tt.b, tt.expected, equal)
				}
			})
		})
	}
}

func TestEqualURLs(t *testing.T) {
	exampleNet, err := url.Parse("http://example.net")
	if err != nil {
		t.Fatal(err)
	}

	exampleOrg, err := url.Parse("https://example.org")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		a        []*url.URL
		b        []*url.URL
		expected bool
	}{
		{
			name:     "both empty",
			a:        []*url.URL{},
			b:        []*url.URL{},
			expected: true,
		},
		{
			name:     "equal",
			a:        []*url.URL{exampleNet, exampleOrg},
			b:        []*url.URL{exampleNet, exampleOrg},
			expected: true,
		},
		{
			name:     "different order",
			a:        []*url.URL{exampleOrg, exampleNet},
			b:        []*url.URL{exampleNet, exampleOrg},
			expected: true,
		},
		{
			name:     "not equal",
			a:        []*url.URL{exampleOrg},
			b:        []*url.URL{exampleNet, exampleOrg},
			expected: false,
		},
		{
			name:     "duplicates",
			a:        []*url.URL{exampleOrg, exampleOrg},
			b:        []*url.URL{exampleNet, exampleOrg},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if equal := equalURLs(tt.a, tt.b); equal != tt.expected {
				t.Errorf("%v == %v :: wanted %v, got %v",
					tt.a, tt.b, tt.expected, equal)
			}
		})
	}
}

func TestEqualIPAddresses(t *testing.T) {
	tenDotOne := net.ParseIP("10.0.0.1")
	tenDotTwo := net.ParseIP("10.0.0.2")

	tests := []struct {
		name     string
		a        []net.IP
		b        []net.IP
		expected bool
	}{
		{
			name:     "both empty",
			a:        []net.IP{},
			b:        []net.IP{},
			expected: true,
		},
		{
			name:     "equal",
			a:        []net.IP{tenDotOne, tenDotTwo},
			b:        []net.IP{tenDotOne, tenDotTwo},
			expected: true,
		},
		{
			name:     "different order",
			a:        []net.IP{tenDotTwo, tenDotOne},
			b:        []net.IP{tenDotOne, tenDotTwo},
			expected: true,
		},
		{
			name:     "not equal",
			a:        []net.IP{tenDotTwo},
			b:        []net.IP{tenDotOne, tenDotTwo},
			expected: false,
		},
		{
			name:     "duplicates",
			a:        []net.IP{tenDotOne, tenDotOne},
			b:        []net.IP{tenDotOne, tenDotTwo},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if equal := equalIPAddresses(tt.a, tt.b); equal != tt.expected {
				t.Errorf("%v == %v :: wanted %v, got %v",
					tt.a, tt.b, tt.expected, equal)
			}
		})
	}
}

func TestCsrSANs(t *testing.T) {
	uri, _ := url.Parse("http://example.com")
	cr := &x509.CertificateRequest{
		DNSNames:       []string{"test.local", "localhost"},
		EmailAddresses: []string{"exaple@test.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{uri},
	}

	sans := sets.NewString(csrSANs(cr)...)
	if !sans.HasAll(
		"http://example.com", "test.local",
		"localhost", "exaple@test.com",
		"127.0.0.1", "10.0.0.1") {
		t.Errorf("Not all SANs were collected")
	}

	if len(csrSANs(nil)) > 0 {
		t.Errorf("No SANs are expected from nil")
	}
}

func TestCertSANs(t *testing.T) {
	uri, _ := url.Parse("http://example.com")
	cert := &x509.Certificate{
		DNSNames:       []string{"test.local", "localhost"},
		EmailAddresses: []string{"exaple@test.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{uri},
	}

	sans := sets.NewString(certSANs(cert)...)
	if !sans.HasAll(
		"http://example.com", "test.local",
		"localhost", "exaple@test.com",
		"127.0.0.1", "10.0.0.1") {
		t.Errorf("Not all SANs were collected")
	}

	if len(certSANs(nil)) > 0 {
		t.Errorf("No SANs are expected from nil")
	}
}
func assertNoChange(t *testing.T, a, b []string, f func(*testing.T)) {
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))

	copy(aCopy, a)
	copy(bCopy, b)

	f(t)

	if !reflect.DeepEqual(aCopy, a) || !reflect.DeepEqual(bCopy, b) {
		t.Errorf("slice modified unexpectedly: "+
			"orinigal a = %v, original b = %v, "+
			"new a = %v, new b = %v", aCopy, bCopy, a, b)
	}
}

func parseCert(t *testing.T, cert string) *x509.Certificate {
	block, _ := pem.Decode([]byte(cert))
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Passed invalid Certificate: %v ", err)
	}
	return parsedCert
}

func parseCR(t *testing.T, csr string) *x509.CertificateRequest {
	block, _ := pem.Decode([]byte(csr))
	parsedCR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Passed invalid Certificate: %v ", err)
	}
	return parsedCR
}

func fakeResponder(t *testing.T, laddr, cert, key string) (server net.Listener) {
	crt, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatalf("Fail to parse key pair: %s", err.Error())
	}

	server, err = tls.Listen("tcp", laddr, &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) { return &crt, nil },
	})
	if err != nil {
		t.Fatalf("Fail to establish TCP listener: %s", err.Error())
	}

	return
}

func respond(server net.Listener) {
	conn, err := server.Accept()
	if err != nil {
		return
	}
	if conn != nil {
		defer conn.Close()
		conn.Write([]byte(server.Addr().String()))
	}
}
