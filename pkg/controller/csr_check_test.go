package controller

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	networkv1 "github.com/openshift/api/network/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/scheme"
	testingclock "k8s.io/utils/clock/testing"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	machinehandlerpkg "github.com/openshift/cluster-machine-approver/pkg/machinehandler"
)

// The following global test variables are populated within the init func
var serverCertGood, serverKeyGood, rootCertGood string

// Generated CRs, are populating within the init func
var goodCSR, goodCSRECDSA, extraAddr, otherName, noNamePrefix, noGroup, clientGood, clientExtraO, clientWithDNS, clientWrongCN, clientEmptyName, emptyCSR, multusCSRPEM string

var presetTimeCorrect, presetTimeExpired time.Time

const (
	differentCert = `-----BEGIN CERTIFICATE-----
MIIB6zCCAZGgAwIBAgIUNukOeYC/OJTuAHe8x0dZGxo/UPcwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtleGFtcGxlLm5ldDAeFw0yMDExMTkxMjU1MDBaFw0yNTEx
MTgxMjU1MDBaMEgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzEUMBIGA1UEAxMLZXhhbXBsZS5uZXQwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAStQMOkXCI/byn1MPc5KYM1d5NsPF4gexjeKqjJrrHcaTow
jJAQOslKXAhHKp0y+jhFzr8lQdDrt5eHUK/LfDpKo1kwVzAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUhJoVW5gCXH0QwkspeVOA4EBG
sBMwFQYDVR0RBA4wDIcEfwAAAYcECgAAATAKBggqhkjOPQQDAgNIADBFAiEAzTu+
fuo0nJuh1ta+w+X7iwhx29AG/1TAPY/S+tnG4OUCIBvy9g6GCEUbgYgwPKF2k8G3
zrzrJ5SCjYy4UbElrjNx
-----END CERTIFICATE-----
`
	differentKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFU6aDkXYwx8YYtXd9AZPIst87daWX49Rzhxsd7D7UwroAoGCCqGSM49
AwEHoUQDQgAErUDDpFwiP28p9TD3OSmDNXeTbDxeIHsY3iqoya6x3Gk6MIyQEDrJ
SlwIRyqdMvo4Rc6/JUHQ67eXh1Cvy3w6Sg==
-----END EC PRIVATE KEY-----
`
)

var baseTime = time.Date(2020, 11, 19, 0, 0, 0, 0, time.UTC)

// Default CSR generation parameters using across the tests,
// actual values sets up within the init function
var defaultOrgs []string
var defaultIPs []net.IP
var defaultDNSNames []string

func init() {
	now = testingclock.NewFakePassiveClock(baseTime).Now
	networkv1.AddToScheme(scheme.Scheme)
	configv1.AddToScheme(scheme.Scheme)

	// Genereate a CA cert valid for the next 12 hours
	rootCert, rootKey, err := generateCertKeyPair(12*time.Hour, nil, nil, "system:node:test")
	if err != nil {
		panic(err)
	}

	// Sign a serving cert based on the previous CA cert
	serverCert, serverKey, err := generateCertKeyPair(time.Hour, rootCert, rootKey, "system:node:test", "node1", "node1.local")
	if err != nil {
		panic(err)
	}

	presetTimeCorrect = time.Now().UTC()
	presetTimeExpired = time.Now().UTC().Add(-24 * time.Hour)

	rootCertGood = string(rootCert)
	serverCertGood = string(serverCert)
	serverKeyGood = string(serverKey)

	defaultOrgs = []string{"system:nodes"}
	defaultIPs = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")}
	defaultDNSNames = []string{"node1", "node1.local"}

	goodCSR = createCSR("system:node:test", defaultOrgs, defaultIPs, defaultDNSNames)
	goodCSRECDSA = createCSRECDSA("system:node:test", defaultOrgs, defaultIPs, defaultDNSNames)
	extraAddr = createCSR(
		"system:node:test",
		defaultOrgs,
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1"), net.ParseIP("99.0.1.1")},
		defaultDNSNames)
	otherName = createCSR("system:node:foobar", defaultOrgs, defaultIPs, defaultDNSNames)
	noNamePrefix = createCSR("test", defaultOrgs, defaultIPs, defaultDNSNames)
	noGroup = createCSR("system:node:test", []string{}, defaultIPs, defaultDNSNames)
	clientGood = createCSR("system:node:panda", defaultOrgs, []net.IP{}, []string{})
	clientExtraO = createCSR("system:node:bear", []string{"bamboo", "system:nodes"}, []net.IP{}, []string{})
	clientWithDNS = createCSR("system:node:monkey", defaultOrgs, []net.IP{}, []string{"banana"})
	clientWrongCN = createCSR("system:notnode:zebra", defaultOrgs, []net.IP{}, []string{})
	clientEmptyName = createCSR("system:node:", defaultOrgs, []net.IP{}, []string{})
	emptyCSR = "-----BEGIN??\n"
	multusCSRPEM = createCSR("system:multus:", defaultOrgs, []net.IP{}, []string{})
}

func generateCertKeyPair(duration time.Duration, parentCertPEM, parentKeyPEM []byte, commonName string, otherNames ...string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"system:nodes"},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(duration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              otherNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")},
		IsCA:                  parentCertPEM == nil,
		BasicConstraintsValid: true, // Required, else IsCA is ignored
	}

	parentCert := &template
	var signerKey crypto.PrivateKey // Key must be a PrivateKey type, but this is an alias for interface{}
	signerKey = priv
	if parentCertPEM != nil {
		certificates, err := tls.X509KeyPair(parentCertPEM, parentKeyPEM)
		if err != nil {
			return nil, nil, err
		}

		signerKey = certificates.PrivateKey

		parentCert, err = x509.ParseCertificate(certificates.Certificate[0])
		if err != nil {
			return nil, nil, err
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &priv.PublicKey, signerKey)
	if err != nil {
		return nil, nil, err
	}

	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, err
	}

	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, nil, err
	}

	return certOut.Bytes(), keyOut.Bytes(), nil
}

func createCSR(commonName string, organizations []string, ipAddressess []net.IP, dnsNames []string) string {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)
	subj := pkix.Name{
		Organization: organizations,
		CommonName:   commonName,
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        ipAddressess,
		DNSNames:           dnsNames,
	}
	csrOut := new(bytes.Buffer)

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csrOut.String()
}

func createCSRECDSA(commonName string, organizations []string, ipAddressess []net.IP, dnsNames []string) string {
	keyBytes, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	subj := pkix.Name{
		Organization: organizations,
		CommonName:   commonName,
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IPAddresses:        ipAddressess,
		DNSNames:           dnsNames,
	}
	csrOut := new(bytes.Buffer)

	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csrOut.String()
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

	hostSubnet := func(name string) *networkv1.HostSubnet {
		return &networkv1.HostSubnet{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}
	}

	withEgressIPs := func(hostSubnet *networkv1.HostSubnet, egressIPs ...networkv1.HostSubnetEgressIP) *networkv1.HostSubnet {
		hostSubnet.EgressIPs = egressIPs
		return hostSubnet
	}

	withEgressCIDRs := func(hostSubnet *networkv1.HostSubnet, egressCIDRs ...networkv1.HostSubnetEgressCIDR) *networkv1.HostSubnet {
		hostSubnet.EgressCIDRs = egressCIDRs
		return hostSubnet
	}

	var makeMachine = func(nodeName string, addresses ...corev1.NodeAddress) machinehandlerpkg.Machine {
		if len(addresses) == 0 {
			addresses = []corev1.NodeAddress{
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
			}
		}
		var nodeRef *corev1.ObjectReference
		if nodeName != "" {
			nodeRef = &corev1.ObjectReference{
				Name: nodeName,
			}
		}
		return machinehandlerpkg.Machine{
			Status: machinehandlerpkg.MachineStatus{
				NodeRef:   nodeRef,
				Addresses: addresses,
			},
		}
	}

	type args struct {
		config        ClusterMachineApproverConfig
		machines      []machinehandlerpkg.Machine
		node          *corev1.Node
		kubeletServer net.Listener
		req           *certificatesv1.CertificateSigningRequest
		csr           string
		ca            []*x509.Certificate
		networkType   string
		hostSubnet    *networkv1.HostSubnet
	}
	tests := []struct {
		name      string
		args      args
		wantErr   string
		authorize bool
	}{
		{
			name: "ok",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: true,
		},
		{
			name: "ok with ECDSA",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSRECDSA,
			},
			wantErr:   "",
			authorize: true,
		},
		{
			name: "bad-csr",
			args: args{
				csr: emptyCSR,
				req: &certificatesv1.CertificateSigningRequest{},
			},
			wantErr:   "PEM block type must be CERTIFICATE REQUEST",
			authorize: false,
		},
		{
			name: "no-node-prefix",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "only-node-prefix",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "no-machine-status-ref",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{},
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
				csr: goodCSR,
			},
			wantErr:   "could not authorize CSR: exhausted all authorization methods: Unable to find machine for node",
			authorize: false,
		},
		{
			name: "missing-groups-1",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "missing-groups-2",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "extra-group",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: true,
		},
		{
			name: "wrong-group",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "usages-missing",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages:   []certificatesv1.KeyUsage{},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		}, {
			name: "usages-missing",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "usages-missing-1",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "usage-missing-2",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "usage-extra",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "csr-cn",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: otherName,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "csr-cn-2",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: noNamePrefix,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "csr-no-o",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: noGroup,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "csr-extra-addr",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: extraAddr,
			},
			wantErr:   "could not authorize CSR: exhausted all authorization methods: IP address '99.0.1.1' not in machine addresses: 127.0.0.1 10.0.0.1",
			authorize: false,
		},
		{
			name: "csr-san-ip-mismatch",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("test", []corev1.NodeAddress{
						{corev1.NodeInternalIP, "127.0.0.1"},
						{corev1.NodeExternalIP, "10.0.0.2"},
						{corev1.NodeExternalDNS, "node1"},
						{corev1.NodeExternalDNS, "node1.local"},
					}...),
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
				csr: goodCSR,
			},
			wantErr:   "could not authorize CSR: exhausted all authorization methods: IP address '10.0.0.1' not in machine addresses: 127.0.0.1 10.0.0.2",
			authorize: false,
		},
		{
			name: "csr-san-dns-mismatch",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("test", []corev1.NodeAddress{
						{corev1.NodeInternalIP, "127.0.0.1"},
						{corev1.NodeExternalIP, "10.0.0.1"},
						{corev1.NodeExternalDNS, "node1.local"},
						{corev1.NodeExternalDNS, "node2"},
					}...),
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
				csr: goodCSR,
			},
			wantErr:   "could not authorize CSR: exhausted all authorization methods: DNS name 'node1' not in machine names: node1.local node2",
			authorize: false,
		},
		{
			name: "client good",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "tigers"}),
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: true,
		},
		{
			name: "client extra O",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "bear"}),
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
				csr: clientExtraO,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client with DNS",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "monkey"}),
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
				csr: clientWithDNS,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but extra usage",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but wrong usage",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but missing usage",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but wrong CN",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "zebra"}),
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
				csr: clientWrongCN,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but wrong user",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but wrong user group",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but empty name",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientEmptyName,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but node exists",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but missing machine",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeExternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "failed to find machine for node panda",
			authorize: false,
		},
		{
			name: "client good but machine has node ref",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("other", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but auto approval is disabled",
			args: args{
				config: ClusterMachineApproverConfig{
					NodeClientCert: NodeClientCert{
						Disabled: true,
					},
				},
				machines: []machinehandlerpkg.Machine{
					makeMachine("other", corev1.NodeAddress{corev1.NodeInternalDNS, "tigers"}),
					makeMachine("other", corev1.NodeAddress{corev1.NodeInternalDNS, "panda"}),
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
				csr: clientGood,
			},
			wantErr:   "CSR orange for node client cert rejected as the flow is disabled",
			authorize: false,
		},
		{
			name: "client good with proper timing",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "tigers"}),
					{
						ObjectMeta: metav1.ObjectMeta{
							CreationTimestamp: creationTimestamp(2 * time.Minute),
						},
						Status: machinehandlerpkg.MachineStatus{
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: true,
		},
		{
			name: "client good with proper timing 2",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("", corev1.NodeAddress{corev1.NodeInternalDNS, "tigers"}),
					{
						ObjectMeta: metav1.ObjectMeta{
							CreationTimestamp: creationTimestamp(3 * time.Minute),
						},
						Status: machinehandlerpkg.MachineStatus{
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: true,
		},
		{
			name: "client good but CSR too early",
			args: args{
				machines: []machinehandlerpkg.Machine{
					makeMachine("other", corev1.NodeAddress{corev1.NodeInternalDNS, "tigers"}),
					{
						ObjectMeta: metav1.ObjectMeta{
							CreationTimestamp: creationTimestamp(3 * time.Minute),
						},
						Status: machinehandlerpkg.MachineStatus{
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but CSR too late",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
						Status: machinehandlerpkg.MachineStatus{
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
				csr: clientGood,
			},
			wantErr:   "",
			authorize: false,
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
				csr: goodCSR,
				ca:  []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			authorize: true,
		},
		{
			name: "successfull fallback to fresh approval",
			args: args{
				machines: []machinehandlerpkg.Machine{makeMachine("test")},
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
				csr: goodCSR,
				ca:  []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			authorize: true,
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
				csr:           goodCSR,
				ca:            []*x509.Certificate{parseCert(t, differentCert)},
				kubeletServer: fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort+1), differentCert, differentKey),
			},
			wantErr:   "could not authorize CSR: exhausted all authorization methods: [current serving cert has bad common name, Unable to find machine for node]",
			authorize: false,
		},
		{
			name: "CSR extra address not in egress IPs",
			args: args{
				node: withName("test", defaultNode()),
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
				csr:         extraAddr,
				networkType: "OpenShiftSDN",
				hostSubnet:  hostSubnet("test"),
				ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			wantErr:   "could not authorize CSR: exhausted all authorization methods: [CSR Subject Alternate Name values do not match current certificate, Unable to find machine for node, CSR Subject Alternate Names includes unknown IP addresses]",
			authorize: false,
		},
		{
			name: "CSR extra address in egress IPs",
			args: args{
				node: withName("test", defaultNode()),
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
				csr:         extraAddr,
				networkType: "OpenShiftSDN",
				hostSubnet:  withEgressIPs(hostSubnet("test"), "99.0.1.1"),
				ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			authorize: true,
		},
		{
			name: "CSR extra address in egress CIDRs",
			args: args{
				node: withName("test", defaultNode()),
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
				csr:         extraAddr,
				networkType: "OpenShiftSDN",
				hostSubnet:  withEgressCIDRs(hostSubnet("test"), "99.0.1.0/24"),
				ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			authorize: true,
		},
	}

	server := fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort), serverCertGood, serverKeyGood)
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kubeletServer := server
			if tt.args.kubeletServer != nil {
				kubeletServer = tt.args.kubeletServer
				defer kubeletServer.Close()
			}

			network := &configv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.NetworkStatus{
					NetworkType: tt.args.networkType,
				},
			}

			objs := []runtime.Object{network}
			if tt.args.node != nil {
				objs = append(objs, tt.args.node)
			}
			if tt.args.hostSubnet != nil {
				objs = append(objs, tt.args.hostSubnet)
			}
			cl := fake.NewFakeClient(objs...)
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
			if authorize, err := authorizeCSR(cl, tt.args.config, tt.args.machines, tt.args.req, parsedCSR, ca); authorize != tt.authorize || errString(err) != tt.wantErr {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, tt.wantErr)
			}
		})

		t.Run("Invalid call", func(t *testing.T) {
			if authorize, err := authorizeCSR(nil, tt.args.config, tt.args.machines, nil, nil, nil); authorize != false {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, "Invalid request")
			}
		})
	}
}

func TestAuthorizeServingRenewal(t *testing.T) {
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
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
		},
		{
			name:        "reject expired",
			nodeName:    "test",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeExpired,
			wantErr:     fmt.Sprintf("x509: certificate has expired or is not yet valid: current time %s is before %s", presetTimeExpired.Format(time.RFC3339), presetTimeCorrect.Format(time.RFC3339)),
		},
		{
			name:        "SAN list differs",
			nodeName:    "test",
			csr:         parseCR(t, extraAddr),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "CSR Subject Alternate Name values do not match current certificate",
		},
		{
			name:        "No certificate match",
			nodeName:    "test",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{},
			time:        presetTimeCorrect,
			wantErr:     "x509: certificate signed by unknown authority",
		},
		{
			name:        "Request from different node",
			nodeName:    "test",
			csr:         parseCR(t, otherName),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "current serving cert and CSR common name mismatch",
		},
		{
			name:        "Unexpected CN",
			nodeName:    "panda",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
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

func TestAuthorizeServingRenewalWithEgressIPs(t *testing.T) {
	testNodeName := "test"

	tests := []struct {
		name        string
		nodeName    string
		csr         *x509.CertificateRequest
		currentCert *x509.Certificate
		ca          []*x509.Certificate
		time        time.Time
		hostSubnet  *networkv1.HostSubnet
		wantErr     string
	}{
		{
			name:     "missing args",
			nodeName: "panda",
			wantErr:  "CSR, serving cert, or CA not provided",
		},
		{
			name:        "all good",
			nodeName:    testNodeName,
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			hostSubnet: &networkv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNodeName,
				},
			},
		},
		{
			name:        "reject expired",
			nodeName:    testNodeName,
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeExpired,
			wantErr:     fmt.Sprintf("x509: certificate has expired or is not yet valid: current time %s is before %s", presetTimeExpired.Format(time.RFC3339), presetTimeCorrect.Format(time.RFC3339)),
		},
		{
			name:        "With additional unknown IP address",
			nodeName:    testNodeName,
			csr:         parseCR(t, extraAddr),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			hostSubnet: &networkv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNodeName,
				},
			},
			wantErr: "CSR Subject Alternate Names includes unknown IP addresses",
		},
		{
			name:        "With additional Egress IP address",
			nodeName:    testNodeName,
			csr:         parseCR(t, extraAddr),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			hostSubnet: &networkv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNodeName,
				},
				EgressIPs: []networkv1.HostSubnetEgressIP{"99.0.1.1"},
			},
		},
		{
			name:        "With additional Egress IP in Egress CIDRs",
			nodeName:    testNodeName,
			csr:         parseCR(t, extraAddr),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			hostSubnet: &networkv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNodeName,
				},
				EgressCIDRs: []networkv1.HostSubnetEgressCIDR{"99.0.1.0/24"},
			},
		},
		{
			name:        "No certificate match",
			nodeName:    testNodeName,
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{},
			time:        presetTimeCorrect,
			wantErr:     "x509: certificate signed by unknown authority",
		},
		{
			name:        "Request from different node",
			nodeName:    testNodeName,
			csr:         parseCR(t, otherName),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "current serving cert and CSR common name mismatch",
		},
		{
			name:        "Unexpected CN",
			nodeName:    "panda",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
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

			objs := []runtime.Object{}
			if tt.hostSubnet != nil {
				objs = append(objs, tt.hostSubnet)
			}
			cl := fake.NewFakeClient(objs...)

			err := authorizeServingRenewalWithEgressIPs(
				cl,
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
			rootCerts: []*x509.Certificate{parseCert(t, rootCertGood)},
		},
		{
			name:      "unknown certificate",
			nodeName:  "test",
			node:      defaultNode,
			rootCerts: []*x509.Certificate{parseCert(t, differentCert)},
			wantErr:   "tls: failed to verify certificate: x509: certificate signed by unknown authority",
		},
		{
			name:      "node not found",
			nodeName:  "test",
			rootCerts: []*x509.Certificate{parseCert(t, rootCertGood)},
			wantErr:   "nodes \"test\" not found",
		},
		{
			name:      "wrong address",
			nodeName:  "test",
			node:      wrongAddr,
			rootCerts: []*x509.Certificate{parseCert(t, rootCertGood)},
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
			rootCerts: []*x509.Certificate{parseCert(t, rootCertGood)},
			wantErr:   "node test has no internal addresses",
		},
	}

	server := fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort), serverCertGood, serverKeyGood)
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
			if err == nil && !serverCert.Equal(parseCert(t, serverCertGood)) {
				t.Fatal("Expected server certificate match on success")
			}
		})
	}
}

func TestRecentlyPendingNodeBootstrapperCSRs(t *testing.T) {
	approvedNodeBootstrapperCSR := certificatesv1.CertificateSigningRequest{
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Username: nodeBootstrapperUsername,
			Groups:   nodeBootstrapperGroups.List(),
		},
		Status: certificatesv1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1.CertificateSigningRequestCondition{{
				Type: certificatesv1.CertificateApproved,
			}},
		},
	}
	pendingNodeBootstrapperCSR := certificatesv1.CertificateSigningRequest{
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Username: nodeBootstrapperUsername,
			Groups:   nodeBootstrapperGroups.List(),
		},
	}
	pendingNodeServerCSR := certificatesv1.CertificateSigningRequest{
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Username: nodeUserPrefix + "clustername-abcde-master-us-west-1a-0",
		},
	}
	pendingCSR := certificatesv1.CertificateSigningRequest{}
	multusCSR := certificatesv1.CertificateSigningRequest{
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Username: nodeUserPrefix + "clustername-abcde-master-us-west-1a-0",
			Request:  []byte(multusCSRPEM),
		},
	}

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
			name:          "recently pending Node bootstrapper csr",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, pendingNodeBootstrapperCSR)},
			expectPending: 1,
		},
		{
			name:          "recently pending Node csr",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, pendingNodeServerCSR)},
			expectPending: 1,
		},
		{
			name:          "recently pending unknown csr",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, pendingCSR)},
			expectPending: 0,
		},
		{
			name:          "recently approved csr",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, approvedNodeBootstrapperCSR)},
			expectPending: 0,
		},
		{
			name:          "pending past approval time",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pastApprovalTime, pendingNodeBootstrapperCSR)},
			expectPending: 0,
		},
		{
			name:          "pending before approval time",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(preApprovalTime, pendingNodeBootstrapperCSR)},
			expectPending: 0,
		},
		{
			name:          "multus node CSR",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, multusCSR)},
			expectPending: 0,
		},
		{
			name: "multiple different csrs",
			csrs: []certificatesv1.CertificateSigningRequest{
				createdAt(pendingTime, pendingNodeBootstrapperCSR),
				createdAt(pendingTime, pendingNodeBootstrapperCSR),
				createdAt(pendingTime, pendingNodeServerCSR),

				createdAt(pendingTime, pendingCSR),
				createdAt(pendingTime, approvedNodeBootstrapperCSR),
				createdAt(pendingTime, multusCSR),
				createdAt(preApprovalTime, approvedNodeBootstrapperCSR),
				createdAt(pastApprovalTime, approvedNodeBootstrapperCSR),
				createdAt(preApprovalTime, pendingNodeBootstrapperCSR),
				createdAt(pastApprovalTime, pendingNodeBootstrapperCSR),
			},
			expectPending: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if pending := recentlyPendingNodeCSRs(tt.csrs); pending != tt.expectPending {
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
	testCases := []struct {
		name        string
		machines    []machinehandlerpkg.Machine
		nodes       []corev1.Node
		expectedMax int
	}{
		{
			name: "with more machines than nodes",
			machines: []machinehandlerpkg.Machine{
				{},
				{},
				{},
			},
			nodes: []corev1.Node{
				{},
				{},
			},
			expectedMax: 3 + maxDiffBetweenPendingCSRsAndMachinesCount,
		},
		{
			name: "with more nodes than machines",
			machines: []machinehandlerpkg.Machine{
				{},
				{},
				{},
			},
			nodes: []corev1.Node{
				{},
				{},
				{},
				{},
			},
			expectedMax: 4 + maxDiffBetweenPendingCSRsAndMachinesCount,
		},
	}

	for _, tc := range testCases {
		nodeList := &corev1.NodeList{
			Items: tc.nodes,
		}
		res := getMaxPending(tc.machines, nodeList)
		if res != tc.expectedMax {
			t.Errorf("getMaxPending returned incorrect value: %v, expect: %v", res, tc.expectedMax)
		}
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

func TestSubsetIPAddresses(t *testing.T) {
	tenDotOne := net.ParseIP("10.0.0.1")
	tenDotTwo := net.ParseIP("10.0.0.2")
	tenDotThree := net.ParseIP("10.0.0.3")
	tenOneThree := net.ParseIP("10.0.1.3")
	_, tenNoughtSlash24, _ := net.ParseCIDR("10.0.0.0/24")

	tests := []struct {
		name     string
		cidrs    []*net.IPNet
		super    []net.IP
		sub      []net.IP
		expected bool
	}{
		{
			name:     "equal sets",
			super:    []net.IP{tenDotOne, tenDotTwo},
			sub:      []net.IP{tenDotOne, tenDotTwo},
			expected: true,
		},
		{
			name:     "sub is a subset",
			super:    []net.IP{tenDotOne, tenDotTwo},
			sub:      []net.IP{tenDotOne},
			expected: true,
		},
		{
			name:     "sub is a superset",
			super:    []net.IP{tenDotOne, tenDotTwo},
			sub:      []net.IP{tenDotOne, tenDotThree},
			expected: false,
		},
		{
			name:     "sub is a subset with duplicates",
			super:    []net.IP{tenDotOne, tenDotTwo},
			sub:      []net.IP{tenDotOne, tenDotOne},
			expected: true,
		},
		{
			name:     "sub is a subset when cidrs are included",
			cidrs:    []*net.IPNet{tenNoughtSlash24},
			super:    []net.IP{tenOneThree},
			sub:      []net.IP{tenDotOne, tenOneThree},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if equal := subsetIPAddresses(tt.cidrs, tt.super, tt.sub); equal != tt.expected {
				t.Errorf("%v subset of %v :: wanted %v, got %v",
					tt.sub, tt.super, tt.expected, equal)
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
