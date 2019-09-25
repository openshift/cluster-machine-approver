package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"

	"github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
)

const (
	nodeUser       = "system:node"
	nodeGroup      = "system:nodes"
	nodeUserPrefix = nodeUser + ":"

	maxPendingDelta = time.Hour
	maxPendingCSRs  = 100

	nodeBootstrapperUsername = "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper"

	maxMachineClockSkew = 10 * time.Second
	maxMachineDelta     = 2 * time.Hour
)

var nodeBootstrapperGroups = sets.NewString(
	"system:serviceaccounts:openshift-machine-config-operator",
	"system:serviceaccounts",
	"system:authenticated",
)

func validateCSRContents(req *certificatesv1beta1.CertificateSigningRequest, csr *x509.CertificateRequest) (string, error) {
	if !strings.HasPrefix(req.Spec.Username, nodeUserPrefix) {
		return "", fmt.Errorf("%q doesn't match expected prefix: %q", req.Spec.Username, nodeUserPrefix)
	}

	nodeAsking := strings.TrimPrefix(req.Spec.Username, nodeUserPrefix)
	if len(nodeAsking) == 0 {
		return "", fmt.Errorf("Empty name")
	}

	// Check groups, we need at least:
	// - system:nodes
	// - system:authenticated
	if len(req.Spec.Groups) < 2 {
		return "", fmt.Errorf("Too few groups")
	}
	groupSet := sets.NewString(req.Spec.Groups...)
	if !groupSet.HasAll(nodeGroup, "system:authenticated") {
		return "", fmt.Errorf("%q not in %q and %q", groupSet, "system:authenticated", nodeGroup)
	}

	// Check usages, we need only:
	// - digital signature
	// - key encipherment
	// - server auth
	if len(req.Spec.Usages) != 3 {
		return "", fmt.Errorf("Too few usages")
	}

	usages := make([]string, 0)
	for i := range req.Spec.Usages {
		usages = append(usages, string(req.Spec.Usages[i]))
	}

	// No extra usages!
	if len(usages) != 3 {
		return "", fmt.Errorf("Unexpected usages: %d", len(usages))
	}

	usageSet := sets.NewString(usages...)
	if !usageSet.HasAll(
		string(certificatesv1beta1.UsageDigitalSignature),
		string(certificatesv1beta1.UsageKeyEncipherment),
		string(certificatesv1beta1.UsageServerAuth),
	) {
		return "", fmt.Errorf("%q is missing usages", usageSet)
	}

	// Check subject: O = system:nodes, CN = system:node:ip-10-0-152-205.ec2.internal
	if csr.Subject.CommonName != req.Spec.Username {
		return "", fmt.Errorf("Mismatched CommonName %s != %s", csr.Subject.CommonName, req.Spec.Username)
	}

	var hasOrg bool
	for i := range csr.Subject.Organization {
		if csr.Subject.Organization[i] == nodeGroup {
			hasOrg = true
			break
		}
	}
	if !hasOrg {
		return "", fmt.Errorf("Organization %v doesn't include %s", csr.Subject.Organization, nodeGroup)
	}

	return nodeAsking, nil
}

// authorizeCSR authorizes the CertificateSigningRequest req for a node's client or server certificate.
// csr should be the parsed CSR from req.Spec.Request.
//
// For client certificates, when the flow is not globally disabled:
// The only information contained in the CSR is the future name of the node.  Thus we perform a best effort check:
//
// 1. User is the node bootstrapper
// 2. Node does not exist
// 3. Use machine API internal DNS to locate matching machine based on node name
// 4. Machine must not have a node ref
// 5. CSR creation timestamp is very close to machine creation timestamp
// 6. CSR is meant for node client auth based on usage, CN, etc
//
// For server certificates:
// Names contained in the CSR are checked against addresses in the corresponding node's machine status.
func authorizeCSR(
	config ClusterMachineApproverConfig,
	machines []v1beta1.Machine,
	nodes corev1client.NodeInterface,
	req *certificatesv1beta1.CertificateSigningRequest,
	csr *x509.CertificateRequest,
	ca *x509.CertPool,
) error {
	if req == nil || csr == nil {
		return fmt.Errorf("Invalid request")
	}

	if isNodeClientCert(req, csr) {
		return authorizeNodeClientCSR(config, machines, nodes, req, csr)
	}

	// node serving cert validation after this point

	nodeAsking, err := validateCSRContents(req, csr)
	if err != nil {
		return err
	}

	// Check for an existing serving cert from the node.  If found, use the
	// renewal flow.  Any error connecting to the node, including validation of
	// the presented cert against the current Kubelet CA, will result in
	// fallback to the original flow relying on the machine-api.
	//
	// This is only supported if we were given a CA to verify against.
	if ca != nil {
		servingCert, err := getServingCert(nodes, nodeAsking, ca)
		if err == nil && servingCert != nil {
			klog.Infof("authorizing serving cert renewal for %s", nodeAsking)
			if authorizeErr := authorizeServingRenewal(nodeAsking, csr, servingCert, ca); authorizeErr != nil {
				// Don't return here so we can fallback to machine-api check.
				klog.Errorf("%v: unable to validate existing serving cert for node %v: %v", req.Name, nodeAsking, authorizeErr)
			} else {
				return nil
			}
		}

		if err != nil {
			klog.Errorf("failed to retrieve current serving cert: %v", err)
		}
	}

	// Fall back to the original machine-api based authorization scheme.
	klog.Infof("%v: Falling back to machine-api based check %s", req.Name, nodeAsking)

	// Check that we have a registered node with the request name
	targetMachine, ok := findMatchingMachineFromNodeRef(nodeAsking, machines)
	if !ok {
		return fmt.Errorf("No target machine for node %q", nodeAsking)
	}

	// SAN checks for both DNS and IPs, e.g.,
	// DNS:ip-10-0-152-205, DNS:ip-10-0-152-205.ec2.internal, IP Address:10.0.152.205, IP Address:10.0.152.205
	// All names in the request must correspond to addresses assigned to a single machine.
	for _, san := range csr.DNSNames {
		if len(san) == 0 {
			continue
		}
		var attemptedAddresses []string
		var foundSan bool
		for _, addr := range targetMachine.Status.Addresses {
			switch addr.Type {
			case corev1.NodeInternalDNS, corev1.NodeExternalDNS, corev1.NodeHostName:
				if san == addr.Address {
					foundSan = true
					break
				} else {
					attemptedAddresses = append(attemptedAddresses, addr.Address)
				}
			default:
			}
		}
		// The CSR requested a DNS name that did not belong to the machine
		if !foundSan {
			return fmt.Errorf("DNS name '%s' not in machine names: %s", san, strings.Join(attemptedAddresses, " "))
		}
	}

	for _, san := range csr.IPAddresses {
		if len(san) == 0 {
			continue
		}
		var attemptedAddresses []string
		var foundSan bool
		for _, addr := range targetMachine.Status.Addresses {
			switch addr.Type {
			case corev1.NodeInternalIP, corev1.NodeExternalIP:
				if san.String() == addr.Address {
					foundSan = true
					break
				} else {
					attemptedAddresses = append(attemptedAddresses, addr.Address)
				}
			default:
			}
		}
		// The CSR requested an IP name that did not belong to the machine
		if !foundSan {
			return fmt.Errorf("IP address '%s' not in machine addresses: %s", san, strings.Join(attemptedAddresses, " "))
		}
	}

	return nil
}

func authorizeNodeClientCSR(config ClusterMachineApproverConfig, machines []v1beta1.Machine, nodes corev1client.NodeInterface, req *certificatesv1beta1.CertificateSigningRequest, csr *x509.CertificateRequest) error {
	if config.NodeClientCert.Disabled {
		return fmt.Errorf("CSR %s for node client cert rejected as the flow is disabled", req.Name)
	}

	if !isReqFromNodeBootstrapper(req) {
		return fmt.Errorf("CSR %s for node client cert has wrong user %s or groups %s", req.Name, req.Spec.Username, sets.NewString(req.Spec.Groups...))
	}

	nodeName := strings.TrimPrefix(csr.Subject.CommonName, nodeUserPrefix)
	if len(nodeName) == 0 {
		return fmt.Errorf("CSR %s has empty node name", req.Name)
	}

	_, err := nodes.Get(nodeName, metav1.GetOptions{})
	switch {
	case err == nil:
		return fmt.Errorf("node %s already exists", nodeName)
	case errors.IsNotFound(err):
		// good, node does not exist
	default:
		return fmt.Errorf("failed to check if node %s already exists: %v", nodeName, err)
	}

	nodeMachine, ok := findMatchingMachineFromInternalDNS(nodeName, machines)
	if !ok {
		return fmt.Errorf("failed to find machine for node %s", nodeName)
	}

	if nodeMachine.Status.NodeRef != nil {
		return fmt.Errorf("machine for node %s already has node ref", nodeName)
	}

	start := nodeMachine.CreationTimestamp.Add(-maxMachineClockSkew)
	end := nodeMachine.CreationTimestamp.Add(maxMachineDelta)
	if !inTimeSpan(start, end, req.CreationTimestamp.Time) {
		return fmt.Errorf("CSR %s creation time %s not in range (%s, %s)", req.Name, req.CreationTimestamp.Time, start, end)
	}

	return nil // approve node client cert
}

// authorizeServingRenewal will authorize the renewal of a kubelet's serving
// certificate.
//
// The current certificate must be signed by the current CA and not expired.
// The common name on the current certificate must match the expected value.
// All Subject Alternate Name values must match between CSR and current cert.
func authorizeServingRenewal(nodeName string, csr *x509.CertificateRequest, currentCert *x509.Certificate, ca *x509.CertPool) error {
	if csr == nil || currentCert == nil || ca == nil {
		return fmt.Errorf("CSR, serving cert, or CA not provided")
	}

	// Check that the serving cert is signed by the given CA, is not expired,
	// and is otherwise valid.
	if _, err := currentCert.Verify(x509.VerifyOptions{Roots: ca}); err != nil {
		return err
	}

	// Check that the CN is correct on the current cert.
	if currentCert.Subject.CommonName != fmt.Sprintf("%s:%s", nodeUser, nodeName) {
		return fmt.Errorf("current serving cert has bad common name")
	}

	// Check that the CN matches on the CSR and current cert.
	if currentCert.Subject.CommonName != csr.Subject.CommonName {
		return fmt.Errorf("current serving cert and CSR common name mismatch")
	}

	// Check that all Subject Alternate Name values are equal.
	match := reflect.DeepEqual(currentCert.DNSNames, csr.DNSNames) &&
		reflect.DeepEqual(currentCert.IPAddresses, csr.IPAddresses) &&
		reflect.DeepEqual(currentCert.EmailAddresses, csr.EmailAddresses) &&
		reflect.DeepEqual(currentCert.URIs, csr.URIs)

	if !match {
		return fmt.Errorf("CSR Subject Alternate Name values do not match current certificate")
	}

	return nil
}

func isReqFromNodeBootstrapper(req *certificatesv1beta1.CertificateSigningRequest) bool {
	return req.Spec.Username == nodeBootstrapperUsername && nodeBootstrapperGroups.Equal(sets.NewString(req.Spec.Groups...))
}

func findMatchingMachineFromNodeRef(nodeName string, machines []v1beta1.Machine) (v1beta1.Machine, bool) {
	for _, machine := range machines {
		if machine.Status.NodeRef != nil && machine.Status.NodeRef.Name == nodeName {
			return machine, true
		}
	}
	return v1beta1.Machine{}, false
}

func findMatchingMachineFromInternalDNS(nodeName string, machines []v1beta1.Machine) (v1beta1.Machine, bool) {
	for _, machine := range machines {
		for _, address := range machine.Status.Addresses {
			if address.Type == corev1.NodeInternalDNS && address.Address == nodeName {
				return machine, true
			}
		}
	}
	return v1beta1.Machine{}, false
}

func inTimeSpan(start, end, check time.Time) bool {
	return check.After(start) && check.Before(end)
}

func isApproved(csr *certificatesv1beta1.CertificateSigningRequest) bool {
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1beta1.CertificateApproved {
			return true
		}
	}
	return false
}

func recentlyPendingCSRs(indexer cache.Indexer) int {
	// assumes we are scheduled on the master meaning our clock is the same
	now := time.Now()
	start := now.Add(-maxPendingDelta)
	end := now.Add(maxMachineClockSkew)

	var pending int

	for _, item := range indexer.List() {
		csr := item.(*certificatesv1beta1.CertificateSigningRequest)

		// ignore "old" CSRs
		if !inTimeSpan(start, end, csr.CreationTimestamp.Time) {
			continue
		}

		if !isApproved(csr) {
			pending++
		}
	}

	return pending
}

// getServingCert fetches the node by the given name and attempts to connect to
// its kubelet on the first advertised address.
//
// If successful, and the returned TLS certificate is validated against the
// given CA, the node's serving certificate as presented over the established
// connection is returned.
func getServingCert(nodes corev1client.NodeInterface, nodeName string, ca *x509.CertPool) (*x509.Certificate, error) {
	if ca == nil {
		return nil, fmt.Errorf("no CA found: will not retrieve serving cert")
	}

	node, err := nodes.Get(nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	host, err := nodeInternalIP(node)
	if err != nil {
		return nil, err
	}

	port := node.Status.DaemonEndpoints.KubeletEndpoint.Port

	kubelet := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	tlsConfig := &tls.Config{
		RootCAs:    ca,
		ServerName: host,
	}

	klog.Infof("retrieving serving cert from %s (%s)", nodeName, kubelet)

	conn, err := tls.DialWithDialer(dialer, "tcp", kubelet, tlsConfig)
	if err != nil {
		return nil, err
	}

	defer conn.Close()

	cert := conn.ConnectionState().PeerCertificates[0]

	return cert, nil
}

// nodeInternalIP returns the first internal IP for the node.
func nodeInternalIP(node *corev1.Node) (string, error) {
	for _, address := range node.Status.Addresses {
		if address.Type == corev1.NodeInternalIP {
			return address.Address, nil
		}
	}

	return "", fmt.Errorf("node %s has no internal addresses", node.Name)
}
