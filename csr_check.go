package main

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
)

const (
	altInternalDNS = "AltInternalDNS"
	nodeUser       = "system:node"
	nodeGroup      = "system:nodes"
	nodeUserPrefix = nodeUser + ":"

	maxPendingDelta = time.Hour
	maxPendingCSRs  = 100

	nodeBootstrapperUsername = "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper"

	maxMachineClockSkew = 10 * time.Second
	maxMachineDelta     = 10 * time.Minute
)

var nodeBootstrapperGroups = sets.NewString(
	"system:serviceaccounts:openshift-machine-config-operator",
	"system:serviceaccounts",
	"system:authenticated",
)

func validateCSRContents(req *certificatesv1beta1.CertificateSigningRequest, csr *x509.CertificateRequest) (string, error) {
	if !strings.HasPrefix(req.Spec.Username, nodeUserPrefix) {
		return "", fmt.Errorf("Doesn't match expected prefix")
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
		return "", fmt.Errorf("Not in system:authenticated")
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
		return "", fmt.Errorf("Missing usages")
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
		return "", fmt.Errorf("Organization doesn't include %s", nodeGroup)
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
func authorizeCSR(config ClusterMachineApproverConfig, machines []v1beta1.Machine, nodes corev1client.NodeInterface, req *certificatesv1beta1.CertificateSigningRequest, csr *x509.CertificateRequest) error {
	if len(machines) == 0 || req == nil || csr == nil {
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
	// Check that we have a registered node with the request name
	targetMachine, ok := findMatchingMachineFromNodeRef(nodeAsking, machines)
	if !ok {
		return fmt.Errorf("No target machine")
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
			case corev1.NodeInternalDNS, corev1.NodeExternalDNS, corev1.NodeHostName, altInternalDNS:
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
		return fmt.Errorf("CSR %s for node client cert has wrong user", req.Name)
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
