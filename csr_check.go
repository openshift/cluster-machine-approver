package main

import (
	"crypto/x509"
	"strings"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
)

const (
	nodeUser       = "system:node"
	nodeGroup      = "system:nodes"
	nodeUserPrefix = nodeUser + ":"
)

func validateCSRContents(req *certificatesv1beta1.CertificateSigningRequest, csr *x509.CertificateRequest) (string, bool) {
	if !strings.HasPrefix(req.Spec.Username, nodeUserPrefix) {
		return "",false
	}

	nodeAsking := strings.TrimPrefix(req.Spec.Username, nodeUserPrefix)
	if len(nodeAsking) < 1 {
		return "",false
	}

	// Check groups, we need at least:
	// - system:nodes
	// - system:authenticated
	if len(req.Spec.Groups) < 2 {
		return "",false
	}
	groupSet := sets.NewString(req.Spec.Groups...)
	if !groupSet.HasAll(nodeGroup, "system:authenticated") {
		return "",false
	}

	// Check usages, we need only:
	// - digital signature
	// - key encipherment
	// - server auth
	if len(req.Spec.Usages) != 3 {
		return "",false
	}

	usages := make([]string, 0)
	for i := range req.Spec.Usages {
		usages = append(usages, string(req.Spec.Usages[i]))
	}

	// No extra usages!
	if len(usages) != 3 {
		return "",false
	}

	usageSet := sets.NewString(usages...)
	if !usageSet.HasAll(
		string(certificatesv1beta1.UsageDigitalSignature),
		string(certificatesv1beta1.UsageKeyEncipherment),
		string(certificatesv1beta1.UsageServerAuth),
	) {
		return "",false
	}

	// Check subject: O = system:nodes, CN = system:node:ip-10-0-152-205.ec2.internal
	if csr.Subject.CommonName != req.Spec.Username {
		return "",false
	}

	var hasOrg bool
	for i := range csr.Subject.Organization {
		if csr.Subject.Organization[i] == nodeGroup {
			hasOrg = true
			break
		}
	}
	if !hasOrg {
		return "",false
	}

	return nodeAsking, true
}

// authorizeCSR authorizes the CertificateSigningRequest req for a node's server certificate.
// csr should be the parsed CSR from req.Spec.Request. Names contained in the CSR are checked against addresses in the
// corresponding node's machine status.
func authorizeCSR(machineList *v1beta1.MachineList, req *certificatesv1beta1.CertificateSigningRequest, csr *x509.CertificateRequest) bool {
	if machineList == nil || len(machineList.Items) < 1 || req == nil || csr == nil {
		return false
	}

	nodeAsking, ok := validateCSRContents(req, csr)
	if !ok {
		return false
	}
	// Check that we have a registered node with the request name
	var targetMachine *v1beta1.MachineStatus
	for _, machine := range machineList.Items {
		if machine.Status.NodeRef != nil && machine.Status.NodeRef.Name == nodeAsking {
			targetMachine = machine.Status.DeepCopy()
			break
		}
	}
	if targetMachine == nil {
		return false
	}

	// SAN checks for both DNS and IPs, e.g.,
	// DNS:ip-10-0-152-205, DNS:ip-10-0-152-205.ec2.internal, IP Address:10.0.152.205, IP Address:10.0.152.205
	// All names in the request must correspond to addresses assigned to a single machine.
	for _, san := range csr.DNSNames {
		if len(san) < 1 {
			continue
		}
		var foundSan bool
		for _, addr := range targetMachine.Addresses {
			switch addr.Type {
			case v1.NodeInternalDNS, v1.NodeExternalDNS, v1.NodeHostName:
				if san == addr.Address {
					foundSan = true
				}
			default:
			}
		}
		// The CSR requested a DNS name that did not belong to the machine
		if !foundSan {
			return false
		}
	}

	for _, san := range csr.IPAddresses {
		if len(san) < 1 {
			continue
		}
		var foundSan bool
		for _, addr := range targetMachine.Addresses {
			switch addr.Type {
			case v1.NodeInternalIP, v1.NodeExternalIP:
				if san.String() == addr.Address {
					foundSan = true
				}
			default:
			}
		}
		// The CSR requested an IP name that did not belong to the machine
		if !foundSan {
			return false
		}
	}

	return true
}
