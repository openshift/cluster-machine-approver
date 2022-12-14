package controller

import (
	"crypto/x509"
	"fmt"
	"reflect"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	capi "k8s.io/api/certificates/v1"
	"k8s.io/klog/v2"
)

// copied from k8s.io/kubernetes/pkg/controller/certificates/approver/sarapprove.go

type KeyUsage string

const (
	UsageSigning           KeyUsage = "signing"
	UsageDigitalSignature  KeyUsage = "digital signature"
	UsageContentCommitment KeyUsage = "content commitment"
	UsageKeyEncipherment   KeyUsage = "key encipherment"
	UsageKeyAgreement      KeyUsage = "key agreement"
	UsageDataEncipherment  KeyUsage = "data encipherment"
	UsageCertSign          KeyUsage = "cert sign"
	UsageCRLSign           KeyUsage = "crl sign"
	UsageEncipherOnly      KeyUsage = "encipher only"
	UsageDecipherOnly      KeyUsage = "decipher only"
	UsageAny               KeyUsage = "any"
	UsageServerAuth        KeyUsage = "server auth"
	UsageClientAuth        KeyUsage = "client auth"
	UsageCodeSigning       KeyUsage = "code signing"
	UsageEmailProtection   KeyUsage = "email protection"
	UsageSMIME             KeyUsage = "s/mime"
	UsageIPsecEndSystem    KeyUsage = "ipsec end system"
	UsageIPsecTunnel       KeyUsage = "ipsec tunnel"
	UsageIPsecUser         KeyUsage = "ipsec user"
	UsageTimestamping      KeyUsage = "timestamping"
	UsageOCSPSigning       KeyUsage = "ocsp signing"
	UsageMicrosoftSGC      KeyUsage = "microsoft sgc"
	UsageNetscapeSGC       KeyUsage = "netscape sgc"
)

var (
	organizationNotSystemNodesErr = fmt.Errorf("subject organization is not system:nodes")
	commonNameNotSystemNode       = fmt.Errorf("subject common name does not begin with system:node:")
	dnsOrIPSANRequiredErr         = fmt.Errorf("DNS or IP subjectAltName is required")
	dnsSANNotAllowedErr           = fmt.Errorf("DNS subjectAltNames are not allowed")
	emailSANNotAllowedErr         = fmt.Errorf("Email subjectAltNames are not allowed")
	ipSANNotAllowedErr            = fmt.Errorf("IP subjectAltNames are not allowed")
	uriSANNotAllowedErr           = fmt.Errorf("URI subjectAltNames are not allowed")
)

var (
	kubeletClientRequiredUsagesNoRSA = sets.NewString(
		string(UsageDigitalSignature),
		string(UsageClientAuth),
	)
	kubeletClientRequiredUsages = sets.NewString(
		string(UsageDigitalSignature),
		string(UsageKeyEncipherment),
		string(UsageClientAuth),
	)
)

func isNodeClientCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if csr.Spec.SignerName != capi.KubeAPIServerClientKubeletSignerName {
		return false
	}

	err := validateKubeletClientCSR(x509cr, usagesToSet(csr.Spec.Usages))
	if err != nil {
		klog.Warningf("couldn't validate kubelet client csr: %s", err)
	}

	return err == nil
}

func usagesToSet(usages []capi.KeyUsage) sets.String {
	result := sets.NewString()

	for _, usage := range usages {
		result.Insert(string(usage))
	}

	return result
}

func validateKubeletClientCSR(req *x509.CertificateRequest, usages sets.String) error {
	if !reflect.DeepEqual([]string{"system:nodes"}, req.Subject.Organization) {
		return organizationNotSystemNodesErr
	}

	if len(req.DNSNames) > 0 {
		return dnsSANNotAllowedErr
	}
	if len(req.EmailAddresses) > 0 {
		return emailSANNotAllowedErr
	}
	if len(req.IPAddresses) > 0 {
		return ipSANNotAllowedErr
	}
	if len(req.URIs) > 0 {
		return uriSANNotAllowedErr
	}

	if !strings.HasPrefix(req.Subject.CommonName, "system:node:") {
		return commonNameNotSystemNode
	}

	if !kubeletClientRequiredUsages.Equal(usages) && !kubeletClientRequiredUsagesNoRSA.Equal(usages) {
		return fmt.Errorf("usages did not match %v", kubeletClientRequiredUsages.List())
	}

	return nil
}
