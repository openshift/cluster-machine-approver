package controller

import (
	"crypto/x509"
	"k8s.io/klog/v2"
	"reflect"
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
)

// copied from k8s.io/kubernetes/pkg/controller/certificates/approver/sarapprove.go

func hasExactUsages(csr *certificatesv1.CertificateSigningRequest, usages []certificatesv1.KeyUsage) bool {
	if len(usages) != len(csr.Spec.Usages) {
		return false
	}

	usageMap := map[certificatesv1.KeyUsage]struct{}{}
	for _, u := range usages {
		usageMap[u] = struct{}{}
	}

	for _, u := range csr.Spec.Usages {
		if _, ok := usageMap[u]; !ok {
			return false
		}
	}

	return true
}

var kubeletClientUsagesLegacy = []certificatesv1.KeyUsage{
	certificatesv1.UsageKeyEncipherment,
	certificatesv1.UsageDigitalSignature,
	certificatesv1.UsageClientAuth,
}

var kubeletClientUsages = []certificatesv1.KeyUsage{
	certificatesv1.UsageKeyEncipherment,
	certificatesv1.UsageClientAuth,
}

func isNodeClientCert(csr *certificatesv1.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if !reflect.DeepEqual([]string{"system:nodes"}, x509cr.Subject.Organization) {
		klog.Infof("isNodeClientCert: failed Subject Organization Check: %+v", x509cr.Subject.Organization)
		return false
	}
	if (len(x509cr.DNSNames) > 0) || (len(x509cr.EmailAddresses) > 0) || (len(x509cr.IPAddresses) > 0) {
		klog.Infof("isNodeClientCert: failed DNS/EMAIL/IPADDRESS check: %+v %+v %+v", x509cr.DNSNames, x509cr.EmailAddresses, x509cr.IPAddresses)
		return false
	}
	if !hasExactUsages(csr, kubeletClientUsagesLegacy) && !hasExactUsages(csr, kubeletClientUsages) {
		klog.Infof("isNodeClientCert: failed exact usages: %+v", csr.Spec.Usages)
		return false
	}
	if !strings.HasPrefix(x509cr.Subject.CommonName, "system:node:") {
		klog.Infof("isNodeClientCert: failed common name check: %+v", x509cr.Subject.CommonName)
		return false
	}
	return true
}
