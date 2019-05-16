package main

import (
	"crypto/x509"
	"reflect"
	"strings"

	capi "k8s.io/api/certificates/v1beta1"
)

// copied from k8s.io/kubernetes/pkg/controller/certificates/approver/sarapprove.go

func hasExactUsages(csr *capi.CertificateSigningRequest, usages []capi.KeyUsage) bool {
	if len(usages) != len(csr.Spec.Usages) {
		return false
	}

	usageMap := map[capi.KeyUsage]struct{}{}
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

var kubeletClientUsages = []capi.KeyUsage{
	capi.UsageKeyEncipherment,
	capi.UsageDigitalSignature,
	capi.UsageClientAuth,
}

func isNodeClientCert(csr *capi.CertificateSigningRequest, x509cr *x509.CertificateRequest) bool {
	if !reflect.DeepEqual([]string{"system:nodes"}, x509cr.Subject.Organization) {
		return false
	}
	if (len(x509cr.DNSNames) > 0) || (len(x509cr.EmailAddresses) > 0) || (len(x509cr.IPAddresses) > 0) {
		return false
	}
	if !hasExactUsages(csr, kubeletClientUsages) {
		return false
	}
	if !strings.HasPrefix(x509cr.Subject.CommonName, "system:node:") {
		return false
	}
	return true
}
