package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	networkv1 "github.com/openshift/api/network/v1"
	machinehandlerpkg "github.com/openshift/cluster-machine-approver/pkg/machinehandler"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	nodeUser       = "system:node"
	nodeGroup      = "system:nodes"
	nodeUserPrefix = nodeUser + ":"

	maxPendingDelta                           = time.Hour
	maxApprovedDelta                          = 30 * time.Second
	maxDiffBetweenPendingCSRsAndMachinesCount = 100

	nodeBootstrapperUsername = "system:serviceaccount:openshift-machine-config-operator:node-bootstrapper"

	maxMachineClockSkew = 10 * time.Second
	maxMachineDelta     = 2 * time.Hour

	networkTypeOpenShiftSDN = "OpenShiftSDN"
	networkClusterName      = "cluster"
)

var nodeBootstrapperGroups = sets.NewString(
	"system:serviceaccounts:openshift-machine-config-operator",
	"system:serviceaccounts",
	"system:authenticated",
)

var now = time.Now

var MaxPendingCSRs uint32
var PendingCSRs uint32

func validateCSRContents(req *certificatesv1.CertificateSigningRequest, csr *x509.CertificateRequest) (string, error) {
	if !strings.HasPrefix(req.Spec.Username, nodeUserPrefix) {
		klog.Infof("%v: CSR does not appear to be a node serving cert", req.Name)
		return "", nil
	}

	nodeAsking := strings.TrimPrefix(req.Spec.Username, nodeUserPrefix)
	if len(nodeAsking) == 0 {
		klog.Infof("%v: CSR does not appear to be a node serving cert", req.Name)
		return "", nil
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

	validationUsageSetLegacy := []string{
		string(certificatesv1.UsageDigitalSignature),
		string(certificatesv1.UsageKeyEncipherment),
		string(certificatesv1.UsageServerAuth),
	}
	validationUsageSet := []string{
		string(certificatesv1.UsageDigitalSignature),
		string(certificatesv1.UsageServerAuth),
	}

	// Check usages, we need only:
	// - digital signature
	// - key encipherment
	if len(req.Spec.Usages) != len(validationUsageSetLegacy) && len(req.Spec.Usages) != len(validationUsageSet) {
		// - server auth
		return "", fmt.Errorf("Too few usages")
	}

	usages := make([]string, len(req.Spec.Usages))
	for i := range req.Spec.Usages {
		usages[i] = string(req.Spec.Usages[i])
	}

	usageSet := sets.NewString(usages...)
	if !usageSet.HasAll(validationUsageSet...) && !usageSet.HasAll(validationUsageSetLegacy...) {
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
	c client.Client,
	config ClusterMachineApproverConfig,
	machines []machinehandlerpkg.Machine,
	req *certificatesv1.CertificateSigningRequest,
	csr *x509.CertificateRequest,
	ca *x509.CertPool,
) (bool, error) {
	if req == nil || csr == nil {
		klog.Errorf("authorizeCSR invalid request")
		return false, nil
	}

	if isNodeClientCert(req, csr) {
		if config.NodeClientCert.Disabled {
			klog.Errorf("%v: CSR rejected as the flow is disabled", req.Name)
			return false, fmt.Errorf("CSR %s for node client cert rejected as the flow is disabled", req.Name)
		}
		return authorizeNodeClientCSR(c, machines, req, csr)
	}

	klog.Infof("%v: CSR does not appear to be client csr", req.Name)
	// node serving cert validation after this point

	nodeAsking, err := validateCSRContents(req, csr)
	if nodeAsking == "" || err != nil {
		if err != nil {
			//TODO: set annotation/emit event here.
			klog.Errorf("%v: Unrecoverable serving cert error, cannot approve: %v", req.Name, err)
		}
		return false, nil
	}

	var approvalErrors []error

	// Check for an existing serving cert from the node.  If found, use the
	// renewal flow.  Any error connecting to the node, including validation of
	// the presented cert against the current Kubelet CA, will result in
	// fallback to the original flow relying on the machine-api.
	//
	// This is only supported if we were given a CA to verify against.
	var servingCert *x509.Certificate
	if ca != nil {
		var err error
		servingCert, err = getServingCert(c, nodeAsking, ca)
		if err != nil {
			klog.Infof("Failed to retrieve current serving cert: %v", err)
		}
	}

	x509VerificationOpts := x509.VerifyOptions{Roots: ca}
	if servingCert != nil {
		klog.Infof("Found existing serving cert for %s", nodeAsking)

		if err := authorizeServingRenewal(nodeAsking, csr, servingCert, x509VerificationOpts); err != nil {
			approvalErrors = append(approvalErrors, err)
			klog.Infof("Could not use current serving cert for renewal: %v", err)
			klog.Infof("Current SAN Values: %v, CSR SAN Values: %v",
				certSANs(servingCert), csrSANs(csr))
		} else {
			// No error, the renewal is authorized.
			return true, nil
		}
	}

	// Fall back to the original machine-api based authorization scheme.
	klog.Infof("Falling back to machine-api authorization for %s", nodeAsking)
	if err := authorizeServingCertWithMachine(machines, req, nodeAsking, csr); err != nil {
		approvalErrors = append(approvalErrors, err)
		klog.Infof("Could not use Machine for serving cert authorization: %v", err)
	} else {
		// No error means the machine was able to authorize the cert
		return true, nil
	}

	egressEnabled, err := needsEgressCheck(c)
	if err != nil {
		klog.Infof("Could not determine if egress enabled: %v", err)
		return false, fmt.Errorf("could not determine if egress enabled: %v", err)
	}

	if servingCert != nil && egressEnabled {
		klog.Infof("Falling back to serving cert renewal with Egress IP checks")
		if err := authorizeServingRenewalWithEgressIPs(c, nodeAsking, csr, servingCert, x509VerificationOpts); err != nil {
			approvalErrors = append(approvalErrors, err)
			klog.Infof("Could not use current serving cert and egress IPs for renewal: %v", err)
		} else {
			// No error means the machine was able to authorize the cert
			return true, nil
		}
	}

	return false, fmt.Errorf("could not authorize CSR: exhausted all authorization methods: %v", kerrors.NewAggregate(approvalErrors))
}

func authorizeNodeClientCSR(c client.Client, machines []machinehandlerpkg.Machine, req *certificatesv1.CertificateSigningRequest, csr *x509.CertificateRequest) (bool, error) {
	if !isReqFromNodeBootstrapper(req) {
		klog.Infof("%v: CSR does not appear to be a valid node bootstrapper client cert request", req.Name)
		return false, nil
	}

	nodeName := strings.TrimPrefix(csr.Subject.CommonName, nodeUserPrefix)
	if len(nodeName) == 0 {
		//TODO: set annotation/emit event here.
		klog.Errorf("%v: CSR does not appear to be a valid node bootstrapper client cert request", req.Name)
		return false, nil
	}

	if err := c.Get(context.Background(), client.ObjectKey{Name: nodeName}, &corev1.Node{}); err != nil && !apierrors.IsNotFound(err) {
		// possible transient API error, requeue
		klog.Errorf("%v: unable to get node %s error: %v", req.Name, nodeName, err)
		return false, fmt.Errorf("failed get existing nodes %s", nodeName)
	} else if err == nil {
		//TODO: set annotation/emit event here.
		klog.Errorf("%v: node %s already exists, cannot approve", req.Name, nodeName)
		return false, nil
	}

	nodeMachine, err := machinehandlerpkg.FindMatchingMachineFromInternalDNS(machines, nodeName)
	if err != nil {
		//TODO: set annotation/emit event here.
		klog.Errorf("%v: failed to find machine for node %s, cannot approve", req.Name, nodeName)
		return false, fmt.Errorf("failed to find machine for node %s", nodeName)
	}

	if nodeMachine.Status.NodeRef != nil {
		//TODO: set annotation/emit event here.
		klog.Errorf("%v: machine for node %v already has node ref, cannot approve", nodeMachine.Status.NodeRef)
		return false, nil
	}

	start := nodeMachine.ObjectMeta.CreationTimestamp.Add(-maxMachineClockSkew)
	end := nodeMachine.ObjectMeta.CreationTimestamp.Add(maxMachineDelta)
	if !inTimeSpan(start, end, req.CreationTimestamp.Time) {
		//TODO: set annotation/emit event here.
		klog.Errorf("%v: CSR creation time %s not in range (%s, %s)", req.Name, req.CreationTimestamp.Time, start, end)
		return false, nil
	}

	return true, nil // approve node client cert
}

// authorizeServingRenewal will authorize the renewal of a kubelet's serving
// certificate.
//
// The current certificate must be signed by the current CA and not expired.
// The common name on the current certificate must match the expected value.
// All Subject Alternate Name values must match between CSR and current cert.
func authorizeServingRenewal(nodeName string, csr *x509.CertificateRequest, currentCert *x509.Certificate, options x509.VerifyOptions) error {
	if err := verifyCertificateCommonName(nodeName, csr, currentCert, options); err != nil {
		return err
	}

	// Check that all Subject Alternate Name values are equal.
	match := equalStrings(currentCert.DNSNames, csr.DNSNames) &&
		equalStrings(currentCert.EmailAddresses, csr.EmailAddresses) &&
		equalIPAddresses(currentCert.IPAddresses, csr.IPAddresses) &&
		equalURLs(currentCert.URIs, csr.URIs)

	if !match {
		return fmt.Errorf("CSR Subject Alternate Name values do not match current certificate")
	}

	return nil
}

// authorizeServingRenewal will authorize the renewal of a kubelet's serving
// certificate.
//
// The current certificate must be signed by the current CA and not expired.
// The common name on the current certificate must match the expected value.
// All non IP address Subject Alternate Name values must match between CSR and current cert.
//
// The requested IP address Subject Alternate Name values must be a subset of the union of the
// IP Address values within the current certificate and the egress IP addresses assigned to the
// Node.
//
// TODO: Once CCMs are GA, we should be able to exclude the egress networks via the CCM configuration.
// Investigate that this is the case and remove this fallback if appropriate.
func authorizeServingRenewalWithEgressIPs(c client.Client, nodeName string, csr *x509.CertificateRequest, currentCert *x509.Certificate, options x509.VerifyOptions) error {
	if err := verifyCertificateCommonName(nodeName, csr, currentCert, options); err != nil {
		return err
	}

	// Check that all Subject Alternate Name values except IP addresses are equal.
	// IP addresses will be verified separately.
	match := equalStrings(currentCert.DNSNames, csr.DNSNames) &&
		equalStrings(currentCert.EmailAddresses, csr.EmailAddresses) &&
		equalURLs(currentCert.URIs, csr.URIs)

	if !match {
		return fmt.Errorf("CSR Subject Alternate Name values do not match current certificate")
	}

	hostSubnet := &networkv1.HostSubnet{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: nodeName}, hostSubnet); err != nil {
		return fmt.Errorf("could not fetch hostsubnet: %v", err)
	}

	allowedIPAddresses := currentCert.IPAddresses
	for _, ipAddr := range hostSubnet.EgressIPs {
		allowedIPAddresses = append(allowedIPAddresses, net.ParseIP(string(ipAddr)))
	}

	allowedCIDRs := []*net.IPNet{}
	for _, egressCIDR := range hostSubnet.EgressCIDRs {
		_, cidr, err := net.ParseCIDR(string(egressCIDR))
		if err != nil {
			return fmt.Errorf("could not parse Egress CIDR: %v", err)
		}
		allowedCIDRs = append(allowedCIDRs, cidr)
	}

	if !subsetIPAddresses(allowedCIDRs, allowedIPAddresses, csr.IPAddresses) {
		return fmt.Errorf("CSR Subject Alternate Names includes unknown IP addresses")
	}

	return nil
}

func authorizeServingCertWithMachine(machines []machinehandlerpkg.Machine, req *certificatesv1.CertificateSigningRequest, nodeAsking string, csr *x509.CertificateRequest) error {
	// Check that we have a registered node with the request name
	targetMachine, err := machinehandlerpkg.FindMatchingMachineFromNodeRef(machines, nodeAsking)
	if err != nil {
		klog.Errorf("%v: Serving Cert: No target machine for node %q", req.Name, nodeAsking)
		//TODO: set annotation/emit event here.
		// Return error so we requeue in case we're racing with node linker.
		return fmt.Errorf("Unable to find machine for node")
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
				if strings.EqualFold(san, addr.Address) {
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
			//TODO: set annotation/emit event here.
			// return error so we requeue, in case machine network is out of date
			// for some reason
			klog.Errorf("%v: DNS name '%s' not in machine names: %s", req.Name, san, strings.Join(attemptedAddresses, " "))
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
			switch corev1.NodeAddressType(addr.Type) {
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
			//TODO: set annotation/emit event here.
			// return error so we requeue, in case machine network is out of date
			// for some reason
			klog.Errorf("%v: IP address '%s' not in machine addresses: %s", req.Name, san, strings.Join(attemptedAddresses, " "))
			return fmt.Errorf("IP address '%s' not in machine addresses: %s", san, strings.Join(attemptedAddresses, " "))
		}
	}

	return nil
}

func verifyCertificateCommonName(nodeName string, csr *x509.CertificateRequest, currentCert *x509.Certificate, options x509.VerifyOptions) error {
	// options.Roots should contain root certificates
	if csr == nil || currentCert == nil || options.Roots == nil {
		return fmt.Errorf("CSR, serving cert, or CA not provided")
	}

	// Check that the serving cert is signed by the given CA, is not expired,
	// and is otherwise valid.
	if _, err := currentCert.Verify(options); err != nil {
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

	return nil
}

func isReqFromNodeBootstrapper(req *certificatesv1.CertificateSigningRequest) bool {
	return req.Spec.Username == nodeBootstrapperUsername && nodeBootstrapperGroups.Equal(sets.NewString(req.Spec.Groups...))
}

func inTimeSpan(start, end, check time.Time) bool {
	return check.After(start) && check.Before(end)
}

func isApproved(csr certificatesv1.CertificateSigningRequest) bool {
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1.CertificateApproved {
			return true
		}
	}
	return false
}

func isRecentlyApproved(csr certificatesv1.CertificateSigningRequest) bool {
	// assumes we are scheduled on the master meaning our clock is the same
	currentTime := now()
	start := currentTime.Add(-maxApprovedDelta)
	end := currentTime.Add(maxMachineClockSkew)

	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1.CertificateApproved {
			return inTimeSpan(start, end, condition.LastTransitionTime.Time)
		}
	}
	return false
}

func isApprovedByCMA(csr certificatesv1.CertificateSigningRequest) bool {
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certificatesv1.CertificateApproved {
			return condition.Message == csrConditionApproveMessage
		}
	}
	return false
}

func recentlyPendingNodeCSRs(csrs []certificatesv1.CertificateSigningRequest) int {
	// assumes we are scheduled on the master meaning our clock is the same
	currentTime := now()
	start := currentTime.Add(-maxPendingDelta)
	end := currentTime.Add(maxMachineClockSkew)

	var pending int

	for _, csr := range csrs {
		// ignore "old" CSRs
		if !inTimeSpan(start, end, csr.CreationTimestamp.Time) {
			continue
		}

		if (isReqFromNodeBootstrapper(&csr) || isRequestFromNodeUser(csr)) && !isApproved(csr) {
			pending++
		}
	}

	return pending
}

func isRequestFromNodeUser(csr certificatesv1.CertificateSigningRequest) bool {
	return strings.HasPrefix(csr.Spec.Username, nodeUserPrefix)
}

// getServingCert fetches the node by the given name and attempts to connect to
// its kubelet on the first advertised address.
//
// If successful, and the returned TLS certificate is validated against the
// given CA, the node's serving certificate as presented over the established
// connection is returned.
func getServingCert(c client.Client, nodeName string, ca *x509.CertPool) (*x509.Certificate, error) {
	if ca == nil {
		return nil, fmt.Errorf("no CA found: will not retrieve serving cert")
	}

	node := &corev1.Node{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: nodeName}, node); err != nil {
		return nil, err
	}

	host, err := nodeInternalIP(node)
	if err != nil {
		return nil, err
	}

	port := strconv.Itoa(int(node.Status.DaemonEndpoints.KubeletEndpoint.Port))

	kubelet := net.JoinHostPort(host, port)
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

// needsEgressCheck determines whether or not egress IP checks should be enabled.
func needsEgressCheck(c client.Client) (bool, error) {
	network := &configv1.Network{}
	if err := c.Get(context.Background(), client.ObjectKey{Name: networkClusterName}, network); err != nil {
		return false, fmt.Errorf("could not fetch cluster network: %v", err)
	}

	return network.Status.NetworkType == networkTypeOpenShiftSDN, nil
}

// equalStrings tests whether two slices of strings are equal.
func equalStrings(a, b []string) bool {
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))

	copy(aCopy, a)
	copy(bCopy, b)

	sort.Strings(aCopy)
	sort.Strings(bCopy)

	return reflect.DeepEqual(aCopy, bCopy)
}

// equalURLs tests whether the string representations of two slices of URLs
// are equal.
func equalURLs(a, b []*url.URL) bool {
	var aStrings, bStrings []string

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		aStrings = append(aStrings, a[i].String())
		bStrings = append(bStrings, b[i].String())
	}

	sort.Strings(aStrings)
	sort.Strings(bStrings)

	return reflect.DeepEqual(aStrings, bStrings)
}

// equalIPAddresses tests whether the string representations of two slices of IP
// Addresses are equal.
func equalIPAddresses(a, b []net.IP) bool {
	var aStrings, bStrings []string

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		aStrings = append(aStrings, a[i].String())
		bStrings = append(bStrings, b[i].String())
	}

	sort.Strings(aStrings)
	sort.Strings(bStrings)

	return reflect.DeepEqual(aStrings, bStrings)
}

// subsetIPAddresses tests whether the set sub is contained within the set super.
// If an element of sub does not exist in super but does exist within cidrs, this
// is also considered a part of the superset.
func subsetIPAddresses(cidrs []*net.IPNet, super, sub []net.IP) bool {
	superSet := make(map[string]struct{})
	for _, ipAddr := range super {
		superSet[ipAddr.String()] = struct{}{}
	}

	for _, ipAddr := range sub {
		if !ipInSet(cidrs, superSet, ipAddr) {
			return false
		}
	}

	return true
}

func ipInSet(cidrs []*net.IPNet, ipSet map[string]struct{}, ipAddr net.IP) bool {
	if _, ok := ipSet[ipAddr.String()]; ok {
		return ok
	}

	for _, cidr := range cidrs {
		if cidr.Contains(ipAddr) {
			return true
		}
	}

	return false
}

// csrSANs returns the Subject Alternative Name values for the given
// certificate request as a slice of strings.
func csrSANs(csr *x509.CertificateRequest) []string {
	sans := []string{}

	if csr == nil {
		return sans
	}

	sans = append(sans, csr.DNSNames...)
	sans = append(sans, csr.EmailAddresses...)

	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}

	for _, uri := range csr.URIs {
		sans = append(sans, uri.String())
	}

	return sans
}

// certSANs returns the Subject Alternative Name values for the given
// certificate as a slice of strings.
func certSANs(cert *x509.Certificate) []string {
	sans := []string{}

	if cert == nil {
		return sans
	}

	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)

	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	return sans
}
