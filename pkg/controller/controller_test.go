package controller

import (
	"context"
	"crypto/x509"
	"fmt"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	timeout   = time.Second * 3
	forPeriod = time.Second * 1
)

// random certificate with test values
const certData = `-----BEGIN CERTIFICATE-----
MIIDCzCCAfMCFCJZrU7XzpyaR08FjUcEcVjwaG5uMA0GCSqGSIb3DQEBCwUAMEIx
CzAJBgNVBAYTAkVVMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxHDAaBgNVBAoME0Rl
ZmF1bHQgQ29tcGFueSBMdGQwHhcNMjAwNzA3MTQxNzM4WhcNMjMwNDA0MTQxNzM4
WjBCMQswCQYDVQQGEwJFVTEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQK
DBNEZWZhdWx0IENvbXBhbnkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAqAfPJziNfrCnzDkA+4PW1n0FUGkfvvtDU1eu0EwOngx5lVrO5B6mdB8I
Y7zP+M6wptPELORKEUYLsBUu/H9m2g9O/AUGfQQy4br97Y5ti/J1+oybulzxAXGS
eI5aK9nHSUU1XP9alCfkPlN57Ue3hR6H27bRBZw2l2H0Rv0pSz7HtApz3qxX2rxl
7ysxBqkknM9CGmh10di8PUjk5AsLqzJ7IzCmCZhqKlQqO259AaBLLIyeEQlYsA9U
XOD3gzYwt+fUNlrma05jLuO0t67J6yLCDZ7Tk76WfApxhZ/5nyVa4/SDO/Uu2bbX
8F4pzcCzc0n4eeYV8z8CzYYie/sMfwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBn
pdDMD/JlLqNIz0AMU14iUye0gPtE6DT2NplSbq1HWYHhF/vVoSDzaWV9ZsG5+NRU
SFQz5O2t5fTMh1QriGSnHnddOKGaAkL7JFejYJwAsKPkDg1x1o/yb/sESrWdHtPD
UIufQ/iMtCuY44vreQdIyUueSqoxH/5f+1XihvRAQz/7KZJ7MRfGte/YayTX8yp9
kBC69E233D64lBNZD+aDlCjERQHMRW5wjJbLgJiO/cBE7+z5WPkhO8Yhljy9r46s
8p74ome2deP4vGrjlw7HYWEx1vexPoTtwmUcXEy4ZnZ2s/YR6Hx6eH3ouqTc/fjH
y+ccmKUcUfbMselUeA5v
-----END CERTIFICATE-----
`

// Mocked copy of clientWrongCN certificate
const certRequest = `-----BEGIN CERTIFICATE REQUEST-----
MIICczCCAVsCAQAwLjEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRUwEwYDVQQDEwxz
eXN0ZW06bm9kZTowggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/m0SP
zooyqB2raVHz183M2oUklhQCRP3DVqBFtt0kC5BB6zzfWdnk5clsu3yyA/vGNFo3
f+jNCrtP9/LVjXrbfiQrWfoyMW10gBOsSO7ovSuMhwPd7/8vEoUs+eOnYqp2khZ5
5KvJLMa7e59WZvzsqBWMMRWp9sCVXFpDwHbq8bAWoDZYhxyLR8f3d8sYH6oncj9m
lbn3NAPakTvSnSJwPepSby3bUykgCP7SuU7P4PrlAXf55kTX/+DV5ZG3TO/cdVhl
7F1rwQ6vetzp1bb36sbWtYv0oDMw9+tNpmiUfDr/9bOf/6zNTUij6ZRylYleo1I1
OKdI21OBRFAhhyVvAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAW5cOsaSYnURz
wnMRVpr7B821+DZu1G8Mv1lUzEvU+ZaVIaIL6Dv0BfDb9QLOYHzfceCYzJmavSOl
SdZLoLkL1SYUp77tGDcbwWQyngWY5G7upZudBMEYOHvG/4YnNPb+5BkIgsREJl/+
jVK2u+yuAkzkDdODM2NwRP9TGhPCbcqFeE2ozdJzluIGYafsQFPFr7kb8liiOV2O
u1xKRHq7Bb54+3sRt1PsmuYhIl4l1Sh1epKIhUGzBxyzJUAKsbsPk6s64euMhCxz
VoJUoVggIY3WxIVV+rpqlC7ThIgdYkq7fZeAeYAnbwB8eM208w5NUgxYTsZN7VDo
rj/Dkdwyag==
-----END CERTIFICATE REQUEST-----
`

var _ = Describe("caConfigMapFilter", func() {
	var configMap *v1.ConfigMap

	BeforeEach(func() {
		configMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubeletCAConfigMap,
				Namespace: configNamespace,
			},
			Data: map[string]string{
				"ca-bundle.crt": certData,
			},
		}
	})

	It("Passes the filter on correct configMap", func() {
		Expect(caConfigMapFilter(configMap, nil)).To(BeTrue())
	})

	It("Passes the filter on correct update for configMap", func() {
		configMapNew := configMap.DeepCopy()
		configMapNew.Data["ca-bundle.crt"] = "somedata"
		Expect(caConfigMapFilter(configMap, configMapNew)).To(BeTrue())
	})

	It("Rejects incorrect object on the filter", func() {
		Expect(caConfigMapFilter(nil, nil)).To(BeFalse())
	})

	It("Rejects incorrect configMap on the filter", func() {
		incorrectConfigMap := &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "someMap",
				Namespace: configNamespace,
			},
		}
		Expect(caConfigMapFilter(incorrectConfigMap, nil)).To(BeFalse())
		Expect(caConfigMapFilter(configMap, incorrectConfigMap)).To(BeFalse())
	})

	It("Rejects configMap without expected ca-bundle.crt in data", func() {
		incorrectConfigMap := configMap.DeepCopy()
		incorrectConfigMap.Data = map[string]string{}
		Expect(caConfigMapFilter(incorrectConfigMap, nil)).To(BeFalse())
		Expect(caConfigMapFilter(configMap, incorrectConfigMap)).To(BeFalse())
	})
})

var _ = It("Should approve and put condition on valid CSR", func() {
	csr := &certificatesv1.CertificateSigningRequest{
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request: []byte(certRequest),
		},
	}
	csr.SetGenerateName("csr")
	Expect(c.Create(context.Background(), csr)).To(Succeed())

	Expect(approve(config, csr)).To(Succeed())
	getCSR := &certificatesv1.CertificateSigningRequest{}
	Expect(c.Get(context.Background(), client.ObjectKey{Name: csr.Name}, getCSR)).To(Succeed())
	conditions := fmt.Sprintf("%s", getCSR.Status.Conditions)
	Expect(conditions).To(ContainSubstring("Approved"))
})

var _ = Describe("Should filter out only pending certificates", func() {
	csr := &certificatesv1.CertificateSigningRequest{
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request: []byte(certRequest),
		},
	}

	It("Should pass pending certificate", func() {
		Expect(pendingCertFilter(csr)).To(BeTrue())
	})

	It("Should reject approved certificate", func() {
		csrCopy := csr.DeepCopy()
		csrCopy.Status = certificatesv1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1.CertificateSigningRequestCondition{{
				Type: certificatesv1.CertificateApproved,
			}},
		}
		Expect(pendingCertFilter(csrCopy)).To(BeFalse())
	})

	It("Should reject other object then certificates", func() {
		machine := &machinev1.Machine{}
		Expect(pendingCertFilter(machine)).To(BeFalse())
	})
})

var _ = Describe("Should verify the CSR is approved", func() {
	It("Confirms the cert is approved", func() {
		csr := &certificatesv1.CertificateSigningRequest{
			Status: certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{{
					Type: certificatesv1.CertificateApproved,
				}},
			},
		}
		Expect(isApproved(*csr)).To(BeTrue())
	})

	It("Confirms the cert is not approved without right condition", func() {
		csr := &certificatesv1.CertificateSigningRequest{}
		Expect(isApproved(*csr)).To(BeFalse())
	})
})

var _ = Describe(("toCSRs should map reconcile requests to all CSRs"), func() {
	const csrTotal = 5
	var approver *CertificateApprover

	BeforeEach(func() {
		csr := &certificatesv1.CertificateSigningRequest{
			Spec: certificatesv1.CertificateSigningRequestSpec{
				Request: []byte(certRequest),
			},
		}
		csr.SetGenerateName("csr")
		for i := 0; i < csrTotal; i++ {
			createCsr := csr.DeepCopy()
			Expect(c.Create(context.Background(), createCsr)).To(Succeed())
		}
		for i := 0; i < csrTotal; i++ {
			createCsr := csr.DeepCopy()
			createCsr.Status = certificatesv1.CertificateSigningRequestStatus{
				Conditions: []certificatesv1.CertificateSigningRequestCondition{{
					Type: certificatesv1.CertificateApproved,
				}},
			}
			Expect(c.Create(context.Background(), createCsr)).To(Succeed())
		}
		approver = &CertificateApprover{
			Client: c,
		}
	})

	It("Expect to get reconcile requests to all non-pending CSRs", func() {
		requests := approver.toCSRs(nil)
		csrList := &certificatesv1.CertificateSigningRequestList{}
		Expect(c.List(context.Background(), csrList)).To(Succeed())
		for _, csr := range csrList.Items {
			key := reconcile.Request{NamespacedName: client.ObjectKey{Name: csr.Name}}
			if isApproved(csr) {
				Expect(requests).ToNot(ContainElement(key))
			} else {
				Expect(requests).To(ContainElement(key))
			}
		}
	})
})

var _ = Describe("Kubelet configMap should provide valid CA bundle", func() {
	var expectedPool *x509.CertPool
	var configMap *v1.ConfigMap
	var approver *CertificateApprover

	ctx := context.Background()

	deleteGracePeriod := int64(0)

	BeforeEach(func() {
		approver = &CertificateApprover{
			Client: c,
		}
	})

	AfterEach(func() {
		// cleanup configMap
		Expect(c.Delete(ctx, configMap, &client.DeleteOptions{GracePeriodSeconds: &deleteGracePeriod})).To(Succeed())

		Eventually(func() bool {
			return apierrors.IsNotFound(c.Get(ctx, client.ObjectKeyFromObject(configMap), configMap))
		}, timeout).Should(BeTrue())
		configMap = nil
		expectedPool = nil
	})

	It("Successfully reads kubelet configMap", func() {
		expectedPool = x509.NewCertPool()
		expectedPool.AppendCertsFromPEM([]byte(certData))
		configMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubeletCAConfigMap,
				Namespace: configNamespace,
			},
			Data: map[string]string{
				"ca-bundle.crt": certData,
			},
		}
		Expect(c.Create(ctx, configMap)).To(Succeed())
		pool := approver.getKubeletCA()
		Expect(pool).To(Equal(expectedPool))
	})

	It("Fails on invalid configMap data", func() {
		configMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubeletCAConfigMap,
				Namespace: configNamespace,
			},
			Data: map[string]string{
				"ca-bundle.crt": "",
			},
		}
		Expect(c.Create(ctx, configMap)).To(Succeed())
		pool := approver.getKubeletCA()
		Expect(pool).To(BeNil())
	})

	It("Fails on wrong configMap data key", func() {
		configMap = &v1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubeletCAConfigMap,
				Namespace: configNamespace,
			},
			Data: map[string]string{
				"ca.crt": certData,
			},
		}
		Expect(c.Create(ctx, configMap)).To(Succeed())
		pool := approver.getKubeletCA()
		Expect(pool).To(BeNil())
	})
})
