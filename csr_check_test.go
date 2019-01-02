package main

import (
	"testing"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/util/certificate/csr"
	capiclient "sigs.k8s.io/cluster-api/pkg/apis/cluster/v1alpha1"
)

/*
  {
    "hosts": [
        "node1",
        "node1.local",
        "10.0.0.1",
        "127.0.0.1"
    ],
    "CN": "system:node:test",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [{
        "O": "system:nodes"
    }]
  }

  $ cfssl genkey test_csr.json | cfssljson -bare certificate
*/

var (
	goodCSR = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = system:node:test
...
        Requested Extensions:
            X509v3 Subject Alternative Name:
                DNS:node1, DNS:node1.local, IP Address:10.0.0.1, IP Address:127.0.0.1
...
-----BEGIN CERTIFICATE REQUEST-----
MIICszCCAZsCAQAwMjEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRkwFwYDVQQDExBz
eXN0ZW06bm9kZTp0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
vgPRW4dXOGcys5wOeoQJO8Z+dHhgcQGMJosuNbsykf3znM2xUSB/20aQB5R4f749
JCOzGICpsHUBVVTWpmEI48TDt85T/ShI9fLrfgpZEoS6pyPRvgaBqZsVxEWSSNj/
Bjk3/iA4nDItK8r4JFbpjXCXlE0vY/+wMwResNyl5h0KJruwNqDZnPD6vTZaIqUw
Xxeb4FOAeKxcySea2WnQj2y57pPlm4i9xSKgiNFgdr4Be9PtjhQhYxdguCfXFO8a
PAFBbOAUgxt2M3yo4hVQqEdMCCJvckqar4a4M7KTUbsmIeClL8/wFfj6duD+ERjp
Bn6hIrlF/iyHMbhzJC3+XwIDAQABoDwwOgYJKoZIhvcNAQkOMS0wKzApBgNVHREE
IjAgggVub2RlMYILbm9kZTEubG9jYWyHBAoAAAGHBH8AAAEwDQYJKoZIhvcNAQEL
BQADggEBADEcf7HSTQsrjQM4RneAKmt8OKYM0+1haN6vC7K/siGRCLx/YWae6gK1
haAMxThWRjAExy/SaEX9KBZVaQRdHlA9FVQrz1hwdMgR5OtCFrepiwHAIMRwwyW0
nS6AyeeWLsoKdQKIXmDkL545Q2FzEVUmSsDTmNsZRU86RJf2gnj4xZiPNDbh5RzC
zvOecIcfEb0CnoidEHytO964xg5caVKyydku0oR9TrFSio4Oyof5b5oxbBRVJqII
8N02uj7bRCzZzEJYynYFcwmUA+3+L+pQd0/idOpNUq/2N5MNzDRddIHtNUHorP2Y
scTUtCJ0MRK3AupLIlqSd+evEMsE/3I=
-----END CERTIFICATE REQUEST-----
`
	extraAddr = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = system:node:test
...
        Requested Extensions:
            X509v3 Subject Alternative Name:
                DNS:node1, DNS:node1.local, IP Address:10.0.0.1, IP Address:127.0.0.1, IP Address:99.0.1.1
...
-----BEGIN CERTIFICATE REQUEST-----
MIICuTCCAaECAQAwMjEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRkwFwYDVQQDExBz
eXN0ZW06bm9kZTp0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
zQPu0iSz7SbmmkpWjLV5VeBK2DAYiofOVMOgEs9rzkgnjYR0rFzaIPBFVyUkDoXb
hDSN0P6A3yX4wg4s5uiBileQvHIgEfraOfWkmD69VE/khsi00GfmToRtttFjLosO
GMVJwoqNFwZ3LZNLlkLlxUFCnkKely+y7LMpHQIMU7y8ZUTbxr8DAqQaFQ8HgYoF
BIexDo6E6XutOLv5IO6HB0NvlwVkBjC4eBPDcLdO8AomHZXTZ7NBgAgrF698Mq4Q
lD6ytYNlOc456gs+f4TJMnrElPz1Uxdw8xg3BIECzSCsd+8NeHDOGy0AZ4onDKk/
N9nE1E+0ZBppczueXAPEzQIDAQABoEIwQAYJKoZIhvcNAQkOMTMwMTAvBgNVHREE
KDAmggVub2RlMYILbm9kZTEubG9jYWyHBAoAAAGHBH8AAAGHBGMAAQEwDQYJKoZI
hvcNAQELBQADggEBAE1se684AUPxTMEzNwFr7BHAvsO0BmrNDCUiRekm4NpHDna5
7UbRLBdeUyERr6TQLjSQqsnwAgBbZh1DVyGxi4f+o6WWD4qWOovM9oMqs29MRSte
rAyFZYysY+lOalmi/c7FTd7TpBwBMyET1ubQemG7RKnooG0wLU3ZotgRvem/A9nc
PnziY7NNRQm7TS5u1jaOIcoUQ9qVtdhgiD9RETdI60RXtkn2+AA25kb+xdu+5sT1
wBIbLh6TnZ4YNdW0iWVqPmRnKzgiZqQToJv4a0W/gArvA7WuafQQBt5VKol/G1Tp
UjVeonKUB6osd0zFbSaa1jAVugOuq/TOtgqqe3I=
-----END CERTIFICATE REQUEST-----
`
	otherName = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = system:node:foobar
...
        Requested Extensions:
            X509v3 Subject Alternative Name:
                DNS:node1, DNS:node1.local, IP Address:10.0.0.1, IP Address:127.0.0.1
...
-----BEGIN CERTIFICATE REQUEST-----
MIICtTCCAZ0CAQAwNDEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRswGQYDVQQDExJz
eXN0ZW06bm9kZTpmb29iYXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDM4YGB+Ie65mWik+JqTg7YS63V5n7IgrN89YVrEeQh6Xo6+egB3cumTXlL3ReE
eoYo+AF/TFuWx1Gblzd0rU1XmRv+zyPPmVBeMNPzOaozsfEYChI/jo1H6tkKd0hX
l4iPOMgTCGLFdQVElFlxxuotetbiLWPF3ieCMaxPmtxqemKRPWPKm+DaZzOD3D1v
vK/KWacuz1Jp1yZ0qD/Twt73Nw3toaDfF65ktBXVPDsNUkIj//YOag0SHMA/Fdpb
d5cn8Vcn4Wl2tvUODxou1XWRE82Peov+ViNwhuTzDI/wUn/ODVmYO32SygvEBHwK
heCoIKwOXKonaWWUQZw8pIgPAgMBAAGgPDA6BgkqhkiG9w0BCQ4xLTArMCkGA1Ud
EQQiMCCCBW5vZGUxggtub2RlMS5sb2NhbIcECgAAAYcEfwAAATANBgkqhkiG9w0B
AQsFAAOCAQEASwwkg4gJJhK68oPHaUdsMRs2MXZaJK8IddO1ikHZusmTOawBMvmy
Lmyc6bo3svH0G9lx+CcN56pwdwkyLvmrGqgDgXleRf1joGe1I1ZS5SnFLNBc+6Rz
XwBfEI/IIahDRnLov5E3EhguoiTtlqjtyh6hiXYS0HfuSdziCNM0f9fB0NIv7EDp
3RIX4AWQAY/BBANop7EUixMyUyArbN9AR1FOr2zN9afFvb7lWmU4aTD3B1El3zI+
xHhp0+EpkGHKwJN+IFchU6UXaWYaAVAYtGA2Zd1IPMr5UqhwvIYkVYYzcEZN/+Wa
+S+DXhS+SVYtdPSJ5DqUuzjE526yZIrdcw==
-----END CERTIFICATE REQUEST-----
`
	noNamePrefix = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = test
...
        Requested Extensions:
            X509v3 Subject Alternative Name:
                DNS:node1, DNS:node1.local, IP Address:10.0.0.1, IP Address:127.0.0.1
...
-----BEGIN CERTIFICATE REQUEST-----
MIICpzCCAY8CAQAwJjEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMQ0wCwYDVQQDEwR0
ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuT/DBVT6Bn5ANmj+
NZBOuWYUw9M6WdXyQnHuDT81qynrhKImltOG9m4M6ckCAXNRiSD8H/lT5fE6tXGO
mDo2ZXqeGF3ZO/5mvWfW5DGD4RzIo4OaFQxDN9TxflHShIeGLITDhnc5P0DheCT0
bfL5A000cLzudbb9Bs4P40R3W8VBTasI/q4ZjeVJYEKWVZaimg0qQDBEy0JkLhZw
XcPmsrmKSR3YJJayAqjkQqlN1efXqIZhtabWUl2SFWrhieqtywrqeP4efIIy10hT
EbNaCQoUMRUBHh4W6L3mi/HOXMuOXHOPMacBP1rN28irq7djvjfpnwioY8P8aAhn
YwwqEQIDAQABoDwwOgYJKoZIhvcNAQkOMS0wKzApBgNVHREEIjAgggVub2RlMYIL
bm9kZTEubG9jYWyHBAoAAAGHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBACd1RaL4
b4+oeg2kjEISED2yitEjhCB3CSQdNH0+ljc/umBi3RPjy/vAf3mop1ogEMBGl4cf
fKgbI3/tonuK8iaQz54TrfwiIUE33oA7JlCeo0t+QGzHYaDeVKx3iKXxX31aBtuV
LylGwsjhTVkG92K4ataWtLtbyFeA7wmqQyihC1Yumhsyi1XS1mDJe0Xv2E9oAjR3
nL49KotmSki8Ny+vLc7z5KYz7ufdzirVFhWc1KmBQO5Ze9zYuQs+di8ScjKqHhfI
MHniHwkC/CDbtBbrSlNa7ODvqNLH0IuvxhzYqmTQKD6GIw2oCdjeSJhCsST7z5f5
BiG1j2N6a5eFFPk=
-----END CERTIFICATE REQUEST-----
`
	noGroup = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = system:node:test
...
        Requested Extensions:
            X509v3 Subject Alternative Name:
                DNS:node1, DNS:node1.local, IP Address:10.0.0.1, IP Address:127.0.0.1
...
-----BEGIN CERTIFICATE REQUEST-----
MIICnDCCAYQCAQAwGzEZMBcGA1UEAxMQc3lzdGVtOm5vZGU6dGVzdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0S8WB/0NFUunEVepkqDCgoQcCPCLrg
wDQnem67xbTwl9YuqX02TWXb9q9g9aDBluxOxcmpA7B3isL8kJ+GOcOjXFVUjeff
gHg3uDz6ZjYCaD4ySfTMAMN5Vkk04NffwylQKjLAAWuuJR6/UaSaJkg3skNKelSU
9o9+3koPaRHEMhT9B3YuKIoqsyP2r91QtNEeW5UFrfJ12Ly3t0Q6Rs7ti7SPJY3f
3p29WBfX5RvJKmSwN6muXf1k32DP4glgwqyYqTOrKEgXdURiPOCmLA5YLhUNRvhI
H5NZVGBFwrLOkbe17DaC3x2OISLGKj4+q67Yl6ATxWnMmkuNAYX+OgsCAwEAAaA8
MDoGCSqGSIb3DQEJDjEtMCswKQYDVR0RBCIwIIIFbm9kZTGCC25vZGUxLmxvY2Fs
hwQKAAABhwR/AAABMA0GCSqGSIb3DQEBCwUAA4IBAQBiLcR0oSAXZ1m2QwDPDF4u
WK3jxd8f5C9J552QsZLs8Si2kutLvzXnOgUQXjGgK9XsOyF0GBLSECivHHWCp10M
sI2re+iuH43vMUR6hUdjrDUnPLMQYr288HwkNHM+wAQm7qFyR5YHsSYRuOjQo9BI
DV5s0hKzo4oj6gC5KdPc+ZsQYRIENCU2+1te8ZewE0Ge/zLfrWgcs3/6wB4dwYle
9uxPramx2SyD+/s3p59BWPG4cdTnWKF2GkrNyq8wFHYVGzn5jTW6dAi90KfYN3A4
cD0UL3P0hRdXiCerOM6zPJvjja7jAka9UogHsG+23e96hyw/c/NmQt2dsgNjTern
-----END CERTIFICATE REQUEST-----
`
)

func TestAuthorizeCSR(t *testing.T) {
	tests := map[string]struct {
		machineList *capiclient.MachineList
		request     *certificatesv1beta1.CertificateSigningRequest
		csr         string
		expected    bool
	}{
		"ok": {
			expected: true,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"no-node-prefix": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"only-node-prefix": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"no-machine-status-ref": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{},
					},
				},
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"no-machine-status": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: nil,
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"missing-groups-1": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
					},
					Username: "system:node:test",
					Groups: []string{
						"system:nodes",
					},
				},
			},
			csr: goodCSR,
		},
		"missing-groups-2": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
					},
					Username: "system:node:test",
					Groups: []string{
						"system:authenticated",
					},
				},
			},
			csr: goodCSR,
		},
		"extra-group": {
			expected: true,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"wrong-group": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"usages-missing": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageServerAuth,
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
		"usages-missing-1": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"usage-missing-2": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
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
		"usage-extra": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
						certificatesv1beta1.UsageSigning,
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
		"csr-cn": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"csr-cn-2": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"csr-no-o": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"csr-extra-addr": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"csr-san-ip-mismatch": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
		"csr-san-dns-mismatch": {
			expected: false,
			machineList: &capiclient.MachineList{
				Items: []capiclient.Machine{
					{
						Status: capiclient.MachineStatus{
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
			},
			request: &certificatesv1beta1.CertificateSigningRequest{
				Spec: certificatesv1beta1.CertificateSigningRequestSpec{
					Usages: []certificatesv1beta1.KeyUsage{
						certificatesv1beta1.UsageDigitalSignature,
						certificatesv1beta1.UsageKeyEncipherment,
						certificatesv1beta1.UsageServerAuth,
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
	}

	for name, tc := range tests {
		parsedCSR, err := csr.ParseCSR(&certificatesv1beta1.CertificateSigningRequest{
			Spec: certificatesv1beta1.CertificateSigningRequestSpec{
				Request: []byte(tc.csr),
			},
		})
		if err != nil {
			t.Fatalf("%s: error parsing test input csr %v", name, err)
		}
		if result := authorizeCSR(tc.machineList, tc.request, parsedCSR); result != tc.expected {
			t.Fatalf("%s: expected %v, got %v", name, tc.expected, result)
		}
	}
}
