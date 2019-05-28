package main

import (
	stderrors "errors"
	"testing"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"

	machinev1beta1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
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

const (
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

	clientGood = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = system:node:panda
...
-----BEGIN CERTIFICATE REQUEST-----
MIICeDCCAWACAQAwMzEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRowGAYDVQQDExFz
eXN0ZW06bm9kZTpwYW5kYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AL7y2GsRlcv4m5gsxmxitBz5/kGRk8uzna/jyVSqNW+j0OdIYdyfkgxG8wKRdKas
eVlQi/84DPxy0Inwu3zWVeCDYXSiTWcxcYpphubaztSOgbY1zr7oJpXvhPyjV4pZ
rOHFX2FLYH+k6ZKLt4kgrZH0IA+Nqgs/YfUnUIY4G0Fqba6MlXRXBNKQxhsA5xLY
NPuFiMOa9tPHan/u79/9A2/GsyJCdVhegx/+MCdejRQ0+lTWshumWFW3iMzxD/1g
YZRvGHwB3uv51QMLdX9gEG1ek52p6dSP5SW8qoJy/KVjJyoOmRx1GQTEN1CiYtLI
LKP4PM0yn2Cj7zSOA0HvXe8CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQAsJa+x
5UOOH9XlfaAVgGJDTFFtKrMT3xAOs5HDdefghmQ9Og8fybppcP6eFCoKHwFmmrAL
XBB96wrmkbXyQf6T2pVlMVqKQisPejtLYuADTNF9hkyutdiKzfVCcnKHwJeh0Ig7
93txMTL2nHZ8fHvY0x0JBDlMr7Sw7zLXf24GKUpQWeq79ptKTFEVUvRUZkBAi8Fd
NXVVvO0FI4cvVK0bCZB1gj7gcH29fFfsV2PZ3gXDjWTbClq29sV3QSpuWl2UfFBB
7y0pZ2l/2ePYhw0O45CMTPC/O/DFLFSEJ9nZXHsf4TyO2+qV4YWZir2dKGnJv7Uh
wyDOuGAJnS9T8DLv
-----END CERTIFICATE REQUEST-----
`
	clientExtraO = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes + O = bamboo, CN = system:node:bear
...
-----BEGIN CERTIFICATE REQUEST-----
MIIChjCCAW4CAQAwQTEkMBMGA1UEChMMc3lzdGVtOm5vZGVzMA0GA1UEChMGYmFt
Ym9vMRkwFwYDVQQDExBzeXN0ZW06bm9kZTpiZWFyMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAySEReBNyuBtXkL0ZTxoGAEYZuPLabGchMyJ2mLc0wDOB
rvOVtlsI3otStbw+d91e7N/69oMSkuq5pL5zgabmLv6g4c2AX2oH0YPxhDRcyT0G
D2r2c6gJN2UVhct3ZGRYt9sivfy8j68EOWJcoRm6adXWNOOlwSK7meTX2SDLvHvS
hUpQMBqNZCtvpJJMR+Z9qTgwOWSWtqrDEa8ggimiSSgzX3S1d6L0u+d2o7Z7mzuL
tYhEKG/VPJINUfXfmwwCKMlqbsl3phRthXr6ZrOXHIfHziy1Vd/CCAboYHLDJ/yF
xjwWfH8QYLL8BNXVETEI810QU4dM/d901An02CWcoQIDAQABoAAwDQYJKoZIhvcN
AQELBQADggEBAJiy9SlQWLr2gztzpWtn9iWcaZTLGZkAJI96gGTF+bZQyvnLzR3f
2CO66bnlhB+gYlPOLyjK2JMeNM3yXs/t2blFqf8s7V3Q00iFKxYOfopaRs+WRD6z
MMbtvej2vsQZTviIiTO6zt9w55/+ylsfURAYpcQU82jK+U8ttINIWkMrEliUoay3
7/4Pkh+9q0HYqJeIUqpml7DEnIozaiZ4DGpgy54p17zDQDmhbP0EVBVKpzTChCV2
dvycNksPtVm6yOlD/LaR8d9l4bOdbtuTNvMYkIk4E6k0RHklW0e6kp5ageXtm1t/
2pqssq/xf6PHvPWnvQL3gptlRh6MMtujmbg=
-----END CERTIFICATE REQUEST-----
`
	clientWithDNS = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = system:node:monkey
...
        Requested Extensions:
            X509v3 Subject Alternative Name: 
                DNS:banana
...
-----BEGIN CERTIFICATE REQUEST-----
MIICnTCCAYUCAQAwNDEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRswGQYDVQQDExJz
eXN0ZW06bm9kZTptb25rZXkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCwSXLVVdqDR2k36jh3jOzYg6WC7s31EGQrn+OmtUx0H8Rp/AHdU+dxuhU/yXqo
14+SbOktgg3YdEYv+7ry0w31kbOOuiYGziHLaksWhJ2jWGIoZc/mzc6pW0w3mn0D
RWbO1izCSTj2IZvuE5F1gX7KcqJ8+8vgFm10n9x/SpTZZFtSsXwEv/aW2Fi9k/OH
51I2Lj/sRx/qM1FBexfz1kC1l+cjMbzFEWBrElSKaVBMpGJNBPXmYqfO7KocR7nq
NlKgR/nooFJ+Ypin5oFW4vQcp+EvD8Yb9s4bUFZC8cR0THPkKlCysvWGmMM5lk9K
ECLk+udZkXNAVBDh6jxqEP5BAgMBAAGgJDAiBgkqhkiG9w0BCQ4xFTATMBEGA1Ud
EQQKMAiCBmJhbmFuYTANBgkqhkiG9w0BAQsFAAOCAQEApY9crYirw3ri1dbzuou9
/DU8ZIIAVdcOKOIxFv4aVXfzKwcynnq9oihBaW64cBWdmNDm0GMWnDdDrU7iUSII
Hc5+sGvm6xhjPOOM3zoELnKaSc3BOk3KsxtJKo1HVZdX5GWULTkjgzC+LYuHmUzL
p+V+Msa7zMo3IIFp1Afq2bGeoxhsAAGyaHHRwI0xg9Lu8Owl4KL8Avxs6AUjktMN
flHQDhama36J++VAP7i+WpJ0Eh+sncxptzPrs+kbA5qD5ZA+Qybgiabahuoey27z
3xFSjy8rgvH9vIMv8DOaCnKrd6KAO7fz5o8wB9TfOOX1eUTgy3wwHAPRAM2iSKCz
rQ==
-----END CERTIFICATE REQUEST-----
`
	clientWrongCN = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = system:notnode:zebra
...
-----BEGIN CERTIFICATE REQUEST-----
MIICezCCAWMCAQAwNjEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMR0wGwYDVQQDExRz
eXN0ZW06bm90bm9kZTp6ZWJyYTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBANw41UjnXcvF3rTOSpnYxkMNquMApc2D33fwVyVtn8SosILT+K0LJN3iISFr
4jvV7KbaFVhL+w98jFa+lHgz0n0B9QZMuzhxgQfax8KhY6Jx86d95IpRwIaS36FB
5oTHRZZPRCRZyAMonBqv1WvqwCPXqJj1x1q5b2ZePYb8NZYXA+8h46QF6zhy1CgU
Uyhh0314dGSp+EAZ1+mCA1pZHn7jm7GxEBgFrj+vmdqaqMGw6ePkyoXf4CwpS1Yk
hWF2pvC8aH1pxXJwgk5TXRgLhGtmxcM/yKy2HKuUs8ZVrfEZ8ubdEY9ZUzJRaVxn
Imz1kqoVqk8H8jS9R6xTAdpTm4MCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQCg
keFlA6YlnX8K6zFg1MrypGmx2/U2EpGIi3LjXUg3RTxtt47nemJyCHqNOVRXUVaA
w/F2U11jFn0Vzd4Dsfa6+Zmhju/8ZiyRcw22lTqj1OHPwaKa5gJpN1TYbajhKs/l
EMD445dySwxCms2mu/wY8dEhwJDWWZXl7cYD8mS8wt3XueciOjq+P2vqqH7t8RPl
QaeQ34WHQsPopbdb49Wwpz+jH/3vpe/GYz8lnDRoxUKpLS8vrYVog8cHO4GP6upR
xdZGDp5UH/komvTyr+PrGCpB6SQnGp01XSjLKBwSYnqSp9JYTG+xKN2LYS65EYrw
mG57VlB8JU+F3mZOeMSC
-----END CERTIFICATE REQUEST-----
`
	clientEmptyName = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = system:node:
...
-----BEGIN CERTIFICATE REQUEST-----
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
)

func Test_authorizeCSR(t *testing.T) {
	type args struct {
		config   ClusterMachineApproverConfig
		machines []machinev1beta1.Machine
		nodeName string
		nodeErr  error
		req      *certificatesv1beta1.CertificateSigningRequest
		csr      string
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "ok",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "",
		},
		{
			name: "no-node-prefix",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Doesn't match expected prefix",
		},
		{
			name: "only-node-prefix",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Empty name",
		},
		{
			name: "no-machine-status-ref",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{},
					},
				},
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "No target machine",
		},
		{
			name: "no-machine-status",
			args: args{
				machines: nil,
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Invalid request",
		},
		{
			name: "missing-groups-1",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Too few groups",
		},
		{
			name: "missing-groups-2",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Too few groups",
		},
		{
			name: "extra-group",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "",
		},
		{
			name: "wrong-group",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Not in system:authenticated",
		},
		{
			name: "usages-missing",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Too few usages",
		},
		{
			name: "usages-missing-1",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Too few usages",
		},
		{
			name: "usage-missing-2",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Too few usages",
		},
		{
			name: "usage-extra",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Too few usages",
		},
		{
			name: "csr-cn",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Mismatched CommonName system:node:foobar != system:node:test",
		},
		{
			name: "csr-cn-2",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Mismatched CommonName test != system:node:test",
		},
		{
			name: "csr-no-o",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "Organization doesn't include system:nodes",
		},
		{
			name: "csr-extra-addr",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "IP address '99.0.1.1' not in machine addresses: 127.0.0.1 10.0.0.1",
		},
		{
			name: "csr-san-ip-mismatch",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "IP address '10.0.0.1' not in machine addresses: 127.0.0.1 10.0.0.2",
		},
		{
			name: "csr-san-dns-mismatch",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
				req: &certificatesv1beta1.CertificateSigningRequest{
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
			wantErr: "DNS name 'node1' not in machine names: node1.local node2",
		},

		{
			name: "client good",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "",
		},
		{
			name: "client extra O",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "bear",
								},
							},
						},
					},
				},
				nodeName: "bear",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "Doesn't match expected prefix",
		},
		{
			name: "client with DNS",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "monkey",
								},
							},
						},
					},
				},
				nodeName: "monkey",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "Doesn't match expected prefix",
		},
		{
			name: "client good but extra usage",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
							certificatesv1beta1.UsageServerAuth,
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
			wantErr: "Doesn't match expected prefix",
		},
		{
			name: "client good but wrong usage",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageServerAuth,
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
			wantErr: "Doesn't match expected prefix",
		},
		{
			name: "client good but missing usage",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "Doesn't match expected prefix",
		},
		{
			name: "client good but wrong CN",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "zebra",
								},
							},
						},
					},
				},
				nodeName: "zebra",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "Doesn't match expected prefix",
		},
		{
			name: "client good but wrong user",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "green"},
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "CSR green for node client cert has wrong user",
		},
		{
			name: "client good but wrong user group",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "blue"},
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "CSR blue for node client cert has wrong user",
		},
		{
			name: "client good but empty name",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "yellow"},
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "CSR yellow has empty node name",
		},
		{
			name: "client good but node exists",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  nil,
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "node panda already exists",
		},
		{
			name: "client good but node unexpected error",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewForbidden(schema.GroupResource{Group: "other", Resource: "minions"}, "stuff", stderrors.New("broken")),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: `failed to check if node panda already exists: minions.other "stuff" is forbidden: broken`,
		},
		{
			name: "client good but missing machine",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeExternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "failed to find machine for node panda",
		},
		{
			name: "client good but machine has node ref",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							NodeRef: &corev1.ObjectReference{Name: "other"},
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "machine for node panda already has node ref",
		},
		{
			name: "client good but auto approval is disabled",
			args: args{
				config: ClusterMachineApproverConfig{
					NodeClientCert: NodeClientCert{
						Disabled: true,
					},
				},
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "orange"},
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "CSR orange for node client cert rejected as the flow is disabled",
		},
		{
			name: "client good with proper timing",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
							CreationTimestamp: creationTimestamp(2 * time.Minute),
						},
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "pink",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "",
		},
		{
			name: "client good with proper timing 2",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "pink",
						CreationTimestamp: creationTimestamp(2*time.Minute + 51*time.Second),
					},
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "",
		},
		{
			name: "client good but CSR too early",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "purple",
						CreationTimestamp: creationTimestamp(2 * time.Minute),
					},
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "CSR purple creation time 2000-01-01 02:32:00 +0000 UTC not in range (2000-01-01 02:32:50 +0000 UTC, 2000-01-01 02:43:00 +0000 UTC)",
		},
		{
			name: "client good but CSR too late",
			args: args{
				machines: []machinev1beta1.Machine{
					{
						Status: machinev1beta1.MachineStatus{
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
						Status: machinev1beta1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				nodeName: "panda",
				nodeErr:  errors.NewNotFound(schema.GroupResource{}, ""),
				req: &certificatesv1beta1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "red",
						CreationTimestamp: creationTimestamp(15 * time.Minute),
					},
					Spec: certificatesv1beta1.CertificateSigningRequestSpec{
						Usages: []certificatesv1beta1.KeyUsage{
							certificatesv1beta1.UsageKeyEncipherment,
							certificatesv1beta1.UsageDigitalSignature,
							certificatesv1beta1.UsageClientAuth,
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
			wantErr: "CSR red creation time 2000-01-01 02:45:00 +0000 UTC not in range (2000-01-01 02:32:50 +0000 UTC, 2000-01-01 02:43:00 +0000 UTC)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.req.Spec.Request = []byte(tt.args.csr)
			parsedCSR, err := parseCSR(tt.args.req)
			if err != nil {
				t.Fatal(err)
			}
			nodes := &testNode{t: t, name: tt.args.nodeName, err: tt.args.nodeErr}

			if err := authorizeCSR(tt.args.config, tt.args.machines, nodes, tt.args.req, parsedCSR); errString(err) != tt.wantErr {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, tt.wantErr)
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
	return metav1.NewTime(time.Date(2000, time.January, 1, 2, 30, 0, 0, time.UTC).Add(delta))
}

type testNode struct {
	corev1client.NodeInterface // panic if anything other than Get is called

	t *testing.T

	name string
	err  error
}

func (n *testNode) Get(name string, _ metav1.GetOptions) (*corev1.Node, error) {
	if name != n.name {
		n.t.Errorf("Get() name = %s, want %s", name, n.name)
	}

	return nil, n.err
}
