package controller

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	networkv1 "github.com/openshift/api/network/v1"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	machinehandlerpkg "github.com/openshift/cluster-machine-approver/pkg/machinehandler"
)

// The following global test variables are populated within the init func
var serverCertGood, serverKeyGood, rootCertGood string

const (
	differentCert = `-----BEGIN CERTIFICATE-----
MIIB6zCCAZGgAwIBAgIUNukOeYC/OJTuAHe8x0dZGxo/UPcwCgYIKoZIzj0EAwIw
SDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMRYwFAYDVQQHEw1TYW4gRnJhbmNp
c2NvMRQwEgYDVQQDEwtleGFtcGxlLm5ldDAeFw0yMDExMTkxMjU1MDBaFw0yNTEx
MTgxMjU1MDBaMEgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzEUMBIGA1UEAxMLZXhhbXBsZS5uZXQwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAStQMOkXCI/byn1MPc5KYM1d5NsPF4gexjeKqjJrrHcaTow
jJAQOslKXAhHKp0y+jhFzr8lQdDrt5eHUK/LfDpKo1kwVzAOBgNVHQ8BAf8EBAMC
AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUhJoVW5gCXH0QwkspeVOA4EBG
sBMwFQYDVR0RBA4wDIcEfwAAAYcECgAAATAKBggqhkjOPQQDAgNIADBFAiEAzTu+
fuo0nJuh1ta+w+X7iwhx29AG/1TAPY/S+tnG4OUCIBvy9g6GCEUbgYgwPKF2k8G3
zrzrJ5SCjYy4UbElrjNx
-----END CERTIFICATE-----
`
	differentKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFU6aDkXYwx8YYtXd9AZPIst87daWX49Rzhxsd7D7UwroAoGCCqGSM49
AwEHoUQDQgAErUDDpFwiP28p9TD3OSmDNXeTbDxeIHsY3iqoya6x3Gk6MIyQEDrJ
SlwIRyqdMvo4Rc6/JUHQ67eXh1Cvy3w6Sg==
-----END EC PRIVATE KEY-----
`
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
ukG4TvbrMbVklA2nLmK0T7+SygWRYebsd0vJMWkw87+zxkYY0tEo+y5ijHXucb1S
3m4mGulmzxP1KQI/0RDuba1HhekAaOxy2TZWYhtQUxCHbrREz3b+OBbDkf2Dzp7Q
o6J3l7fYBRCD/AnTzSCaK5LwzmH0X3TCJnrLBIf8gFrqAHsCXadNV3JQ2Iip6Gjs
8VCqnZHS/oFhXpKiMnrB0IMpC6F21/T4Uoe+vyWoUTZQTAjZVBcIDLp3r8c6FnmF
5YjouWafNVfbttVczNpuSt/3YxXLb2P/EQfb8QniNUXnkxSNwOpZx6QO2PZHSSBW
cW+q+EUeFXsInl41dK5avwIDAQABoDwwOgYJKoZIhvcNAQkOMS0wKzApBgNVHREE
IjAgggVub2RlMYILbm9kZTEubG9jYWyHBAoAAAGHBH8AAAEwDQYJKoZIhvcNAQEL
BQADggEBAEFFAuuhgUGs7Mhg9hMdj8csuBiLHUah5bkavvi/dwH3CaHpXRAxMwRI
0K+puuDsHn7Y7xInO2IfyYVaZ6Xr2ppT9u0Hjn9DzN3Wmd/ngTWbWsctvXVMkGw4
Mkc4v7oq9wBbMDbsT3xKaRqWvxqAsD3NXUVGW4tIJhqZnKk3QtZ70p/q4L4/TbEV
yOf1lhGA26sAJX4gMeTHUxPu85NedLzTg5DYDyPPvIYPKw7ww8tm2fYb67sr21WU
p1VlUzB7qtkVJ4coGNFPwl7vu3rps5VPN7ONV9JG8+PVvjxhyQD5ZBqLVPbT7ZGI
NKbWRRtEF/XLPoZs3kq95YCgn2oQ9ws=
-----END CERTIFICATE REQUEST-----
`
	emptyCSR = `
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = system:nodes, CN = system:node:test
...
        Requested Extensions:
            X509v3 Subject Alternative Name:
                DNS:node1, DNS:node1.local, IP Address:10.0.0.1, IP Address:127.0.0.1
...
-----BEGIN??
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

var baseTime = time.Date(2020, 11, 19, 0, 0, 0, 0, time.UTC)

func init() {
	now = clock.NewFakePassiveClock(baseTime).Now
	networkv1.AddToScheme(scheme.Scheme)
	configv1.AddToScheme(scheme.Scheme)

	// Genereate a CA cert valid for the next 12 hours
	rootCert, rootKey, err := generateCertKeyPair(12*time.Hour, nil, nil, "system:node:test")
	if err != nil {
		panic(err)
	}

	// Sign a serving cert based on the previous CA cert
	serverCert, serverKey, err := generateCertKeyPair(time.Hour, rootCert, rootKey, "system:node:test", "node1", "node1.local")
	if err != nil {
		panic(err)
	}

	rootCertGood = string(rootCert)
	serverCertGood = string(serverCert)
	serverKeyGood = string(serverKey)
}

func generateCertKeyPair(duration time.Duration, parentCertPEM, parentKeyPEM []byte, commonName string, otherNames ...string) ([]byte, []byte, error) {
	var err error
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"system:nodes"},
			CommonName:   commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(duration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              otherNames,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")},
		IsCA:                  parentCertPEM == nil,
		BasicConstraintsValid: true, // Required, else IsCA is ignored
	}

	parentCert := &template
	var signerKey crypto.PrivateKey // Key must be a PrivateKey type, but this is an alias for interface{}
	signerKey = priv
	if parentCertPEM != nil {
		certificates, err := tls.X509KeyPair(parentCertPEM, parentKeyPEM)
		if err != nil {
			return nil, nil, err
		}

		signerKey = certificates.PrivateKey

		parentCert, err = x509.ParseCertificate(certificates.Certificate[0])
		if err != nil {
			return nil, nil, err
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, parentCert, &priv.PublicKey, signerKey)
	if err != nil {
		return nil, nil, err
	}

	certOut := new(bytes.Buffer)
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, err
	}

	keyOut := new(bytes.Buffer)
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return nil, nil, err
	}

	return certOut.Bytes(), keyOut.Bytes(), nil
}

func Test_authorizeCSR(t *testing.T) {
	defaultPort := int32(25435)
	defaultAddr := "127.0.0.1"
	defaultNode := func() *corev1.Node {
		return &corev1.Node{
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: defaultAddr},
				},
				DaemonEndpoints: corev1.NodeDaemonEndpoints{
					KubeletEndpoint: corev1.DaemonEndpoint{
						Port: defaultPort,
					},
				},
			},
		}
	}

	withName := func(name string, node *corev1.Node) *corev1.Node {
		node.Name = name
		return node
	}
	withPort := func(port int32, node *corev1.Node) *corev1.Node {
		node.Status.DaemonEndpoints.KubeletEndpoint.Port = port
		return node
	}

	hostSubnet := func(name string) *networkv1.HostSubnet {
		return &networkv1.HostSubnet{
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
		}
	}

	withEgressIPs := func(hostSubnet *networkv1.HostSubnet, egressIPs ...networkv1.HostSubnetEgressIP) *networkv1.HostSubnet {
		hostSubnet.EgressIPs = egressIPs
		return hostSubnet
	}

	withEgressCIDRs := func(hostSubnet *networkv1.HostSubnet, egressCIDRs ...networkv1.HostSubnetEgressCIDR) *networkv1.HostSubnet {
		hostSubnet.EgressCIDRs = egressCIDRs
		return hostSubnet
	}

	type args struct {
		config        ClusterMachineApproverConfig
		machines      []machinehandlerpkg.Machine
		node          *corev1.Node
		kubeletServer net.Listener
		req           *certificatesv1.CertificateSigningRequest
		csr           string
		ca            []*x509.Certificate
		networkType   string
		hostSubnet    *networkv1.HostSubnet
	}
	tests := []struct {
		name      string
		args      args
		wantErr   string
		authorize bool
	}{
		{
			name: "ok",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: true,
		},
		{
			name: "bad-csr",
			args: args{
				csr: emptyCSR,
				req: &certificatesv1.CertificateSigningRequest{},
			},
			wantErr:   "PEM block type must be CERTIFICATE REQUEST",
			authorize: false,
		},
		{
			name: "no-node-prefix",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "only-node-prefix",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "no-machine-status-ref",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "could not authorize CSR: exhausted all authorization methods: Unable to find machine for node",
			authorize: false,
		},
		{
			name: "missing-groups-1",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:nodes",
						},
					},
				},
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "missing-groups-2",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
						},
					},
				},
				csr: goodCSR,
			},
			wantErr:   "",
			authorize: false,
		},
		{
			name: "extra-group",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: true,
		},
		{
			name: "wrong-group",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "usages-missing",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		}, {
			name: "usages-missing",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "usages-missing-1",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "usage-missing-2",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "usage-extra",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
							certificatesv1.UsageSigning,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "csr-cn",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "csr-cn-2",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "csr-no-o",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "csr-extra-addr",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "could not authorize CSR: exhausted all authorization methods: IP address '99.0.1.1' not in machine addresses: 127.0.0.1 10.0.0.1",
			authorize: false,
		},
		{
			name: "csr-san-ip-mismatch",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "could not authorize CSR: exhausted all authorization methods: IP address '10.0.0.1' not in machine addresses: 127.0.0.1 10.0.0.2",
			authorize: false,
		},
		{
			name: "csr-san-dns-mismatch",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "could not authorize CSR: exhausted all authorization methods: DNS name 'node1' not in machine names: node1.local node2",
			authorize: false,
		},

		{
			name: "client good",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: true,
		},
		{
			name: "client extra O",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "bear",
								},
							},
						},
					},
				},
				node: withName("bear", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client with DNS",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "monkey",
								},
							},
						},
					},
				},
				node: withName("monkey", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but extra usage",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but wrong usage",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but missing usage",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but wrong CN",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "zebra",
								},
							},
						},
					},
				},
				node: withName("zebra", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but wrong user",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "green"},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but wrong user group",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "blue"},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but empty name",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "yellow"},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but node exists",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but missing machine",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeExternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "failed to find machine for node panda",
			authorize: false,
		},
		{
			name: "client good but machine has node ref",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but auto approval is disabled",
			args: args{
				config: ClusterMachineApproverConfig{
					NodeClientCert: NodeClientCert{
						Disabled: true,
					},
				},
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				node: withName("panda", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{Name: "orange"},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "CSR orange for node client cert rejected as the flow is disabled",
			authorize: false,
		},
		{
			name: "client good with proper timing",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "pink",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: true,
		},
		{
			name: "client good with proper timing 2",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "pink",
						CreationTimestamp: creationTimestamp(2*time.Minute + 51*time.Second),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: true,
		},
		{
			name: "client good but CSR too early",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "purple",
						CreationTimestamp: creationTimestamp(2 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "client good but CSR too late",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
						Status: machinehandlerpkg.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "panda",
								},
							},
						},
					},
				},
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "red",
						CreationTimestamp: creationTimestamp(25 * time.Hour),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageClientAuth,
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
			wantErr:   "",
			authorize: false,
		},
		{
			name: "successfull renew flow",
			args: args{
				node: withName("test", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "renew",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: goodCSR,
				ca:  []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			authorize: true,
		},
		{
			name: "successfull fallback to fresh approval",
			args: args{
				machines: []machinehandlerpkg.Machine{
					{
						Status: machinehandlerpkg.MachineStatus{
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
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "renew",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr: goodCSR,
				ca:  []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			authorize: true,
		},
		{
			name: "successfull fallback to fresh approval from incorrect server cert",
			args: args{
				node: withPort(defaultPort+1, withName("test", defaultNode())),
				req: &certificatesv1.CertificateSigningRequest{
					ObjectMeta: metav1.ObjectMeta{
						Name:              "renew",
						CreationTimestamp: creationTimestamp(10 * time.Minute),
					},
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr:           goodCSR,
				ca:            []*x509.Certificate{parseCert(t, differentCert)},
				kubeletServer: fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort+1), differentCert, differentKey),
			},
			wantErr:   "could not authorize CSR: exhausted all authorization methods: [current serving cert has bad common name, Unable to find machine for node]",
			authorize: false,
		},
		{
			name: "CSR extra address not in egress IPs",
			args: args{
				node: withName("test", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr:         extraAddr,
				networkType: "OpenShiftSDN",
				hostSubnet:  hostSubnet("test"),
				ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			wantErr:   "could not authorize CSR: exhausted all authorization methods: [CSR Subject Alternate Name values do not match current certificate, Unable to find machine for node, CSR Subject Alternate Names includes unknown IP addresses]",
			authorize: false,
		},
		{
			name: "CSR extra address in egress IPs",
			args: args{
				node: withName("test", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr:         extraAddr,
				networkType: "OpenShiftSDN",
				hostSubnet:  withEgressIPs(hostSubnet("test"), "99.0.1.1"),
				ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			authorize: true,
		},
		{
			name: "CSR extra address in egress CIDRs",
			args: args{
				node: withName("test", defaultNode()),
				req: &certificatesv1.CertificateSigningRequest{
					Spec: certificatesv1.CertificateSigningRequestSpec{
						Usages: []certificatesv1.KeyUsage{
							certificatesv1.UsageDigitalSignature,
							certificatesv1.UsageKeyEncipherment,
							certificatesv1.UsageServerAuth,
						},
						Username: "system:node:test",
						Groups: []string{
							"system:authenticated",
							"system:nodes",
						},
					},
				},
				csr:         extraAddr,
				networkType: "OpenShiftSDN",
				hostSubnet:  withEgressCIDRs(hostSubnet("test"), "99.0.1.0/24"),
				ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			},
			authorize: true,
		},
	}

	server := fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort), serverCertGood, serverKeyGood)
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kubeletServer := server
			if tt.args.kubeletServer != nil {
				kubeletServer = tt.args.kubeletServer
				defer kubeletServer.Close()
			}

			network := &configv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
				Status: configv1.NetworkStatus{
					NetworkType: tt.args.networkType,
				},
			}

			objs := []runtime.Object{network}
			if tt.args.node != nil {
				objs = append(objs, tt.args.node)
			}
			if tt.args.hostSubnet != nil {
				objs = append(objs, tt.args.hostSubnet)
			}
			cl := fake.NewFakeClient(objs...)
			tt.args.req.Spec.Request = []byte(tt.args.csr)
			parsedCSR, err := parseCSR(tt.args.req)
			if err != nil {
				if errString(err) != tt.wantErr {
					t.Errorf("parseCSR() error = %v, wantErr %s", err, tt.wantErr)
				}
				return
			}

			var ca *x509.CertPool
			if len(tt.args.ca) > 0 {
				// Start renewal flow
				ca = x509.NewCertPool()
				for _, cert := range tt.args.ca {
					ca.AddCert(cert)
				}
				go respond(kubeletServer)
			}
			if authorize, err := authorizeCSR(cl, tt.args.config, tt.args.machines, tt.args.req, parsedCSR, ca); authorize != tt.authorize || errString(err) != tt.wantErr {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, tt.wantErr)
			}
		})

		t.Run("Invalid call", func(t *testing.T) {
			if authorize, err := authorizeCSR(nil, tt.args.config, tt.args.machines, nil, nil, nil); authorize != false {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, "Invalid request")
			}
		})
	}
}

func TestAuthorizeServingRenewal(t *testing.T) {
	presetTimeCorrect := time.Now()
	presetTimeExpired := time.Now().Add(-24 * time.Hour)

	tests := []struct {
		name        string
		nodeName    string
		csr         *x509.CertificateRequest
		currentCert *x509.Certificate
		ca          []*x509.Certificate
		time        time.Time
		wantErr     string
	}{
		{
			name:     "missing args",
			nodeName: "panda",
			wantErr:  "CSR, serving cert, or CA not provided",
		},
		{
			name:        "all good",
			nodeName:    "test",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
		},
		{
			name:        "reject expired",
			nodeName:    "test",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeExpired,
			wantErr:     fmt.Sprintf("x509: certificate has expired or is not yet valid: current time %s is before %s", presetTimeExpired.Format(time.RFC3339), presetTimeCorrect.Format(time.RFC3339)),
		},
		{
			name:        "SAN list differs",
			nodeName:    "test",
			csr:         parseCR(t, extraAddr),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "CSR Subject Alternate Name values do not match current certificate",
		},
		{
			name:        "No certificate match",
			nodeName:    "test",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{},
			time:        presetTimeCorrect,
			wantErr:     "x509: certificate signed by unknown authority",
		},
		{
			name:        "Request from different node",
			nodeName:    "test",
			csr:         parseCR(t, otherName),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "current serving cert and CSR common name mismatch",
		},
		{
			name:        "Unexpected CN",
			nodeName:    "panda",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "current serving cert has bad common name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPool := x509.NewCertPool()
			for _, cert := range tt.ca {
				certPool.AddCert(cert)
			}
			err := authorizeServingRenewal(
				tt.nodeName,
				tt.csr,
				tt.currentCert,
				x509.VerifyOptions{Roots: certPool, CurrentTime: tt.time},
			)

			if errString(err) != tt.wantErr {
				t.Errorf("got: %v, want: %s", err, tt.wantErr)
			}
		})
	}
}

func TestAuthorizeServingRenewalWithEgressIPs(t *testing.T) {
	presetTimeCorrect := time.Now()
	presetTimeExpired := time.Now().Add(-24 * time.Hour)
	testNodeName := "test"

	tests := []struct {
		name        string
		nodeName    string
		csr         *x509.CertificateRequest
		currentCert *x509.Certificate
		ca          []*x509.Certificate
		time        time.Time
		hostSubnet  *networkv1.HostSubnet
		wantErr     string
	}{
		{
			name:     "missing args",
			nodeName: "panda",
			wantErr:  "CSR, serving cert, or CA not provided",
		},
		{
			name:        "all good",
			nodeName:    testNodeName,
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			hostSubnet: &networkv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNodeName,
				},
			},
		},
		{
			name:        "reject expired",
			nodeName:    testNodeName,
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeExpired,
			wantErr:     fmt.Sprintf("x509: certificate has expired or is not yet valid: current time %s is before %s", presetTimeExpired.Format(time.RFC3339), presetTimeCorrect.Format(time.RFC3339)),
		},
		{
			name:        "With additional unknown IP address",
			nodeName:    testNodeName,
			csr:         parseCR(t, extraAddr),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			hostSubnet: &networkv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNodeName,
				},
			},
			wantErr: "CSR Subject Alternate Names includes unknown IP addresses",
		},
		{
			name:        "With additional Egress IP address",
			nodeName:    testNodeName,
			csr:         parseCR(t, extraAddr),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			hostSubnet: &networkv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNodeName,
				},
				EgressIPs: []networkv1.HostSubnetEgressIP{"99.0.1.1"},
			},
		},
		{
			name:        "With additional Egress IP in Egress CIDRs",
			nodeName:    testNodeName,
			csr:         parseCR(t, extraAddr),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			hostSubnet: &networkv1.HostSubnet{
				ObjectMeta: metav1.ObjectMeta{
					Name: testNodeName,
				},
				EgressCIDRs: []networkv1.HostSubnetEgressCIDR{"99.0.1.0/24"},
			},
		},
		{
			name:        "No certificate match",
			nodeName:    testNodeName,
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{},
			time:        presetTimeCorrect,
			wantErr:     "x509: certificate signed by unknown authority",
		},
		{
			name:        "Request from different node",
			nodeName:    testNodeName,
			csr:         parseCR(t, otherName),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "current serving cert and CSR common name mismatch",
		},
		{
			name:        "Unexpected CN",
			nodeName:    "panda",
			csr:         parseCR(t, goodCSR),
			currentCert: parseCert(t, serverCertGood),
			ca:          []*x509.Certificate{parseCert(t, rootCertGood)},
			time:        presetTimeCorrect,
			wantErr:     "current serving cert has bad common name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPool := x509.NewCertPool()
			for _, cert := range tt.ca {
				certPool.AddCert(cert)
			}

			objs := []runtime.Object{}
			if tt.hostSubnet != nil {
				objs = append(objs, tt.hostSubnet)
			}
			cl := fake.NewFakeClient(objs...)

			err := authorizeServingRenewalWithEgressIPs(
				cl,
				tt.nodeName,
				tt.csr,
				tt.currentCert,
				x509.VerifyOptions{Roots: certPool, CurrentTime: tt.time},
			)

			if errString(err) != tt.wantErr {
				t.Errorf("got: %v, want: %s", err, tt.wantErr)
			}
		})
	}
}

func TestGetServingCert(t *testing.T) {
	defaultPort := int32(25535)
	defaultAddr := "127.0.0.1"
	defaultNode := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: defaultAddr},
			},
			DaemonEndpoints: corev1.NodeDaemonEndpoints{
				KubeletEndpoint: corev1.DaemonEndpoint{
					Port: defaultPort,
				},
			},
		},
	}

	wrongAddr := defaultNode.DeepCopy()
	wrongAddr.Status.DaemonEndpoints.KubeletEndpoint.Port = int32(25544)

	uninitialized := defaultNode.DeepCopy()
	uninitialized.Status = corev1.NodeStatus{}

	tests := []struct {
		name      string
		nodeName  string
		node      *corev1.Node
		rootCerts []*x509.Certificate
		wantErr   string
	}{
		{
			name:      "all good",
			nodeName:  "test",
			node:      defaultNode,
			rootCerts: []*x509.Certificate{parseCert(t, rootCertGood)},
		},
		{
			name:      "unknown certificate",
			nodeName:  "test",
			node:      defaultNode,
			rootCerts: []*x509.Certificate{parseCert(t, differentCert)},
			wantErr:   "x509: certificate signed by unknown authority",
		},
		{
			name:      "node not found",
			nodeName:  "test",
			rootCerts: []*x509.Certificate{parseCert(t, rootCertGood)},
			wantErr:   "nodes \"test\" not found",
		},
		{
			name:      "wrong address",
			nodeName:  "test",
			node:      wrongAddr,
			rootCerts: []*x509.Certificate{parseCert(t, rootCertGood)},
			wantErr:   "dial tcp 127.0.0.1:25544: connect: connection refused",
		},
		{
			name:     "no pool provided",
			nodeName: "test",
			node:     defaultNode,
			wantErr:  "no CA found: will not retrieve serving cert",
		},
		{
			name:      "node with no addr",
			nodeName:  "test",
			node:      uninitialized,
			rootCerts: []*x509.Certificate{parseCert(t, rootCertGood)},
			wantErr:   "node test has no internal addresses",
		},
	}

	server := fakeResponder(t, fmt.Sprintf("%s:%v", defaultAddr, defaultPort), serverCertGood, serverKeyGood)
	defer server.Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var certPool *x509.CertPool
			if len(tt.rootCerts) > 0 {
				certPool = x509.NewCertPool()
				for _, cert := range tt.rootCerts {
					certPool.AddCert(cert)
				}
			}

			objects := []runtime.Object{}
			if tt.node != nil {
				objects = append(objects, tt.node)
			}
			cl := fake.NewFakeClient(objects...)

			go respond(server)
			serverCert, err := getServingCert(cl, tt.nodeName, certPool)
			if errString(err) != tt.wantErr {
				t.Fatalf("got: %v, want: %s", err, tt.wantErr)
			}
			if err == nil && !serverCert.Equal(parseCert(t, serverCertGood)) {
				t.Fatal("Expected server certificate match on success")
			}
		})
	}
}

func TestRecentlyPendingCSRs(t *testing.T) {
	approvedCSR := certificatesv1.CertificateSigningRequest{
		Status: certificatesv1.CertificateSigningRequestStatus{
			Conditions: []certificatesv1.CertificateSigningRequestCondition{{
				Type: certificatesv1.CertificateApproved,
			}},
		},
	}
	pendingCSR := certificatesv1.CertificateSigningRequest{}
	pendingTime := baseTime.Add(time.Second)
	pastApprovalTime := baseTime.Add(-maxPendingDelta)
	preApprovalTime := baseTime.Add(10 * time.Second)

	createdAt := func(time time.Time, csr certificatesv1.CertificateSigningRequest) certificatesv1.CertificateSigningRequest {
		csr.CreationTimestamp.Time = time
		return csr
	}

	tests := []struct {
		name          string
		csrs          []certificatesv1.CertificateSigningRequest
		expectPending int
	}{
		{
			name:          "recently pending csr",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, pendingCSR)},
			expectPending: 1,
		},
		{
			name:          "recently approved csr",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pendingTime, approvedCSR)},
			expectPending: 0,
		},
		{
			name:          "pending past approval time",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(pastApprovalTime, pendingCSR)},
			expectPending: 0,
		},
		{
			name:          "pending before approval time",
			csrs:          []certificatesv1.CertificateSigningRequest{createdAt(preApprovalTime, pendingCSR)},
			expectPending: 0,
		},
		{
			name: "multiple different csrs",
			csrs: []certificatesv1.CertificateSigningRequest{
				createdAt(pendingTime, pendingCSR),
				createdAt(pendingTime, pendingCSR),

				createdAt(pendingTime, approvedCSR),
				createdAt(preApprovalTime, approvedCSR),
				createdAt(pastApprovalTime, approvedCSR),
				createdAt(preApprovalTime, pendingCSR),
				createdAt(pastApprovalTime, pendingCSR),
			},
			expectPending: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if pending := recentlyPendingCSRs(tt.csrs); pending != tt.expectPending {
				t.Errorf("Expected %v pending CSRs, got: %v", tt.expectPending, pending)
			}
		})
	}
}

func TestNodeInternalIP(t *testing.T) {
	tests := []struct {
		name    string
		node    *corev1.Node
		wantIP  string
		wantErr string
	}{
		{
			name: "no addresses",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "no-addresses",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{},
				},
			},
			wantErr: "node no-addresses has no internal addresses",
		},
		{
			name: "no internal ip",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "no-internal-ip",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeHostName, Address: "host.example.com"},
					},
				},
			},
			wantErr: "node no-internal-ip has no internal addresses",
		},
		{
			name: "has internal ip",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "has-internal-ip",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
					},
				},
			},
			wantIP: "10.0.0.1",
		},
		{
			name: "has ipv6 address",
			node: &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name: "has-ipv6-address",
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeInternalIP, Address: "2600:1f18:4254:5100:ef8a:7b65:7782:9248"},
					},
				},
			},
			wantIP: "2600:1f18:4254:5100:ef8a:7b65:7782:9248",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, err := nodeInternalIP(tt.node)

			if errString(err) != tt.wantErr {
				t.Errorf("got: %v, want: %s", err, tt.wantErr)
			}

			if ip != tt.wantIP {
				t.Errorf("got: %v, want: %s", err, tt.wantIP)
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
	return metav1.NewTime(baseTime.Add(delta))
}

func TestGetMaxPending(t *testing.T) {
	ml := []machinehandlerpkg.Machine{
		{
			Status: machinehandlerpkg.MachineStatus{},
		},
		{
			Status: machinehandlerpkg.MachineStatus{},
		},
	}

	res := getMaxPending(ml)
	expected := len(ml) + maxDiffBetweenPendingCSRsAndMachinesCount
	if res != expected {
		t.Errorf("getMaxPending returned incorrect value: %v, expect: %v", res, expected)
	}
}

func TestEqualStrings(t *testing.T) {
	tests := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "both empty",
			a:        []string{},
			b:        []string{},
			expected: true,
		},
		{
			name:     "equal",
			a:        []string{"a", "b"},
			b:        []string{"a", "b"},
			expected: true,
		},
		{
			name:     "different order",
			a:        []string{"b", "a"},
			b:        []string{"a", "b"},
			expected: true,
		},
		{
			name:     "not equal",
			a:        []string{"a"},
			b:        []string{"a", "b"},
			expected: false,
		},
		{
			name:     "duplicates",
			a:        []string{"a", "a"},
			b:        []string{"a", "b"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertNoChange(t, tt.a, tt.b, func(t *testing.T) {
				if equal := equalStrings(tt.a, tt.b); equal != tt.expected {
					t.Errorf("%v == %v :: wanted %v, got %v",
						tt.a, tt.b, tt.expected, equal)
				}
			})
		})
	}
}

func TestEqualURLs(t *testing.T) {
	exampleNet, err := url.Parse("http://example.net")
	if err != nil {
		t.Fatal(err)
	}

	exampleOrg, err := url.Parse("https://example.org")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		a        []*url.URL
		b        []*url.URL
		expected bool
	}{
		{
			name:     "both empty",
			a:        []*url.URL{},
			b:        []*url.URL{},
			expected: true,
		},
		{
			name:     "equal",
			a:        []*url.URL{exampleNet, exampleOrg},
			b:        []*url.URL{exampleNet, exampleOrg},
			expected: true,
		},
		{
			name:     "different order",
			a:        []*url.URL{exampleOrg, exampleNet},
			b:        []*url.URL{exampleNet, exampleOrg},
			expected: true,
		},
		{
			name:     "not equal",
			a:        []*url.URL{exampleOrg},
			b:        []*url.URL{exampleNet, exampleOrg},
			expected: false,
		},
		{
			name:     "duplicates",
			a:        []*url.URL{exampleOrg, exampleOrg},
			b:        []*url.URL{exampleNet, exampleOrg},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if equal := equalURLs(tt.a, tt.b); equal != tt.expected {
				t.Errorf("%v == %v :: wanted %v, got %v",
					tt.a, tt.b, tt.expected, equal)
			}
		})
	}
}

func TestEqualIPAddresses(t *testing.T) {
	tenDotOne := net.ParseIP("10.0.0.1")
	tenDotTwo := net.ParseIP("10.0.0.2")

	tests := []struct {
		name     string
		a        []net.IP
		b        []net.IP
		expected bool
	}{
		{
			name:     "both empty",
			a:        []net.IP{},
			b:        []net.IP{},
			expected: true,
		},
		{
			name:     "equal",
			a:        []net.IP{tenDotOne, tenDotTwo},
			b:        []net.IP{tenDotOne, tenDotTwo},
			expected: true,
		},
		{
			name:     "different order",
			a:        []net.IP{tenDotTwo, tenDotOne},
			b:        []net.IP{tenDotOne, tenDotTwo},
			expected: true,
		},
		{
			name:     "not equal",
			a:        []net.IP{tenDotTwo},
			b:        []net.IP{tenDotOne, tenDotTwo},
			expected: false,
		},
		{
			name:     "duplicates",
			a:        []net.IP{tenDotOne, tenDotOne},
			b:        []net.IP{tenDotOne, tenDotTwo},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if equal := equalIPAddresses(tt.a, tt.b); equal != tt.expected {
				t.Errorf("%v == %v :: wanted %v, got %v",
					tt.a, tt.b, tt.expected, equal)
			}
		})
	}
}

func TestSubsetIPAddresses(t *testing.T) {
	tenDotOne := net.ParseIP("10.0.0.1")
	tenDotTwo := net.ParseIP("10.0.0.2")
	tenDotThree := net.ParseIP("10.0.0.3")
	tenOneThree := net.ParseIP("10.0.1.3")
	_, tenNoughtSlash24, _ := net.ParseCIDR("10.0.0.0/24")

	tests := []struct {
		name     string
		cidrs    []*net.IPNet
		super    []net.IP
		sub      []net.IP
		expected bool
	}{
		{
			name:     "equal sets",
			super:    []net.IP{tenDotOne, tenDotTwo},
			sub:      []net.IP{tenDotOne, tenDotTwo},
			expected: true,
		},
		{
			name:     "sub is a subset",
			super:    []net.IP{tenDotOne, tenDotTwo},
			sub:      []net.IP{tenDotOne},
			expected: true,
		},
		{
			name:     "sub is a superset",
			super:    []net.IP{tenDotOne, tenDotTwo},
			sub:      []net.IP{tenDotOne, tenDotThree},
			expected: false,
		},
		{
			name:     "sub is a subset with duplicates",
			super:    []net.IP{tenDotOne, tenDotTwo},
			sub:      []net.IP{tenDotOne, tenDotOne},
			expected: true,
		},
		{
			name:     "sub is a subset when cidrs are included",
			cidrs:    []*net.IPNet{tenNoughtSlash24},
			super:    []net.IP{tenOneThree},
			sub:      []net.IP{tenDotOne, tenOneThree},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if equal := subsetIPAddresses(tt.cidrs, tt.super, tt.sub); equal != tt.expected {
				t.Errorf("%v subset of %v :: wanted %v, got %v",
					tt.sub, tt.super, tt.expected, equal)
			}
		})
	}
}

func TestCsrSANs(t *testing.T) {
	uri, _ := url.Parse("http://example.com")
	cr := &x509.CertificateRequest{
		DNSNames:       []string{"test.local", "localhost"},
		EmailAddresses: []string{"exaple@test.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{uri},
	}

	sans := sets.NewString(csrSANs(cr)...)
	if !sans.HasAll(
		"http://example.com", "test.local",
		"localhost", "exaple@test.com",
		"127.0.0.1", "10.0.0.1") {
		t.Errorf("Not all SANs were collected")
	}

	if len(csrSANs(nil)) > 0 {
		t.Errorf("No SANs are expected from nil")
	}
}

func TestCertSANs(t *testing.T) {
	uri, _ := url.Parse("http://example.com")
	cert := &x509.Certificate{
		DNSNames:       []string{"test.local", "localhost"},
		EmailAddresses: []string{"exaple@test.com"},
		IPAddresses:    []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")},
		URIs:           []*url.URL{uri},
	}

	sans := sets.NewString(certSANs(cert)...)
	if !sans.HasAll(
		"http://example.com", "test.local",
		"localhost", "exaple@test.com",
		"127.0.0.1", "10.0.0.1") {
		t.Errorf("Not all SANs were collected")
	}

	if len(certSANs(nil)) > 0 {
		t.Errorf("No SANs are expected from nil")
	}
}
func assertNoChange(t *testing.T, a, b []string, f func(*testing.T)) {
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))

	copy(aCopy, a)
	copy(bCopy, b)

	f(t)

	if !reflect.DeepEqual(aCopy, a) || !reflect.DeepEqual(bCopy, b) {
		t.Errorf("slice modified unexpectedly: "+
			"orinigal a = %v, original b = %v, "+
			"new a = %v, new b = %v", aCopy, bCopy, a, b)
	}
}

func parseCert(t *testing.T, cert string) *x509.Certificate {
	block, _ := pem.Decode([]byte(cert))
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Passed invalid Certificate: %v ", err)
	}
	return parsedCert
}

func parseCR(t *testing.T, csr string) *x509.CertificateRequest {
	block, _ := pem.Decode([]byte(csr))
	parsedCR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("Passed invalid Certificate: %v ", err)
	}
	return parsedCR
}

func fakeResponder(t *testing.T, laddr, cert, key string) (server net.Listener) {
	crt, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatalf("Fail to parse key pair: %s", err.Error())
	}

	server, err = tls.Listen("tcp", laddr, &tls.Config{
		GetCertificate: func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) { return &crt, nil },
	})
	if err != nil {
		t.Fatalf("Fail to establish TCP listener: %s", err.Error())
	}

	return
}

func respond(server net.Listener) {
	conn, err := server.Accept()
	if err != nil {
		return
	}
	if conn != nil {
		defer conn.Close()
		conn.Write([]byte(server.Addr().String()))
	}
}
