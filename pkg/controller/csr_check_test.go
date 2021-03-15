package controller

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
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

	Generate CSR
	$ cfssl genkey test_csr.json | cfssljson -bare ca

	Generate server certificate
	$ cfssl gencert -ca=ca.pem -ca-key=ca-key.pem test_csr.json | cfssljson -bare server

	Generate root certificate
	$ cfssl gencert -initca test_csr.json | cfssljson -bare root
*/

const (
	serverCertGood = `-----BEGIN CERTIFICATE-----
MIIDfTCCAmWgAwIBAgIUbAsUQZRjkLyGoY50hiYPohSchAYwDQYJKoZIhvcNAQEL
BQAwMjEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRkwFwYDVQQDExBzeXN0ZW06bm9k
ZTp0ZXN0MB4XDTIwMTExODIwMTIwMFoXDTIxMTExODIwMTIwMFowMjEVMBMGA1UE
ChMMc3lzdGVtOm5vZGVzMRkwFwYDVQQDExBzeXN0ZW06bm9kZTp0ZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9w75bQ5bUympW/LYWWE91Lpzc7kJ
e4MYmJqr8Sa8rCsSykdHsfWpn0oiW28QQY3k1fgB+WeA3FhOoiDsa5anprhJWqDV
gaAW2jwPq6D2oi3c6YSa80q8n1oTT3LzkLKnDLQx/xwGJDgnXrLfEOqDuy4z5RvS
wOO5CmTQZRt+FieeVHKLuZhDOE0CJ62HclntNj04IM+sbeHhozz1iWrLz2C3Pm0F
LIIfmpA2Cb3pp9eUknyxDAur8JatIM3CoEoWEW9wHeqhu8/TkNKGfUdocT88tq4r
+0x4wedQ7vXikBAlF2VBBwVj86jrhDgi2wn4ErEp9dQ322rvRoo5EYFYCQIDAQAB
o4GKMIGHMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUijDhx2Lznrf2OAw+x2d08pVm
Qa0wKQYDVR0RBCIwIIIFbm9kZTGCC25vZGUxLmxvY2FshwQKAAABhwR/AAABMA0G
CSqGSIb3DQEBCwUAA4IBAQARJOrMYBokpT/mj1XXN1Z0rpiYcJjzbqmF6BTqn/Z0
AuW9zJJcAKajcRx7x97LClajvAH7j0qXfw6PJYoFOukJyJzVD93hawNXWBy0xkYg
u+Xyf2bwoLCS+gHoyXqknOFgaMNCtBBum1+CxxalANfZmeDHbS7ZXcP7u8KAmHJ4
kqkTSAhi7WeiYlXRQ0YoXy9NSQ25yXrw1Z2PPJbWUZu9jrBHUi9l2EUbcudujxHt
87fbFaRLZzhRrFqmDK73fhQ3f5ajiw5uwIvVdy3JIXnfau9+ZKJ8aR7Mj74tTecV
jPZ67rYFh/lRj5PMorF///1taHNXCaR905Wx9WxzPLK/
-----END CERTIFICATE-----
`
	serverKeyGood = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA9w75bQ5bUympW/LYWWE91Lpzc7kJe4MYmJqr8Sa8rCsSykdH
sfWpn0oiW28QQY3k1fgB+WeA3FhOoiDsa5anprhJWqDVgaAW2jwPq6D2oi3c6YSa
80q8n1oTT3LzkLKnDLQx/xwGJDgnXrLfEOqDuy4z5RvSwOO5CmTQZRt+FieeVHKL
uZhDOE0CJ62HclntNj04IM+sbeHhozz1iWrLz2C3Pm0FLIIfmpA2Cb3pp9eUknyx
DAur8JatIM3CoEoWEW9wHeqhu8/TkNKGfUdocT88tq4r+0x4wedQ7vXikBAlF2VB
BwVj86jrhDgi2wn4ErEp9dQ322rvRoo5EYFYCQIDAQABAoIBAQD2LSae43pekJng
NEgeL8YjrbIS8qMfPo8IqL6B6b6As97iTkqDai2duoonn7CMEa6fAqQ890SwyxF3
feT2g8UEXIdDVhXJN1LuHIDk3NxE1/xTd73KhYMUKfYp6XoHiezovLlA4ZTBDG82
bnfVbEjc//nX5nSHnaIpWDFLPizSNqzJymPlD3hOetPKzZ8e4bjnkil9cTpg4QO6
3xruCTEmGwG1ApYp7XAE32r2MCQalOf8pKIR+6IvTA1mYZd70geLmj/bbN/Zi6f6
dGpRzFr2Jx0yPExebjds6UqcdIRxur6w9ya++nmBrKvrGzPjee3NH2rk2ZKySKQ8
JTtP4J+BAoGBAP/5Nrv/TeCQIaRtYskZrfna8ugXbfYPLSMo+qKvIcpEwFEuaxkH
K5G7a5UnkJIIWCGUKhQmsCb6amz8SmuH/SmZXEavMMDTIWriOZ1YA5yR4oc+tO1a
UdM33qrVbMfH8g6kJKRXML1yxoqbSv6RSye1FlfqHp0lcqpQZ1bcVHexAoGBAPcV
hi+8OMdDyd64EE07N0xmCgd3um1LFn7Wc2W3UA3Fdcp4YJ8pwfmx+BN/48hhZuwa
AC8o3UHgLv/ypveoBjjA36ARBt20WETByfwJPp5md5mYQSFzsdhsN8t80VagVrGM
tO/ZZEG5AkhazKm7hYz4NlGOfyyf6tw9CPIkkdPZAoGBAL2hO1pExcXSIQo1+xPu
EUPjX0ZvbQf3sEG27w6sXYUCL9M0ZyTweeeJiCbEW8bDpb6ijBXHn4IQy90Xfm5x
HSy/L2wyBxUilEQheftFo89PCBmXa+PWoH2wiyXV3LOYPYt5MKgK69G9gLZYW1OC
AcJV1kqk568VegAQdq4TpgPRAoGBAPHY66NFxP2maK3L1IkD8TiimCZ/Fsdru/Ui
y4lASOdx473u3gRsxyU1AfF0OO0mCawINy3x/cBBQz/br3qxyIU8pKb0g5f2sn96
f85m7hf1jBOXaAjqSaXhJyvSXMVB5Bmd9GzgiLWb9ZQE7Fcm6a32NpTVub1gOm6g
f2UkTmjhAoGAMr7qeQ1AJrEg5pYEaeYeQ9jvxxvgTOO6Q6gi7K3D/BUSbHukZ8Kd
keiTZ5+55Pi21jvHNXE/Rn9RrJHkryoPCqnRIuSFigrUMBMiloCzL2j0jCIzbw5n
iWrekSBGrM0WHjrzgzLwIQY1nuXUx9TZgw+tgXTFt9Grgz0L7NmSyJI=
-----END RSA PRIVATE KEY-----
`
	rootCertGood = `-----BEGIN CERTIFICATE-----
MIIDSzCCAjOgAwIBAgIUUEs81eUj5S9T5cglpZ0gQV06Y9owDQYJKoZIhvcNAQEL
BQAwMjEVMBMGA1UEChMMc3lzdGVtOm5vZGVzMRkwFwYDVQQDExBzeXN0ZW06bm9k
ZTp0ZXN0MB4XDTIwMTExODIwMTEwMFoXDTI1MTExNzIwMTEwMFowMjEVMBMGA1UE
ChMMc3lzdGVtOm5vZGVzMRkwFwYDVQQDExBzeXN0ZW06bm9kZTp0ZXN0MIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAukG4TvbrMbVklA2nLmK0T7+SygWR
Yebsd0vJMWkw87+zxkYY0tEo+y5ijHXucb1S3m4mGulmzxP1KQI/0RDuba1HhekA
aOxy2TZWYhtQUxCHbrREz3b+OBbDkf2Dzp7Qo6J3l7fYBRCD/AnTzSCaK5LwzmH0
X3TCJnrLBIf8gFrqAHsCXadNV3JQ2Iip6Gjs8VCqnZHS/oFhXpKiMnrB0IMpC6F2
1/T4Uoe+vyWoUTZQTAjZVBcIDLp3r8c6FnmF5YjouWafNVfbttVczNpuSt/3YxXL
b2P/EQfb8QniNUXnkxSNwOpZx6QO2PZHSSBWcW+q+EUeFXsInl41dK5avwIDAQAB
o1kwVzAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
Hrk7KIVyk8Iio60VmtNhBX8NoWAwFQYDVR0RBA4wDIcECgAAAYcEfwAAATANBgkq
hkiG9w0BAQsFAAOCAQEAc8MxeqY7IVOfoDrbpeFAmZlmG93WE8Aolzj9rN0ZfQYr
SuNL644WQVUS0JcJOWpXYP7IBIh1dTSx3eOBnN4Et8t+grKJLMjtGC4+4Q08tOT+
+wmy8vKRk6YDxR38nmhluEUFLdtMCdNsDTgXdOx5r/jE+9b+HCMaTRuejt2rxgNg
NxxCBFzlUF3qm11AGXU37RobjPciHu+NxLnC7OWvu1xUawf1qryJhd0fahM+ZTQ0
QweKOXA34JfqaTjLPHob/xaeBZ2zk8JuiPeHnuXUfiBPgkCKfUlidPQH7G2B9QNn
mhTXEUnJbr+N31t6dGQdnvk88+a7QA1y4ypl9XolWA==
-----END CERTIFICATE-----
`
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

	type args struct {
		config        ClusterMachineApproverConfig
		machines      []machinev1.Machine
		node          *corev1.Node
		kubeletServer net.Listener
		req           *certificatesv1.CertificateSigningRequest
		csr           string
		ca            []*x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		wantErr string
	}{
		{
			name: "ok",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "",
		},
		{
			name: "bad-csr",
			args: args{
				csr: emptyCSR,
				req: &certificatesv1.CertificateSigningRequest{},
			},
			wantErr: "PEM block type must be CERTIFICATE REQUEST",
		},
		{
			name: "no-node-prefix",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "\"test\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "only-node-prefix",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Empty name",
		},
		{
			name: "no-machine-status-ref",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{},
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
			wantErr: "No target machine for node \"test\"",
		},
		{
			name: "missing-groups-1",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Too few groups",
		},
		{
			name: "missing-groups-2",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Too few groups",
		},
		{
			name: "extra-group",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "",
		},
		{
			name: "wrong-group",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "map[\"system:authenticated\":{} \"system:foo-bar\":{}] not in \"system:authenticated\" and \"system:nodes\"",
		},
		{
			name: "usages-missing",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Too few usages",
		},
		{
			name: "usages-missing",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: `map["client auth":{} "digital signature":{} "key encipherment":{}] is missing usages`,
		},
		{
			name: "usages-missing-1",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Too few usages",
		},
		{
			name: "usage-missing-2",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Too few usages",
		},
		{
			name: "usage-extra",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Too few usages",
		},
		{
			name: "csr-cn",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Mismatched CommonName system:node:foobar != system:node:test",
		},
		{
			name: "csr-cn-2",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Mismatched CommonName test != system:node:test",
		},
		{
			name: "csr-no-o",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "Organization [] doesn't include system:nodes",
		},
		{
			name: "csr-extra-addr",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "IP address '99.0.1.1' not in machine addresses: 127.0.0.1 10.0.0.1",
		},
		{
			name: "csr-san-ip-mismatch",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "IP address '10.0.0.1' not in machine addresses: 127.0.0.1 10.0.0.2",
		},
		{
			name: "csr-san-dns-mismatch",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "DNS name 'node1' not in machine names: node1.local node2",
		},
		{
			name: "client good",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "",
		},
		{
			name: "client extra O",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client with DNS",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but extra usage",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but wrong usage",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but missing usage",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but wrong CN",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "\"system:serviceaccount:openshift-machine-config-operator:node-bootstrapper\" doesn't match expected prefix: \"system:node:\"",
		},
		{
			name: "client good but wrong user",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "CSR green for node client cert has wrong user system:serviceaccount:openshift-machine-config-operator:node-bootstrapper-not or groups map[system:authenticated:{} system:serviceaccounts:{} system:serviceaccounts:openshift-machine-config-operator:{}]",
		},
		{
			name: "client good but wrong user group",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "CSR blue for node client cert has wrong user system:serviceaccount:openshift-machine-config-operator:node-bootstrapper or groups map[extra-group:{} system:authenticated:{} system:serviceaccounts:{} system:serviceaccounts:openshift-machine-config-operator:{}]",
		},
		{
			name: "client good but empty name",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "CSR yellow has empty node name",
		},
		{
			name: "client good but node exists",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "node panda already exists or other error: <nil>",
		},
		{
			name: "client good but missing machine",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "failed to find machine for node panda",
		},
		{
			name: "client good but machine has node ref",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
							Addresses: []corev1.NodeAddress{
								{
									Type:    corev1.NodeInternalDNS,
									Address: "tigers",
								},
							},
						},
					},
					{
						Status: machinev1.MachineStatus{
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
			wantErr: "CSR orange for node client cert rejected as the flow is disabled",
		},
		{
			name: "client good with proper timing",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
						Status: machinev1.MachineStatus{
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
			wantErr: "",
		},
		{
			name: "client good with proper timing 2",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
						Status: machinev1.MachineStatus{
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
			wantErr: "",
		},
		{
			name: "client good but CSR too early",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
						Status: machinev1.MachineStatus{
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
			wantErr: "CSR purple creation time 2020-11-19 00:02:00 +0000 UTC not in range (2020-11-19 00:02:50 +0000 UTC, 2020-11-19 02:03:00 +0000 UTC)",
		},
		{
			name: "client good but CSR too late",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
						Status: machinev1.MachineStatus{
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
			wantErr: "CSR red creation time 2020-11-20 01:00:00 +0000 UTC not in range (2020-11-19 00:02:50 +0000 UTC, 2020-11-19 02:03:00 +0000 UTC)",
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
		},
		{
			name: "successfull fallback to fresh approval",
			args: args{
				machines: []machinev1.Machine{
					{
						Status: machinev1.MachineStatus{
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
			wantErr: `No target machine for node "test"`,
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

			nodes := []runtime.Object{}
			if tt.args.node != nil {
				nodes = []runtime.Object{tt.args.node}
			}
			cl := fake.NewFakeClient(nodes...)
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
			if err := authorizeCSR(cl, tt.args.config, tt.args.machines, tt.args.req, parsedCSR, ca); errString(err) != tt.wantErr {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, tt.wantErr)
			}
		})

		t.Run("Invalid call", func(t *testing.T) {
			if err := authorizeCSR(nil, tt.args.config, tt.args.machines, nil, nil, nil); errString(err) != "Invalid request" {
				t.Errorf("authorizeCSR() error = %v, wantErr %s", err, "Invalid request")
			}
		})
	}
}

func TestAuthorizeServingRenewal(t *testing.T) {
	presetTimeCorrect := time.Date(2020, 11, 19, 0, 0, 0, 0, time.UTC)
	presetTimeExpired := time.Date(2020, 11, 18, 0, 0, 0, 0, time.UTC)

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
			wantErr:     "x509: certificate has expired or is not yet valid: current time 2020-11-18T00:00:00Z is before 2020-11-18T20:12:00Z",
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
	ml := []machinev1.Machine{
		{
			Status: machinev1.MachineStatus{},
		},
		{
			Status: machinev1.MachineStatus{},
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
