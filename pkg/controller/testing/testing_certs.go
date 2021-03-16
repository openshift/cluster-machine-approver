package machine_approver_test_certs

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
	ServerCertGood = `-----BEGIN CERTIFICATE-----
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
	ServerKeyGood = `-----BEGIN RSA PRIVATE KEY-----
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
	RootCertGood = `-----BEGIN CERTIFICATE-----
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
	DifferentCert = `-----BEGIN CERTIFICATE-----
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
	DifferentKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFU6aDkXYwx8YYtXd9AZPIst87daWX49Rzhxsd7D7UwroAoGCCqGSM49
AwEHoUQDQgAErUDDpFwiP28p9TD3OSmDNXeTbDxeIHsY3iqoya6x3Gk6MIyQEDrJ
SlwIRyqdMvo4Rc6/JUHQ67eXh1Cvy3w6Sg==
-----END EC PRIVATE KEY-----
`
	GoodCSR = `
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
	EmptyCSR = `
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
	ExtraAddr = `
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
	OtherName = `
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
	NoNamePrefix = `
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
	NoGroup = `
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

	ClientGood = `
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
	ClientExtraO = `
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
	ClientWithDNS = `
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
	ClientWrongCN = `
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
	ClientEmptyName = `
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
