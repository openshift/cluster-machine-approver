package metrics

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func certificate(t *testing.T, parent *x509.Certificate, signer *ecdsa.PrivateKey, cn string, usage x509.ExtKeyUsage, isCA bool) ([]byte, []byte, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: []string{"localhost"}}
	if parent == nil {
		parent, signer = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), parsed, key
}

func TestServingOptions(t *testing.T) {
	caPEM, _, ca, caKey := certificate(t, nil, nil, "trusted CA", x509.ExtKeyUsageAny, true)
	_, _, otherCA, otherKey := certificate(t, nil, nil, "other CA", x509.ExtKeyUsageAny, true)
	const cn = "system:serviceaccount:hypershift:prometheus"
	goodPEM, goodKey, _, _ := certificate(t, ca, caKey, cn, x509.ExtKeyUsageClientAuth, false)
	wrongCNPEM, wrongCNKey, _, _ := certificate(t, ca, caKey, "different", x509.ExtKeyUsageClientAuth, false)
	wrongCAPEM, wrongCAKey, _, _ := certificate(t, otherCA, otherKey, cn, x509.ExtKeyUsageClientAuth, false)
	serverPEM, serverKey, _, _ := certificate(t, ca, caKey, "localhost", x509.ExtKeyUsageServerAuth, false)
	dir := t.TempDir()
	file := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caFile := file("ca.crt", caPEM)
	certFile := file("tls.crt", serverPEM)
	keyFile := file("tls.key", serverKey)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defaultOptions, err := ServingOptions(ctx, "127.0.0.1:0", "", "", "", "", func(*tls.Config) {})
	if err != nil {
		t.Fatal(err)
	}
	filter, err := defaultOptions.FilterProvider(&rest.Config{Host: "http://127.0.0.1:1"}, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	defaultHandler, err := filter(logr.Discard(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	defaultHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("default authentication returned %d without credentials, want 401", recorder.Code)
	}
	for _, tc := range []struct{ ca, cn, cert, key string }{{caFile, "", certFile, keyFile}, {"", cn, certFile, keyFile}, {caFile, cn, "", ""}, {caFile, cn, certFile, ""}} {
		if _, err := ServingOptions(ctx, "127.0.0.1:0", tc.ca, tc.cn, tc.cert, tc.key, func(*tls.Config) {}); err == nil {
			t.Errorf("expected incomplete configuration to fail: %+v", tc)
		}
	}
	options, err := ServingOptions(ctx, "127.0.0.1:0", caFile, cn, certFile, keyFile, func(*tls.Config) {})
	if err != nil {
		t.Fatal(err)
	}
	metricsServer, err := server.NewServer(options, nil, nil) // No API client in local mode.
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- metricsServer.Start(serverCtx) }()
	address := metricsServer.(interface{ GetBindAddr() string })
	var url string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if addr := address.GetBindAddr(); addr != "" {
			url = "https://" + addr + "/metrics"
			break
		}
	}
	if url == "" {
		t.Fatal("metrics server did not start")
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := func(certPEM, keyPEM []byte) *http.Client {
		config := &tls.Config{RootCAs: roots, ServerName: "localhost"}
		if certPEM != nil {
			pair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			config.Certificates = []tls.Certificate{pair}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: config}, Timeout: 3 * time.Second}
	}
	for _, tc := range []struct {
		name      string
		cert, key []byte
		status    int
		metric    string
	}{
		{"When a trusted authorized client connects, it should serve metrics without an API server", goodPEM, goodKey, http.StatusOK, "mapi_current_pending_csr"},
		{"When no client certificate is provided, it should reject the handshake", nil, nil, 0, ""},
		{"When a different CA signs the client, it should reject the handshake", wrongCAPEM, wrongCAKey, 0, ""},
		{"When a trusted certificate has the wrong CN, it should deny metrics", wrongCNPEM, wrongCNKey, http.StatusForbidden, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response, err := client(tc.cert, tc.key).Get(url)
			if tc.status == 0 {
				if err == nil {
					response.Body.Close()
					t.Fatal("expected TLS handshake to fail")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", response.StatusCode, tc.status)
			}
			if tc.metric != "" {
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				for _, metric := range []string{tc.metric, "mapi_max_pending_csr"} {
					if !strings.Contains(string(body), metric) {
						t.Errorf("metrics body does not include %s", metric)
					}
				}
			}
		})
	}
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("metrics server did not stop")
	}
}
