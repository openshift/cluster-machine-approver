package metrics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// ServingOptions retains API-backed metrics authentication unless a client CA and
// authorized subject CN are explicitly configured. Local mode never calls the
// API server to authenticate or authorize a scrape.
func ServingOptions(ctx context.Context, bindAddress, clientCAFile, allowedClientCN, certFile, keyFile string, profileTLSConfig func(*tls.Config)) (server.Options, error) {
	options := server.Options{
		BindAddress:    bindAddress,
		SecureServing:  true,
		FilterProvider: filters.WithAuthenticationAndAuthorization,
		TLSOpts:        []func(*tls.Config){profileTLSConfig},
	}

	if (certFile == "") != (keyFile == "") {
		return server.Options{}, fmt.Errorf("--metrics-cert-file and --metrics-key-file must be specified together")
	}
	if (clientCAFile == "") != (allowedClientCN == "") {
		return server.Options{}, fmt.Errorf("--metrics-client-ca-file and --metrics-allowed-client-cn must be specified together")
	}
	if clientCAFile != "" && certFile == "" {
		return server.Options{}, fmt.Errorf("local metrics authentication requires --metrics-cert-file and --metrics-key-file")
	}

	var watcher *certwatcher.CertWatcher
	if certFile != "" {
		var err error
		watcher, err = certwatcher.New(certFile, keyFile)
		if err != nil {
			return server.Options{}, fmt.Errorf("load metrics serving certificate: %w", err)
		}
		options.TLSOpts = append(options.TLSOpts, func(cfg *tls.Config) {
			cfg.GetCertificate = watcher.GetCertificate
		})
	}

	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return server.Options{}, fmt.Errorf("read metrics client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return server.Options{}, fmt.Errorf("--metrics-client-ca-file contains no valid CA certificates")
		}
		options.TLSOpts = append(options.TLSOpts, func(cfg *tls.Config) {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
			cfg.ClientCAs = pool
		})
		options.FilterProvider = func(_ *rest.Config, _ *http.Client) (server.Filter, error) {
			return func(_ logr.Logger, handler http.Handler) (http.Handler, error) {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
						http.Error(w, "Unauthorized", http.StatusUnauthorized)
						return
					}
					if r.TLS.PeerCertificates[0].Subject.CommonName != allowedClientCN {
						http.Error(w, "Forbidden", http.StatusForbidden)
						return
					}
					handler.ServeHTTP(w, r)
				}), nil
			}, nil
		}
	}
	if watcher != nil {
		go func() {
			if err := watcher.Start(ctx); err != nil && ctx.Err() == nil {
				klog.Errorf("metrics certificate watcher stopped: %v", err)
			}
		}()
	}
	return options, nil
}
