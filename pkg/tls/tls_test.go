/*
Copyright 2026 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"crypto/tls"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	configv1 "github.com/openshift/api/config/v1"
	libgocrypto "github.com/openshift/library-go/pkg/crypto"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("ResolveTLSConfig", func() {
	Context("when CLI flags override the cluster-wide TLS profile", func() {
		It("should apply TLS 1.2 with the specified cipher suites", func() {
			result, err := ResolveTLSConfig(ctx, cfg, "VersionTLS12", []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
			})
			Expect(err).NotTo(HaveOccurred())

			tlsCfg := &tls.Config{}
			result.TLSConfig(tlsCfg)

			Expect(tlsCfg.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(tlsCfg.CipherSuites).To(Equal([]uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			}))
		})

		It("should not set cipher suites when TLS 1.3 is specified", func() {
			result, err := ResolveTLSConfig(ctx, cfg, "VersionTLS13", []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			})
			Expect(err).NotTo(HaveOccurred())

			tlsCfg := &tls.Config{}
			result.TLSConfig(tlsCfg)

			Expect(tlsCfg.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			Expect(tlsCfg.CipherSuites).To(BeNil())
		})

		It("should accept TLS 1.3 cipher suites from the Modern profile", func() {
			modernProfile := configv1.TLSProfiles[configv1.TLSProfileModernType]
			result, err := ResolveTLSConfig(ctx, cfg, string(modernProfile.MinTLSVersion), modernProfile.Ciphers)
			Expect(err).NotTo(HaveOccurred())

			tlsCfg := &tls.Config{}
			result.TLSConfig(tlsCfg)

			Expect(tlsCfg.MinVersion).To(Equal(uint16(tls.VersionTLS13)))
			Expect(tlsCfg.CipherSuites).To(BeNil())
		})

		It("should not populate TLSAdherencePolicy or TLSProfileSpec", func() {
			result, err := ResolveTLSConfig(ctx, cfg, "VersionTLS12", []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(result.TLSAdherencePolicy).To(BeEmpty())
			Expect(result.TLSProfileSpec).To(Equal(configv1.TLSProfileSpec{}))
		})

		It("should return an error for an invalid TLS version", func() {
			_, err := ResolveTLSConfig(ctx, cfg, "InvalidVersion", []string{
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid --tls-min-version"))
		})

		It("should return an error for an invalid cipher suite", func() {
			_, err := ResolveTLSConfig(ctx, cfg, "VersionTLS12", []string{
				"INVALID_CIPHER_SUITE",
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid --tls-cipher-suites"))
		})
	})

	Context("when using the cluster-wide TLS profile", func() {
		AfterEach(func() {
			apiServer := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			}
			Eventually(func() bool {
				err := k8sClient.Delete(ctx, apiServer)
				return err == nil || apierrors.IsNotFound(err)
			}).Should(BeTrue())
		})

		It("should use the cluster profile when adherence is StrictAllComponents", func() {
			apiServer := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
					},
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
				},
			}
			Eventually(func() error {
				return k8sClient.Create(ctx, apiServer)
			}).Should(Succeed())

			result, err := ResolveTLSConfig(ctx, cfg, "", nil)
			Expect(err).NotTo(HaveOccurred())

			tlsCfg := &tls.Config{}
			result.TLSConfig(tlsCfg)

			oldProfile := configv1.TLSProfiles[configv1.TLSProfileOldType]
			expectedMinVersion := libgocrypto.TLSVersionOrDie(string(oldProfile.MinTLSVersion))
			Expect(tlsCfg.MinVersion).To(Equal(expectedMinVersion))
			Expect(tlsCfg.CipherSuites).NotTo(BeEmpty())

			Expect(result.TLSAdherencePolicy).To(Equal(configv1.TLSAdherencePolicyStrictAllComponents))
			Expect(result.TLSProfileSpec).To(Equal(*oldProfile))
		})

		It("should use the default profile when adherence is NoOpinion", func() {
			apiServer := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
					},
				},
			}
			Eventually(func() error {
				return k8sClient.Create(ctx, apiServer)
			}).Should(Succeed())

			result, err := ResolveTLSConfig(ctx, cfg, "", nil)
			Expect(err).NotTo(HaveOccurred())

			tlsCfg := &tls.Config{}
			result.TLSConfig(tlsCfg)

			// NoOpinion means the default (Intermediate) profile is applied,
			// even though the Old profile is configured on the APIServer.
			defaultProfile := configv1.TLSProfiles[libgocrypto.DefaultTLSProfileType]
			expectedMinVersion := libgocrypto.TLSVersionOrDie(string(defaultProfile.MinTLSVersion))
			Expect(tlsCfg.MinVersion).To(Equal(expectedMinVersion))

			// TLSProfileSpec still reflects what was fetched from the cluster.
			oldProfile := configv1.TLSProfiles[configv1.TLSProfileOldType]
			Expect(result.TLSProfileSpec).To(Equal(*oldProfile))
		})

		It("should use the default profile when adherence is LegacyAdheringComponentsOnly", func() {
			apiServer := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
					},
					TLSAdherence: configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly,
				},
			}
			Eventually(func() error {
				return k8sClient.Create(ctx, apiServer)
			}).Should(Succeed())

			result, err := ResolveTLSConfig(ctx, cfg, "", nil)
			Expect(err).NotTo(HaveOccurred())

			tlsCfg := &tls.Config{}
			result.TLSConfig(tlsCfg)

			defaultProfile := configv1.TLSProfiles[libgocrypto.DefaultTLSProfileType]
			expectedMinVersion := libgocrypto.TLSVersionOrDie(string(defaultProfile.MinTLSVersion))
			Expect(tlsCfg.MinVersion).To(Equal(expectedMinVersion))

			Expect(result.TLSAdherencePolicy).To(Equal(configv1.TLSAdherencePolicyLegacyAdheringComponentsOnly))
		})

		It("should apply a custom TLS profile when adherence is StrictAllComponents", func() {
			customCiphers := []string{"ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"}
			apiServer := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileCustomType,
						Custom: &configv1.CustomTLSProfile{
							TLSProfileSpec: configv1.TLSProfileSpec{
								Ciphers:       customCiphers,
								MinTLSVersion: configv1.VersionTLS12,
							},
						},
					},
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
				},
			}
			Eventually(func() error {
				return k8sClient.Create(ctx, apiServer)
			}).Should(Succeed())

			result, err := ResolveTLSConfig(ctx, cfg, "", nil)
			Expect(err).NotTo(HaveOccurred())

			tlsCfg := &tls.Config{}
			result.TLSConfig(tlsCfg)

			Expect(tlsCfg.MinVersion).To(Equal(uint16(tls.VersionTLS12)))
			Expect(tlsCfg.CipherSuites).NotTo(BeEmpty())

			Expect(result.TLSProfileSpec.Ciphers).To(Equal(customCiphers))
			Expect(result.TLSProfileSpec.MinTLSVersion).To(Equal(configv1.VersionTLS12))
		})

		It("should gracefully default when no APIServer resource exists", func() {
			result, err := ResolveTLSConfig(ctx, cfg, "", nil)
			Expect(err).NotTo(HaveOccurred())

			tlsCfg := &tls.Config{}
			result.TLSConfig(tlsCfg)

			// Falls back to the Intermediate profile when the APIServer is missing.
			defaultProfile := configv1.TLSProfiles[libgocrypto.DefaultTLSProfileType]
			expectedMinVersion := libgocrypto.TLSVersionOrDie(string(defaultProfile.MinTLSVersion))
			Expect(tlsCfg.MinVersion).To(Equal(expectedMinVersion))

			Expect(result.TLSAdherencePolicy).To(BeEmpty())
			Expect(result.TLSProfileSpec).To(Equal(configv1.TLSProfileSpec{}))
		})

		It("should populate TLSAdherencePolicy and TLSProfileSpec from the cluster", func() {
			apiServer := &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
					},
					TLSAdherence: configv1.TLSAdherencePolicyStrictAllComponents,
				},
			}
			Eventually(func() error {
				return k8sClient.Create(ctx, apiServer)
			}).Should(Succeed())

			result, err := ResolveTLSConfig(ctx, cfg, "", nil)
			Expect(err).NotTo(HaveOccurred())

			Expect(result.TLSAdherencePolicy).To(Equal(configv1.TLSAdherencePolicyStrictAllComponents))
			Expect(result.TLSProfileSpec).To(Equal(*configv1.TLSProfiles[configv1.TLSProfileOldType]))
		})
	})
})
