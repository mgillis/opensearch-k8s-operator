package reconcilers

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	opsterv1 "github.com/Opster/opensearch-k8s-operator/opensearch-operator/api/v1"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/mocks/github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconcilers/k8s"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/helpers"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/tls"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/stretchr/testify/mock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func newTLSReconciler(k8sClient *k8s.MockK8sClient, spec *opsterv1.OpenSearchCluster) (*ReconcilerContext, *TLSReconciler) {
	reconcilerContext := NewReconcilerContext(&helpers.MockEventRecorder{}, spec, spec.Spec.NodePools)
	underTest := &TLSReconciler{
		client:            k8sClient,
		reconcilerContext: &reconcilerContext,
		instance:          spec,
		logger:            log.FromContext(context.Background()),
		pki:               tls.NewPKI(),
	}
	return &reconcilerContext, underTest
}

var _ = Describe("TLS Controller", func() {
	format.MaxLength = 0

	Context("When Reconciling the TLS configuration with no existing secrets", func() {
		It("should create the needed secrets ", func() {
			clusterName := "tls-test"
			caSecretName := clusterName + "-ca"
			transportSecretName := clusterName + "-transport-cert"
			httpSecretName := clusterName + "-http-cert"
			adminSecretName := clusterName + "-admin-cert"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{
						Version: "2.0.0",
					},
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
						Transport: &opsterv1.TlsConfigTransport{Generate: true},
						Http:      &opsterv1.TlsConfigHttp{Generate: true},
					}},
				},
			}

			mockClient := k8s.NewMockK8sClient(GinkgoT())
			mockClient.EXPECT().Context().Return(context.Background())
			mockClient.EXPECT().Scheme().Return(scheme.Scheme)
			mockClient.EXPECT().GetSecret(caSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(transportSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(httpSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(adminSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())

			var caSecretData, transportSecretData, httpSecretData, adminSecretData map[string][]byte

			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == caSecretName })).
				Run(func(args mock.Arguments) { caSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == transportSecretName })).
				Run(func(args mock.Arguments) { transportSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == httpSecretName })).
				Run(func(args mock.Arguments) { httpSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == adminSecretName })).
				Run(func(args mock.Arguments) { adminSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)

			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())

			caCertData := caSecretData["ca.crt"]
			Expect(caCertData).ToNot(BeNil(), "a ca.crt exists in CA Secret")
			ExpectAllCertificatesValidAndSignedByIncludedCA(transportSecretData, "transport")
			ExpectAllCertificatesValidAndSignedByIncludedCA(httpSecretData, "http")
			ExpectAllCertificatesValidAndSignedByIncludedCA(adminSecretData, "admin")

			// spot check
			ExpectPublicKeyAlgorithm(transportSecretData["tls.crt"]).To(Equal(x509.Ed25519))
			ExpectPublicKeyAlgorithm(httpSecretData["tls.crt"]).To(Equal(x509.RSA))

			Expect(reconcilerContext.Volumes).Should(HaveLen(2))
			Expect(reconcilerContext.VolumeMounts).Should(HaveLen(2))
			value, exists := reconcilerContext.OpenSearchConfig["plugins.security.nodes_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=tls-test,OU=tls-test\"]"))
			value, exists = reconcilerContext.OpenSearchConfig["plugins.security.authcz.admin_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=admin,OU=tls-test\"]"))
		})
	})

	Context("When Reconciling the TLS configuration with no existing secrets and perNode certs activated", func() {
		It("should create the needed secrets ", func() {
			clusterName := "tls-pernode"
			caSecretName := clusterName + "-ca"
			transportSecretName := clusterName + "-transport-cert"
			httpSecretName := clusterName + "-http-cert"
			adminSecretName := clusterName + "-admin-cert"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{
						Version: "2.0.0",
					},
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
						Transport: &opsterv1.TlsConfigTransport{Generate: true, PerNode: true},
						Http:      &opsterv1.TlsConfigHttp{Generate: true},
					}},
					NodePools: []opsterv1.NodePool{
						{
							Component: "masters",
							Replicas:  3,
						},
						{
							// sufficiently large to be above the pool cap
							Component: "data",
							Replicas:  12,
						},
					},
				}}
			mockClient := k8s.NewMockK8sClient(GinkgoT())
			mockClient.EXPECT().Context().Return(context.Background())
			mockClient.EXPECT().Scheme().Return(scheme.Scheme)
			mockClient.EXPECT().GetSecret(caSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(transportSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(httpSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(adminSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())

			var caSecretData, transportSecretData, httpSecretData, adminSecretData map[string][]byte

			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == caSecretName })).
				Run(func(args mock.Arguments) { caSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == transportSecretName })).
				Run(func(args mock.Arguments) { transportSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == httpSecretName })).
				Run(func(args mock.Arguments) { httpSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == adminSecretName })).
				Run(func(args mock.Arguments) { adminSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)

			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())

			caCertData := caSecretData["ca.crt"]
			Expect(caCertData).ToNot(BeNil(), "ca.crt exists in CA Secret")
			ExpectAllCertificatesValidAndSignedByIncludedCA(transportSecretData, "transport")
			ExpectAllCertificatesValidAndSignedByIncludedCA(httpSecretData, "http")
			ExpectAllCertificatesValidAndSignedByIncludedCA(adminSecretData, "admin")

			Expect(transportSecretData["ca.crt"]).ToNot(BeNil(), "ca.crt missing from transport secret")
			for _, nodePool := range spec.Spec.NodePools {
				var i int32
				for i = 0; i < nodePool.Replicas; i++ {
					name := fmt.Sprintf("tls-pernode-%s-%d", nodePool.Component, i)
					Expect(transportSecretData[name+".crt"]).ToNot(BeNil(), "%s.crt missing from transport secret", name)
					Expect(transportSecretData[name+".key"]).ToNot(BeNil(), "%s.key missing from transport secret", name)
				}
			}

			Expect(reconcilerContext.Volumes).Should(HaveLen(2))
			Expect(reconcilerContext.VolumeMounts).Should(HaveLen(2))

			value, exists := reconcilerContext.OpenSearchConfig["plugins.security.nodes_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=tls-pernode-*,OU=tls-pernode\"]"))
			value, exists = reconcilerContext.OpenSearchConfig["plugins.security.authcz.admin_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=admin,OU=tls-pernode\"]"))
		})
	})

	Context("When Reconciling the TLS configuration with external certificates", func() {
		It("Should not create secrets but only mount them", func() {
			clusterName := "tls-test-existingsecrets"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{General: opsterv1.GeneralConfig{Version: "2.8.0"}, Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
					Transport: &opsterv1.TlsConfigTransport{
						Generate: false,
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							Secret:   corev1.LocalObjectReference{Name: "cert-transport"},
							CaSecret: corev1.LocalObjectReference{Name: "casecret-transport"},
						},
						NodesDn: []string{"CN=mycn", "CN=othercn"},
					},
					Http: &opsterv1.TlsConfigHttp{
						Generate: false,
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							Secret:   corev1.LocalObjectReference{Name: "cert-http"},
							CaSecret: corev1.LocalObjectReference{Name: "casecret-http"},
						},
						AdminDn: []string{"CN=admin1", "CN=admin2"},
					},
				},
				}}}
			mockClient := k8s.NewMockK8sClient(GinkgoT())
			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())

			Expect(reconcilerContext.Volumes).Should(HaveLen(4))
			Expect(reconcilerContext.VolumeMounts).Should(HaveLen(4))
			// With new mounting logic: CaSecret.Name != Secret.Name, so we mount both as directories
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, "casecret-transport", "transport-ca")).Should((BeTrue()))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, "cert-transport", "transport-certs")).Should((BeTrue()))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, "casecret-http", "http-ca")).Should((BeTrue()))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, "cert-http", "http-certs")).Should((BeTrue()))

			value, exists := reconcilerContext.OpenSearchConfig["plugins.security.nodes_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=mycn\",\"CN=othercn\"]"))
			value, exists = reconcilerContext.OpenSearchConfig["plugins.security.authcz.admin_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=admin1\",\"CN=admin2\"]"))
		})
	})

	Context("When Reconciling the TLS configuration with external per-node certificates", func() {
		It("Should not create secrets but only mount them", func() {
			clusterName := "tls-test-existingsecretspernode"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{General: opsterv1.GeneralConfig{Version: "2.0.0"}, Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
					Transport: &opsterv1.TlsConfigTransport{
						Generate: false,
						PerNode:  true,
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							Secret: corev1.LocalObjectReference{Name: "my-transport-certs"},
						},
						NodesDn: []string{"CN=mycn", "CN=othercn"},
					},
					Http: &opsterv1.TlsConfigHttp{
						Generate: false,
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							Secret: corev1.LocalObjectReference{Name: "my-http-certs"},
						},
					},
				},
				}}}
			mockClient := k8s.NewMockK8sClient(GinkgoT())
			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())
			Expect(reconcilerContext.Volumes).Should(HaveLen(2))
			Expect(reconcilerContext.VolumeMounts).Should(HaveLen(2))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, "my-transport-certs", "transport-certs")).Should((BeTrue()))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, "my-http-certs", "http-certs")).Should((BeTrue()))

			value, exists := reconcilerContext.OpenSearchConfig["plugins.security.nodes_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=mycn\",\"CN=othercn\"]"))
		})
	})

	Context("When Reconciling the TLS configuration with external CA certificate", func() {
		It("Should create certificates using that CA", func() {
			clusterName := "tls-withca"
			caSecretName := clusterName + "-myca"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{General: opsterv1.GeneralConfig{Version: "2.8.0"}, Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
					Transport: &opsterv1.TlsConfigTransport{
						Generate: true,
						PerNode:  true,
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							CaSecret: corev1.LocalObjectReference{Name: caSecretName},
						},
					},
					Http: &opsterv1.TlsConfigHttp{
						Generate: true,
						TlsCertificateConfig: opsterv1.TlsCertificateConfig{
							CaSecret: corev1.LocalObjectReference{Name: caSecretName},
						},
					},
				},
				}}}

			mockClient := k8s.NewMockK8sClient(GinkgoT())
			mockClient.EXPECT().Context().Return(context.Background())
			mockClient.EXPECT().Scheme().Return(scheme.Scheme)

			var testCaCertData []byte
			{
				testCaPki := tls.NewPKI()
				testCa, err := testCaPki.GenerateCA("test CA")
				if err != nil {
					panic(fmt.Sprintf("setup of test CA failed: %v", err))
				}

				data := map[string][]byte{
					"ca.crt": testCa.CertData(),
					"ca.key": testCa.KeyData(),
				}
				caSecret := corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: caSecretName, Namespace: clusterName},
					Data:       data,
				}
				mockClient.EXPECT().GetSecret(caSecretName, clusterName).Return(caSecret, nil)
				testCaCertData = testCa.CertData()
			}

			mockClient.EXPECT().GetSecret(clusterName+"-transport-cert", clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(clusterName+"-http-cert", clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(clusterName+"-admin-cert", clusterName).Return(corev1.Secret{}, NotFoundError())

			var transportSecretData, httpSecretData, adminSecretData map[string][]byte

			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == clusterName+"-transport-cert" })).
				Run(func(args mock.Arguments) { transportSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == clusterName+"-http-cert" })).
				Run(func(args mock.Arguments) { httpSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == clusterName+"-admin-cert" })).
				Run(func(args mock.Arguments) { adminSecretData = args.Get(0).(*corev1.Secret).Data }).
				Return(&ctrl.Result{}, nil)

			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())
			ExpectAllCertificatesValidAndSignedByCA(transportSecretData, "transport", testCaCertData)
			ExpectAllCertificatesValidAndSignedByCA(httpSecretData, "http", testCaCertData)
			ExpectAllCertificatesValidAndSignedByCA(adminSecretData, "admin", testCaCertData)

			Expect(reconcilerContext.Volumes).Should(HaveLen(2))
			Expect(reconcilerContext.VolumeMounts).Should(HaveLen(2))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, clusterName+"-transport-cert", "transport-cert")).Should((BeTrue()))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, clusterName+"-http-cert", "http-cert")).Should((BeTrue()))

			value, exists := reconcilerContext.OpenSearchConfig["plugins.security.nodes_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=tls-withca-*,OU=tls-withca\"]"))
		})
	})

	Context("When Reconciling the TLS configuration with same CaSecret and Secret names", func() {
		It("Should mount only one secret as directory", func() {
			clusterName := "tls-same-secrets"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "2.8.0"},
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
						Transport: &opsterv1.TlsConfigTransport{
							Generate: false,
							TlsCertificateConfig: opsterv1.TlsCertificateConfig{
								Secret:   corev1.LocalObjectReference{Name: "same-secret"},
								CaSecret: corev1.LocalObjectReference{Name: "same-secret"}, // Same name
							},
							NodesDn: []string{"CN=mycn"},
						},
						Http: &opsterv1.TlsConfigHttp{
							Generate: false,
							TlsCertificateConfig: opsterv1.TlsCertificateConfig{
								Secret:   corev1.LocalObjectReference{Name: "same-secret"},
								CaSecret: corev1.LocalObjectReference{Name: "same-secret"}, // Same name
							},
						},
					},
					},
				}}
			mockClient := k8s.NewMockK8sClient(GinkgoT())
			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())

			// Should have only 2 volumes/mounts (one for transport, one for http)
			Expect(reconcilerContext.Volumes).Should(HaveLen(2))
			Expect(reconcilerContext.VolumeMounts).Should(HaveLen(2))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, "same-secret", "transport-certs")).Should((BeTrue()))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, "same-secret", "http-certs")).Should((BeTrue()))
		})
	})

	Context("When Reconciling the TLS configuration with hot reload enabled", func() {
		It("Should enable hot reload configuration for supported versions", func() {
			clusterName := "tls-hotreload"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "2.19.1"}, // Version that supports hot reload
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
						Transport: &opsterv1.TlsConfigTransport{
							Generate: false,
							TlsCertificateConfig: opsterv1.TlsCertificateConfig{
								Secret:          corev1.LocalObjectReference{Name: "cert-transport"},
								CaSecret:        corev1.LocalObjectReference{Name: "casecret-transport"},
								EnableHotReload: true,
							},
							NodesDn: []string{"CN=mycn"},
						},
						Http: &opsterv1.TlsConfigHttp{
							Generate: false,
							TlsCertificateConfig: opsterv1.TlsCertificateConfig{
								Secret:          corev1.LocalObjectReference{Name: "cert-http"},
								CaSecret:        corev1.LocalObjectReference{Name: "casecret-http"},
								EnableHotReload: true,
							},
						},
					},
					},
				}}
			mockClient := k8s.NewMockK8sClient(GinkgoT())
			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())

			// Check that hot reload is enabled
			value, exists := reconcilerContext.OpenSearchConfig["plugins.security.ssl.certificates_hot_reload.enabled"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("true"))
		})

		It("Should not enable hot reload configuration for unsupported versions", func() {
			clusterName := "tls-hotreload-unsupported"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{Version: "2.18.0"}, // Version that doesn't support hot reload
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
						Transport: &opsterv1.TlsConfigTransport{
							Generate: false,
							TlsCertificateConfig: opsterv1.TlsCertificateConfig{
								Secret:          corev1.LocalObjectReference{Name: "cert-transport"},
								CaSecret:        corev1.LocalObjectReference{Name: "casecret-transport"},
								EnableHotReload: true,
							},
							NodesDn: []string{"CN=mycn"},
						},
						Http: &opsterv1.TlsConfigHttp{
							Generate: false,
							TlsCertificateConfig: opsterv1.TlsCertificateConfig{
								Secret:          corev1.LocalObjectReference{Name: "cert-http"},
								CaSecret:        corev1.LocalObjectReference{Name: "casecret-http"},
								EnableHotReload: true,
							},
						},
					},
					},
				}}
			mockClient := k8s.NewMockK8sClient(GinkgoT())
			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())

			// Check that hot reload is not enabled for unsupported version
			_, exists := reconcilerContext.OpenSearchConfig["plugins.security.ssl.certificates_hot_reload.enabled"]
			Expect(exists).To(BeFalse())
		})
	})

	Context("When Reconciling the TLS configuration with custom FQDN", func() {
		It("Should include custom FQDN in certificate DNS names", func() {
			clusterName := "tls-custom-fqdn"
			customFQDN := "opensearch.example.com"
			caSecretName := clusterName + "-ca"
			httpSecretName := clusterName + "-http-cert"
			adminSecretName := clusterName + "-admin-cert"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{
						ServiceName: clusterName,
						HttpPort:    9200,
					},
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
						Transport: &opsterv1.TlsConfigTransport{Generate: true},
						Http: &opsterv1.TlsConfigHttp{
							Generate:   true,
							CustomFQDN: &customFQDN,
						},
					}},
				},
			}

			mockClient := k8s.NewMockK8sClient(GinkgoT())
			mockClient.EXPECT().Context().Return(context.Background())
			mockClient.EXPECT().Scheme().Return(scheme.Scheme)
			mockClient.EXPECT().GetSecret(caSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(clusterName+"-transport-cert", clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(httpSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(adminSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())

			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == caSecretName })).Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == adminSecretName })).Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == clusterName+"-transport-cert" })).Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == httpSecretName })).Return(&ctrl.Result{}, nil)

			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())

			Expect(reconcilerContext.Volumes).Should(HaveLen(2))
			Expect(reconcilerContext.VolumeMounts).Should(HaveLen(2))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, clusterName+"-transport-cert", "transport-cert")).Should((BeTrue()))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, clusterName+"-http-cert", "http-cert")).Should((BeTrue()))

			value, exists := reconcilerContext.OpenSearchConfig["plugins.security.nodes_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=tls-custom-fqdn,OU=tls-custom-fqdn\"]"))
			value, exists = reconcilerContext.OpenSearchConfig["plugins.security.authcz.admin_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=admin,OU=tls-custom-fqdn\"]"))
		})

		It("Should handle empty custom FQDN gracefully", func() {
			clusterName := "tls-empty-fqdn"
			emptyFQDN := ""
			caSecretName := clusterName + "-ca"
			httpSecretName := clusterName + "-http-cert"
			adminSecretName := clusterName + "-admin-cert"
			spec := opsterv1.OpenSearchCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName, Namespace: clusterName, UID: "dummyuid"},
				Spec: opsterv1.ClusterSpec{
					General: opsterv1.GeneralConfig{
						ServiceName: clusterName,
						HttpPort:    9200,
					},
					Security: &opsterv1.Security{Tls: &opsterv1.TlsConfig{
						Transport: &opsterv1.TlsConfigTransport{Generate: true},
						Http: &opsterv1.TlsConfigHttp{
							Generate:   true,
							CustomFQDN: &emptyFQDN,
						},
					}},
				},
			}

			mockClient := k8s.NewMockK8sClient(GinkgoT())
			mockClient.EXPECT().Context().Return(context.Background())
			mockClient.EXPECT().Scheme().Return(scheme.Scheme)
			mockClient.EXPECT().GetSecret(caSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(clusterName+"-transport-cert", clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(httpSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())
			mockClient.EXPECT().GetSecret(adminSecretName, clusterName).Return(corev1.Secret{}, NotFoundError())

			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == caSecretName })).Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == adminSecretName })).Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == clusterName+"-transport-cert" })).Return(&ctrl.Result{}, nil)
			mockClient.On("CreateSecret", mock.MatchedBy(func(secret *corev1.Secret) bool { return secret.ObjectMeta.Name == httpSecretName })).Return(&ctrl.Result{}, nil)

			reconcilerContext, underTest := newTLSReconciler(mockClient, &spec)
			_, err := underTest.Reconcile()
			Expect(err).ToNot(HaveOccurred())

			Expect(reconcilerContext.Volumes).Should(HaveLen(2))
			Expect(reconcilerContext.VolumeMounts).Should(HaveLen(2))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, clusterName+"-transport-cert", "transport-cert")).Should((BeTrue()))
			Expect(helpers.CheckVolumeExists(reconcilerContext.Volumes, reconcilerContext.VolumeMounts, clusterName+"-http-cert", "http-cert")).Should((BeTrue()))

			value, exists := reconcilerContext.OpenSearchConfig["plugins.security.nodes_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=tls-empty-fqdn,OU=tls-empty-fqdn\"]"))
			value, exists = reconcilerContext.OpenSearchConfig["plugins.security.authcz.admin_dn"]
			Expect(exists).To(BeTrue())
			Expect(value).To(Equal("[\"CN=admin,OU=tls-empty-fqdn\"]"))
		})
	})
})

func ExpectAllCertificatesValidAndSignedByIncludedCA(secretData map[string][]byte, description string) {
	Expect(secretData).ToNot(BeNil(), "%s has secret data", description)

	caCertData := secretData["ca.crt"]
	Expect(caCertData).ToNot(BeNil(), "%s has a ca.crt", description)

	ExpectAllCertificatesValidAndSignedByCA(secretData, description, caCertData)
}

func ExpectAllCertificatesValidAndSignedByCA(secretData map[string][]byte, description string, caCertData []byte) {
	pemBlock, _ := pem.Decode(caCertData)
	ca509Cert, err := x509.ParseCertificate(pemBlock.Bytes)
	Expect(err).ToNot(HaveOccurred(), "%s has a parseable CA cert")

	signingCertPool := x509.NewCertPool()
	signingCertPool.AddCert(ca509Cert)

	_, err = ca509Cert.Verify(x509.VerifyOptions{
		Roots: signingCertPool,
	})
	Expect(err).ToNot(HaveOccurred(), "%s %s is a valid, self-signed certificate", description, "CA Cert")

	for certFileName, certData := range secretData {
		Expect(certData).ToNot(BeNil(), "%s %s has data", description, certFileName)

		if certFileName == "ca.crt" {
			continue
		}

		if strings.HasSuffix(certFileName, ".crt") {

			keyFileName := strings.TrimSuffix(certFileName, ".crt") + ".key"
			keyData := secretData[keyFileName]
			Expect(keyData).ToNot(BeNil(), "%s %s has matching .key file in secret", description, certFileName)

			tlsCert, err := cryptotls.X509KeyPair(certData, keyData)
			Expect(err).ToNot(HaveOccurred(), "%s %s and %s is a valid cert and key pair", description, certFileName, keyFileName)

			_, err = tlsCert.Leaf.Verify(x509.VerifyOptions{
				Roots: signingCertPool,
			})
			Expect(err).ToNot(HaveOccurred(), "%s %s is signed by the CA in its ca.crt", description, certFileName)

		}
	}
}

func ExpectPublicKeyAlgorithm(certPemData []byte) Assertion {
	pemBlock, _ := pem.Decode(certPemData)
	cert, _ := x509.ParseCertificate(pemBlock.Bytes)
	return Expect(cert.PublicKeyAlgorithm)
}
