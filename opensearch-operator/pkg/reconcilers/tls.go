package reconcilers

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/Masterminds/semver"
	opsterv1 "github.com/Opster/opensearch-k8s-operator/opensearch-operator/api/v1"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/builders"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/builders/certificates"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/helpers"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconciler"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconcilers/k8s"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconcilers/secrets"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/tls"
	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type TLSReconciler struct {
	client              k8s.K8sClient
	reconcilerContext   *ReconcilerContext
	instance            *opsterv1.OpenSearchCluster
	logger              logr.Logger
	pki                 tls.PKI
	recorder            record.EventRecorder
	tlsSecretReconciler *secrets.TLSSecretReconciler
}

func NewTLSReconciler(
	client client.Client,
	ctx context.Context,
	recorder record.EventRecorder,
	reconcilerContext *ReconcilerContext,
	instance *opsterv1.OpenSearchCluster,
	opts ...reconciler.ResourceReconcilerOption,
) *TLSReconciler {
	k8sClient := k8s.NewK8sClient(client, ctx, append(opts, reconciler.WithLog(log.FromContext(ctx).WithValues("reconciler", "tls")))...)
	pki := tls.NewPKI()
	return &TLSReconciler{
		client:            k8sClient,
		recorder:          recorder,
		reconcilerContext: reconcilerContext,
		instance:          instance,
		logger:            log.FromContext(ctx),
		pki:               pki,
		tlsSecretReconciler: secrets.NewTLSSecretReconciler(
			pki, k8sClient, ctx, recorder, instance,
		),
	}
}

const (
	CaCertKey                     = "ca.crt"
	SimultaneousCertGenerationCap = 8
)

func (r *TLSReconciler) Reconcile() (ctrl.Result, error) {
	if r.instance.Spec.General.DisableSSL {
		r.logger.Info("HTTP TLS is disabled. Disabling SSL for HTTP layer")
		r.reconcilerContext.AddConfig("plugins.security.ssl.http.enabled", "false")
		return ctrl.Result{}, nil
	}

	if r.instance.Spec.Security == nil || r.instance.Spec.Security.Tls == nil {
		r.logger.Info("No security specified. Not doing anything")
		return ctrl.Result{}, nil
	}

	tlsConfig := r.instance.Spec.Security.Tls
	overallResult := reconciler.CombinedResult{}

	if tlsConfig.Transport != nil {
		res, err := r.handleTransport()
		if err != nil {
			r.logger.Error(err, "Failed to reconcile transport certificates")
			r.recorder.Eventf(r.instance, "Warning", "ReconcileCertsError", "Couldn't reconcile transport certs: %v", err)
		}
		overallResult.Combine(res, err)
	}
	if tlsConfig.Http != nil {
		res, err := r.handleHttp()
		if err != nil {
			r.logger.Error(err, "Failed to reconcile http certificates")
			r.recorder.Eventf(r.instance, "Warning", "ReconcileCertsError", "Couldn't reconcile http certs: %v", err)
		}
		overallResult.Combine(res, err)
	}
	if r.shouldReconcileAdminCert() {
		res, err := r.handleAdminCertificate()
		if err != nil {
			r.logger.Error(err, "Failed to reconcile admin certificate")
			r.recorder.Eventf(r.instance, "Warning", "ReconcileCertsError", "Couldn't reconcile admin cert: %v", err)
		}
		overallResult.Combine(res, err)
	}

	return overallResult.Result, overallResult.Err
}

func (r *TLSReconciler) handleTransport() (*ctrl.Result, error) {
	config := r.instance.Spec.Security.Tls.Transport

	if config.Generate {
		return r.handleTransportGenerate()
	} else {
		return r.handleTransportExistingCerts()
	}
}

func (r *TLSReconciler) handleAdminCertificate() (*ctrl.Result, error) {
	tlsConfig := r.instance.Spec.Security.Tls.Http
	clusterName := r.instance.Name
	secretName := r.instance.Name + "-admin-cert"

	var certDN string
	if tlsConfig.Generate || (r.instance.Spec.Security.Config != nil && r.instance.Spec.Security.Config.AdminSecret.Name == "") {
		ca, err := certificates.GetReferencedCaCertOrDefault(r.pki, r.client, r.instance, r.adminCAConfig())
		if err != nil {
			return nil, err
		}

		res, err := r.tlsSecretReconciler.Reconcile(
			ca,
			secretName,
			certificates.Description{
				Context:    certificates.ContextAdmin,
				CommonName: "admin",
				DnsNames:   nil,
				Config:     tlsConfig.TlsCertificateConfig,
			},
		)
		if err != nil || !res.IsZero() {
			return res, err
		}
		certDN = fmt.Sprintf("CN=admin,OU=%s", clusterName)

	} else {
		certDN = strings.Join(tlsConfig.AdminDn, "\",\"")
	}

	r.reconcilerContext.AddConfig("plugins.security.authcz.admin_dn", fmt.Sprintf("[\"%s\"]", certDN))
	return nil, nil
}

func (r *TLSReconciler) checkVersionConstraint(constraint string, defaultOnError bool, errMsg string) bool {
	versionConstraint, err := semver.NewConstraint(constraint)
	if err != nil {
		panic(err)
	}

	version, err := semver.NewVersion(r.instance.Spec.General.Version)
	if err != nil {
		r.logger.Error(err, errMsg)
		return defaultOnError
	}
	return versionConstraint.Check(version)
}

func (r *TLSReconciler) securityChangeVersion() bool {
	return r.checkVersionConstraint(
		">=2.0.0",
		true,
		"unable to parse version, assuming >= 2.0.0",
	)
}

func (r *TLSReconciler) supportsHotReload() bool {
	return r.checkVersionConstraint(
		">=2.19.1",
		false,
		"unable to parse version for hot reload check, assuming not supported",
	)
}

func (r *TLSReconciler) shouldReconcileAdminCert() bool {
	if r.securityChangeVersion() {
		return r.instance.Spec.Security.Tls.Http != nil && r.instance.Spec.Security.Tls.Transport != nil
	}
	return r.instance.Spec.Security.Tls.Transport != nil
}

func (r *TLSReconciler) adminCAConfig() corev1.LocalObjectReference {
	if r.securityChangeVersion() {
		return r.instance.Spec.Security.Tls.Http.CaSecret
	}
	return r.instance.Spec.Security.Tls.Transport.CaSecret
}

func (r *TLSReconciler) handleTransportGenerate() (*ctrl.Result, error) {
	namespace := r.instance.Namespace
	clusterName := r.instance.Name
	nodeSecretName := clusterName + "-transport-cert"
	config := r.instance.Spec.Security.Tls.Transport
	generatePerNode := config.PerNode

	ca, err := certificates.GetReferencedCaCertOrDefault(r.pki, r.client, r.instance, config.CaSecret)
	if err != nil {
		return &ctrl.Result{Requeue: true}, err
	}

	nodeSecret, err := r.client.GetSecret(nodeSecretName, namespace)
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			r.logger.Error(err, "Failed to get secret for transport certificate(s)")
			return &ctrl.Result{Requeue: true}, err
		}

		nodeSecret.ObjectMeta = metav1.ObjectMeta{Name: nodeSecretName, Namespace: namespace}
		if generatePerNode {
			nodeSecret.Data = make(map[string][]byte)
		} else {
			nodeSecret.Type = corev1.SecretTypeTLS
		}

		if err := ctrl.SetControllerReference(r.instance, &nodeSecret, r.client.Scheme()); err != nil {
			return &ctrl.Result{Requeue: true}, err
		}
	}

	if !generatePerNode {
		newCertData, err := certificates.GenerateNewIfNeeded(
			r.pki, r.client, r.instance, r.logger,
			ca,
			certificates.Description{
				Context:    certificates.ContextTransport,
				CommonName: clusterName,
				DnsNames: []string{
					clusterName,
					fmt.Sprintf("%s.%s", clusterName, namespace),
					fmt.Sprintf("%s.%s.svc", clusterName, namespace),
					fmt.Sprintf("%s.%s.svc.%s", clusterName, namespace, helpers.ClusterDnsBase()),
				},
				Config: config.TlsCertificateConfig,
			},
			nodeSecret.Data[corev1.TLSCertKey],
		)
		if err != nil {
			r.recorder.Eventf(r.instance, "Warning", "ErrorGeneratingCert",
				"Error generating transport cert: %v", err)
			return nil, err
		}
		if newCertData != nil {
			nodeSecret.Data = newCertData.SecretData(ca)
		}

	} else {
		if nodeSecret.Data == nil {
			// covers both the case where nodeSecret is new, or nodeSecret existed
			// but was nil for some unknown reason (maybe a past failure)
			nodeSecret.Data = make(map[string][]byte)
		}
		nodeSecret.Data[CaCertKey] = ca.CertData()

		eg, _ := errgroup.WithContext(r.client.Context())
		eg.SetLimit(min(SimultaneousCertGenerationCap, runtime.GOMAXPROCS(0)))
		secretMutex := sync.Mutex{}

		for _, nodePool := range r.instance.Spec.NodePools {
			for i := 0; i < int(nodePool.Replicas); i++ {
				podName := fmt.Sprintf("%s-%s-%d", clusterName, nodePool.Component, i)

				r.goReconcileTransportCertForOneNode(podName, &nodeSecret,
					&secretMutex, eg, ca, config.TlsCertificateConfig)
			}
		}

		if !r.instance.Status.Initialized {
			bootstrapPodName := builders.BootstrapPodName(r.instance)
			r.goReconcileTransportCertForOneNode(bootstrapPodName, &nodeSecret,
				&secretMutex, eg, ca, config.TlsCertificateConfig)
		}

		err := eg.Wait()
		if err != nil {
			r.logger.Error(err, "Not all required certificates could be created")
			return nil, err
		}
	}

	res, err := r.client.CreateSecret(&nodeSecret)
	if err != nil || !res.IsZero() {
		return res, nil
	}

	// Tell cluster controller to mount secrets
	volume := corev1.Volume{Name: "transport-cert", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: nodeSecretName}}}
	r.reconcilerContext.Volumes = append(r.reconcilerContext.Volumes, volume)
	mount := corev1.VolumeMount{Name: "transport-cert", MountPath: "/usr/share/opensearch/config/tls-transport"}
	r.reconcilerContext.VolumeMounts = append(r.reconcilerContext.VolumeMounts, mount)

	// Extend opensearch.yml
	if generatePerNode {
		r.reconcilerContext.AddConfig("plugins.security.nodes_dn", fmt.Sprintf("[\"CN=%s-*,OU=%s\"]", clusterName, clusterName))
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemcert_filepath", "tls-transport/${HOSTNAME}.crt")
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemkey_filepath", "tls-transport/${HOSTNAME}.key")
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.enforce_hostname_verification", "true")
	} else {
		r.reconcilerContext.AddConfig("plugins.security.nodes_dn", fmt.Sprintf("[\"CN=%s,OU=%s\"]", clusterName, clusterName))
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemcert_filepath", fmt.Sprintf("tls-transport/%s", corev1.TLSCertKey))
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemkey_filepath", fmt.Sprintf("tls-transport/%s", corev1.TLSPrivateKeyKey))
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.enforce_hostname_verification", "false")
	}

	r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemtrustedcas_filepath", fmt.Sprintf("tls-transport/%s", CaCertKey))

	return nil, nil
}

func (r *TLSReconciler) goReconcileTransportCertForOneNode(
	podName string,
	secret *corev1.Secret,
	secretMutex *sync.Mutex,
	eg *errgroup.Group,
	ca tls.Cert,
	config opsterv1.TlsCertificateConfig,
) {
	clusterName := r.instance.Name
	namespace := r.instance.Namespace

	certName := fmt.Sprintf("%s.crt", podName)
	keyName := fmt.Sprintf("%s.key", podName)
	secretMutex.Lock()
	certData := secret.Data[certName]
	_, keyExists := secret.Data[keyName]
	secretMutex.Unlock()
	if certData != nil && !keyExists {
		r.logger.Info("Node certificate exists but has no key, forcing regeneration",
			"interface", "transport", "node", podName)
		certData = nil
	}
	dnsNames := []string{
		podName,
		clusterName,
		builders.DiscoveryServiceName(r.instance),
		fmt.Sprintf("%s.%s", podName, clusterName),
		fmt.Sprintf("%s.%s", clusterName, namespace),
		fmt.Sprintf("%s.%s.%s", podName, clusterName, namespace),
		fmt.Sprintf("%s.%s.svc", clusterName, namespace),
		fmt.Sprintf("%s.%s.%s.svc", podName, clusterName, namespace),
		fmt.Sprintf("%s.%s.svc.%s", clusterName, namespace, helpers.ClusterDnsBase()),
		fmt.Sprintf("%s.%s.%s.svc.%s", podName, clusterName, namespace,
			helpers.ClusterDnsBase()),
	}

	eg.Go(func() error {
		newCertData, err := certificates.GenerateNewIfNeeded(
			r.pki, r.client, r.instance, r.logger,
			ca,
			certificates.Description{
				Context:    certificates.ContextTransport,
				CommonName: podName,
				DnsNames:   dnsNames,
				Config:     config,
			},
			certData,
		)
		if err != nil {
			r.recorder.Eventf(r.instance, "Warning", "ErrorGeneratingCert",
				"Error generating transport cert: %v", err)
			return err
		}
		if newCertData != nil {
			secretMutex.Lock()
			secret.Data[certName] = newCertData.CertData()
			secret.Data[keyName] = newCertData.KeyData()
			secretMutex.Unlock()
		}
		return nil
	})
}

func (r *TLSReconciler) handleTransportExistingCerts() (*ctrl.Result, error) {
	tlsConfig := r.instance.Spec.Security.Tls.Transport
	if tlsConfig.Secret.Name == "" {
		err := errors.New("missing secret in spec")
		r.logger.Error(err, "Not all secrets for transport provided")
		//		r.recorder.Event(r.instance, "Warning", "Security", "Notice - Not all secrets for transport provided")
		return nil, err
	}

	if tlsConfig.PerNode {
		mountFolder("transport", "certs", tlsConfig.Secret.Name, r.reconcilerContext)
		// Extend opensearch.yml
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemcert_filepath", "tls-transport/${HOSTNAME}.crt")
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemkey_filepath", "tls-transport/${HOSTNAME}.key")
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.enforce_hostname_verification", "true")
	} else {
		// Implement new mounting logic based on CaSecret.Name configuration
		switch name := tlsConfig.CaSecret.Name; name {
		case "":
			// If CaSecret.Name is empty, mount Secret.Name as a directory
			mountFolder("transport", "certs", tlsConfig.Secret.Name, r.reconcilerContext)
		case tlsConfig.Secret.Name:
			// If CaSecret.Name is same as Secret.Name, mount only Secret.Name as a directory
			mountFolder("transport", "certs", tlsConfig.Secret.Name, r.reconcilerContext)
		default:
			// If CaSecret.Name is different from Secret.Name, mount both secrets as directories
			// Mount Secret.Name as tls-transport/
			mountFolder("transport", "certs", tlsConfig.Secret.Name, r.reconcilerContext)
			// Mount CaSecret.Name as tls-transport-ca/
			mountFolder("transport", "ca", tlsConfig.CaSecret.Name, r.reconcilerContext)
		}

		// Extend opensearch.yml with appropriate file paths based on mounting logic
		if tlsConfig.CaSecret.Name == "" || tlsConfig.CaSecret.Name == tlsConfig.Secret.Name {
			// Single secret mounted as directory
			r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemcert_filepath", fmt.Sprintf("tls-transport/%s", corev1.TLSCertKey))
			r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemkey_filepath", fmt.Sprintf("tls-transport/%s", corev1.TLSPrivateKeyKey))
			r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemtrustedcas_filepath", fmt.Sprintf("tls-transport/%s", CaCertKey))
		} else {
			// Separate secrets mounted as directories
			r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemcert_filepath", fmt.Sprintf("tls-transport/%s", corev1.TLSCertKey))
			r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemkey_filepath", fmt.Sprintf("tls-transport/%s", corev1.TLSPrivateKeyKey))
			r.reconcilerContext.AddConfig("plugins.security.ssl.transport.pemtrustedcas_filepath", fmt.Sprintf("tls-transport-ca/%s", CaCertKey))
		}
		r.reconcilerContext.AddConfig("plugins.security.ssl.transport.enforce_hostname_verification", "false")

		// Enable hot reload if configured and version supports it
		if tlsConfig.EnableHotReload && r.supportsHotReload() {
			r.reconcilerContext.AddConfig("plugins.security.ssl.certificates_hot_reload.enabled", "true")
		}
	}
	dnList := strings.Join(tlsConfig.NodesDn, "\",\"")
	r.reconcilerContext.AddConfig("plugins.security.nodes_dn", fmt.Sprintf("[\"%s\"]", dnList))
	return nil, nil
}

func (r *TLSReconciler) handleHttp() (*ctrl.Result, error) {
	tlsConfig := r.instance.Spec.Security.Tls.Http
	namespace := r.instance.Namespace
	clusterName := r.instance.Name

	if tlsConfig.Generate {
		nodeSecretName := clusterName + "-http-cert"

		ca, err := certificates.GetReferencedCaCertOrDefault(r.pki, r.client, r.instance, tlsConfig.CaSecret)
		if err != nil {
			return &ctrl.Result{Requeue: true}, err
		}

		// Generate node cert and put it into secret
		// Build default DNS names
		dnsNames := []string{
			clusterName,
			r.instance.Spec.General.ServiceName,
			builders.DiscoveryServiceName(r.instance),
			fmt.Sprintf("%s.%s", clusterName, namespace),
			fmt.Sprintf("%s.%s.svc", clusterName, namespace),
			fmt.Sprintf("%s.%s.svc.%s", clusterName, namespace, helpers.ClusterDnsBase()),
		}

		// Prepend custom FQDN if provided
		if tlsConfig.CustomFQDN != nil && *tlsConfig.CustomFQDN != "" {
			dnsNames = append([]string{*tlsConfig.CustomFQDN}, dnsNames...)
		}
		res, err := r.tlsSecretReconciler.Reconcile(
			ca,
			nodeSecretName,
			certificates.Description{
				Context:    certificates.ContextHttp,
				CommonName: clusterName,
				DnsNames:   dnsNames,
				Config:     tlsConfig.TlsCertificateConfig,
			},
		)
		if err != nil || !res.IsZero() {
			return res, nil
		}

		// Tell cluster controller to mount secrets
		volume := corev1.Volume{Name: "http-cert", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: nodeSecretName}}}
		r.reconcilerContext.Volumes = append(r.reconcilerContext.Volumes, volume)
		mount := corev1.VolumeMount{Name: "http-cert", MountPath: "/usr/share/opensearch/config/tls-" + "http"}
		r.reconcilerContext.VolumeMounts = append(r.reconcilerContext.VolumeMounts, mount)

	} else {
		if tlsConfig.Secret.Name == "" {
			err := errors.New("missing secret in spec")
			r.logger.Error(err, "Not all secrets for http provided")
			//		r.recorder.Event(r.instance, "Warning", "Security", "Notice - Not all secrets for http provided")
			return &ctrl.Result{}, err
		}

		// Implement new mounting logic based on CaSecret.Name configuration
		switch name := tlsConfig.CaSecret.Name; name {
		case "":
			// If CaSecret.Name is empty, mount Secret.Name as a directory
			mountFolder("http", "certs", tlsConfig.Secret.Name, r.reconcilerContext)
		case tlsConfig.Secret.Name:
			// If CaSecret.Name is same as Secret.Name, mount only Secret.Name as a directory
			mountFolder("http", "certs", tlsConfig.Secret.Name, r.reconcilerContext)
		default:
			// If CaSecret.Name is different from Secret.Name, mount both secrets as directories
			// Mount Secret.Name as tls-http/
			mountFolder("http", "certs", tlsConfig.Secret.Name, r.reconcilerContext)
			// Mount CaSecret.Name as tls-http-ca/
			mountFolder("http", "ca", tlsConfig.CaSecret.Name, r.reconcilerContext)
		}
	}
	// Extend opensearch.yml with appropriate file paths based on mounting logic
	r.reconcilerContext.AddConfig("plugins.security.ssl.http.enabled", "true")

	// Set certificate file paths based on mounting configuration
	if tlsConfig.CaSecret.Name == "" || tlsConfig.CaSecret.Name == tlsConfig.Secret.Name {
		// Single secret mounted as directory
		r.reconcilerContext.AddConfig("plugins.security.ssl.http.pemcert_filepath", fmt.Sprintf("tls-http/%s", corev1.TLSCertKey))
		r.reconcilerContext.AddConfig("plugins.security.ssl.http.pemkey_filepath", fmt.Sprintf("tls-http/%s", corev1.TLSPrivateKeyKey))
		r.reconcilerContext.AddConfig("plugins.security.ssl.http.pemtrustedcas_filepath", fmt.Sprintf("tls-http/%s", CaCertKey))
	} else {
		// Separate secrets mounted as directories
		r.reconcilerContext.AddConfig("plugins.security.ssl.http.pemcert_filepath", fmt.Sprintf("tls-http/%s", corev1.TLSCertKey))
		r.reconcilerContext.AddConfig("plugins.security.ssl.http.pemkey_filepath", fmt.Sprintf("tls-http/%s", corev1.TLSPrivateKeyKey))
		r.reconcilerContext.AddConfig("plugins.security.ssl.http.pemtrustedcas_filepath", fmt.Sprintf("tls-http-ca/%s", CaCertKey))
	}

	// Enable hot reload if configured and version supports it
	if tlsConfig.EnableHotReload && r.supportsHotReload() {
		r.reconcilerContext.AddConfig("plugins.security.ssl.certificates_hot_reload.enabled", "true")
	}
	return nil, nil
}

func mountFolder(interfaceName string, name string, secretName string, reconcilerContext *ReconcilerContext) {
	volume := corev1.Volume{Name: interfaceName + "-" + name, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: secretName}}}
	reconcilerContext.Volumes = append(reconcilerContext.Volumes, volume)

	var mountPath string
	if name == "ca" {
		mountPath = fmt.Sprintf("/usr/share/opensearch/config/tls-%s-ca", interfaceName)
	} else {
		mountPath = fmt.Sprintf("/usr/share/opensearch/config/tls-%s", interfaceName)
	}

	mount := corev1.VolumeMount{Name: interfaceName + "-" + name, MountPath: mountPath}
	reconcilerContext.VolumeMounts = append(reconcilerContext.VolumeMounts, mount)
}

func (r *TLSReconciler) DeleteResources() (ctrl.Result, error) {
	result := reconciler.CombinedResult{}
	return result.Result, result.Err
}
