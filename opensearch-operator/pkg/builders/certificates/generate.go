package certificates

import (
	"fmt"
	"time"

	v1 "github.com/Opster/opensearch-k8s-operator/opensearch-operator/api/v1"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/helpers"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconcilers/k8s"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/tls"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ContextType string

const (
	ContextTransport  ContextType = "transport"
	ContextHttp       ContextType = "http"
	ContextAdmin      ContextType = "admin"
	ContextDashboards ContextType = "dashboards"
	ContextBootstrap  ContextType = "bootstrap"
)

type Description struct {
	Context    ContextType
	CommonName string
	DnsNames   []string
	Config     v1.TlsCertificateConfig
}

func GenerateNewIfNeeded(
	pki tls.PKI,
	k8sClient k8s.K8sClient,
	instance *v1.OpenSearchCluster,
	logger logr.Logger,
	ca tls.Cert,
	desc Description,
	existingCertData []byte,
) (tls.Cert, error) {
	generateNeeded := generateNeeded(instance, logger, ca, desc, existingCertData)

	if generateNeeded {
		return GenerateNew(pki, k8sClient, instance, logger, ca, desc)
	}

	return nil, nil
}

func generateNeeded(
	instance *v1.OpenSearchCluster,
	logger logr.Logger,
	ca tls.Cert,
	desc Description,
	existingCertData []byte,
) bool {
	if existingCertData == nil {
		return true
	}

	certConfig := applyConfigDefaults(desc)

	timeLeftGauge := helpers.TlsCertificateDaysRemaining.WithLabelValues(instance.Namespace,
		instance.Name, string(desc.Context), desc.CommonName)
	validator, err := tls.NewCertValidator(
		existingCertData,
		timeLeftGauge,
		tls.WithExpiryThreshold(time.Duration(24*certConfig.RotateDaysBeforeExpiry)*time.Hour),
	)
	if err != nil {
		logger.Error(err, "Failed to parse "+string(desc.Context)+" certificate for renewal check - not renewing", "interface",
			desc.Context, "certificateName", desc.CommonName)
		return false
	}

	if certConfig.RotateDaysBeforeExpiry != -1 {
		if validator.IsExpiringSoon() {
			logger.Info(string(desc.Context)+" certificate is expiring within the threshold and will be renewed",
				"interface", desc.Context, "certificateName", desc.CommonName)
			return true
		}
	}

	isSignedByOurCa, err := validator.IsSignedByCA(ca)
	if err != nil {
		logger.Error(err, "Failed to verify that "+string(desc.Context)+" cert is signed by CA  - not renewing", "interface",
			desc.Context, "certificateName", desc.CommonName)
		return false
	}

	if !isSignedByOurCa {
		logger.Info(string(desc.Context)+" certificate is not signed by the correct CA and will be regenerated",
			"interface", desc.Context, "certificateName", desc.CommonName)
		return true
	}

	return false
}

func GenerateNew(
	pki tls.PKI,
	k8sClient k8s.K8sClient,
	instance *v1.OpenSearchCluster,
	logger logr.Logger,
	ca tls.Cert,
	desc Description,
) (tls.Cert, error) {
	clusterName := instance.Name

	certConfig := applyConfigDefaults(desc)

	logger.Info(fmt.Sprintf("Generating %s certificate for %s", desc.Context, desc.CommonName))

	nodeCert, err := ca.CreateAndSignCertificate(desc.CommonName, clusterName,
		desc.DnsNames, certConfig.Duration.Duration, certConfig.KeyGenMethod)
	if err != nil {
		logger.Error(err, "Failed to create certificate", "interface",
			desc.Context, "certificateName", desc.CommonName)
		return nil, err
	}

	logger.Info(fmt.Sprintf("Generated %s certificate for %s", desc.Context, desc.CommonName))
	return nodeCert, nil
}

func applyConfigDefaults(desc Description) v1.TlsCertificateConfig {
	config := desc.Config

	switch desc.Context {
	case ContextHttp:
		if config.KeyGenMethod == "" {
			config.KeyGenMethod = tls.KeyGenMethodRSA4096
		}
		break
	case ContextAdmin:
		if config.RotateDaysBeforeExpiry == 0 {
			config.RotateDaysBeforeExpiry = 5
		}
		fallthrough
	case ContextTransport:
		fallthrough
	case ContextDashboards:
		fallthrough
	case ContextBootstrap:
		if config.KeyGenMethod == "" {
			// these are used internally to the cluster and so we ought to be
			// able to use any algorithm we want -- use a fast one
			config.KeyGenMethod = tls.KeyGenMethodEd25519
		}
		break
	default:
		panic("unrecognized certDescription.certContext value")
	}

	if config.Duration == nil {
		config.Duration = &metav1.Duration{Duration: 365 * 24 * time.Hour}
	}

	return config
}
