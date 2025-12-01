package certificates

import (
	v1 "github.com/Opster/opensearch-k8s-operator/opensearch-operator/api/v1"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconcilers/k8s"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/tls"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func GetReferencedCaCertOrDefault(
	pki tls.PKI,
	k8sClient k8s.K8sClient,
	instance *v1.OpenSearchCluster,
	secretReference corev1.LocalObjectReference,
) (tls.Cert, error) {
	if secretReference.Name == "" {
		return readOrGenerateCaCert(pki, k8sClient, instance)
	}

	var ca tls.Cert
	caSecret, err := k8sClient.GetSecret(secretReference.Name, instance.Namespace)
	if err != nil {
		return ca, err
	}
	data := caSecret.Data
	if _, ok := caSecret.Annotations["cert-manager.io/issuer-kind"]; ok {
		data = map[string][]byte{
			"ca.crt": caSecret.Data["tls.crt"],
			"ca.key": caSecret.Data["tls.key"],
		}
	}
	ca = pki.CAFromSecret(data)
	return ca, nil
}

func readOrGenerateCaCert(pki tls.PKI, k8sClient k8s.K8sClient, instance *v1.OpenSearchCluster) (tls.Cert, error) {
	namespace := instance.Namespace
	clusterName := instance.Name
	secretName := clusterName + "-ca"
	logger := log.FromContext(k8sClient.Context())
	var ca tls.Cert
	caSecret, err := k8sClient.GetSecret(secretName, namespace)
	if err != nil {
		// Generate CA cert and put it into secret
		logger.Info("Generating new CA certificate")
		ca, err = pki.GenerateCA(clusterName)
		if err != nil {
			logger.Error(err, "Failed to create CA")
			return ca, err
		}
		caSecret = corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: namespace}, Data: ca.SecretDataCA()}
		if err := ctrl.SetControllerReference(instance, &caSecret, k8sClient.Scheme()); err != nil {
			return ca, err
		}
		if _, err := k8sClient.CreateSecret(&caSecret); err != nil {
			logger.Error(err, "Failed to store CA in secret")
			return ca, err
		}
	} else {
		ca = pki.CAFromSecret(caSecret.Data)
	}
	return ca, nil
}
