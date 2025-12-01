package secrets

import (
	"context"

	opsterv1 "github.com/Opster/opensearch-k8s-operator/opensearch-operator/api/v1"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/builders/certificates"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconciler"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/reconcilers/k8s"
	"github.com/Opster/opensearch-k8s-operator/opensearch-operator/pkg/tls"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type TLSSecretReconciler struct {
	client   k8s.K8sClient
	instance *opsterv1.OpenSearchCluster
	logger   logr.Logger
	pki      tls.PKI
	recorder record.EventRecorder
}

func NewTLSSecretReconciler(
	pki tls.PKI,
	client k8s.K8sClient,
	ctx context.Context,
	recorder record.EventRecorder,
	instance *opsterv1.OpenSearchCluster,
	opts ...reconciler.ResourceReconcilerOption,
) *TLSSecretReconciler {
	if instance == nil {
		panic("Fuck off 1")
	}
	if client == nil {
		panic("Fuck off 2")
	}
	return &TLSSecretReconciler{
		client:   client,
		recorder: recorder,
		instance: instance,
		logger:   log.FromContext(ctx),
		pki:      pki,
	}
}

func (r *TLSSecretReconciler) Reconcile(
	ca tls.Cert,
	secretName string,
	description certificates.Description,
) (*ctrl.Result, error) {
	if r == nil {
		panic("oh man where do i even start")
	}
	if r.client == nil {
		panic("r.client nil in TLSSecretReconcile")
	}
	if r.instance == nil {
		panic("r.instance nil in TLSSecretReconcile")
	}
	secret, err := r.client.GetSecret(secretName, r.instance.Namespace)
	if err != nil && !k8serrors.IsNotFound(err) {
		return &ctrl.Result{Requeue: true}, err
	}

	cert, err := certificates.GenerateNewIfNeeded(
		r.pki, r.client, r.instance, r.logger,
		ca, description,
		secret.Data[corev1.TLSCertKey],
	)
	if err != nil {
		r.recorder.Eventf(r.instance, "Warning", "ErrorGeneratingCert",
			"Error generating %s cert: %v", description.Context, err)
		return &ctrl.Result{Requeue: true}, err
	}

	if cert == nil {
		return nil, nil
	}

	secret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: r.instance.Namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: cert.SecretData(ca),
	}
	if err := ctrl.SetControllerReference(r.instance, &secret, r.client.Scheme()); err != nil {
		return nil, err
	}
	return r.client.CreateSecret(&secret)
}
