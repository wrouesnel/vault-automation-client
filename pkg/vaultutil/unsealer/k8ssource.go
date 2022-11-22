package unsealer

import (
	"context"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesSource reads the unseal key from a K8S secret in a given cluster.
// ClusterAddr and ServiceAccount are optional - if not specified defaults to the
// current cluster and current service account if it can be loaded from the
// environment. SecretNamespace is optional will default to the current namespace
// if not specified.
type KubernetesSource struct {
	// ClusterAddr where the cluster should be accessed. If blank, the current
	// cluster is used (or the default configured in the environment).
	ClusterAddr string `mapstructure:"cluster_addr,omitempty" help:"Kubernetes API server address"`
	// Token if non-blank should be the JWT which authenticates to the cluster.
	BearerToken string `mapstructure:"bearer_token,omitempty" help:"Optional bearer token to access cluster"`
	// TLSNoVerify disabled TLS auth for connections to the Kubernetes server
	TLSNoVerify bool `mapstructure:"tls_no_verify,omitempty" help:"Disable TLS verification to cluster (not recommended)"`
	// SecretNamespace is the namespace the secret is found in
	SecretNamespace string `mapstructure:"namespace,omitempty" help:"Namespace of the secret - if blank uses current namespace"`
	// SecretName is the name of the secret
	SecretName string `mapstructure:"secret_name" help:"Name of the secret"`
	// SecretKey is the key within the secret.
	SecretKey string `mapstructure:"secret_key" help:"Key within the secret"`
}

func (k *KubernetesSource) GetUnsealKey() (string, error) {
	logger := zap.L().With(zap.String("secret_name", k.SecretName),
		zap.String("secret_key", k.SecretKey))
	logger.Debug("Checking for in-cluster config")
	config, err := rest.InClusterConfig()
	if errors.Is(err, rest.ErrNotInCluster) {
		logger.Debug("Not in cluster. Attempting to configure for external operation.")
		loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
		configOverrides := &clientcmd.ConfigOverrides{}
		kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
		config, err = kubeConfig.ClientConfig()
		if err != nil {
			logger.Error("Failed to build a local kubernetes client", zap.Error(err))
			return "", errors.Wrap(err, "all K8S client attempts failed")
		}
	}

	if k.ClusterAddr != "" {
		logger.Debug("ClusterAddr specified - setting config")
		config.Host = k.ClusterAddr
	}

	if k.BearerToken != "" {
		logger.Debug("BearerToken specified - setting config")
		config.BearerToken = k.BearerToken
	}

	config.TLSClientConfig.Insecure = k.TLSNoVerify

	logger.Debug("Build Kubernetes client")
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Error("Failed to build kubernetes client", zap.Error(err))
		return "", errors.Wrap(err, "GetUnsealKey:kubernetes.NewForConfig")
	}

	core := client.CoreV1()
	secrets := core.Secrets(k.SecretNamespace)

	secret, err := secrets.Get(context.Background(), k.SecretName, metav1.GetOptions{})
	if err != nil {
		logger.Error("Failed to retrieve secret", zap.Error(err))
		return "", errors.Wrap(err, "GetUnsealKey:secrets.Get")
	}

	logger.Info("Secret retrieved",
		zap.String("resource_version", secret.ResourceVersion))

	unsealKey, ok := secret.StringData[k.SecretKey]
	if !ok {
		logger.Error("SecretKey not found in Secret")
		return "", &KeySourceErr{msg: "SecretKey not found in Secret"}
	}

	return unsealKey, nil
}
