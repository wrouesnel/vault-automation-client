package unsealer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	"github.com/wrouesnel/vault-automation-client/pkg/certutils"
	"github.com/wrouesnel/vault-automation-client/pkg/urlutil"
	"go.uber.org/zap"
)

// UnsealerCommand implements the command line interface for starting the unsealer.
type UnsealerCommand struct {
	TLSNoVerify bool     `help:"disable TLS verification"`
	TLSCAFiles  []string `help:"additional TLS CA certificate files"`

	KeySource struct {
		Name        string            `help:"source of the unseal key" default:"file" enum:"file,k8s,vault"`
		FileSource  *FileSource       `embed:"" prefix:"file." help:"Configuration for file source unsealing"`
		K8SSource   *KubernetesSource `embed:"" prefix:"k8s." help:"Configuration for kubernetes source unsealing"`
		VaultSource *VaultSource      `embed:"" prefix:"vault." help:"Configuration for Vault source unsealing"`
	} `embed:"" prefix:"key-source."`

	Initialize bool `help:"initialize the Vault instance (raft join)" default:"true"`
	Unseal     bool `help:"unseal the Vault instance" default:"true"`

	InitOptions struct {
		LeaderCACert string `help:"leader CA certificate to use when performing Raft joins. Either filepath or literal value"`
	} `embed:"" prefix:"init."`

	VaultEndpoint *url.URL      `arg:"" help:"vault HA endpoint for API access"`
	VaultInstance *url.URL      `arg:"" help:"vault instance address to monitor"`
	PollFrequency time.Duration `help:"frequency to check the Vault instance for unlocks" default:"1s"`
}

func UnsealerEntrypoint(ctx context.Context, uc *UnsealerCommand) error {
	logger := zap.L()
	instanceHTTPClient := resty.New()
	endpointHTTPClient := resty.New()

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return errors.Wrap(err, "UnsealerEntrypoint")
	}

	for _, fpath := range uc.TLSCAFiles {
		if _, err := os.Stat(fpath); err == nil {
			logger.Debug("Adding certificate from file to trusted roots", zap.String("certificate_filepath", fpath))
			certbytes, err := ioutil.ReadFile(fpath)
			if err != nil {
				return errors.Wrap(err, "UnsealerEntrypoint: reading certificates")
			}

			certs, err := certutils.LoadCertificatesFromPem(certbytes)
			if err != nil {
				return errors.Wrap(err, "UnsealerEntrypoint: loading certificates")
			}

			for _, cert := range certs {
				rootCAs.AddCert(cert)
			}
		}
	}

	var leaderCACert *x509.Certificate
	if uc.InitOptions.LeaderCACert != "" {
		certs, err := certutils.ReadCertificate(uc.InitOptions.LeaderCACert)
		if err != nil {
			return errors.Wrap(err, "leader-ca-cert could not be parsed for a certificate")
		}

		if len(certs) > 1 {
			logger.Warn("leader-ca-cert contains multiple certificates - only first will be used")
		}
		leaderCACert = certs[0]
	}

	instanceHTTPClient.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: uc.TLSNoVerify,
		RootCAs:            rootCAs,
	})

	endpointHTTPClient.SetTLSClientConfig(&tls.Config{
		InsecureSkipVerify: uc.TLSNoVerify,
		RootCAs:            rootCAs,
	})

	instanceHTTPClient.SetBaseURL(uc.VaultInstance.String())
	endpointHTTPClient.SetBaseURL(uc.VaultEndpoint.String())

	initConfig := VaultUnsealerInitializationConfig{
		Logger:         logger,
		InstanceClient: instanceHTTPClient,
		EndpointClient: endpointHTTPClient,
		URLCloner:      urlutil.CloneURL,
		Now:            time.Now,
		NewTicker:      time.NewTicker,
	}

	unsealer, err := NewVaultUnsealer(initConfig)
	if err != nil {
		return errors.Wrap(err, "NewVaultUnsealer")
	}

	var unsealKeySource KeySource
	switch uc.KeySource.Name {
	case KeySourceFile:
		unsealKeySource = uc.KeySource.FileSource
	case KeySourceKubernetes:
		unsealKeySource = uc.KeySource.K8SSource
	case KeySourceVault:
		unsealKeySource = uc.KeySource.VaultSource
	default:
		panic(fmt.Sprintf("%s is not a recognized source name", uc.KeySource.Name))
	}

	errCh := unsealer.Start(VaultUnsealerConfig{
		PollFrequency:   uc.PollFrequency,
		UnsealKeySource: unsealKeySource,
		CanUnseal:       uc.Unseal,
		CanInitialize:   uc.Initialize,
		LeaderCACert:    leaderCACert,
	})

	logger.Info("Unsealer started")
	<-ctx.Done()
	unsealer.Stop()
	err = <-errCh
	logger.Info("Unsealed finished", zap.Error(err))

	return nil
}
