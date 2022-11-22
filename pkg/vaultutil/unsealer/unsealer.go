package unsealer

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/ldez/mimetype"
	"github.com/pkg/errors"
	"github.com/wrouesnel/vault-automation-client/pkg/certutils"
	"go.uber.org/zap"
	"go.withmatt.com/httpheaders"
)

//type KeySource string
//
//const (
//	// KeySourceFile should mostly not be used, and is intended when the key source is a file on disk.
//	KeySourceFile KeySource = "file"
//	// KeySourceK8Secret indicates the key source is a Kubernetes cluster secret entry
//	KeySourceK8Secret KeySource = "k8s-secret"
//	// KeySourceVault is used when the key source is a key in a vault cluster.
//	KeySourceVault KeySource = "vault"
//)

//type KeySource struct {
//	Vehicles    []interface{}     `json:"-"`
//	RawVehicles []json.RawMessage `json:"vehicles"`
//}
//
//type KeySourceSpecFile struct {
//	FilePath string `json:"filepath"`
//}
//
//type KeySourceSpecK8Secret struct {
//	ClusterAddr    *url.URL `json:"cluster_addr"`
//	ServiceAccount string   `json:"service_account"`
//}
//
//type KeySourceSpecVault struct {
//	VaultClusterAddr *url.URL `json:"vault_cluster_addr"`
//	AuthPath             string   `json:"path"`
//	Key              string   `json:"key"`
//}

// KeySource interfaces implement the method to get a key source.
type KeySource interface {
	GetUnsealKey() (string, error)
}

type VaultUnsealerConfig struct {
	PollFrequency   time.Duration
	UnsealKeySource KeySource
	// CanInitialize means this agent should try and initialize uninitialized instances
	CanInitialize bool
	// CanUnseal means this agent should try and unseal sealed instances
	CanUnseal bool
	// LeaderCACert is the certificate used with the Raft leader.
	// If nil, then it is not sent and system CA certs will be used.
	LeaderCACert *x509.Certificate
}

type VaultUnsealerInitializationError struct {
	msg string
}

func (v VaultUnsealerInitializationError) Error() string {
	return fmt.Sprintf("vault unsealer init: %s", v.msg)
}

type VaultUnsealerConfigError struct {
	msg string
}

func (v VaultUnsealerConfigError) Error() string {
	return fmt.Sprintf("vault unsealer config: %s", v.msg)
}

type VaultUnsealerOperationError struct {
	msg string
}

func (v VaultUnsealerOperationError) Error() string {
	return fmt.Sprintf("vault unsealer operation: %s", v.msg)
}

// VaultUnsealer implements a watcher which will attempt to unseal a targeted Vault instance.
type VaultUnsealer interface {
	Start(config VaultUnsealerConfig) chan error
	Stop()
}

// VaultUnsealerInitializationConfig provides initialization parameters for the Vault Unsealer.
type VaultUnsealerInitializationConfig struct {
	// Logger is the *zap.Logger to use
	Logger *zap.Logger
	// InstanceClient is the resty Client instance for contacting the Vault Instance
	InstanceClient *resty.Client
	// EndpointClient is the resty Client instance to use for contacting the Vault Endpoint
	EndpointClient *resty.Client

	// URLCloner function for copying URLs safely
	URLCloner func(url *url.URL) *url.URL
	// Now function for getting time
	Now func() time.Time
	// NewTimer function for creating timers
	NewTicker func(duration time.Duration) *time.Ticker
}

// NewVaultUnsealer initializes a new VaultUnsealer and validates it's configuration.
func NewVaultUnsealer(config VaultUnsealerInitializationConfig) (VaultUnsealer, error) {
	if config.Logger == nil {
		return nil, &VaultUnsealerInitializationError{"no logger provided"}
	}

	if config.InstanceClient == nil {
		return nil, &VaultUnsealerInitializationError{"no httpClient provided"}
	}

	return &vaultUnsealer{
		config:                            nil,
		exitCh:                            make(chan struct{}),
		VaultUnsealerInitializationConfig: config,
	}, nil
}

// vaultUnsealer.
type vaultUnsealer struct {
	// configCh receives configuration when SetConfig is called
	config *VaultUnsealerConfig
	exitCh chan struct{}
	VaultUnsealerInitializationConfig
}

func (vu *vaultUnsealer) log() *zap.Logger {
	return vu.Logger
}

func (vu *vaultUnsealer) setConfig(config VaultUnsealerConfig) error {
	vu.config = &config

	if vu.config.UnsealKeySource == nil {
		vu.log().Warn("UnsealKeySource is nil - no unsealing actions will succeed!")
	}

	return nil
}

func (vu *vaultUnsealer) checkVaultInit() bool {
	vu.log().Debug("Checking if Vault is initialized")
	resp, err := vu.InstanceClient.R().Get("/v1/sys/init")
	if err != nil {
		vu.log().Warn("Error while checking initialization status of cluster", zap.Error(err))
		return false
	}

	jsonResp := map[string]interface{}{}
	if err := json.Unmarshal(resp.Body(), &jsonResp); err != nil {
		vu.log().Error("Could not unmarshal response from Vault instance", zap.Error(err))
		return false
	}

	if initialized, ok := jsonResp["initialized"].(bool); !ok {
		vu.log().Error("Unexpected type (not bool) from /v1/sys/init")
		return false
	} else if initialized == false {
		vu.log().Warn("Vault instance is not initialized. Unsealing cannot proceed.")
		return false
	}
	vu.log().Debug("Vault is initialized")
	return true
}

func (vu *vaultUnsealer) doVaultInit() error {
	vu.log().Info("Attempting to initialize uninitialized Vault instance")

	vu.log().Debug("Discovering leader")
	resp, jsonResp, isError, err := vaultRequest(vu.EndpointClient.R().Get("/v1/sys/leader"))
	if err != nil {
		vu.log().Error("HTTP request to find leader instance failed", zap.Error(err))
		return errors.Wrap(err, "doVaultInit:request")
	}

	if isError {
		vu.log().Error("Error while discovering leader",
			zap.Int("status_code", resp.StatusCode()),
			zap.String("status_msg", resp.Status()),
			zap.Strings("errors", errorResponse(jsonResp)))
		return &VaultUnsealerOperationError{msg: "leader discovery failed"}
	}

	if _, found := jsonResp["leader_address"]; !found {
		vu.log().Error("leader_address not in response - is this an HA Raft cluster?")
		return &VaultUnsealerOperationError{msg: "leader_address not in response"}
	}

	leaderAddress, ok := jsonResp["leader_address"].(string)
	if !ok {
		vu.log().Error("Unexpected type for leader_address - expected string", zap.String("type", fmt.Sprintf("%T", jsonResp["leader_address"])))
		return &VaultUnsealerOperationError{msg: "unexpected type for leader_address"}
	}

	vu.log().Info("Discovered raft leader address successfully", zap.String("leader_address", leaderAddress))

	vu.log().Info("Attempting to join cluster")
	joinRequest := map[string]interface{}{
		"leader_api_addr": leaderAddress,
	}
	if vu.config.LeaderCACert != nil {
		joinRequest["leader_ca_cert"] = certutils.EncodeX509ToPem(vu.config.LeaderCACert)
	}

	resp, jsonResp, isError, err = vaultRequest(vu.InstanceClient.R().SetBody(joinRequest).Put("/v1/sys/storage/raft/join"))
	if err != nil {
		vu.log().Error("HTTP request to join Raft cluster failed", zap.Error(err))
		return errors.Wrap(err, "doVaultInit: joining cluster")
	}

	if isError {
		vu.log().Error("Error while trying to join the Raft cluster",
			zap.Int("status_code", resp.StatusCode()),
			zap.String("status_msg", resp.Status()),
			zap.Strings("errors", errorResponse(jsonResp)))
		return &VaultUnsealerOperationError{msg: "raft join failed"}
	}

	vu.log().Info("Raft join request sent")
	return nil
}

// checkVaultSealStatus checks if Vault is sealed. It will return false for error cases where the status cannot be
// determined after logging the error.
func (vu *vaultUnsealer) checkVaultSealStatus() (bool, error) {
	vu.log().Debug("Checking Vault seal-status")
	resp, err := vu.InstanceClient.R().Get("/v1/sys/seal-status")
	if err != nil {
		vu.log().Warn("Error while checking initialization status of cluster", zap.Error(err))
		return false, errors.Wrap(err, "checkVaultSealStatus: error contacting Vault")
	}

	jsonResp := map[string]interface{}{}
	if err := json.Unmarshal(resp.Body(), &jsonResp); err != nil {
		vu.log().Error("Could not unmarshal response from Vault instance", zap.Error(err))
		return false, errors.Wrap(err, "checkVaultSealStatus: error unmarshalling response")
	}

	sealed, ok := jsonResp["sealed"].(bool)
	if !ok {
		vu.log().Error("Unexpected type (not bool) from /v1/sys/seal-status.sealed")
		return false, &VaultUnsealerOperationError{msg: "non-bool response for sealed"}
	}
	vu.log().Debug("Vault Seal Status", zap.Bool("seal_status", sealed))

	return sealed, nil
}

func (vu *vaultUnsealer) doVaultUnseal() error {
	vu.log().Info("Attempt to get unseal key")
	if vu.config.UnsealKeySource == nil {
		vu.log().Warn("Vault sealed but no unseal key source specified - cannot unseal")
		return &VaultUnsealerOperationError{msg: "no unseal key source provided"}
	}
	unsealKey, err := vu.config.UnsealKeySource.GetUnsealKey()
	if err != nil {
		vu.log().Error("Get unseal key failed", zap.Error(err))
		return errors.Wrap(err, "doVaultUnseal: GetUnsealKey failed")
	}

	requestBody := map[string]string{
		"key": unsealKey,
	}

	vu.log().Info("Sending unseal request")
	resp, err := vu.InstanceClient.R().SetHeader(httpheaders.ContentType, mimetype.ApplicationJSON).SetBody(requestBody).Post("/v1/sys/unseal")
	if err != nil {
		vu.log().Error("Error sending unseal request", zap.Error(err))
		return errors.Wrap(err, "doVaultUnseal: unseal request error")
	}

	if resp.IsError() {
		vu.log().Error("Error response from unseal request")
		return &VaultUnsealerOperationError{msg: "unseal request responded with error"}
	}

	vu.log().Info("Successfully sent unseal request.")
	return nil
}

func (vu *vaultUnsealer) unsealPoll() {
	initialized := vu.checkVaultInit()
	if !initialized && !vu.config.CanInitialize {
		vu.log().Warn("Vault not initialized and this agent is configured not to initialize it.", zap.Bool("can_initialize", vu.config.CanInitialize))
		return
	}

	if !initialized {
		if err := vu.doVaultInit(); err != nil {
			vu.log().Warn("Error while trying to join Raft node to cluster")
			// We fail out here, since nothing else will succeed. Retry again in a bit.
			return
		}
	}

	sealed, err := vu.checkVaultSealStatus()
	if err != nil {
		vu.log().Warn("Error while checking seal status. Seal status undetermined.")
		return
	}

	if sealed && !vu.config.CanUnseal {
		vu.log().Warn("Vault sealed and this agent is configured not to unseal it.", zap.Bool("can_unseal", vu.config.CanUnseal))
	}

	if !sealed {
		vu.log().Debug("Vault is unsealed. No action necessary.")
		return
	} else if !vu.config.CanUnseal {
		vu.log().Warn("Vault is sealed but agent is configured to not unseal")
		return
	}

	vu.log().Info("Vault instance is sealed. Attempting to unseal it.")
	if err := vu.doVaultUnseal(); err != nil {
		vu.log().Error("Vault Unseal operation FAILED.", zap.Error(err))
		return
	}
}

// Start initializes the Vault unsealer to watch the instance.
func (vu *vaultUnsealer) Start(config VaultUnsealerConfig) chan error {
	errCh := make(chan error)
	go func() {

		if err := vu.setConfig(config); err != nil {
			errCh <- err
			return
		}

		ticker := vu.NewTicker(vu.config.PollFrequency)

	mainLoop:
		for {
			select {
			case <-vu.exitCh:
				vu.log().Info("Shutdown requested")
				break mainLoop

			case t := <-ticker.C:
				// Timer fired.
				vu.log().Debug("Tick fired. Do next poll.", zap.Time("trigger_time", t),
					zap.Time("response_time", vu.Now()))
				vu.unsealPoll()
			}
		}

		vu.log().Debug("Shutdown complete")
		ticker.Stop()
		errCh <- nil
		close(errCh)
	}()

	return errCh
}

func (vu *vaultUnsealer) Stop() {
	select {
	case <-vu.exitCh:
		return
	default:
		close(vu.exitCh)
	}
}
