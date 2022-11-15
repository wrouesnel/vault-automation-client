package unsealer

// VaultSource retreives the unseal key from a path in Hashicorp Vault
// This source would be used in an HA mode where there's a common endpoint
// which will find a functional Vault instance to retrieve the key from.
type VaultSource struct {
	VaultAddr string `mapstructure:"vault_addr,required"`

	// AuthType to use with Vault. May be "token", "userpass" or "k8s".
	AuthType string `mapstructure:"auth_type,required"`
	// Path path to the auth method's mount point
	Path string `mapstructure:"path"`
	// AuthParameters is a freeform set of parameters sent to the Vault auth path
	// to acquire a token.
	AuthParameters map[string]interface{} `mapstructure:",remain"`
}

func (k *VaultSource) GetUnsealKey() (string, error) {
	//TODO implement me
	panic("implement me")
}
