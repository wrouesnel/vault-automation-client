package unsealer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/wrouesnel/vault-automation-client/pkg/certutils"
	"strings"
)

// VaultSource retreives the unseal key from a path in Hashicorp Vault
// This source would be used in an HA mode where there's a common endpoint
// which will find a functional Vault instance to retrieve the key from.
type VaultSource struct {
	VaultAddr string `help:"Vault Server address to connect to"`

	VaultCACerts     string `help:"CA Certificate to authenticate Vault"`
	VaultTLSNoVerify bool   `help:"Disable TLS verification to the endpoint"`

	// AuthType to use with Vault. May be any valid Vault type.
	AuthType string `help:"Authentication type to attempt with Vault"`
	// AuthPath path to the auth method's mount point
	AuthPath string `help:"Mount path of the authentication method"`
	// AuthParameters is a freeform set of parameters sent to the Vault auth path
	// to acquire a token.
	AuthParameters map[string]string `help:"Authentication parameters (see Vault documentation)"`

	// SecretPath is the HTTP path to the secret to read.
	SecretPath string `help:"Path to the secret to read as specified to the HTTP API of Vault."`
	// SecretKey is the subkey of the secret to read
	SecretKey string `help:"subkey of the secret to read." default:"value"`
}

// TODO: determine GetUnsealKey utility at startup
func (k *VaultSource) GetUnsealKey() (string, error) {
	// Build the HTTP client
	httpClient := resty.New()

	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return "", errors.Wrap(err, "GetUnsealKey")
	}

	certs, err := certutils.ReadCertificate(k.VaultCACerts)
	if err != nil {
		return "", errors.Wrap(err, "vault-ca-certs could not be parsed for a certificate")
	}

	for _, cert := range certs {
		rootCAs.AddCert(cert)
	}

	httpClient.SetBaseURL(k.VaultAddr)
	httpClient.SetTLSClientConfig(&tls.Config{RootCAs: rootCAs, InsecureSkipVerify: k.VaultTLSNoVerify})

	// Determine path
	if k.AuthPath == "" {
		k.AuthPath = fmt.Sprintf("auth/%s", k.AuthType)
	}

	var clientToken string
	if k.AuthType != "token" {
		// This is necessary because *some* but not all Vault login methods accept the username
		// as part of the AuthPath. This doesn't seem to be a continuing trend, so we can support them
		// by specialcasing here and looking for "username" parameters.
		loginSpecialCase := ""
		loginParams := map[string]string{}
		switch k.AuthType {
		// Login with username in path
		case "ldap", "okta", "radius", "userpass":
			loginSpecialCase = fmt.Sprintf("/%s", k.AuthParameters["username"])
			loginParams = lo.OmitByKeys(k.AuthParameters, []string{"username"})
		// Login with "role" in path
		case "oci":
			loginSpecialCase = fmt.Sprintf("/%s", k.AuthParameters["role"])
			loginParams = lo.OmitByKeys(k.AuthParameters, []string{"role"})
		}

		// Execute a login to the key-holding Vault.
		_, jsonResp, isError, err := vaultRequest(httpClient.R().SetBody(loginParams).Post(fmt.Sprintf("%s/login%s", loginSpecialCase)))
		if err != nil {
			return "", errors.Wrap(err, fmt.Sprintf("error making HTTP request to Vault: %s", k.VaultAddr))
		}

		if isError {
			return "", &KeySourceErr{msg: fmt.Sprintf("VaultSource: login failed: %s", strings.Join(errorResponse(jsonResp), ","))}
		}

		authResp, ok := jsonResp["auth"].(map[string]interface{})
		if !ok {
			return "", &KeySourceErr{msg: "auth not found in login response"}
		}

		clientTokenIntf, ok := authResp["client_token"]
		if !ok {
			return "", &KeySourceErr{msg: "auth.client_token not found in login response"}
		}

		token, ok := clientTokenIntf.(string)
		if !ok {
			return "", &KeySourceErr{msg: "client_token was not a string type"}
		}
		clientToken = token
	} else {
		token, ok := k.AuthParameters["token"]
		if !ok {
			return "", &KeySourceErr{msg: "auth-parameters did not contain \"token\" for token auth"}
		}
		clientToken = token
	}

	// Okay we have the clientToken. Now we can actually fetch the secret.
	_, jsonResp, isError, err := vaultRequest(httpClient.R().SetHeader("X-Vault-Token", clientToken).Get(k.SecretPath))
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("error making HTTP request to Vault: %s %s", k.VaultAddr, k.SecretPath))
	}

	if isError {
		return "", &KeySourceErr{msg: fmt.Sprintf("VaultSource: get secret failed: %s", strings.Join(errorResponse(jsonResp), ","))}
	}

	// Got the secret. Pull subkey from "data".
	data, ok := jsonResp["data"].(map[string]interface{})
	if !ok {
		return "", &KeySourceErr{msg: "no data field in secret response"}
	}

	unsealKey, ok := data[k.SecretKey].(string)
	if !ok {
		return "", &KeySourceErr{msg: fmt.Sprintf("secret does not contain field: %s", k.SecretKey)}
	}

	return unsealKey, nil
}
