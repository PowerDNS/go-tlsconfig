// Package tlsconfig provide YAML and JSON configuration options for both clients
// and servers.
package tlsconfig

import (
	"time"
)

const (
	DefaultWatchCertsPollInterval = 5 * time.Second
)

type Config struct {
	// Optional CA file to use (PEM)
	CAFile string `yaml:"ca_file" json:"ca_file"`
	CA     string `yaml:"ca" json:"ca"`

	// AddSystemCAPool adds the system CA pool if private CAs are enabled, when set.
	// By default we do not load system CAs when a private CA cert was loaded.
	AddSystemCAPool bool `yaml:"add_system_ca_pool" json:"add_system_ca_pool"`

	// These are required for the server and optional for clients.
	// They must be in PEM format.
	CertFile string `yaml:"cert_file" json:"cert_file"`
	Cert     string `yaml:"cert" json:"cert"`
	KeyFile  string `yaml:"key_file" json:"key_file"`
	Key      string `yaml:"key" json:"key"`

	// TODO: Perhaps add encrypted key support, but this is more hairy than I thought...
	//Passphrase Secret

	// WatchCerts enables background reloading of certificate files.
	// This only affects certificates loaded from files.
	// By default certificates are only loaded on startup.
	WatchCerts bool `yaml:"watch_certs" json:"watch_certs"`
	// By default, we check for changes every 5 seconds
	WatchCertsPollInterval time.Duration `yaml:"watch_certs_poll_interval" json:"watch_certs_poll_interval"`

	// RequireClientCert can be set on servers to require a client certificate.
	// If enabled, the CA must be set.
	RequireClientCert bool `yaml:"require_client_cert" json:"require_client_cert"`

	// InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	// If InsecureSkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`

	// InsecureKeyLogFile optionally specifies a destination for TLS master secrets
	// in NSS key log format that can be used to allow external programs
	// such as Wireshark to decrypt TLS connections.
	// See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format.
	// Use of InsecureKeyLogFile compromises security and should only be
	// used for debugging.
	InsecureKeyLogFile string `yaml:"insecure_key_log_file" json:"insecure_key_log_file"`
}

// HasCA returns true if a custom CA was defined in the config
func (c Config) HasCA() bool {
	return c.CA != "" || c.CAFile != ""
}

// HasCertWithKey returns true if a Cert and Key was defined in the config
func (c Config) HasCertWithKey() bool {
	hasCert := c.Cert != "" || c.CertFile != ""
	hasKey := c.Key != "" || c.KeyFile != ""
	return hasCert && hasKey
}
