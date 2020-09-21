// Package tlsconfig provide YAML and JSON configuration options for both clients
// and servers.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"time"
)

const (
	DefaultWatchCertsPollInterval = 5 * time.Second
)

type Config struct {
	// Optional CA file to use (PEM)
	CAFile string `yaml:"ca_file" json:"ca_file"`
	CA     string `yaml:"ca" json:"ca"`

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

func (c Config) CAData() ([]byte, error) {
	if c.CA == "" && c.CAFile == "" {
		return nil, nil
	}
	return loadFileOrString(c.CAFile, c.CA)
}

// RootCAs returns a CertPool for the configured CA, or the system pool if
// not specified.
func (c Config) RootCAs() (*x509.CertPool, error) {
	caCert, err := c.CAData()
	if err != nil {
		return nil, err
	}
	if caCert == nil {
		return nil, nil // will use the system's CAs
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("ca/ca_file: failed to load cert")
	}
	return caCertPool, nil
}

func (c Config) TLSConfig() (*tls.Config, error) {
	caCertPool, err := c.RootCAs()
	if err != nil {
		return nil, err
	}

	var clientAuth tls.ClientAuthType
	if c.RequireClientCert {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	var certificates []tls.Certificate
	if c.Cert != "" || c.CertFile != "" {
		cert, err := c.X509KeyPair()
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, cert)
	}

	var keyLogWriter io.Writer
	if c.InsecureKeyLogFile != "" {
		keyLogWriter, err = keyLogFile(c.InsecureKeyLogFile)
		if err != nil {
			return nil, err
		}
	}

	tlsConfig := &tls.Config{
		Certificates:       certificates,
		RootCAs:            caCertPool,
		ClientCAs:          caCertPool,
		ClientAuth:         clientAuth,
		InsecureSkipVerify: c.InsecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	tlsConfig.RootCAs = caCertPool
	return tlsConfig, nil
}

func (c Config) CertData() ([]byte, error) {
	return loadFileOrString(c.CertFile, c.Cert)
}

func (c Config) KeyData() ([]byte, error) {
	return loadFileOrString(c.Key, c.KeyFile)
}

func (c Config) checkCommon() error {
	if c.CA == "" && c.CAFile == "" && c.RequireClientCert {
		return fmt.Errorf("require_client_cert: a custom CA is required when set")
	}
	return nil
}

func (c Config) ValidateForServer() error {
	if _, err := c.CertData(); err != nil {
		return fmt.Errorf("cert: %w", err)
	}
	if _, err := c.KeyData(); err != nil {
		return fmt.Errorf("key: %w", err)
	}
	return c.checkCommon()
}

func (c Config) ValidateForClient() error {
	return c.checkCommon()
}

// X509KeyPair returns a X509 key pair for TLS use
func (c Config) X509KeyPair() (tls.Certificate, error) {
	return tls.LoadX509KeyPair(c.CertFile, c.KeyFile) // TODO: passphrase
}

/*

	// TLS config
	// TODO: Support client certs
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify,
	}
	if cfg.TLSCAFile != "" {
		caCert, err := ioutil.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls_ca_file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("load tls_ca_file: failed to load cert")
		}
		tlsConfig.RootCAs = caCertPool
	}

	// Custom http client
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 10 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsConfig,
		},
		Timeout: 60 * time.Second,
	}

*/
