package tlsconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/PowerDNS/go-tlsconfig/filewatcher"
	"github.com/go-logr/logr"
)

// Options configure how the Manager works and performs Config validation
type Options struct {
	// IsServer indicates this is a server config (cert required)
	IsServer bool

	// IsClient indicates this is a client config
	IsClient bool

	// RequireClientCert requires the use of a client cert for clients
	RequireClientCert bool

	// Logr allows custom handling of logging. By default nothing is logged.
	Logr logr.Logger
}

// NewManager creates a new Manager.
// This also starts any needed background worker goroutines. These can be cancelled
// through the provided context.
func NewManager(ctx context.Context, config Config, options Options) (*Manager, error) {
	// Options validation
	if options.IsServer && options.IsClient {
		return nil, fmt.Errorf("options: cannot use both IsServer and IsClient")
	}
	if !options.IsServer && !options.IsClient {
		return nil, fmt.Errorf("options: one of IsServer and IsClient is required")
	}
	log := options.Logr
	// TODO: Since v1 this is a concrete type and we can no longer compare with
	//       nil. Unfortunately, there is no clean way to check this against a
	//       zero type either and we do not want to change the signature of
	//       the option if not needed, so instead we check if the LogSink is nil
	//       to determine if it is uninitialized.
	//       See https://github.com/go-logr/logr/issues/152
	if log.GetSink() == nil {
		log = logr.Discard()
	}

	// Create a Manager
	m := &Manager{
		config:  config,
		options: options,
		log:     log,
	}

	// Config validation
	if err := m.validateConfig(); err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}

	// Load CAs and certificates if needed
	if err := m.initCA(ctx); err != nil {
		return nil, err
	}
	if err := m.initCert(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// Manager performs Config validation, certificate loading, and provides
// convenience methods for using the TLS configuration and automated certificate
// refreshing.
type Manager struct {
	config  Config
	options Options
	log     logr.Logger

	// Internal mutable fields
	mu      sync.Mutex
	ca      *x509.CertPool
	caPEM   []byte
	cert    *tls.Certificate
	certPEM []byte
	keyPEM  []byte
}

// TLSConfig creates a tls.Config from the current config. This works for both
// clients and servers, depending on the Options.
// This config uses the default Go security settings. If you have different
// needs, you can override the ciphers and versions on the returned object.
func (m *Manager) TLSConfig() (*tls.Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var clientAuth tls.ClientAuthType
	if m.config.RequireClientCert {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	var keyLogWriter io.Writer
	if m.config.InsecureKeyLogFile != "" {
		var err error
		keyLogWriter, err = keyLogFile(m.config.InsecureKeyLogFile)
		if err != nil {
			return nil, err
		}
	}

	// We dynamically get the cert to allow for updates
	getCert := func(optional bool) (*tls.Certificate, error) {
		m.mu.Lock()
		cert := m.cert
		m.mu.Unlock()

		if cert == nil {
			if optional {
				return &tls.Certificate{}, nil
			}
			return nil, ErrNoCertificate
		}
		return cert, nil
	}

	tlsConfig := &tls.Config{
		// Use a function to allow dynamic cert updates
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return getCert(false)
		},
		// Use a function to allow dynamic cert updates
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			// We pass optional=true for this:
			//
			// If GetClientCertificate returns an error, the handshake will be
			// aborted and that error will be returned. Otherwise
			// GetClientCertificate must return a non-nil Certificate. If
			// Certificate.Certificate is empty then no certificate will be sent to
			// the server. If this is unacceptable to the server then it may abort
			// the handshake.
			return getCert(true)
		},
		RootCAs:            m.ca,
		ClientCAs:          m.ca,
		ClientAuth:         clientAuth,
		InsecureSkipVerify: m.config.InsecureSkipVerify,
		KeyLogWriter:       keyLogWriter,
	}
	return tlsConfig, nil
}

// HTTPClient creates an http.Client with the custom TLS config and some opinionated defaults.
// This is mostly here for convenience, you are recommended to create your own based on this.
// For example, this is not suitable for huge downloads, because it will timeout
// a connection after 15 minutes.
// These opinionated defaults may also change in future releases.
func (m *Manager) HTTPClient() (*http.Client, error) {
	if !m.options.IsClient {
		return nil, ErrNotClient
	}
	tlsConfig, err := m.TLSConfig()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 10 * time.Second,
		TLSClientConfig:       tlsConfig,
	}
	updateHTTPTransport(transport) // Go version dependent things
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Minute, // includes reading response body!
	}
	return httpClient, nil
}

func (m *Manager) validateConfig() error {
	c := m.config
	o := m.options
	if o.IsServer {
		if !c.HasCertWithKey() {
			return fmt.Errorf("servers require a cert and key")
		}
	}
	return nil
}

func (m *Manager) watcherInterval() time.Duration {
	watcherInterval := m.config.WatchCertsPollInterval
	if watcherInterval == 0 {
		watcherInterval = DefaultWatchCertsPollInterval
	}
	return watcherInterval
}

// initCA loads any configured custom CA certificates and starts a background
// watcher to keep track of changes.
func (m *Manager) initCA(ctx context.Context) error {
	if !m.config.HasCA() {
		return nil
	}

	watcher, err := filewatcher.New(ctx, filewatcher.Options{
		Contents: []byte(m.config.CA),
		FilePath: m.config.CAFile,
		Interval: m.watcherInterval(),
		Logr:     m.log.WithName("ca-watcher"),
		OnChange: func(contents []byte) {
			// Not called for initial load
			// Ignore any returned errors, they get logged by this function
			// NOTE: Existing tls.Configs will not see the new CA pool!
			_ = m.loadCAs(contents)
		},
	})
	if err != nil {
		return err
	}

	// Initial load must succeed
	return m.loadCAs(watcher.Contents())
}

// initCA loads any configured custom client/server certificates and starts
// a background watcher to keep track of changes.
func (m *Manager) initCert(ctx context.Context) error {
	if !m.config.HasCertWithKey() {
		return nil
	}

	var err error
	var certPEM []byte
	var keyPEM []byte

	// Common function for any change in cert or key
	reloadCert := func() {
		if err := m.loadCert(certPEM, keyPEM); err != nil {
			// This could happen if we catch it in the middle of an update
			// where one is updated but the other one is not.
			m.log.V(1).Error(err, "failed to reload cert and key, keeping old one")
		}
	}

	// Cert
	certWatcher, err := filewatcher.New(ctx, filewatcher.Options{
		Contents: []byte(m.config.Cert),
		FilePath: m.config.CertFile,
		Interval: m.watcherInterval(),
		Logr:     m.log.WithName("cert-watcher"),
		OnChange: func(contents []byte) {
			certPEM = contents
			reloadCert()
		},
	})
	if err != nil {
		return err
	}
	certPEM = certWatcher.Contents()

	// Key
	keyWatcher, err := filewatcher.New(ctx, filewatcher.Options{
		Contents: []byte(m.config.Key),
		FilePath: m.config.KeyFile,
		Interval: m.watcherInterval(),
		Logr:     m.log.WithName("key-watcher"),
		OnChange: func(contents []byte) {
			keyPEM = contents
			reloadCert()
		},
	})
	if err != nil {
		return err
	}
	keyPEM = keyWatcher.Contents()

	// Initial load must succeed
	if err := m.loadCert(certPEM, keyPEM); err != nil {
		return fmt.Errorf("create X509 keypair: %v", err)
	}
	return nil
}

func (m *Manager) loadCAs(data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var caCertPool *x509.CertPool
	if m.config.AddSystemCAPool {
		var err error
		if caCertPool, err = x509.SystemCertPool(); err != nil {
			// We do not consider this an error to stay consistent with the
			// default operation if no custom CA was provided.
			m.log.V(1).Info("loadCAs: failed to load system CA pool")
		}
	} else {
		caCertPool = x509.NewCertPool()
	}
	if !caCertPool.AppendCertsFromPEM(data) {
		m.log.V(1).Info("loadCAs: failed to load cert", "cert", string(data))
		return fmt.Errorf("loadCAs: failed to load cert")
	}
	m.ca = caCertPool
	m.caPEM = data
	return nil
}

func (m *Manager) loadCert(certPEM, keyPEM []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("create X509 keypair: %v", err)
	}
	m.certPEM = certPEM
	m.keyPEM = keyPEM
	m.cert = &cert
	return nil
}

var (
	ErrNoCertificate = errors.New("no certificate found")
	ErrNotClient     = errors.New("this is not a client config")
)
