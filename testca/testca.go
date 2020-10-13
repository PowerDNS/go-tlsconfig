package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	rand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/PowerDNS/go-tlsconfig"
)

// Options are options for the test CA
type Options struct {
	ExpiresAfter time.Duration // default: 1 hour
}

// New creates a testCA that can generate configurations for testing.
//
// Heavily inspired by:
// https://www.youtube.com/watch?v=VwPQKS9Njv0
// https://docs.google.com/presentation/d/16y-HTvL7ASzf9JspCBX0OVmhwUWVoLj9epzJfNMQRr8/edit
func New(opts Options) (*TestCA, error) {
	if opts.ExpiresAfter == 0 {
		opts.ExpiresAfter = time.Hour
	}

	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate: %w", err)
	}
	// Generate a self-signed certificate
	caTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "my-ca"},
		SerialNumber:          newSerialNum(),
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(opts.ExpiresAfter),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPriv.Public(), caPriv)
	if err != nil {
		return nil, fmt.Errorf("ca: create: %w", err)
	}

	caPrivDER, err := x509.MarshalECPrivateKey(caPriv)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal: %w", err)
	}
	// PEM encode the certificate and private key
	caCertPEM := pemEncode(caCertDER, "CERTIFICATE")
	caPrivPEM := pemEncode(caPrivDER, "EC PRIVATE KEY")

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return nil, err
	}

	ca := &TestCA{
		Opts:    opts,
		CertPEM: caCertPEM,
		PrivPEM: caPrivPEM,
		CertDER: caCertDER,
		PrivDER: caPrivDER,
		Priv:    caPriv,
		Cert:    caCert,
	}
	return ca, nil
}

type TestCA struct {
	Opts    Options
	CertPEM []byte
	PrivPEM []byte
	CertDER []byte
	PrivDER []byte
	Priv    *ecdsa.PrivateKey
	Cert    *x509.Certificate
}

func (ca *TestCA) createCert(name string, isClient bool) (certPEM, privPEM []byte, err error) {
	// Generate a key pair and certificate template
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: name},
		SerialNumber: newSerialNum(),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(ca.Opts.ExpiresAfter),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	if isClient {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{name}
	}
	// Sign the serving cert with the CA private key
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, priv.Public(), ca.Priv)
	if err != nil {
		return nil, nil, err
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pemEncode(certDER, "CERTIFICATE")
	privPEM = pemEncode(privDER, "EC PRIVATE KEY")
	return certPEM, privPEM, nil
}

func (ca *TestCA) ServerConfig(name string) (tlsconfig.Config, error) {
	certPEM, privPEM, err := ca.createCert(name, false)
	if err != nil {
		return tlsconfig.Config{}, err
	}
	return tlsconfig.Config{
		CA:                string(ca.CertPEM),
		Cert:              string(certPEM),
		Key:               string(privPEM),
		RequireClientCert: true,
	}, nil
}

func (ca *TestCA) ClientConfig(name string) (tlsconfig.Config, error) {
	certPEM, privPEM, err := ca.createCert(name, true)
	if err != nil {
		return tlsconfig.Config{}, err
	}
	return tlsconfig.Config{
		CA:   string(ca.CertPEM),
		Cert: string(certPEM),
		Key:  string(privPEM),
	}, nil
}

func pemEncode(data []byte, typeName string) []byte {
	return pem.EncodeToMemory(&pem.Block{Bytes: data, Type: typeName})
}

func newSerialNum() *big.Int {
	return big.NewInt(time.Now().UnixNano())
}
