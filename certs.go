package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"sync"
)

func loadCertPoolFromFile(certFile string) (*x509.CertPool, error) {
	caCert, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to load cert")
	}
	return caCertPool, nil
}

func loadKeyPairFromFiles(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func loadFileOrString(certFile, cert string) ([]byte, error) {
	if certFile != "" && cert != "" {
		return nil, fmt.Errorf("cannot specify both file and literal cert string")
	}
	if certFile != "" {
		certBytes, err := ioutil.ReadFile(certFile)
		if err != nil {
			return nil, err
		}
		cert = string(certBytes)
	}
	cert = strings.TrimSpace(cert)
	if !strings.HasPrefix(cert, "-----") {
		return nil, fmt.Errorf("a certificate must start with '-----'")
	}
	return []byte(cert), nil
}

func checkCert(cert string) error {
	cert = strings.TrimSpace(string(cert))
	if !strings.HasPrefix(cert, "-----") {
		return fmt.Errorf("a certificate must start with '-----'")
	}
	return nil
}

var (
	keyLogMutex sync.Mutex
	keyLogCache = make(map[string]*os.File)
)

func keyLogFile(filePath string) (io.Writer, error) {
	keyLogMutex.Lock()
	defer keyLogMutex.Unlock()

	if f, exists := keyLogCache[filePath]; exists {
		return f, nil
	}

	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	keyLogCache[filePath] = f
	return f, nil
}
