package testca

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/wojas/go-tlsconfig"
	"golang.org/x/sync/errgroup"
)

func TestTestCA(t *testing.T) {
	if err := func() error {
		ca, err := New(Options{})
		if err != nil {
			return err
		}

		server, err := ca.ServerConfig("server1")
		if err != nil {
			return err
		}
		checkContains(t, string(server.Cert), "-----BEGIN CERTIFICATE-----")
		checkContains(t, string(server.Key), "-----BEGIN EC PRIVATE KEY-----")

		client, err := ca.ClientConfig("client1")
		if err != nil {
			return err
		}
		checkContains(t, string(client.Cert), "-----BEGIN CERTIFICATE-----")
		checkContains(t, string(client.Key), "-----BEGIN EC PRIVATE KEY-----")

		return nil
	}(); err != nil {
		t.Fatal(err)
	}
}

func checkContains(t testing.TB, haystack, needle string) {
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected %q in string, got: %q", needle, haystack)
	}
}

// TestTestCA_client_server provides an example of how to use the TestCA for a
// client-server connection with client certificate authentication.
func TestTestCA_client_server(t *testing.T) {
	// Tests client-server http communication using the CA and client certs
	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, ctx := errgroup.WithContext(rootCtx)

	if err := func() error {
		ca, err := New(Options{})
		if err != nil {
			return err
		}

		// Server

		serverConfig, err := ca.ServerConfig("server1")
		if err != nil {
			return err
		}
		serverManager, err := tlsconfig.NewManager(ctx, serverConfig, tlsconfig.Options{
			IsServer:          true,
			RequireClientCert: true,
			Logr:              nil,
		})
		if err != nil {
			return err
		}
		serverTLSConfig, err := serverManager.TLSConfig()
		if err != nil {
			return err
		}

		// This HTTP handler extracts the client certificate name
		var handlerFunc http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			clientCert := r.TLS.PeerCertificates[0]
			t.Log("http handler:", clientCert.Subject)
			w.WriteHeader(200)
			_, _ = w.Write([]byte(clientCert.Subject.CommonName))
		}

		// Example of how to use a custom TLSConfig
		hs := http.Server{
			Handler:   handlerFunc,
			TLSConfig: serverTLSConfig,
		}
		defer hs.Close()
		listener, err := net.Listen("tcp", "127.0.0.1:0") // OS chosen port
		if err != nil {
			panic(err)
		}
		g.Go(func() error {
			t.Log("starting server on", listener.Addr().String())
			defer t.Log("server exited")
			return hs.ServeTLS(listener, "", "")
		})

		// Client

		clientConfig, err := ca.ClientConfig("client123")
		if err != nil {
			return err
		}
		clientManager, err := tlsconfig.NewManager(ctx, clientConfig, tlsconfig.Options{
			IsClient:          true,
			RequireClientCert: true,
			Logr:              nil,
		})
		if err != nil {
			return err
		}
		clientTLSConfig, err := clientManager.TLSConfig()
		if err != nil {
			return err
		}
		// This is only needed for this test to prevent a TLS error due to the
		// use of an IP+port in the URL. Usually you would connect using a domain name.
		clientTLSConfig.ServerName = "server1"
		transport := &http.Transport{
			TLSClientConfig: clientTLSConfig,
		}
		client := &http.Client{Transport: transport}
		resp, err := client.Get(fmt.Sprintf("https://%s/foo", listener.Addr().String()))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if string(body) != "client123" {
			t.Errorf("expected client cert name in returned body, got: %s", string(body))
		}

		return nil
	}(); err != nil {
		t.Fatal(err)
	}

}
