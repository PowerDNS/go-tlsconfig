package testca

import (
	"strings"
	"testing"
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
