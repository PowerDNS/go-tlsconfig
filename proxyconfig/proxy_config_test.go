package proxyconfig

import (
	"fmt"
	"strings"
	"testing"
)

func TestProxy_marshal(t *testing.T) {
	p := ProxyConfig{URL: "http://user:password@localhost:8080"}
	expectedMaskedURL := "http://omitted:omitted@localhost:8080"

	maskedYAML, err := p.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML error: %v", err)
	}
	if got := fmt.Sprint(maskedYAML); !strings.Contains(got, expectedMaskedURL) {
		t.Errorf("expected masked URL in YAML output, got: %v", maskedYAML)
	}

	maskedJSON, err := p.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	if !strings.Contains(string(maskedJSON), expectedMaskedURL) {
		t.Errorf("expected masked URL in JSON output, got: %s", maskedJSON)
	}
}
