package proxyconfig

import (
	"fmt"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name    string
		proxy   ProxyConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty URL",
			proxy:   ProxyConfig{URL: ""},
			wantErr: false,
		},
		{
			name:    "valid HTTP proxy",
			proxy:   ProxyConfig{URL: "http://localhost:8080"},
			wantErr: false,
		},
		{
			name:    "valid HTTPS proxy",
			proxy:   ProxyConfig{URL: "https://localhost:8080"},
			wantErr: false,
		},
		{
			name:    "valid SOCKS5 proxy",
			proxy:   ProxyConfig{URL: "socks5://localhost:1080"},
			wantErr: false,
		},
		{
			name:    "valid SOCKS5h proxy",
			proxy:   ProxyConfig{URL: "socks5h://localhost:1080"},
			wantErr: false,
		},
		{
			name:    "HTTP proxy with credentials",
			proxy:   ProxyConfig{URL: "http://user:password@proxy.example.com:8080"},
			wantErr: false,
		},
		{
			name:    "HTTP proxy uppercase scheme",
			proxy:   ProxyConfig{URL: "HTTP://localhost:8080"},
			wantErr: false,
		},
		{
			name:    "invalid URL",
			proxy:   ProxyConfig{URL: "ht!tp://localhost:8080"},
			wantErr: true,
			errMsg:  "invalid proxy url",
		},
		{
			name:    "missing host",
			proxy:   ProxyConfig{URL: "http://"},
			wantErr: true,
			errMsg:  "missing host",
		},
		{
			name:    "invalid scheme",
			proxy:   ProxyConfig{URL: "ftp://localhost:8080"},
			wantErr: true,
			errMsg:  "expected <scheme>://<host> with scheme http, https, socks5 or socks5h",
		},
		{
			name:    "no scheme",
			proxy:   ProxyConfig{URL: "localhost:8080"},
			wantErr: true,
			errMsg:  "missing host",
		},
		{
			name:    "SOCK5 typo",
			proxy:   ProxyConfig{URL: "sock5://localhost:8080"},
			wantErr: true,
			errMsg:  "expected <scheme>://<host> with scheme http, https, socks5 or socks5h",
		},
		{
			name:    "invalid scheme with credentials does not leak userinfo",
			proxy:   ProxyConfig{URL: "ftp://user:password@localhost:8080"},
			wantErr: true,
			errMsg:  "expected <scheme>://<host> with scheme http, https, socks5 or socks5h",
		},
		{
			name:    "parse error with credentials does not leak userinfo",
			proxy:   ProxyConfig{URL: "http://user:password@localhost:abc"},
			wantErr: true,
			errMsg:  "invalid proxy url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.proxy.Check()
			if (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				errMsg := err.Error()
				if !strings.Contains(errMsg, tt.errMsg) {
					t.Errorf("Check() error = %q, expected to contain %q", errMsg, tt.errMsg)
				}
				if strings.Contains(errMsg, "user:password") {
					t.Errorf("Check() error leaked credentials: %q", errMsg)
				}
			}
		})
	}
}

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
