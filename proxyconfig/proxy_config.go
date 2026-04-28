// Package proxyconfig provide YAML and JSON configuration options for proxy settings.
package proxyconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type ProxyConfig struct {
	// Proxy URL, e.g. http://user:password@localhost:8080
	URL string `yaml:"url" json:"url"`
}

func (p ProxyConfig) MarshalYAML() (interface{}, error) {
	type Alias ProxyConfig
	p.URL = maskProxyUserInfo(p.URL)
	return (Alias)(p), nil
}

func (p ProxyConfig) MarshalJSON() ([]byte, error) {
	type Alias ProxyConfig
	p.URL = maskProxyUserInfo(p.URL)
	return json.Marshal((Alias)(p))
}

func (p ProxyConfig) Check() error {
	if p.URL == "" {
		return nil
	}

	parsedURL, err := url.Parse(p.URL)
	if err != nil {
		return fmt.Errorf("invalid proxy url")
	}
	if parsedURL.Hostname() == "" {
		return errors.New("invalid proxy url, missing hostname")
	}

	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "socks5" && scheme != "socks5h" {
		return errors.New("invalid proxy url, expected <scheme>://<host> with scheme http, https, socks5 or socks5h")
	}
	return nil
}

func maskProxyUserInfo(proxyUrl string) string {
	if proxyUrl == "" {
		return proxyUrl
	}
	u, err := url.Parse(proxyUrl)
	if err != nil || u.User == nil {
		return proxyUrl
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		u.User = url.UserPassword("omitted", "omitted")
	} else {
		u.User = url.User("omitted")
	}
	return u.String()
}
