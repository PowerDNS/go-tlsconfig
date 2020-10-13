# Go TLS configuration module

[![Go Doc](https://godoc.org/github.com/PowerDNS/go-tlsconfig?status.svg)](http://godoc.org/github.com/PowerDNS/go-tlsconfig)
[![Build Status](https://travis-ci.org/PowerDNS/go-tlsconfig.svg?branch=master)](https://travis-ci.org/PowerDNS/go-tlsconfig)

This module eases configuration of TLS for clients and servers written in Go.

Features:

- The `Config` struct has YAML and JSON struct tags.
- It can be used for both clients and servers.
- A `Manager` can generate a corresponding `tls.Config`.
- On-disk certificates can be automatically reloaded without downtime.

## YAML configuration examples

Note that depending on the application, the configuration can also be in JSON or another format.

The examples below group all TLS options under a `tls` key, but this name depends on the name used in the program.

### Servers

Load certificate from file:

```yaml
tls:
  cert_file: path/to/cert.pem
  key_file: path/to/key.pem
```

With automatic reloading:

```yaml
tls:
  cert_file: path/to/cert.pem
  key_file: path/to/key.pem
  watch_certs: true
  watch_certs_poll_interval: 5s
```

Same with a custom CA and client certificate support:

```yaml
tls:
  ca_file: path/to/ca.pem
  cert_file: path/to/cert.pem
  key_file: path/to/key.pem
  watch_certs: true
  watch_certs_poll_interval: 5s
  require_client_cert: true
```

### Clients

Clients that just want to use OS provides CAs can leave the configuration empty.

To use custom CA certs to verify the connection:

```yaml
tls:
  ca_file: path/to/ca.pem
```

To use a client certificate:

```yaml
tls:
  ca_file: path/to/ca.pem
  cert_file: path/to/cert.pem
  key_file: path/to/key.pem
```

INSECURE - to disable certificate validation:


```yaml
tls:
  insecure_skip_verify: true
``` 

### General options

The `ca_file`, `cert_file` and `key_file` options have corresponding `ca`, `cert` and `key` options that allow
you to inline the PEM certificate into the config file:

```yaml
tls:
  cert: |
    -----BEGIN CERTIFICATE-----
    ...
```

Note that there is no way to do automatic reloading this way.

The `insecure_key_log_file` option can be set to a log file path for the use of tools like Wireshark to decode encrypted traffic in development.
See [this Mozilla page](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format) for more information. 


## Usage in Go code

You can use the `Config` struct in you existing configuration structures:

```go
import "github.com/PowerDNS/go-tlsconfig"

type MyConfig struct {
	Server Server `yaml:"server"`
	// ...
}

type Server struct {
	TLS tlsconfig.Config `yaml:"tls"`
}
```

After you have loaded your configration, you can the use a `Manager` to generate a `tls.Config` (error handling omitted):

```go
manager, err := tlsconfig.NewManager(ctx, config.Server.TLS, tlsconfig.Options{
	IsServer: true,
})

tlsConfig, err := manager.TLSConfig()

hs := http.Server{
	TLSConfig: tlsConfig,
}
err = hs.ListenAndServeTLS("", "") // Certificates are handled by the TLSConfig
```

Example of how to use a custom TLS config with an HTTP client:

```go
manager, err := tlsconfig.NewManager(ctx, config.Client.TLS, tlsconfig.Options{
	IsClient: true,
})

tlsConfig, err := manager.TLSConfig()

transport := &http.Transport{
	TLSClientConfig: tlsConfig,
}
client := &http.Client{Transport: transport}
resp, err := client.Get("https://some.example/")
```

The `testca/testca_test.go` file contains an example that uses client certificates.

## Stability

At this point we do not guarantee any API and config file format stability between versions. If you want to use it in your own project,
pin it at a speciifc version. Once we are confident that our approach is sane, we will release a 1.0.0 version that will have these
guarantees.


