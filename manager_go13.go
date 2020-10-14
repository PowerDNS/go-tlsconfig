// +build go1.13

package tlsconfig

import "net/http"

func updateHTTPTransport(transport *http.Transport) {
	transport.ForceAttemptHTTP2 = true
}
