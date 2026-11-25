package tor

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed certs/authority-certs.pem
var authorityCertsPEM string

// EmbeddedAuthorityCerts returns authority trust anchors embedded in the binary.
// No external network call is needed at startup; all authority keys travel
// inside the static distroless binary.
func EmbeddedAuthorityCerts() ([]*AuthorityCert, error) {
	var certs []*AuthorityCert
	parts := strings.Split(authorityCertsPEM, "dir-key-certificate-version")
	var lastErr error
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		certText := "dir-key-certificate-version " + part
		cert, err := parseAuthorityCert([]byte(certText))
		if err == nil {
			certs = append(certs, cert)
		} else {
			lastErr = err
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("tor: no authority certs embedded (last error: %v)", lastErr)
	}
	return certs, nil
}
