package authtest

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"time"
)

// buildLeafTemplate builds the x509 template for a leaf certificate signed by the
// test CA. When isServer is set it adds the server ExtKeyUsage plus loopback SANs.
// Pure; extracted from GenerateCert so the shell cert factory stays under the
// thin-shell complexity budget.
func buildLeafTemplate(isServer bool) x509.Certificate {
	extKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if isServer {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	tmpl := x509.Certificate{ //nolint:exhaustruct // test template; only these fields matter
		SerialNumber:          big.NewInt(testLeafSerial),
		Subject:               pkix.Name{Organization: []string{"Acme Co"}}, //nolint:exhaustruct // org only
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(testCertValidity),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
	}
	if isServer {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
	}
	return tmpl
}
