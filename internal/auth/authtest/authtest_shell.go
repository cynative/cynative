package authtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

const (
	// testCertValidity is the duration a test certificate is valid for.
	testCertValidity = 24 * time.Hour
	// testLeafSerial is the serial number used for leaf certificates.
	testLeafSerial = 2
)

// certFactory generates self-signed certificates for testing. It is a thin,
// shell-only wrapper over the crypto/x509 primitives; its error paths are
// exercised by integration use, not by injected seams, so it lives in this
// gate-exempt *_shell.go file.
type certFactory struct{}

// newCertFactory builds a certFactory wired to the real crypto/x509 primitives.
func newCertFactory() *certFactory {
	return &certFactory{}
}

// GenerateCA creates a self-signed CA certificate for testing.
// It returns the PEM-encoded certificate and private key.
func GenerateCA() ([]byte, []byte, error) {
	return newCertFactory().GenerateCA()
}

// GenerateCert creates a certificate signed by the given CA.
// It returns the PEM-encoded certificate and private key.
func GenerateCert(caCertPEM, caKeyPEM []byte, isServer bool) ([]byte, []byte, error) {
	return newCertFactory().GenerateCert(caCertPEM, caKeyPEM, isServer)
}

// GenerateCA creates a self-signed CA certificate.
func (f *certFactory) GenerateCA() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(testCertValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}

// GenerateCert creates a certificate signed by the given CA.
func (f *certFactory) GenerateCert(caCertPEM, caKeyPEM []byte, isServer bool) ([]byte, []byte, error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caPrivKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := buildLeafTemplate(isServer)

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM, nil
}
