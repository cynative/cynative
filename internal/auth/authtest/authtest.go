// Package authtest provides test doubles for the auth package.
package authtest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
)

// FailingProvider is an auth.Provider that always returns an error from InjectAuth.
type FailingProvider struct{}

func (p *FailingProvider) Name() string        { return "failing" }
func (p *FailingProvider) Description() string { return "always fails" }
func (p *FailingProvider) InjectAuth(_ *http.Request, _ json.RawMessage) error {
	return errors.New("injection failed")
}

func (p *FailingProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

// LoopbackProvider is a test auth.Provider that authorizes ALL hosts and supplies
// a CA cert, for driving the transport against an httptest TLS server under the
// host-bound, https-only rules. CACert is base64-PEM (e.g. from the server leaf).
type LoopbackProvider struct {
	ProviderName string // defaults to "loopback".
	CACert       string // base64 PEM; returned from CACertData for TLS trust.
	Token        string // optional bearer injected into requests.
}

func (p *LoopbackProvider) Name() string {
	if p.ProviderName == "" {
		return "loopback"
	}

	return p.ProviderName
}

func (p *LoopbackProvider) Description() string { return "test loopback provider" }

func (p *LoopbackProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}

	return nil
}

func (p *LoopbackProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

func (p *LoopbackProvider) CACertData(_ context.Context, _ json.RawMessage) (string, error) {
	return p.CACert, nil
}

// AuthorizesAddr authorizes every resolved IP so the transport can dial the
// loopback httptest server under the dial-time IP guard.
func (p *LoopbackProvider) AuthorizesAddr(
	_ context.Context, _ netip.Addr, _ json.RawMessage,
) (bool, error) {
	return true, nil
}

// CertProvider is a single configurable auth.Provider double covering every
// CA-cert / client-cert test scenario the EKS/GKE/AKS/failing doubles provided.
// CACert supplies a static base64-PEM CA; ExtractEKSCACert instead reads it from
// the request's eks_auth.cluster_ca_cert_data; CACertErr forces a CACertData
// failure. Bearer is injected unless mTLS client certs are present. It implements
// auth.Provider, auth.CACertProvider, auth.ClientCertProvider, and
// auth.AddrAuthorizer.
type CertProvider struct {
	ProviderName     string // returned from Name().
	Desc             string // returned from Description().
	Bearer           string // bearer token; suppressed when ClientCert+ClientKey are set.
	CACert           string // static base64-PEM CA (ignored when ExtractEKSCACert is true).
	ExtractEKSCACert bool   // when true, CACertData reads eks_auth.cluster_ca_cert_data.
	CACertErr        error  // when non-nil, CACertData returns this error.
	ClientCert       string // base64-PEM client cert for mTLS.
	ClientKey        string // base64-PEM client key for mTLS.
}

// NewEKSCert builds the EKS double: Name "eks", JSON-extracting CACertData, and a
// static bearer token.
func NewEKSCert() *CertProvider {
	return &CertProvider{ //nolint:gosec // test double – fake bearer token, not a real credential.
		ProviderName:     "eks",
		Desc:             "Test EKS",
		Bearer:           "k8s-aws-v1.test",
		ExtractEKSCACert: true,
	}
}

// NewGKECert builds the GKE double: Name "gke", a static CA, and a bearer token.
func NewGKECert(caCert string) *CertProvider {
	return &CertProvider{ //nolint:gosec // test double – fake bearer token, not a real credential.
		ProviderName: "gke",
		Desc:         "Test GKE",
		Bearer:       "ya29.test-gke-token",
		CACert:       caCert,
	}
}

// NewAKSCert builds the AKS double: Name "aks", a static CA, optional client
// cert/key for mTLS, and a bearer token suppressed when mTLS certs are present.
func NewAKSCert(caCert, clientCert, clientKey string) *CertProvider {
	return &CertProvider{ //nolint:gosec // test double – fake bearer token, not a real credential.
		ProviderName: "aks",
		Desc:         "Test AKS",
		Bearer:       "eyJ0eXAiOi.test-aks-token",
		CACert:       caCert,
		ClientCert:   clientCert,
		ClientKey:    clientKey,
	}
}

// NewFailingCert builds a double whose CACertData always errors (Name "ca-fail").
func NewFailingCert() *CertProvider {
	return &CertProvider{
		ProviderName: "ca-fail",
		Desc:         "CA cert always fails",
		CACertErr:    errors.New("CA cert resolution failed"),
	}
}

func (p *CertProvider) Name() string        { return p.ProviderName }
func (p *CertProvider) Description() string { return p.Desc }

func (p *CertProvider) InjectAuth(req *http.Request, _ json.RawMessage) error {
	if p.Bearer != "" && (p.ClientCert == "" || p.ClientKey == "") {
		req.Header.Set("Authorization", "Bearer "+p.Bearer)
	}

	return nil
}

func (p *CertProvider) AuthorizesHost(_ context.Context, _ string, _ json.RawMessage) (bool, error) {
	return true, nil
}

// CACertData returns CACertErr when set, the eks_auth-extracted CA when
// ExtractEKSCACert is set, otherwise the static CACert value.
func (p *CertProvider) CACertData(_ context.Context, rawArgs json.RawMessage) (string, error) {
	if p.CACertErr != nil {
		return "", p.CACertErr
	}

	if !p.ExtractEKSCACert {
		return p.CACert, nil
	}

	var parsed struct {
		EKSAuth *struct {
			CACert string `json:"cluster_ca_cert_data"`
		} `json:"eks_auth"`
	}

	if err := json.Unmarshal(rawArgs, &parsed); err != nil || parsed.EKSAuth == nil {
		return "", nil //nolint:nilerr // test double – swallow parse errors
	}

	return parsed.EKSAuth.CACert, nil
}

// ClientCertData returns the configured client cert and key (empty for non-mTLS).
func (p *CertProvider) ClientCertData(_ context.Context, _ json.RawMessage) (string, string, error) {
	return p.ClientCert, p.ClientKey, nil
}

// AuthorizesAddr authorizes every resolved IP so the transport can dial the
// loopback httptest server under the dial-time IP guard.
func (p *CertProvider) AuthorizesAddr(_ context.Context, _ netip.Addr, _ json.RawMessage) (bool, error) {
	return true, nil
}
