package azure

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// tokenFunc acquires a raw JWT for the given scope from the home-tenant
// authority. One-call seam over azcore so the SDK GetToken is the only
// non-injectable line; tests inject a fake.
type tokenFunc func(ctx context.Context, scope string) (string, error)

// IdentityConfig configures the real identity prober. Credential is the
// operator's home-tenant-authority TokenCredential; TokenFunc overrides token
// acquisition in tests (when set, Credential is ignored); Scope is the resolved
// cloud's ARM audience the probe token is minted for.
type IdentityConfig struct {
	Credential azcore.TokenCredential
	TokenFunc  tokenFunc
	Scope      string
}

type realIdentity struct {
	token tokenFunc
	scope string
}

// NewIdentityProber builds the real ADC-token identity prober. Excluded from
// the coverage gate.
func NewIdentityProber(cfg IdentityConfig) identityProber {
	token := cfg.TokenFunc
	if token == nil {
		token = defaultAzureNewTokenSource(cfg.Credential)
	}
	return &realIdentity{token: token, scope: cfg.Scope}
}

// defaultAzureNewTokenSource wraps a TokenCredential into a tokenFunc that
// returns the raw ARM JWT. The single non-injectable SDK call.
func defaultAzureNewTokenSource(cred azcore.TokenCredential) tokenFunc {
	return func(ctx context.Context, scope string) (string, error) {
		tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
		if err != nil {
			return "", fmt.Errorf("acquire ARM token: %w", err)
		}
		return tok.Token, nil
	}
}

// Probe acquires the home-tenant ARM token and decodes its claims into an
// Identity. Fails closed if the token has no resolvable tenant.
func (r *realIdentity) Probe(ctx context.Context) (Identity, error) {
	return probeIdentity(ctx, r.token, r.scope)
}
