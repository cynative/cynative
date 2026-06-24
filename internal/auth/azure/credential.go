package azure

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// unavailableOnError wraps an azcore.TokenCredential so that any GetToken error
// is reported as a credentialUnavailable error. A ChainedTokenCredential
// advances to its next source only when a source returns credentialUnavailable,
// so wrapping makes the inner credential's failures non-fatal: the chain falls
// through to the next source instead of aborting.
//
// This neutralizes the IMDS-IP-collision footgun. ManagedIdentityCredential
// probes http://169.254.169.254 (Azure IMDS); on a non-Azure host whose
// link-local metadata server occupies that IP (e.g. a GCP VM, which answers
// 404), the SDK returns a fatal AuthenticationFailedError that would otherwise
// abort the chain before a working operator credential (Azure CLI) is reached.
type unavailableOnError struct {
	inner azcore.TokenCredential
	name  string
}

// GetToken returns the inner credential's token on success; on any error it
// returns a credentialUnavailable error so credential chains continue to the
// next source.
func (u unavailableOnError) GetToken(
	ctx context.Context, opts policy.TokenRequestOptions,
) (azcore.AccessToken, error) {
	tok, err := u.inner.GetToken(ctx, opts)
	if err != nil {
		return azcore.AccessToken{}, azidentity.NewCredentialUnavailableError(u.name + ": " + err.Error())
	}
	return tok, nil
}
