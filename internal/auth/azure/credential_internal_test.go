package azure

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// fakeCred is a minimal azcore.TokenCredential: it returns token, or err if set.
type fakeCred struct {
	token string
	err   error
}

func (f fakeCred) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	return azcore.AccessToken{Token: f.token}, nil
}

func TestUnavailableOnErrorPassesTokenThrough(t *testing.T) {
	t.Parallel()

	wrapped := unavailableOnError{inner: fakeCred{token: "tok"}, name: "ManagedIdentityCredential"}
	got, err := wrapped.GetToken(context.Background(), policy.TokenRequestOptions{})
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if got.Token != "tok" {
		t.Errorf("Token = %q, want tok", got.Token)
	}
}

func TestUnavailableOnErrorLetsChainContinue(t *testing.T) {
	t.Parallel()

	// A failing inner credential, once wrapped, must report credentialUnavailable
	// so a ChainedTokenCredential falls through to the next (working) source
	// instead of aborting. This is the structural guarantee that a foreign IMDS
	// response (e.g. a GCP metadata server's 404) can never abort the chain.
	failing := unavailableOnError{
		inner: fakeCred{err: errors.New("imds 404")},
		name:  "ManagedIdentityCredential",
	}
	working := fakeCred{token: "operator-token"}

	chain, err := azidentity.NewChainedTokenCredential(
		[]azcore.TokenCredential{failing, working}, nil,
	)
	if err != nil {
		t.Fatalf("NewChainedTokenCredential: %v", err)
	}

	got, err := chain.GetToken(context.Background(), policy.TokenRequestOptions{})
	if err != nil {
		t.Fatalf("chain GetToken: %v", err)
	}
	if got.Token != "operator-token" {
		t.Errorf("Token = %q, want operator-token (chain must fall through past wrapped failure)", got.Token)
	}
}
