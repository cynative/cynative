package azure_test

import (
	"testing"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
)

// TestNewCredentialChainBuilds asserts the real credential chain constructs
// without error and returns a usable credential. The AzureCLI/azd/PowerShell/MI
// constructors defer all I/O to GetToken, so construction succeeds even on a
// host with no Azure auth — the chain is always built. Not gated.
func TestNewCredentialChainBuilds(t *testing.T) {
	cred, err := azurehardening.NewCredentialChain(azurehardening.ResolveCloudConfig("AzureCloud", "", nil))
	if err != nil {
		t.Fatalf("NewCredentialChain: %v", err)
	}
	if cred == nil {
		t.Fatal("NewCredentialChain returned a nil credential")
	}
}
