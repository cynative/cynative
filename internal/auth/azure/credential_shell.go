package azure

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// NewCredentialChain builds the Azure credential chain cynative authenticates
// with. It mirrors azidentity.DefaultAzureCredential's set of sources but
// demotes ManagedIdentityCredential to LAST and makes its failures non-fatal
// (see unavailableOnError).
//
// DefaultAzureCredential probes the IMDS endpoint (http://169.254.169.254)
// during ManagedIdentityCredential, before AzureCLICredential. On a non-Azure
// host whose link-local metadata server occupies that IP — e.g. a GCP VM, whose
// metadata server answers 404 — the probe concludes IMDS is present, the real
// token request gets a fatal (non-credentialUnavailable) response, and the chain
// aborts before reaching the Azure CLI, even when `az login` is valid. Demoting
// managed identity to last and softening its errors means operator/dev/CI
// credentials are tried first and IMDS is only contacted when nothing else can
// authenticate (i.e. genuinely on Azure).
//
// Sources whose constructor errors (e.g. an incompletely-configured
// EnvironmentCredential) are skipped rather than aborting the chain; an error is
// returned only when no source could be constructed at all.
//
// The resolved cloud is supplied to every AAD-authority-aware credential
// (Environment/WorkloadIdentity/ManagedIdentity) via ClientOptions.Cloud, so a
// sovereign-cloud operator's token is minted against the correct Entra ID
// authority; the CLI/Developer/PowerShell credentials determine their own cloud.
//
// Lives in the imperative shell: every line is a non-injectable SDK constructor.
func NewCredentialChain(cc CloudConfig) (azcore.TokenCredential, error) {
	clientOpts := azcore.ClientOptions{Cloud: ToSDKCloud(cc)} //nolint:exhaustruct // only Cloud set.

	var (
		sources []azcore.TokenCredential
		skipped []string
	)
	add := func(name string, cred azcore.TokenCredential, err error) {
		if err != nil {
			skipped = append(skipped, name+": "+err.Error())
			return
		}
		sources = append(sources, cred)
	}

	envCred, envErr := azidentity.NewEnvironmentCredential(
		&azidentity.EnvironmentCredentialOptions{ClientOptions: clientOpts}, //nolint:exhaustruct // only Cloud set.
	)
	add("EnvironmentCredential", envCred, envErr)

	wiCred, wiErr := azidentity.NewWorkloadIdentityCredential(
		&azidentity.WorkloadIdentityCredentialOptions{
			ClientOptions: clientOpts,
		}, //nolint:exhaustruct // only Cloud set.
	)
	add("WorkloadIdentityCredential", wiCred, wiErr)

	cliCred, cliErr := azidentity.NewAzureCLICredential(nil)
	add("AzureCLICredential", cliCred, cliErr)

	azdCred, azdErr := azidentity.NewAzureDeveloperCLICredential(nil)
	add("AzureDeveloperCLICredential", azdCred, azdErr)

	pwshCred, pwshErr := azidentity.NewAzurePowerShellCredential(nil)
	add("AzurePowerShellCredential", pwshCred, pwshErr)

	// Managed identity LAST and non-fatal: only reached when no operator
	// credential authenticates, and never able to abort the chain (see
	// unavailableOnError and the IMDS-IP-collision note above).
	if miCred, miErr := azidentity.NewManagedIdentityCredential(
		&azidentity.ManagedIdentityCredentialOptions{ClientOptions: clientOpts}, //nolint:exhaustruct // only Cloud set.
	); miErr != nil {
		skipped = append(skipped, "ManagedIdentityCredential: "+miErr.Error())
	} else {
		sources = append(sources, unavailableOnError{inner: miCred, name: "ManagedIdentityCredential"})
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("azure: no usable credential source: %s", strings.Join(skipped, "; "))
	}
	return azidentity.NewChainedTokenCredential(sources, nil)
}
