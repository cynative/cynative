package azure

import (
	"os"
	"path/filepath"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
)

// envLookup is the injected process-environment reader ([os.LookupEnv] in
// production). Mirrors the composition-root seam so the shell stays testable
// without t.Setenv.
type envLookup func(string) (string, bool)

// ToSDKCloud builds the azcore/cloud.Configuration the credential chain and ARM
// SDK clients consume from a resolved CloudConfig. We set Audience == Endpoint so
// the SDK requests the modern endpoint-based "<endpoint>/.default" ARM scope
// (matching the historical public-cloud behavior). Exported so the parent auth
// package can build the SDK cloud for the AKS ARM client.
func ToSDKCloud(cc CloudConfig) cloud.Configuration {
	return cloud.Configuration{
		ActiveDirectoryAuthorityHost: cc.AuthorityHost,
		Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: cc.ARMEndpoint, Audience: cc.ARMEndpoint},
		},
	}
}

// azureAuthorityHostEnv is the env var azidentity itself honors for the AAD
// authority; we read it as a cloud-detection signal.
const azureAuthorityHostEnv = "AZURE_AUTHORITY_HOST"

// ReadAzureCLIConfig returns the bytes of the Azure CLI config file the active
// cloud is stored in — $AZURE_CONFIG_DIR/config if set, else ~/.azure/config.
// Returns nil when neither is readable (auto-detect then falls through).
func ReadAzureCLIConfig(lookup envLookup) []byte {
	var dir string
	if d, ok := lookup("AZURE_CONFIG_DIR"); ok && d != "" {
		dir = d
	} else if home, err := os.UserHomeDir(); err == nil {
		dir = filepath.Join(home, ".azure")
	} else {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dir, "config"))
	if err != nil {
		return nil
	}
	return b
}

// ResolveCloudFromEnv resolves the cloud for a configured value, reading the
// AZURE_AUTHORITY_HOST env var and the Azure CLI config only when configured is
// "auto"/empty. Production passes [os.LookupEnv].
func ResolveCloudFromEnv(configured string, lookup envLookup) CloudConfig {
	if name := canonicalizeCloudName(configured); name != "" && name != "auto" {
		return ResolveCloudConfig(configured, "", nil)
	}
	authority, _ := lookup(azureAuthorityHostEnv)
	return ResolveCloudConfig(configured, authority, ReadAzureCLIConfig(lookup))
}
