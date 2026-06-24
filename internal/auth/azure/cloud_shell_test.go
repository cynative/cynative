package azure_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"

	azurehardening "github.com/cynative/cynative/internal/auth/azure"
)

func TestToSDKCloud(t *testing.T) {
	t.Parallel()

	cc := azurehardening.ResolveCloudConfig("AzureUSGovernment", "", nil)
	got := azurehardening.ToSDKCloud(cc)
	if got.ActiveDirectoryAuthorityHost != "https://login.microsoftonline.us/" {
		t.Errorf("authority = %q", got.ActiveDirectoryAuthorityHost)
	}
	svc, ok := got.Services[cloud.ResourceManager]
	if !ok {
		t.Fatal("missing ResourceManager service config")
	}
	wantARM := "https://management.usgovcloudapi.net"
	if svc.Endpoint != wantARM || svc.Audience != wantARM {
		t.Errorf("ARM service = %+v", svc)
	}
}

func TestReadAzureCLIConfig_AzureConfigDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(dir, "config"),
		[]byte("[cloud]\nname = AzureChinaCloud\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	lookup := func(k string) (string, bool) {
		if k == "AZURE_CONFIG_DIR" {
			return dir, true
		}

		return "", false
	}
	// End-to-end: ReadAzureCLIConfig feeds the resolver, which must pick China via cli.
	got := azurehardening.ResolveCloudFromEnv("auto", lookup)
	if got.Name != azurehardening.CloudChina || got.Source != "cli" {
		t.Errorf("resolved = %+v, want China via cli", got)
	}
	// And the raw read returns the file bytes.
	if raw := azurehardening.ReadAzureCLIConfig(lookup); len(raw) == 0 {
		t.Error("ReadAzureCLIConfig returned no bytes")
	}
}

func TestResolveCloudFromEnv_ExplicitConfigSkipsReads(t *testing.T) {
	t.Parallel()

	lookup := func(string) (string, bool) { return "", false }
	got := azurehardening.ResolveCloudFromEnv("AzureUSGovernment", lookup)
	if got.Name != azurehardening.CloudUSGov || got.Source != "config" {
		t.Errorf("got %+v", got)
	}
}
