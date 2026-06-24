package azure

import "testing"

func TestCanonicalizeCloudName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{"AzureCloud", "AzureCloud"},
		{"azurecloud", "AzureCloud"}, // case-insensitive.
		{"AzureUSGovernment", "AzureUSGovernment"},
		{"AzureChinaCloud", "AzureChinaCloud"},
		{"azurechinacloud", "AzureChinaCloud"}, // case-insensitive.
		{"", ""},                               // empty passes through (means "no claim").
		{"Bogus", "Bogus"},                     // unknown passes through unchanged (Verify rejects on mismatch).
	}
	for _, tc := range tests {
		if got := canonicalizeCloudName(tc.in); got != tc.want {
			t.Errorf("canonicalizeCloudName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCloudByName(t *testing.T) {
	t.Parallel()

	cc, ok := cloudByName("AzureUSGovernment")
	if !ok {
		t.Fatal("cloudByName(AzureUSGovernment) ok=false")
	}
	if cc.Scope != "https://management.usgovcloudapi.net/.default" ||
		cc.AuthorityHost != "https://login.microsoftonline.us/" {
		t.Errorf("AzureUSGovernment constants wrong: %+v", cc)
	}
	if _, okNope := cloudByName("Nope"); okNope {
		t.Error("cloudByName(Nope) ok=true, want false")
	}
}

func TestResolveCloudConfig(t *testing.T) {
	t.Parallel()

	const govINI = "[cloud]\nname = AzureUSGovernment\n"
	const chinaINI = "[core]\noutput = json\n[cloud]\nname = AzureChinaCloud\n"

	tests := []struct {
		name       string
		configured string
		authority  string
		cliINI     string
		wantName   string
		wantSource string
	}{
		{"explicit gov wins", "AzureUSGovernment", "https://login.microsoftonline.com/", govINI, CloudUSGov, "config"},
		{"explicit china canonical", "AzureChinaCloud", "", "", CloudChina, "config"},
		{"auto env gov", "auto", "https://login.microsoftonline.us/", "", CloudUSGov, "env"},
		{"auto env trailing-slash-insensitive", "auto", "https://login.microsoftonline.us", "", CloudUSGov, "env"},
		{"auto env china", "auto", "https://login.chinacloudapi.cn/", "", CloudChina, "env"},
		{"auto env beats cli", "auto", "https://login.microsoftonline.us/", chinaINI, CloudUSGov, "env"},
		{"auto cli gov", "auto", "", govINI, CloudUSGov, "cli"},
		{"auto cli china other keys", "auto", "", chinaINI, CloudChina, "cli"},
		{
			"auto cli skips non-name keys in [cloud]",
			"auto",
			"",
			"[cloud]\nsubscription = abc\nname = AzureUSGovernment\n",
			CloudUSGov,
			"cli",
		},
		{
			"auto unknown env falls to cli",
			"auto",
			"https://login.partner.microsoftonline.cn/",
			govINI,
			CloudUSGov,
			"cli",
		},
		{
			"auto unknown everything to public",
			"auto",
			"https://weird/",
			"[cloud]\nname = Mars\n",
			CloudPublic,
			"default",
		},
		{"auto nothing to public", "auto", "", "", CloudPublic, "default"},
		{"empty configured treated as auto", "", "", "", CloudPublic, "default"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ResolveCloudConfig(tc.configured, tc.authority, []byte(tc.cliINI))
			if got.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tc.wantName)
			}
			if got.Source != tc.wantSource {
				t.Errorf("Source = %q, want %q", got.Source, tc.wantSource)
			}
		})
	}
}
