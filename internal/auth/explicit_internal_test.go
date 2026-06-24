package auth

import (
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

func envFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestAWSExplicitlyConfigured(t *testing.T) {
	t.Parallel()

	const home = "/home/u"
	credPath := filepath.Join(home, ".aws", "credentials")
	cfgPath := filepath.Join(home, ".aws", "config")

	cases := []struct {
		name   string
		env    map[string]string
		exists map[string]bool
		want   bool
	}{
		{"nothing", nil, nil, false},
		{"access key id", map[string]string{"AWS_ACCESS_KEY_ID": "AKIA"}, nil, true},
		{"only secret", map[string]string{"AWS_SECRET_ACCESS_KEY": "s"}, nil, true},
		{"only session token", map[string]string{"AWS_SESSION_TOKEN": "t"}, nil, true},
		{"profile", map[string]string{"AWS_PROFILE": "dev"}, nil, true},
		{"default profile", map[string]string{"AWS_DEFAULT_PROFILE": "dev"}, nil, true},
		{"role arn", map[string]string{"AWS_ROLE_ARN": "arn:..."}, nil, true},
		{"web identity", map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/t"}, nil, true},
		{"shared creds file", map[string]string{"AWS_SHARED_CREDENTIALS_FILE": "/c"}, nil, true},
		{"config file env", map[string]string{"AWS_CONFIG_FILE": "/c"}, nil, true},
		{"container relative", map[string]string{"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/x"}, nil, true},
		{"container full", map[string]string{"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://x"}, nil, true},
		{"metadata endpoint", map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT": "http://x"}, nil, true},
		{"metadata endpoint mode", map[string]string{"AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE": "IPv6"}, nil, true},
		{"empty env value is not set", map[string]string{"AWS_PROFILE": ""}, nil, false},
		{"credentials file exists", nil, map[string]bool{credPath: true}, true},
		{"region-only config does NOT count", nil, map[string]bool{cfgPath: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			exists := func(p string) bool { return tc.exists[p] }
			if got := awsExplicitlyConfigured(envFrom(tc.env), exists, home, false); got != tc.want {
				t.Fatalf("awsExplicitlyConfigured = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAWSExplicitlyConfigured_DefaultProfileCreds(t *testing.T) {
	t.Parallel()

	noEnv := envFrom(nil)
	noFile := func(string) bool { return false }

	// A credential-declaring [default] profile makes AWS explicit even with no
	// env and no ~/.aws/credentials; otherwise it stays ambient.
	if !awsExplicitlyConfigured(noEnv, noFile, "/home/u", true) {
		t.Fatal("defaultProfileHasCreds=true must be explicit")
	}
	if awsExplicitlyConfigured(noEnv, noFile, "/home/u", false) {
		t.Fatal("no signal must be ambient")
	}
}

func TestSharedConfigHasCreds(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		sc   awsconfig.SharedConfig
		want bool
	}{
		{"empty", awsconfig.SharedConfig{}, false},
		{"region only", awsconfig.SharedConfig{Region: "us-east-1"}, false},
		{
			"static keys",
			awsconfig.SharedConfig{Credentials: aws.Credentials{AccessKeyID: "AKIA", SecretAccessKey: "s"}},
			true,
		},
		{"credential source", awsconfig.SharedConfig{CredentialSource: "Ec2InstanceMetadata"}, true},
		{"credential process", awsconfig.SharedConfig{CredentialProcess: "/opt/cp"}, true},
		{"web identity", awsconfig.SharedConfig{WebIdentityTokenFile: "/t"}, true},
		{"role arn", awsconfig.SharedConfig{RoleARN: "arn:aws:iam::1:role/x"}, true},
		{"source profile", awsconfig.SharedConfig{SourceProfileName: "base"}, true},
		{"sso session name", awsconfig.SharedConfig{SSOSessionName: "corp"}, true},
		{"sso start url", awsconfig.SharedConfig{SSOStartURL: "https://x.awsapps.com/start"}, true},
		{"sso account+role", awsconfig.SharedConfig{SSOAccountID: "1", SSORoleName: "r"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := sharedConfigHasCreds(tc.sc); got != tc.want {
				t.Fatalf("sharedConfigHasCreds(%+v) = %v, want %v", tc.sc, got, tc.want)
			}
		})
	}
}

func TestGCPExplicitlyConfigured(t *testing.T) {
	t.Parallel()

	const home = "/home/u"
	adc := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
	const appData = `C:\Users\u\AppData\Roaming`
	winAdc := filepath.Join(appData, "gcloud", "application_default_credentials.json")

	cases := []struct {
		name   string
		env    map[string]string
		exists map[string]bool
		want   bool
	}{
		{"nothing", nil, nil, false},
		{"GAC env", map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": "/k.json"}, nil, true},
		{"empty GAC is not set", map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": ""}, nil, false},
		{"adc file exists", nil, map[string]bool{adc: true}, true},
		{"windows ADC via APPDATA", map[string]string{"APPDATA": appData}, map[string]bool{winAdc: true}, true},
		{"APPDATA set but no windows ADC file", map[string]string{"APPDATA": appData}, nil, false},
		{"empty APPDATA ignored", map[string]string{"APPDATA": ""}, map[string]bool{winAdc: true}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			exists := func(p string) bool { return tc.exists[p] }
			if got := gcpExplicitlyConfigured(envFrom(tc.env), exists, home); got != tc.want {
				t.Fatalf("gcpExplicitlyConfigured = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAzureExplicitlyConfigured(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"nothing (interactive-only is NOT explicit)", nil, false},
		{"tenant id", map[string]string{"AZURE_TENANT_ID": "t"}, true},
		{"client id", map[string]string{"AZURE_CLIENT_ID": "c"}, true},
		{"client secret", map[string]string{"AZURE_CLIENT_SECRET": "s"}, true},
		{"client cert path", map[string]string{"AZURE_CLIENT_CERTIFICATE_PATH": "/p"}, true},
		{"username", map[string]string{"AZURE_USERNAME": "u"}, true},
		{"password", map[string]string{"AZURE_PASSWORD": "p"}, true},
		{"federated token file", map[string]string{"AZURE_FEDERATED_TOKEN_FILE": "/f"}, true},
		{"empty value not set", map[string]string{"AZURE_TENANT_ID": ""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := azureExplicitlyConfigured(envFrom(tc.env)); got != tc.want {
				t.Fatalf("azureExplicitlyConfigured = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestKubeExplicitlyConfigured(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		env  map[string]string
		want bool
	}{
		{"nothing", nil, false},
		{"KUBECONFIG env set", map[string]string{"KUBECONFIG": "/k"}, true},
		{"KUBECONFIG empty not set", map[string]string{"KUBECONFIG": ""}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := kubeExplicitlyConfigured(envFrom(tc.env)); got != tc.want {
				t.Fatalf("kubeExplicitlyConfigured = %v, want %v", got, tc.want)
			}
		})
	}
}
