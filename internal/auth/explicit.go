package auth

import (
	"path/filepath"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

// envSet reports whether lookupEnv returns a non-empty value for key (empty ==
// unset, matching the config layer's AutomaticEnv semantics).
func envSet(lookupEnv func(string) (string, bool), key string) bool {
	v, ok := lookupEnv(key)

	return ok && v != ""
}

// awsExplicitlyConfigured reports whether the host carries an explicit AWS
// credential/config signal. Mere existence of ~/.aws/config is intentionally NOT
// a signal: it commonly holds only a default region with no credentials, which
// would otherwise re-trigger the noise. Credential-bearing config is
// caught via the *_FILE / *_PROFILE env vars, the ~/.aws/credentials file, or a
// credential-declaring [default] profile (defaultProfileHasCreds, computed by the
// shell from ~/.aws/config) — so a default SSO/credential_process/role profile
// counts as explicit while a region-only [default] stays ambient.
func awsExplicitlyConfigured(
	lookupEnv func(string) (string, bool), fileExists func(string) bool, homeDir string, defaultProfileHasCreds bool,
) bool {
	envs := []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_EC2_METADATA_SERVICE_ENDPOINT", "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
	}
	for _, e := range envs {
		if envSet(lookupEnv, e) {
			return true
		}
	}

	if homeDir != "" && fileExists(filepath.Join(homeDir, ".aws", "credentials")) {
		return true
	}

	return defaultProfileHasCreds
}

// sharedConfigHasCreds reports whether a resolved AWS shared-config profile
// declares any credential-bearing field (SSO, credential_process, role chaining,
// web identity, an explicit credential source, or static keys). The shell parses
// ~/.aws/config with the AWS SDK's own grammar (so [profile default] aliasing,
// inline comments, ':'/'=' separators and key casing all match the SDK) and
// passes the resolved SharedConfig here for the pure decision. A region-only
// profile has no such field, so the region-only case stays ambient.
func sharedConfigHasCreds(sc awsconfig.SharedConfig) bool {
	return sc.Credentials.HasKeys() ||
		sc.CredentialSource != "" ||
		sc.CredentialProcess != "" ||
		sc.WebIdentityTokenFile != "" ||
		sc.RoleARN != "" ||
		sc.SourceProfileName != "" ||
		sc.SSOSessionName != "" ||
		sc.SSOStartURL != "" ||
		sc.SSOAccountID != "" ||
		sc.SSORoleName != ""
}

// gcpExplicitlyConfigured reports whether the host carries an explicit GCP ADC
// signal: GOOGLE_APPLICATION_CREDENTIALS, or the well-known gcloud ADC file. It
// mirrors google.FindDefaultCredentials' platform-specific well-known path —
// %APPDATA%\gcloud\... on Windows, $HOME/.config/gcloud/... elsewhere — so a
// Windows-only ADC config still counts as explicit (loud on a broken/revoked ADC).
func gcpExplicitlyConfigured(
	lookupEnv func(string) (string, bool), fileExists func(string) bool, homeDir string,
) bool {
	if envSet(lookupEnv, "GOOGLE_APPLICATION_CREDENTIALS") {
		return true
	}

	const adcFile = "application_default_credentials.json"

	if homeDir != "" && fileExists(filepath.Join(homeDir, ".config", "gcloud", adcFile)) {
		return true
	}

	// Windows well-known ADC path. APPDATA is a Windows env var, so on other
	// platforms this branch is skipped (it stays unset).
	if appData, ok := lookupEnv("APPDATA"); ok && appData != "" {
		return fileExists(filepath.Join(appData, "gcloud", adcFile))
	}

	return false
}

// azureExplicitlyConfigured reports whether the host carries an explicit Azure
// env credential signal. Interactive CLI credentials (az login / azd /
// PowerShell) are deliberately NOT treated as explicit (spec exception 2).
func azureExplicitlyConfigured(lookupEnv func(string) (string, bool)) bool {
	envs := []string{
		"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
		"AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_USERNAME", "AZURE_PASSWORD",
		"AZURE_FEDERATED_TOKEN_FILE",
	}
	for _, e := range envs {
		if envSet(lookupEnv, e) {
			return true
		}
	}

	return false
}

// kubeExplicitlyConfigured reports whether the user explicitly aimed cynative's
// self-managed Kubernetes connector at a target. With discovery now purely
// kubectl-default, the sole explicit signal is the KUBECONFIG env var.
func kubeExplicitlyConfigured(lookupEnv func(string) (string, bool)) bool {
	return envSet(lookupEnv, "KUBECONFIG")
}
