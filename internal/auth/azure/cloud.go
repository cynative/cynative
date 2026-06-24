package azure

import "strings"

// CloudConfig is the resolved per-cloud constant set. It is intentionally
// SDK-free (plain strings): the azcore/cloud.Configuration the credential chain
// and ARM SDK clients consume is built from it by the shell helper ToSDKCloud.
type CloudConfig struct {
	Name          string // canonical: AzureCloud | AzureUSGovernment | AzureChinaCloud.
	ARMEndpoint   string // e.g. "https://management.usgovcloudapi.net".
	Scope         string // e.g. "https://management.usgovcloudapi.net/.default".
	AuthorityHost string // e.g. "https://login.microsoftonline.us/" (AAD authority).
	Source        string // how it was resolved: config | env | cli | default.
}

// Canonical cloud names. We adopt Azure's own vocabulary (az/azd/PowerShell) so
// auto-detection is a direct string match.
const (
	CloudPublic = "AzureCloud"
	CloudUSGov  = "AzureUSGovernment"
	CloudChina  = "AzureChinaCloud"
)

// cloudTable is the immutable per-cloud constant set, keyed by canonical name.
var cloudTable = map[string]CloudConfig{ //nolint:gochecknoglobals // immutable lookup table
	CloudPublic: {
		Name: CloudPublic, ARMEndpoint: "https://management.azure.com",
		Scope:         "https://management.azure.com/.default",
		AuthorityHost: "https://login.microsoftonline.com/",
	},
	CloudUSGov: {
		Name: CloudUSGov, ARMEndpoint: "https://management.usgovcloudapi.net",
		Scope:         "https://management.usgovcloudapi.net/.default",
		AuthorityHost: "https://login.microsoftonline.us/",
	},
	CloudChina: {
		Name: CloudChina, ARMEndpoint: "https://management.chinacloudapi.cn",
		Scope:         "https://management.chinacloudapi.cn/.default",
		AuthorityHost: "https://login.chinacloudapi.cn/",
	},
}

// canonicalizeCloudName maps a cloud-name input (config knob, auto-detect signal,
// or model-supplied azure_auth.cloud) to its canonical form. Empty passes through
// (means "no claim"); an unrecognized non-empty name passes through UNCHANGED so a
// downstream equality check fails closed rather than silently accepting.
func canonicalizeCloudName(name string) string {
	if name == "" {
		return ""
	}
	for canonical := range cloudTable {
		if strings.EqualFold(name, canonical) {
			return canonical
		}
	}
	return name
}

// cloudByName returns the CloudConfig for a canonical-or-alias name.
func cloudByName(name string) (CloudConfig, bool) {
	cc, ok := cloudTable[canonicalizeCloudName(name)]
	return cc, ok
}

// authorityHostToCloud reverse-maps a (trailing-slash-insensitive) AAD authority
// host to a canonical cloud name.
var authorityHostToCloud = map[string]string{ //nolint:gochecknoglobals // immutable lookup table
	"https://login.microsoftonline.com": CloudPublic,
	"https://login.microsoftonline.us":  CloudUSGov,
	"https://login.chinacloudapi.cn":    CloudChina,
}

// ResolveCloudConfig resolves the cloud from (in priority order): an explicit
// non-"auto" configured name; else AZURE_AUTHORITY_HOST (authorityHost); else the
// Azure CLI config's [cloud] name (cliINI); else the public-cloud fallback. The
// env signal outranks the CLI signal because the credential chain tries
// environment/workload-identity credentials before the CLI credential. Pure: the
// caller (shell) supplies the already-read env value and config bytes.
func ResolveCloudConfig(configured, authorityHost string, cliINI []byte) CloudConfig {
	if name := canonicalizeCloudName(configured); name != "" && name != "auto" {
		if cc, ok := cloudTable[name]; ok {
			cc.Source = "config"
			return cc
		}
	}
	if name, ok := cloudFromAuthorityHost(authorityHost); ok {
		cc := cloudTable[name]
		cc.Source = "env"
		return cc
	}
	if name, ok := cloudNameFromCLIConfig(cliINI); ok {
		cc := cloudTable[name]
		cc.Source = "cli"
		return cc
	}
	cc := cloudTable[CloudPublic]
	cc.Source = "default"
	return cc
}

// cloudFromAuthorityHost maps an AZURE_AUTHORITY_HOST value to a known cloud,
// tolerant of a trailing slash. Unknown/empty → (_, false).
func cloudFromAuthorityHost(host string) (string, bool) {
	h := strings.TrimRight(strings.TrimSpace(host), "/")
	if h == "" {
		return "", false
	}
	name, ok := authorityHostToCloud[strings.ToLower(h)]
	return name, ok
}

// cloudNameFromCLIConfig parses the Azure CLI config INI for the [cloud] section's
// name key and canonicalizes it. Returns (_, false) when the section/key is absent
// or the name is unrecognized. Minimal INI scan (the file is operator-trusted; we
// only read one key) — tolerant of surrounding whitespace and other sections.
func cloudNameFromCLIConfig(ini []byte) (string, bool) {
	inCloud := false
	for raw := range strings.SplitSeq(string(ini), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inCloud = strings.EqualFold(strings.TrimSpace(line[1:len(line)-1]), "cloud")
			continue
		}
		if !inCloud {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "name") {
			continue
		}
		if cc, okName := cloudByName(strings.TrimSpace(val)); okName {
			return cc.Name, true
		}
		return "", false // [cloud] name present but unrecognized.
	}
	return "", false
}
