// Package config handles all application configuration — loading from files,
// environment variables, and defaults — and unmarshaling into typed structs.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/creasty/defaults"
	"github.com/go-playground/validator/v10"
	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	gcphardening "github.com/cynative/cynative/internal/auth/gcp"
	"github.com/cynative/cynative/internal/llm"
)

// validate is the singleton validator instance.
var validate = validator.New(validator.WithRequiredStructEnabled()) //nolint:gochecknoglobals // singleton

var (
	// ErrLLMProviderMissing means no llm.provider was configured (first-run case).
	ErrLLMProviderMissing = errors.New("llm.provider is required — set CYNATIVE_LLM_PROVIDER or 'llm.provider'")
	// ErrLLMModelMissing means a provider was set but no llm.model.
	ErrLLMModelMissing = errors.New("llm.model is required — set CYNATIVE_LLM_MODEL or 'llm.model'")
)

// AWSConfig holds AWS-specific hardening configuration.
type AWSConfig struct {
	Policy string `mapstructure:"policy" json:"policy" default:"arn:aws:iam::aws:policy/SecurityAudit" validate:"required,startswith=arn:aws:iam:" errmsg:"connectors.aws.policy must be an IAM policy ARN (e.g. arn:aws:iam::aws:policy/SecurityAudit)"` //nolint:lll // struct tags
}

// GCPConfig holds GCP-specific hardening configuration. Role mirrors aws.policy:
// the single role the Layer-2 action-authorization evaluator authorizes each
// request against (default roles/viewer). Accepts a predefined role (roles/<id>)
// or a custom role (projects/<p>/roles/<r>, organizations/<o>/roles/<r>); the
// form is validated by validateGCPRole.
type GCPConfig struct {
	Role string `mapstructure:"role" json:"role" default:"roles/viewer" validate:"required" errmsg:"connectors.gcp.role must be a predefined role (roles/<id>) or a custom role (projects/<p>/roles/<r> or organizations/<o>/roles/<r>)"` //nolint:lll // struct tags
}

// validateGCPRole checks connectors.gcp.role is a predefined or custom role
// reference, delegating to the authoritative gcp.ParseRoleReference. Empty is
// left to the `required` struct tag.
func validateGCPRole(role string) error {
	if role == "" {
		return nil // the `required` tag reports the empty case.
	}
	if _, err := gcphardening.ParseRoleReference(role); err != nil {
		return fmt.Errorf(
			"connectors.gcp.role must be a predefined role (roles/<id>) or a custom role "+
				"(projects/<p>/roles/<r> or organizations/<o>/roles/<r>), got %q", role,
		)
	}
	return nil
}

// AzureConfig holds Azure-specific hardening configuration. RoleDefinition
// mirrors gcp.role and aws.policy: the single predefined RBAC role the Layer-2
// action-authorization evaluator authorizes each request against (default
// Reader). Azure has no credential-downscoping primitive, so RoleDefinition is
// the sole role-definition enforcement.
type AzureConfig struct {
	RoleDefinition string `mapstructure:"role_definition" json:"role_definition" default:"Reader" validate:"required"                                                         errmsg:"connectors.azure.role_definition must be an Azure RBAC role name or role-definition GUID (e.g. Reader)"` //nolint:lll // struct tags
	Cloud          string `mapstructure:"cloud"           json:"cloud"           default:"auto"   validate:"required,oneof=auto AzureCloud AzureUSGovernment AzureChinaCloud" errmsg:"connectors.azure.cloud must be one of: auto, AzureCloud, AzureUSGovernment, AzureChinaCloud"`            //nolint:lll // struct tags
}

// ClusterRoleConfig is the shared per-connector Kubernetes hardening block used
// by the eks/gke/aks/kubernetes connectors. ClusterRole mirrors the cloud
// connectors' policy/role knobs: the read-only ClusterRole the Kubernetes
// authorization gate derives its allow-policy from (default "view"). The managed
// K8s connectors and the generic/self-managed kubernetes connector all discover
// their cluster from credentials/kubeconfig; like github they do not use the
// top-level cache: block (the ClusterRole policy is cached in memory only).
type ClusterRoleConfig struct {
	ClusterRole string `mapstructure:"cluster_role" json:"cluster_role" default:"view"`
}

// GithubConfig holds GitHub-specific hardening configuration. permissions is a
// category[/subcategory] → read|write|none map; an empty map means the secure
// baseline (read-only, secret-scanning blocked) applied downstream. Besides the
// YAML/JSON map form, it accepts a compact CYNATIVE_CONNECTORS_GITHUB_PERMISSIONS
// scalar ("default=read,issues=write,secret-scanning=none") split by
// [llm.StringToStringMapHookFunc]; a non-empty env value replaces the file map
// wholesale (a blank value is treated as unset, leaving the file map in place).
type GithubConfig struct {
	Permissions map[string]string `mapstructure:"permissions" json:"permissions"`
}

// GitLabConfig holds GitLab-specific hardening configuration. host defaults to
// gitlab.com; permissions is a category → read|write|none map (empty = the secure
// baseline: read-only, ci-variables blocked) applied downstream. Like github's
// permissions it accepts a compact CYNATIVE_CONNECTORS_GITLAB_PERMISSIONS scalar
// ("default=read,issues=write,ci-variables=none") split by the env decode hook.
type GitLabConfig struct {
	Host                string            `mapstructure:"host"                  json:"host"                  default:"gitlab.com"`
	APIHost             string            `mapstructure:"api_host"              json:"api_host"              default:""`
	AllowPrivateNetwork bool              `mapstructure:"allow_private_network" json:"allow_private_network" default:"false"`
	CACert              string            `mapstructure:"ca_cert"               json:"ca_cert"               default:""`
	Permissions         map[string]string `mapstructure:"permissions"           json:"permissions"`
}

// CacheConfig configures the shared on-disk cache for connector hardening
// metadata (service catalogs, IAM datasets, model archives). It is pure data;
// per-consumer namespacing happens at the composition root, and a generic
// namespacing API is deferred to internal/cache.
type CacheConfig struct {
	Dir string        `mapstructure:"dir" json:"dir" default:"~/.cynative/cache" errmsg:"cache.dir must be a writable directory path"`                          //nolint:lll // struct tags
	TTL time.Duration `mapstructure:"ttl" json:"ttl" default:"24h"               errmsg:"cache.ttl must be at least 1m (Go duration syntax)" validate:"min=1m"` //nolint:lll // struct tags
}

// AuditConfig configures the persistent tool-call audit log. It is on by default;
// set enabled:false to disable. Like cache:, it is a top-level block, not under
// connectors:.
type AuditConfig struct {
	Enabled       bool   `mapstructure:"enabled"        json:"enabled"        default:"true"`
	Path          string `mapstructure:"path"           json:"path"           default:"~/.cynative/audit.log" errmsg:"audit.path must be a writable file path"`                  //nolint:lll // struct tags
	MaxSizeMB     int    `mapstructure:"max_size_mb"    json:"max_size_mb"    default:"100"                   errmsg:"audit.max_size_mb must be at least 1"    validate:"min=1"` //nolint:lll // struct tags
	RetentionDays int    `mapstructure:"retention_days" json:"retention_days" default:"30"                    errmsg:"audit.retention_days must be at least 1" validate:"min=1"` //nolint:lll // struct tags
	Compress      bool   `mapstructure:"compress"       json:"compress"       default:"false"`
}

// ConnectorsConfig groups the per-connector hardening blocks under the
// top-level `connectors:` key.
type ConnectorsConfig struct {
	Github     GithubConfig      `mapstructure:"github"     json:"github"`
	GitLab     GitLabConfig      `mapstructure:"gitlab"     json:"gitlab"`
	AWS        AWSConfig         `mapstructure:"aws"        json:"aws"`
	EKS        ClusterRoleConfig `mapstructure:"eks"        json:"eks"`
	GCP        GCPConfig         `mapstructure:"gcp"        json:"gcp"`
	GKE        ClusterRoleConfig `mapstructure:"gke"        json:"gke"`
	Azure      AzureConfig       `mapstructure:"azure"      json:"azure"`
	AKS        ClusterRoleConfig `mapstructure:"aks"        json:"aks"`
	Kubernetes ClusterRoleConfig `mapstructure:"kubernetes" json:"kubernetes"`
}

// Config holds the application configuration, unmarshaled from Viper.
type Config struct {
	LLM                    llm.ProviderEntry `mapstructure:"llm"                      json:"llm"`
	Cache                  CacheConfig       `mapstructure:"cache"                    json:"cache"`
	Audit                  AuditConfig       `mapstructure:"audit"                    json:"audit"`
	Connectors             ConnectorsConfig  `mapstructure:"connectors"               json:"connectors"`
	RenderStyle            string            `mapstructure:"render_style"             json:"render_style"             default:"adaptive" validate:"required,oneof=adaptive notty" errmsg:"render style must be one of: adaptive, notty"`                                                                                                            //nolint:lll // struct tags
	MaxIterations          int               `mapstructure:"max_iterations"           json:"max_iterations"           default:"32"       validate:"min=1"                         errmsg:"max_iterations must be at least 1 (defaults to 32; check your override in CYNATIVE_MAX_ITERATIONS or 'max_iterations')"`                                  //nolint:lll // struct tags
	MaxSubagentIterations  int               `mapstructure:"max_subagent_iterations"  json:"max_subagent_iterations"  default:"10"       validate:"min=1"                         errmsg:"max_subagent_iterations must be at least 1 (defaults to 10; check your override in CYNATIVE_MAX_SUBAGENT_ITERATIONS or 'max_subagent_iterations')"`       //nolint:lll // struct tags
	SandboxMaxConcurrency  int               `mapstructure:"sandbox_max_concurrency"  json:"sandbox_max_concurrency"  default:"16"       validate:"min=1,max=64"                  errmsg:"sandbox_max_concurrency must be between 1 and 64 (defaults to 16; check your override in CYNATIVE_SANDBOX_MAX_CONCURRENCY or 'sandbox_max_concurrency')"` //nolint:lll // struct tags
	MaxTotalTokens         int               `mapstructure:"max_total_tokens"         json:"max_total_tokens"         default:"0"        validate:"min=0"                         errmsg:"max_total_tokens must be 0 (unbounded) or a positive token ceiling (env CYNATIVE_MAX_TOTAL_TOKENS or 'max_total_tokens')"`                                //nolint:lll // struct tags
	MaxConsecutiveFailures int               `mapstructure:"max_consecutive_failures" json:"max_consecutive_failures" default:"5"        validate:"min=0"                         errmsg:"max_consecutive_failures must be 0 (disabled) or a positive count (env CYNATIVE_MAX_CONSECUTIVE_FAILURES or 'max_consecutive_failures')"`                 //nolint:lll // struct tags
}

// DefaultConfig returns the configuration populated from struct default tags.
func DefaultConfig() Config {
	var cfg Config

	// defaults.Set cannot fail on simple string fields.
	_ = defaults.Set(&cfg)

	return cfg
}

// defaultLLMMaxRetries is cynative's retry budget for LLM calls, replacing
// Bifrost's default of 0 retries, under which a single transient 429/5xx or
// network error fails the turn (and a one-shot run outright). Bifrost retries
// only retryable failures (HTTP 429/500/502/503/504, provider errors it
// recognizes as rate limits, and transport errors) with exponential backoff
// (its 500ms-initial/5s-max backoff defaults fill any unset backoff fields).
// An explicit llm.network_config.max_retries in the file or env (including 0
// to disable retries) wins over this default via viper layering; a negative
// value is rejected by llm.ValidateNetworkConfig.
const defaultLLMMaxRetries = 3

// setDefaults registers default values into Viper so fields with `default`
// struct tags take effect when neither the config file nor an env var sets
// them. Top-level scalar fields are registered directly under their json key.
// Top-level struct-typed fields (e.g. Connectors) are handed to
// registerStructDefaults, which recurses through nested structs so every leaf
// default reaches viper under its full dotted key (e.g. connectors.aws.policy).
//
// The LLM block's env keys (provider, model, and every nested leaf) are
// resolved separately by applyEnv in Load. It carries no `default` struct tags
// (ProviderEntry embeds Bifrost's ProviderConfig, whose fields cynative cannot
// tag), so its one cynative-owned default is registered by hand below.
func setDefaults(v *viper.Viper) {
	cfg := DefaultConfig()
	val := reflect.ValueOf(cfg)
	t := val.Type()

	for i := range t.NumField() {
		field := t.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if field.Type.Kind() == reflect.Struct && name != "llm" {
			registerStructDefaults(v, name, val.Field(i))

			continue
		}
		if field.Tag.Get("default") == "" {
			continue
		}
		v.SetDefault(name, val.Field(i).Interface())
	}

	v.SetDefault("llm.network_config.max_retries", defaultLLMMaxRetries)
}

// registerStructDefaults walks the fields of a nested Config struct (e.g.
// Connectors, or connectors.AWS) and registers each scalar leaf under its full
// dotted `<prefix>.<child>` key in viper. It recurses through nested structs
// (Connectors → AWS/GCP/Azure/Github → fields) so a leaf such as
// connectors.aws.policy lands under its full key rather than a struct value
// being registered at connectors.aws. [time.Duration] is Int64-kinded, so it is
// not mistaken for a struct and falls through to SetDefault.
//
// [time.Duration] values are stored in their .String() form (e.g. "24h") so the
// project's strict duration decode-hook chain (which rejects non-string
// duration inputs) accepts them on unmarshal.
func registerStructDefaults(v *viper.Viper, prefix string, val reflect.Value) {
	t := val.Type()
	for i := range t.NumField() {
		field := t.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		key := prefix + "." + name
		if field.Type.Kind() == reflect.Map {
			// Maps (e.g. connectors.github.permissions, connectors.gitlab.permissions)
			// have no scalar default to register; their compact CYNATIVE_* env form is
			// resolved on the env-key path (applyEnv) and split by the decode-hook
			// chain, not via a viper default.
			continue
		}
		if field.Type.Kind() == reflect.Struct {
			registerStructDefaults(v, key, val.Field(i))

			continue
		}
		v.SetDefault(key, defaultValueForViper(val.Field(i)))
	}
}

// defaultValueForViper returns the value to hand viper.SetDefault. Most types
// pass through; [time.Duration] is rendered as its string form so the strict
// duration decode-hook accepts it (it rejects raw int64).
func defaultValueForViper(v reflect.Value) any {
	if v.Type() == reflect.TypeFor[time.Duration]() {
		d, _ := v.Interface().(time.Duration)

		return d.String()
	}

	return v.Interface()
}

// errMsg returns the `errmsg` struct tag for the field that caused the
// validation error, walking through the type hierarchy via the namespace.
// Returns an empty string when the tag is absent.
func errMsg(fe validator.FieldError) string {
	return errMsgFromType(fe, reflect.TypeFor[Config]())
}

// errMsgFromType walks the struct hierarchy rooted at t using the field
// namespace from fe, returning the first "errmsg" tag found. Pointer types are
// dereferenced so fields on pointer-to-struct types are reachable.
func errMsgFromType(fe validator.FieldError, t reflect.Type) string {
	// Namespace looks like "Config.LLM.Model" — the first segment is the
	// root struct name, subsequent segments are field names.
	parts := strings.Split(fe.Namespace(), ".")
	if len(parts) < 2 { //nolint:mnd // root + at least one field
		return ""
	}

	for _, name := range parts[1:] {
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}

		if t.Kind() != reflect.Struct {
			return ""
		}

		f, ok := t.FieldByName(name)
		if !ok {
			return ""
		}

		if msg := f.Tag.Get("errmsg"); msg != "" {
			return msg
		}

		t = f.Type
	}

	return ""
}

// formatValidationErrors translates validator.ValidationErrors into
// user-friendly messages, one per line.
func formatValidationErrors(errs validator.ValidationErrors) string {
	var b strings.Builder

	for i, fe := range errs {
		if i > 0 {
			b.WriteByte('\n')
		}

		if msg := errMsg(fe); msg != "" {
			b.WriteString("  • " + msg)
		} else {
			// Fallback for any field without an errmsg tag.
			fmt.Fprintf(&b, "  • %s failed validation (%s)", fe.Namespace(), fe.Tag())
		}
	}

	return b.String()
}

// validateClusterRoleName rejects ClusterRole names that are empty or unsafe as a
// URL path segment (the name is interpolated into the clusterroles fetch path).
// ':' is allowed so built-in system: roles and custom roles pass.
func validateClusterRoleName(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must be a valid Kubernetes ClusterRole name (must not be empty)", field)
	}
	if value == "." || value == ".." {
		return fmt.Errorf("%s must be a valid Kubernetes ClusterRole name (not %q)", field, value)
	}
	for _, r := range value {
		if r == '/' || r == '%' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return fmt.Errorf(
				"%s must be a valid Kubernetes ClusterRole name (no '/', '%%', or whitespace): %q",
				field, value,
			)
		}
	}

	return nil
}

// githubPermKeyRE matches a valid permissions key: "default", a category, or
// "category/subcategory".
var githubPermKeyRE = regexp.MustCompile(
	`^(default|[a-z][a-z-]+(/[a-z][a-z-]+)?)$`,
)

// githubLevels is the set of valid permission values (kept local so config does
// not depend on the auth/github package).
//
//nolint:gochecknoglobals // immutable lookup table.
var githubLevels = map[string]bool{
	"read":  true,
	"write": true,
	"none":  true,
}

// validateGithubPermissions checks each configured permissions key/value is
// well-formed. It does not require "default" (the baseline supplies it) and does
// not check keys against live GitHub categories (that is the provider's
// table-time, fail-closed job).
func validateGithubPermissions(cfg Config) error {
	for key, val := range cfg.Connectors.Github.Permissions {
		if !githubLevels[val] {
			return fmt.Errorf("connectors.github.permissions[%q] must be read|write|none, got %q", key, val)
		}
		if !githubPermKeyRE.MatchString(key) {
			return fmt.Errorf("connectors.github.permissions key %q is malformed "+
				"(want default, a category, or category/subcategory)", key)
		}
	}

	return nil
}

// gitlabPermKeyRE matches a valid gitlab permissions key: "default" or a
// normalized-tag category (lowercase alphanumeric with single hyphens). GitLab
// has no subcategory layer, so no "/" form.
var gitlabPermKeyRE = regexp.MustCompile(
	`^(default|[a-z0-9]+(-[a-z0-9]+)*)$`,
)

// validateGitLabPermissions checks each configured gitlab permissions key/value
// is well-formed. It reuses the github read|write|none value set and does not
// check keys against live GitLab categories (that is the provider's table-time,
// fail-closed job).
func validateGitLabPermissions(cfg Config) error {
	for key, val := range cfg.Connectors.GitLab.Permissions {
		if !githubLevels[val] { // reuse the read|write|none set.
			return fmt.Errorf("connectors.gitlab.permissions[%q] must be read|write|none, got %q", key, val)
		}
		if !gitlabPermKeyRE.MatchString(key) {
			return fmt.Errorf("connectors.gitlab.permissions key %q is malformed (want default or a category)", key)
		}
	}
	return nil
}

// validateClusterRoleNames checks every connector's configured cluster_role is
// non-empty and a safe URL path segment; empty values are rejected by
// validateClusterRoleName's empty-rejection branch (not struct required tags).
func validateClusterRoleNames(cfg Config) error {
	for _, cr := range []struct{ field, value string }{
		{"connectors.eks.cluster_role", cfg.Connectors.EKS.ClusterRole},
		{"connectors.gke.cluster_role", cfg.Connectors.GKE.ClusterRole},
		{"connectors.aks.cluster_role", cfg.Connectors.AKS.ClusterRole},
		{"connectors.kubernetes.cluster_role", cfg.Connectors.Kubernetes.ClusterRole},
	} {
		if err := validateClusterRoleName(cr.field, cr.value); err != nil {
			return err
		}
	}

	return nil
}

// validateGitLabHost rejects a connectors.gitlab host that is not a bare
// hostname or a hostname with an optional numeric :port (self-managed GitLab
// served on a non-443 port). It is interpolated into request/probe URLs and host
// pinning. allowEmpty=true permits the optional api_host to be unset.
func validateGitLabHost(field, host string, allowEmpty bool) error {
	if host == "" {
		if allowEmpty {
			return nil
		}

		return fmt.Errorf("%s must be a hostname (e.g. gitlab.com)", field)
	}

	if strings.ContainsAny(host, "/ ") || strings.Contains(host, "://") {
		return fmt.Errorf("%s must be a bare hostname, not a URL: %q", field, host)
	}

	// A colon is permitted only as a host:port separator with a numeric port
	// (e.g. gitlab.internal:8443); anything else with a colon is rejected.
	if strings.Contains(host, ":") {
		hostname, port, err := net.SplitHostPort(host)
		if err != nil || hostname == "" || !validTCPPort(port) {
			return fmt.Errorf("%s must be a bare hostname or host:port, not %q", field, host)
		}
	}

	return nil
}

// validTCPPort reports whether port is a canonical decimal integer in the valid
// TCP port range 1-65535. The canonical round-trip check rejects
// [strconv.Atoi]-accepted-but-URL-invalid forms like "+443" and "08443", which
// would pass validation yet make [url.Parse] fail at request/probe time.
func validTCPPort(port string) bool {
	n, err := strconv.Atoi(port)

	return err == nil && n >= 1 && n <= 65535 && port == strconv.Itoa(n)
}

// validateGitLabConfig validates the host/api_host fields. It is split out of
// Load to keep Load's cognitive complexity in budget.
func validateGitLabConfig(cfg *Config) error {
	if err := validateGitLabHost("connectors.gitlab.host", cfg.Connectors.GitLab.Host, false); err != nil {
		return err
	}

	return validateGitLabHost("connectors.gitlab.api_host", cfg.Connectors.GitLab.APIHost, true)
}

// Validate checks the Config against its struct validation tags.
func (c Config) Validate() error {
	return validateConfig(c, validate.Struct)
}

// validateConfig runs validateStruct against c and renders friendly messages.
// It is separated from Validate so tests can inject a validateStruct stub that
// returns a non-ValidationErrors error, exercising the defensive branch below.
func validateConfig(c Config, validateStruct func(any) error) error {
	if err := validateStruct(c); err != nil {
		// validate.Struct on a struct value always returns validator.ValidationErrors.
		var validationErrs validator.ValidationErrors
		if !errors.As(err, &validationErrs) {
			return fmt.Errorf("config validation failed: %w", err)
		}

		return fmt.Errorf("invalid configuration:\n%s", formatValidationErrors(validationErrs))
	}

	return nil
}

// Loader reads and validates configuration. Its outside-world collaborators —
// environment lookup and home-directory resolution — are injected so loading is
// hermetic and parallel-safe; NewLoader wires the real implementations.
type Loader struct {
	env     llm.LookupEnv
	homeDir func() (string, error)
}

// LoaderOption customizes a Loader; tests use these to inject fakes.
type LoaderOption func(*Loader)

// NewLoader returns a Loader that resolves CYNATIVE_* and canonical-env
// variables through env and the home directory via [os.UserHomeDir].
func NewLoader(env llm.LookupEnv, opts ...LoaderOption) *Loader {
	l := &Loader{env: env, homeDir: os.UserHomeDir}
	for _, opt := range opts {
		opt(l)
	}

	return l
}

// applyEnv resolves each CYNATIVE_* environment variable through env and sets
// the matching config key on v. This replaces viper.AutomaticEnv (which reads
// [os.Getenv] directly and so cannot be injected); a present env var overrides
// the config file, matching AutomaticEnv's precedence.
func applyEnv(v *viper.Viper, env llm.LookupEnv) {
	for _, key := range envKeys() {
		name := "CYNATIVE_" + strings.ToUpper(strings.ReplaceAll(key, ".", "_"))
		// An empty or whitespace-only value counts as unset, so a blank env var
		// never silently overrides the config file or default (this matters for the
		// github permissions map, where a blank value would otherwise wholesale-wipe
		// the file map to the baseline). viper.AutomaticEnv treats only an
		// exact-empty value as unset; we additionally trim whitespace.
		if val, ok := env(name); ok && strings.TrimSpace(val) != "" {
			v.Set(key, val)
		}
	}
}

// envKeys returns every config key settable from a CYNATIVE_* env var: each
// bindable ProviderEntry leaf, every nested non-llm leaf (including the
// connectors.github.permissions string-map leaf, split from a compact
// "k=v,k2=v2" value on unmarshal), and every top-level scalar Config field.
func envKeys() []string {
	keys := llm.ProviderEnvKeys()

	for field := range reflect.TypeFor[Config]().Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "llm" {
			continue
		}
		if field.Type.Kind() == reflect.Struct {
			keys = append(keys, structEnvKeys(field.Type, name)...)

			continue
		}
		keys = append(keys, name)
	}

	return keys
}

// structEnvKeys returns the dotted json-tag path of every leaf reachable from a
// nested config struct t, rooted at prefix. It recurses through nested structs
// (connectors → aws → policy) so each leaf lands under its full key;
// [time.Duration] is Int64-kinded and is treated as a leaf. A map[string]string
// leaf (e.g. connectors.github.permissions, connectors.gitlab.permissions) is
// bindable too: its compact "k=v,k2=v2" CYNATIVE_* value is split by
// [llm.StringToStringMapHookFunc] on unmarshal, so it is enumerated here like any
// other leaf.
func structEnvKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for field := range t.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		key := prefix + "." + name
		if field.Type.Kind() == reflect.Struct {
			keys = append(keys, structEnvKeys(field.Type, key)...)

			continue
		}
		keys = append(keys, key)
	}

	return keys
}

// ValidateLLM runs the LLM-block checks the struct tags cannot express: required
// provider/model presence and the llm package's provider/key/env/reasoning
// validators. It is called by the CLI to classify the LLM startup status — it is
// NOT called by Load, so a missing/invalid LLM block no longer hard-fails config
// loading (the CLI renders it as an LLM status block instead).
func ValidateLLM(entry *llm.ProviderEntry) error {
	if entry.Provider == "" {
		return ErrLLMProviderMissing
	}

	if err := llm.ValidateProvider(entry); err != nil {
		return err
	}

	if entry.Model == "" {
		return ErrLLMModelMissing
	}

	if err := llm.ValidateKeyConfigs(entry); err != nil {
		return err
	}

	if err := llm.ValidateEnvVars(entry); err != nil {
		return err
	}

	if err := llm.ValidateKeyPresence(entry); err != nil {
		return err
	}

	if err := llm.ValidateNetworkConfig(entry); err != nil {
		return err
	}

	return llm.ValidateReasoning(entry)
}

// Load reads configuration from cfgFile (or the default location when empty),
// merges CYNATIVE_* environment variables resolved through the Loader's env,
// and returns the populated Config.
func (l *Loader) Load(cfgFile string) (Config, error) {
	v := viper.New()
	setDefaults(v)

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := l.homeDir()
		if err != nil {
			return Config{}, fmt.Errorf("failed to get home directory: %w", err)
		}

		v.AddConfigPath(filepath.Join(home, ".cynative"))
		v.SetConfigType("yaml")
		v.SetConfigName("config")
	}

	applyEnv(v, l.env)

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if cfgFile != "" || !errors.As(err, &notFound) {
			return Config{}, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(
		&cfg,
		viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
			llm.RejectNonStringDurationHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			llm.StringToStringMapHookFunc(),
			llm.StringToEnvVarHookFunc(l.env),
			llm.StringToEnvVarPtrHookFunc(l.env),
		)),
		func(c *mapstructure.DecoderConfig) { c.TagName = "json" },
	); err != nil {
		return Config{}, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if err := detectAliasConflicts(&cfg.LLM); err != nil {
		return Config{}, err
	}

	materializeLLM(&cfg.LLM, l.env)

	expandedCacheDir, expandErr := expandTilde(cfg.Cache.Dir, l.homeDir)
	if expandErr != nil {
		return Config{}, fmt.Errorf("expand cache.dir: %w", expandErr)
	}

	cfg.Cache.Dir = expandedCacheDir

	expandedAuditPath, expandErr := expandTilde(cfg.Audit.Path, l.homeDir)
	if expandErr != nil {
		return Config{}, fmt.Errorf("expand audit.path: %w", expandErr)
	}

	cfg.Audit.Path = expandedAuditPath

	if err := validateGCPRole(cfg.Connectors.GCP.Role); err != nil {
		return Config{}, err
	}

	if err := validateClusterRoleNames(cfg); err != nil {
		return Config{}, err
	}

	if err := validateGithubPermissions(cfg); err != nil {
		return Config{}, err
	}

	if err := validateGitLabConfig(&cfg); err != nil {
		return Config{}, err
	}

	if err := validateGitLabPermissions(cfg); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

// expandTilde replaces a leading "~" or "~/" in path with the home directory
// returned by homeDir. Other forms (e.g. "~user/foo") are returned unchanged
// so users with unusual paths are not surprised.
func expandTilde(path string, homeDir func() (string, error)) (string, error) {
	if path == "" || (path != "~" && !strings.HasPrefix(path, "~/")) {
		return path, nil
	}

	home, err := homeDir()
	if err != nil {
		return "", fmt.Errorf("home directory: %w", err)
	}

	if path == "~" {
		return home, nil
	}

	return filepath.Join(home, path[2:]), nil
}
