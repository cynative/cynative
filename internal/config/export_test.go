package config

import "github.com/go-playground/validator/v10"

// ErrMsg is an exported alias for errMsg, used only by tests.
var ErrMsg = errMsg //nolint:gochecknoglobals // test export

// ErrMsgFromType is an exported alias for errMsgFromType, used only by tests.
var ErrMsgFromType = errMsgFromType //nolint:gochecknoglobals // test export

// ValidateGCPRole is an exported alias for validateGCPRole, used only by tests.
var ValidateGCPRole = validateGCPRole //nolint:gochecknoglobals // test export

// FormatValidationErrors wraps formatValidationErrors for testing,
// accepting []FieldError so test stubs can be passed in.
func FormatValidationErrors(errs []validator.FieldError) string {
	return formatValidationErrors(validator.ValidationErrors(errs))
}

// ValidateConfig exposes validateConfig so tests can inject a validateStruct
// stub that returns a non-ValidationErrors error (the defensive branch).
func ValidateConfig(c Config, validateStruct func(any) error) error {
	return validateConfig(c, validateStruct)
}

// WithHomeDir overrides a Loader's home-directory resolver so tests can point
// the default config path at a temp dir (or force a failure) without touching
// the real home directory.
func WithHomeDir(fn func() (string, error)) LoaderOption {
	return func(l *Loader) { l.homeDir = fn }
}

// ExpandTilde exposes expandTilde for unit tests.
func ExpandTilde(path string, homeDir func() (string, error)) (string, error) {
	return expandTilde(path, homeDir)
}

// ValidateClusterRoleName re-exports validateClusterRoleName for tests.
var ValidateClusterRoleName = validateClusterRoleName //nolint:gochecknoglobals // test export

// ValidateGitLabHost re-exports validateGitLabHost for tests.
var ValidateGitLabHost = validateGitLabHost //nolint:gochecknoglobals // test export

// StubFieldError implements validator.FieldError for testing edge cases.
type StubFieldError struct {
	validator.FieldError

	NamespaceVal string
	TagVal       string
}

func (s StubFieldError) Namespace() string { return s.NamespaceVal }
func (s StubFieldError) Tag() string       { return s.TagVal }

// EnvKeys re-exports envKeys so tests can pin what does — and does not — get a
// CYNATIVE_* alias.
var EnvKeys = envKeys //nolint:gochecknoglobals // test export

// StructEnvKeys re-exports structEnvKeys so tests can walk a synthetic struct.
var StructEnvKeys = structEnvKeys //nolint:gochecknoglobals // test export

// RegisterStructDefaults re-exports registerStructDefaults for the same reason.
var RegisterStructDefaults = registerStructDefaults //nolint:gochecknoglobals // test export
