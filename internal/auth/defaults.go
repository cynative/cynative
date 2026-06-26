package auth

// Curated read-only default ceilings, mirrored from internal/config's shipped
// defaults so internal/auth need not import internal/config. defaults_internal_test.go
// pins these against config.DefaultConfig() to catch drift. defaultClusterRole
// (the K8s default "view") already lives in k8sgate.go.
const (
	defaultAWSPolicyARN        = "arn:aws:iam::aws:policy/SecurityAudit"
	defaultGCPRole             = "roles/viewer"
	defaultAzureRoleDefinition = "Reader"
)

// Posture token vocabulary (verbatim; see the design spec).
const (
	accessDefault               = "default(read-only)"
	accessCustom                = "custom"
	enforcedClient              = "client"
	enforcedClientAWS           = "client+aws"
	enforcedClientAWSUnverified = "client+aws(unverified)"
)
