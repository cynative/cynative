package aws

const labelDisabled = "disabled"

// CredScopeLabel maps an effective CredScopeMode to its inventory/posture label
// (assume_role | disabled). Pure: no I/O. Exported so the registration inventory
// can render the AWS sts= column from the effective mode.
func CredScopeLabel(m CredScopeMode) string {
	switch m {
	case CredScopeAssumeRole:
		return "assume_role"
	case CredScopeDisabled:
		return labelDisabled
	}
	return labelDisabled
}

// ScopeLabel renders the inventory sts= token from a ScopeResult. It is the
// pure, covered replacement for the label logic previously inlined in the shell's
// resolveScopeAWS. Rules (in order):
//   - disabled with a reason → "disabled (degraded: <reason>)"
//   - disabled without a reason → "disabled"
//   - Verified → CredScopeLabel(r.Mode)  (e.g. "assume_role")
//   - otherwise → CredScopeLabel(r.Mode) + " (unverified)"
//
// Pure: no I/O.
func ScopeLabel(r ScopeResult) string {
	if r.Mode == CredScopeDisabled && r.Reason != "" {
		return labelDisabled + " (degraded: " + r.Reason + ")"
	}
	if r.Mode == CredScopeDisabled {
		return labelDisabled
	}
	if r.Verified {
		return CredScopeLabel(r.Mode)
	}
	return CredScopeLabel(r.Mode) + " (unverified)"
}
