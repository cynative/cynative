package auth

import (
	"slices"
	"strings"

	"github.com/cynative/cynative/internal/apiref"
)

// gitlabRefusedInput reports a request input the gitlab connector rejects whatever the permission level. It reads
// the same names, with the same normalization, as the checks that reject them: the smuggled controls
// (rejectGitLabSmuggledControls), the credential headers and query parameters every connector refuses
// (rejectModelSuppliedCredential) and the body credentials (rejectGitLabBodyCredential).
func gitlabRefusedInput(loc apiref.Location, name string) bool {
	switch loc {
	case apiref.LocationQuery:
		base := baseParamName(name)

		return strings.EqualFold(base, gitlabSudoParam) || strings.EqualFold(base, gitlabTokenParam) ||
			isCredentialParam(name)
	case apiref.LocationHeader:
		return strings.EqualFold(name, gitlabSudoHeader) ||
			slices.ContainsFunc(credentialHeaders, func(h string) bool { return credentialHeaderIs(name, h) })
	case apiref.LocationBody:
		return isGitLabCredentialParam(name)
	case apiref.LocationPath:
	}

	return false
}
