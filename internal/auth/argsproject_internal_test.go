package auth

import (
	"encoding/json"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// noArgs is the absent ProviderArgs, which is what a connector that declares no
// per-call arguments block is handed on every request. Spelling it as a call
// rather than the authreq.ProviderArgs{} literal keeps these gate invocations on
// one line.
func noArgs() authreq.ProviderArgs {
	return authreq.ProviderArgs{}
}

// providerArgs projects a whole http_request tool call down to name's own
// "<name>_auth" block, exactly as the auth dispatchers do before they hand a
// gate its arguments. Tests keep writing the whole tool call, so the projection
// they exercise is the production one: a provider named here that does not own
// the block the call carries sees absent args, and the test fails.
func providerArgs(name, toolCall string) authreq.ProviderArgs {
	return authreq.NewProviderArgs(json.RawMessage(toolCall), name)
}

// marshalArgs is providerArgs for a tool call built as a Go value rather than a
// JSON literal.
func marshalArgs(t *testing.T, name string, toolCall any) authreq.ProviderArgs {
	t.Helper()

	raw, err := json.Marshal(toolCall)
	if err != nil {
		t.Fatalf("marshal tool call: %v", err)
	}

	return authreq.NewProviderArgs(raw, name)
}
