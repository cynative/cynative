package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"

	"github.com/cynative/cynative/internal/auth/authreq"
)

// narrowingToolCall is a whole http_request tool call: the request fields, a
// sibling connector's block, and the spy's own block. Every dispatcher is fed
// this, and the spy must only ever see the "spy_auth" half.
const narrowingToolCall = `{
	"method": "POST",
	"url": "https://api.example.com/secrets",
	"auth_provider": "spy",
	"body": "{\"password\":\"hunter2\"}",
	"gcp_auth": {"service": "compute"},
	"spy_auth": {"marker": "mine"}
}`

// leakShape decodes what a gate must NOT be able to reach alongside the field it
// may. Every field but Marker names something outside the spy's own block: the
// request the narrowed authreq.View exists to be the single source for, and a
// sibling connector's arguments.
type leakShape struct {
	Marker       string          `json:"marker"`
	Method       string          `json:"method"`
	URL          string          `json:"url"`
	AuthProvider string          `json:"auth_provider"`
	Body         string          `json:"body"`
	GCPAuth      json.RawMessage `json:"gcp_auth"`
	SpyAuth      json.RawMessage `json:"spy_auth"`
}

// spyArgsProvider records the arguments handed to each capability so one tool
// call can be driven through every dispatcher.
type spyArgsProvider struct {
	seen map[string]authreq.ProviderArgs
}

func newSpyArgsProvider() *spyArgsProvider {
	return &spyArgsProvider{seen: map[string]authreq.ProviderArgs{}}
}

func (p *spyArgsProvider) record(capability string, args authreq.ProviderArgs) {
	p.seen[capability] = args
}

// Name is deliberately capitalized: the dispatchers derive the args key from
// this value, so a provider that does not spell its own name in lower case must
// still reach its lower-case "spy_auth" block.
func (p *spyArgsProvider) Name() string { return "SPY" }

func (p *spyArgsProvider) Description() string { return "records the args each capability receives" }

func (p *spyArgsProvider) InjectAuth(_ *http.Request, args authreq.ProviderArgs) error {
	p.record("InjectAuth", args)

	return nil
}

func (p *spyArgsProvider) AuthorizesHost(_ context.Context, _ string, args authreq.ProviderArgs) (bool, error) {
	p.record("AuthorizesHost", args)

	return true, nil
}

func (p *spyArgsProvider) AuthorizesAddr(_ context.Context, _ netip.Addr, args authreq.ProviderArgs) (bool, error) {
	p.record("AuthorizesAddr", args)

	return true, nil
}

func (p *spyArgsProvider) AuthorizeAction(_ context.Context, _ authreq.View, args authreq.ProviderArgs) error {
	p.record("AuthorizeAction", args)

	return nil
}

func (p *spyArgsProvider) CACertData(_ context.Context, args authreq.ProviderArgs) (string, error) {
	p.record("CACertData", args)

	return "", nil
}

func (p *spyArgsProvider) ClientCertData(_ context.Context, args authreq.ProviderArgs) (string, string, error) {
	p.record("ClientCertData", args)

	return "", "", nil
}

func (p *spyArgsProvider) ServerNameData(_ context.Context, args authreq.ProviderArgs) (string, error) {
	p.record("ServerNameData", args)

	return "", nil
}

// TestDispatchersHandProvidersOnlyTheirOwnArgs is the boundary test for
// cynative#250: every dispatcher must project the tool call down to the
// provider's own block before the provider sees it. Without the projection each
// of these seven entry points is a second, un-narrowed view of the request,
// which is what made authreq.View a convention rather than a boundary.
func TestDispatchersHandProvidersOnlyTheirOwnArgs(t *testing.T) {
	t.Parallel()

	spy := newSpyArgsProvider()
	providers := []Provider{spy}
	ctx := context.Background()
	raw := json.RawMessage(narrowingToolCall)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.example.com/secrets", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}

	// The model's selector differs in case from the provider's own Name, which
	// is how a real run reaches a provider: find matches case-insensitively.
	const selector = "spy"

	if err = Inject(req, selector, providers, raw); err != nil {
		t.Fatalf("Inject: %v", err)
	}

	if err = AuthorizeHost(ctx, selector, "api.example.com", providers, raw); err != nil {
		t.Fatalf("AuthorizeHost: %v", err)
	}

	if err = AuthorizeAction(ctx, selector, authreq.NewView(req, ""), providers, raw); err != nil {
		t.Fatalf("AuthorizeAction: %v", err)
	}

	if err = AuthorizeAddr(ctx, selector, netip.MustParseAddr("93.184.216.34"), providers, raw); err != nil {
		t.Fatalf("AuthorizeAddr: %v", err)
	}

	if _, err = GetCACertData(ctx, selector, providers, raw); err != nil {
		t.Fatalf("GetCACertData: %v", err)
	}

	if _, _, err = GetClientCertData(ctx, selector, providers, raw); err != nil {
		t.Fatalf("GetClientCertData: %v", err)
	}

	if _, err = GetServerNameData(ctx, selector, providers, raw); err != nil {
		t.Fatalf("GetServerNameData: %v", err)
	}

	capabilities := []string{
		"InjectAuth", "AuthorizesHost", "AuthorizesAddr", "AuthorizeAction",
		"CACertData", "ClientCertData", "ServerNameData",
	}

	for _, capability := range capabilities {
		args, ok := spy.seen[capability]
		if !ok {
			t.Errorf("%s was never dispatched to the provider", capability)

			continue
		}

		assertOwnBlockOnly(t, capability, args)
	}
}

// assertOwnBlockOnly fails unless args are exactly the spy's own block: the
// marker it planted, and nothing from the request or from a sibling connector.
func assertOwnBlockOnly(t *testing.T, capability string, args authreq.ProviderArgs) {
	t.Helper()

	got, err := authreq.Parse[leakShape](args)
	if err != nil {
		t.Errorf("%s: parse args: %v", capability, err)

		return
	}

	if got == nil {
		t.Errorf("%s: args are absent, want the provider's own spy_auth block", capability)

		return
	}

	if got.Marker != "mine" {
		t.Errorf("%s: marker = %q, want %q: the provider did not receive its own block",
			capability, got.Marker, "mine")
	}

	if got.Method != "" || got.URL != "" || got.AuthProvider != "" || got.Body != "" {
		t.Errorf("%s: the request leaked into the args: %+v", capability, *got)
	}

	if got.GCPAuth != nil {
		t.Errorf("%s: a sibling connector's block leaked into the args: %s", capability, got.GCPAuth)
	}

	if got.SpyAuth != nil {
		t.Errorf("%s: args were not projected; the whole tool call came through", capability)
	}
}
