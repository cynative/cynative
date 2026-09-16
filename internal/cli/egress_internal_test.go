package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

func proxiedEgress(t *testing.T) *auth.Egress {
	t.Helper()
	e, err := auth.NewEgress(func(k string) (string, bool) {
		switch k {
		case "HTTPS_PROXY":
			return "http://alice:s3cret@proxy.corp:3128", true
		case "NO_PROXY":
			return "10.0.0.0/8", true
		default:
			return "", false
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	return e
}

func TestRenderEgress_PrintsTheLineOnlyWithAProxy(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	renderEgress(&buf, auth.NoProxy())
	if buf.Len() != 0 {
		t.Fatalf("no proxy must print nothing, got %q", buf.String())
	}
	renderEgress(&buf, proxiedEgress(t))
	want := "  ~ egress      https_proxy http://proxy.corp:3128 · no_proxy 10.0.0.0/8\n"
	if buf.String() != want {
		t.Fatalf("line = %q, want %q", buf.String(), want)
	}
}

func TestRunResearch_EgressErrorAbortsBeforeProviders(t *testing.T) {
	t.Parallel()

	var errOut bytes.Buffer
	d := testDeps()
	d.errOut = &errOut
	providersBuilt := false
	d.getProviders = func(auth.HardeningConfig, bool, func(auth.ConnectorStatus)) []auth.Provider {
		providersBuilt = true

		return nil
	}
	boom := errors.New("HTTPS_PROXY: unsupported scheme \"https\"")
	d.newEgress = func() (*auth.Egress, error) { return nil, boom }

	err := d.runResearch(context.Background(), taskReq("hi"), validCfg(), researchFlags{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the egress error", err)
	}
	if providersBuilt {
		t.Fatal("providers must not be built after an egress error")
	}
	if !strings.Contains(errOut.String(), "✗ egress") || !strings.Contains(errOut.String(), "unsupported scheme") {
		t.Fatalf("stderr = %q, want the egress failure line", errOut.String())
	}
}

func TestRunDoctor_EgressErrorAbortsBeforeProviders(t *testing.T) {
	t.Parallel()

	var errOut bytes.Buffer
	d := testDeps()
	d.errOut = &errOut
	providersBuilt := false
	d.getProviders = func(auth.HardeningConfig, bool, func(auth.ConnectorStatus)) []auth.Provider {
		providersBuilt = true

		return nil
	}
	boom := errors.New("HTTPS_PROXY: not a valid proxy URL")
	d.newEgress = func() (*auth.Egress, error) { return nil, boom }

	if err := d.runDoctor(context.Background(), validCfg(), false, false); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the egress error", err)
	}
	if providersBuilt {
		t.Fatal("providers must not be built after an egress error")
	}
	if !strings.Contains(errOut.String(), "✗ egress") {
		t.Fatalf("stderr = %q, want the egress failure line", errOut.String())
	}
}

func TestBuildProviders_ThreadsTheEgressPolicy(t *testing.T) {
	t.Parallel()

	d := testDeps()
	var got *auth.Egress
	d.getProviders = func(hc auth.HardeningConfig, _ bool, _ func(auth.ConnectorStatus)) []auth.Provider {
		got = hc.Egress

		return nil
	}
	e := proxiedEgress(t)
	d.buildProviders(validCfg(), false, e)
	if got != e {
		t.Fatal("buildProviders must hand the policy to GetProviders through HardeningConfig.Egress")
	}
}

func TestBuildToolSet_ForwardsTheEgressToTheHTTPTool(t *testing.T) {
	t.Parallel()

	// Nothing below the tool constructor looks at the policy again, so a nil or
	// stale value here would only show up as a request leaving direct.
	d := testDeps()
	var got *auth.Egress
	d.newHTTPRequestTool = func(providers []auth.Provider, e *auth.Egress) schema.InvokableTool {
		got = e

		return tools.NewHTTPRequestTool(providers, e)
	}
	e := proxiedEgress(t)
	if _, err := d.buildToolSet(nil, e, validCfg(), researchFlags{}, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if got != e {
		t.Fatal("buildToolSet must hand the egress policy to newHTTPRequestTool")
	}
}

func TestRunResearch_PrintsTheEgressLineBeforeConnectors(t *testing.T) {
	t.Parallel()

	var errOut bytes.Buffer
	d := testDeps()
	d.errOut = &errOut
	d.newEgress = func() (*auth.Egress, error) { return proxiedEgress(t), nil }
	_ = d.runResearch(context.Background(), taskReq("hi"), validCfg(), researchFlags{})
	out := errOut.String()
	egressAt := strings.Index(out, "~ egress")
	connectorsAt := strings.Index(out, "(no connectors detected)")
	if egressAt < 0 || connectorsAt < 0 || egressAt > connectorsAt {
		t.Fatalf("egress line must precede the connector inventory:\n%s", out)
	}
}
