package cli_test

import (
	"io/fs"
	"sort"
	"testing"

	cynative "github.com/cynative/cynative"
	"github.com/cynative/cynative/internal/agentcatalog"
)

// wantBuiltinAgents returns the authoritative roster of built-in agents. It is a
// function, not a package-level var, because gochecknoglobals bans test globals.
// A name added or dropped without updating this list fails the test, matching the
// house style for the connector and llm-smoke roster goldens.
func wantBuiltinAgents() []string {
	return []string{
		"aws-behavior-anomalies",
		"aws-container-isolation",
		"aws-credential-exposure",
		"aws-data-encryption",
		"aws-destruction-resilience",
		"aws-detection-coverage",
		"aws-domain-takeover",
		"aws-hardcoded-secrets",
		"aws-inference-exposure",
		"aws-metadata-theft",
		"aws-network-exposure",
		"aws-perimeter-bypass",
		"aws-policy-exposure",
		"aws-privilege-escalation",
		"aws-public-datastores",
		"aws-public-storage",
		"aws-snapshot-exposure",
		"aws-supply-chain",
		"aws-transport-encryption",
		"aws-unpatched-workloads",
		"azure-aks-exposure",
		"azure-appservice-exposure",
		"azure-detection-coverage",
		"azure-inference-exposure",
		"azure-keyvault-exposure",
		"azure-network-exposure",
		"azure-privilege-escalation",
		"azure-public-datastores",
		"azure-storage-exposure",
		"azure-supply-chain",
		"azure-vm-hardening",
		"gcp-audit-coverage",
		"gcp-inference-exposure",
		"gcp-network-exposure",
		"gcp-public-bindings",
		"gcp-static-credentials",
		"github-branch-protection",
		"github-org-access",
		"github-unpatched-dependencies",
		"github-workflow-trust",
		"k8s-pod-privilege",
		"k8s-self-managed-apiserver-access",
		"k8s-self-managed-cluster-secrets",
		"k8s-self-managed-controller-exposure",
		"k8s-self-managed-kubelet-access",
	}
}

// (Indentation inside the returned slice is fixed by `golangci-lint fmt`; run
// `make format` after pasting. The list content is what matters.)

// builtinRoot builds a catalog root over the embedded built-in tier alone. It
// never uses OpenSources, so a developer's real ~/.cynative/agents cannot shadow
// an entry and flake the test.
func builtinRoot(t *testing.T) agentcatalog.Root {
	t.Helper()

	sub, err := fs.Sub(cynative.BuiltinAgents(), "agents")
	if err != nil {
		t.Fatalf("fs.Sub(BuiltinAgents(), \"agents\") = %v", err)
	}

	return agentcatalog.Root{Source: agentcatalog.SourceBuiltin, FS: sub, DisplayPath: "built-in"}
}

// TestBuiltinManifest_RawInventory pins the embedded file set directly, catching
// an embed-directive mistake (a stray or nested file, a missing agent) that a
// catalog-only test would silently ignore.
func TestBuiltinManifest_RawInventory(t *testing.T) {
	t.Parallel()

	sub, err := fs.Sub(cynative.BuiltinAgents(), "agents")
	if err != nil {
		t.Fatalf("fs.Sub() = %v", err)
	}

	entries, err := fs.ReadDir(sub, ".")
	if err != nil {
		t.Fatalf("ReadDir() = %v", err)
	}

	names := wantBuiltinAgents()

	var got []string
	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("embedded agents tree contains a directory %q; only <name>.md files may ship", e.Name())

			continue
		}
		got = append(got, e.Name())
	}
	sort.Strings(got)

	want := make([]string, len(names))
	for i, n := range names {
		want[i] = n + ".md"
	}
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("embedded set has %d files, want %d\n got %v\nwant %v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("embedded file[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestBuiltinManifest_Catalog proves every expected agent resolves through the
// production catalog as an active, built-in, parseable entry.
func TestBuiltinManifest_Catalog(t *testing.T) { //nolint:gocognit // test function with many assertions by design.
	t.Parallel()

	want := wantBuiltinAgents()
	cat := agentcatalog.New(builtinRoot(t))

	names, err := cat.Names()
	if err != nil {
		t.Fatalf("Names() = %v", err)
	}
	if len(names) != len(want) {
		t.Fatalf("Names() has %d entries, want %d\n got %v", len(names), len(want), names)
	}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("Names()[%d] = %q, want %q", i, names[i], n)
		}
	}

	// List() is a separate implementation from Names(); assert its length and
	// names too so an empty or partial List() cannot pass vacuously.
	entries, err := cat.List()
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(entries) != len(want) {
		t.Fatalf("List() has %d entries, want %d", len(entries), len(want))
	}
	for i, e := range entries {
		if e.Name != want[i] {
			t.Errorf("List()[%d].Name = %q, want %q", i, e.Name, want[i])
		}
		if e.Source != agentcatalog.SourceBuiltin {
			t.Errorf("entry %q source = %v, want builtin", e.Name, e.Source)
		}
		if e.Shadowed {
			t.Errorf("entry %q is shadowed in a built-in-only catalog", e.Name)
		}
		if e.Err != nil {
			t.Errorf("entry %q is invalid: %v", e.Name, e.Err)
		}
	}

	// Resolve() sets Source and Path independently; assert both on every agent.
	for _, n := range want {
		def, rerr := cat.Resolve(n)
		if rerr != nil {
			t.Errorf("Resolve(%q) = %v, want nil", n, rerr)

			continue
		}
		if def.Source != agentcatalog.SourceBuiltin {
			t.Errorf("Resolve(%q).Source = %v, want builtin", n, def.Source)
		}
		if def.Path != "built-in/"+n+".md" {
			t.Errorf("Resolve(%q).Path = %q, want built-in/%s.md", n, def.Path, n)
		}
	}
}
