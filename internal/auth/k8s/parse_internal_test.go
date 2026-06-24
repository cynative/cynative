package k8s

import (
	"errors"
	"testing"
)

const sampleClusterRole = `{
  "kind": "ClusterRole",
  "apiVersion": "rbac.authorization.k8s.io/v1",
  "metadata": {"name": "view"},
  "rules": [
    {"apiGroups": [""], "resources": ["pods", "pods/log"], "verbs": ["get", "list", "watch"]},
    {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "list", "watch"]}
  ]
}`

func TestParseClusterRoleRules(t *testing.T) {
	t.Parallel()

	rules, err := ParseClusterRoleRules([]byte(sampleClusterRole))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Resources[1] != "pods/log" {
		t.Fatalf("rule[0].Resources[1] = %q, want pods/log", rules[0].Resources[1])
	}
}

func TestParseClusterRoleRulesRejectsBadInput(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"invalid json":  `{not json`,
		"wrong kind":    `{"kind":"Status","code":403,"rules":[]}`,
		"no rules":      `{"kind":"ClusterRole","rules":[]}`,
		"missing rules": `{"kind":"ClusterRole"}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseClusterRoleRules([]byte(body)); err == nil {
				t.Fatalf("expected error for %q, got nil", name)
			} else if !errors.Is(err, ErrUnclassifiable) {
				t.Fatalf("expected ErrUnclassifiable for %q, got %v", name, err)
			}
		})
	}
}
