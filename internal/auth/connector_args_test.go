package auth_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cynative/cynative/internal/transport"
)

// argsKeySuffix is the suffix authreq.NewProviderArgs appends to a provider's
// name to derive the tool-call key it projects. It is spelled here rather than
// imported because pinning the wire contract is the point of this file.
const argsKeySuffix = "_auth"

// connectorArgsKeys maps each registered connector id to the json tag of its
// per-call arguments block in transport.RequestArgs (the block the model fills
// in), or "" for a connector that takes no per-call arguments.
//
// The gates never look this up: authreq.NewProviderArgs derives the key from
// the matched provider's own Name(), so a connector whose block were tagged
// anything but "<id>_auth" would be handed absent arguments on every request
// instead of failing. That is a silent, fail-open-shaped drift, which is what
// this table exists to catch. Keep it in sync with connectorDocs.
var connectorArgsKeys = map[string]string{ //nolint:gochecknoglobals // test data table.
	"github":     "",
	"gitlab":     "",
	"aws":        "aws_auth",
	"eks":        "eks_auth",
	"gcp":        "gcp_auth",
	"gke":        "gke_auth",
	"azure":      "azure_auth",
	"aks":        "aks_auth",
	"kubernetes": "kubernetes_auth",
}

func TestConnectorArgsKeysCoverEveryConnector(t *testing.T) {
	t.Parallel()

	for id := range connectorDocs {
		if _, ok := connectorArgsKeys[id]; !ok {
			t.Errorf("connector %q has a doc entry but no connectorArgsKeys entry", id)
		}
	}

	for id := range connectorArgsKeys {
		if _, ok := connectorDocs[id]; !ok {
			t.Errorf("connector %q has a connectorArgsKeys entry but no doc entry", id)
		}
	}
}

// TestConnectorArgsKeyIsDerivedFromTheConnectorName pins the derivation the
// dispatchers rely on: the model-facing block name is exactly the connector id
// plus "_auth", so projecting by provider name reaches the block the model
// filled in.
func TestConnectorArgsKeyIsDerivedFromTheConnectorName(t *testing.T) {
	t.Parallel()

	for id, key := range connectorArgsKeys {
		if key == "" {
			continue
		}

		if want := id + argsKeySuffix; key != want {
			t.Errorf("connector %q declares args key %q, but the gates are handed %q", id, key, want)
		}
	}
}

// TestRequestArgsBlocksMatchTheConnectorTable walks the model-facing tool schema
// and requires its "*_auth" blocks to be exactly the ones the table claims. It
// closes the other direction: a new block added to RequestArgs under a name no
// connector answers to would otherwise be a field the model can fill in and no
// gate can ever read.
func TestRequestArgsBlocksMatchTheConnectorTable(t *testing.T) {
	t.Parallel()

	want := map[string]string{}
	for id, key := range connectorArgsKeys {
		if key != "" {
			want[key] = id
		}
	}

	got := map[string]bool{}

	for field := range reflect.TypeFor[transport.RequestArgs]().Fields() {
		tag, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if !strings.HasSuffix(tag, argsKeySuffix) {
			continue
		}

		got[tag] = true

		if _, ok := want[tag]; !ok {
			t.Errorf("RequestArgs.%s is tagged %q, which no registered connector answers to",
				field.Name, tag)
		}
	}

	for key, id := range want {
		if !got[key] {
			t.Errorf("connector %q expects a %q block in RequestArgs, but the tool schema has none", id, key)
		}
	}
}
