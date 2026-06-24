package auth_test

import (
	"os"
	"path/filepath"
	"testing"
)

// connectorDocs maps each registered connector id to its guide file under
// docs/connectors/. Keep this in sync with the providers GetProviders can
// register; the test fails if a guide is missing.
var connectorDocs = map[string]string{ //nolint:gochecknoglobals // test data table.
	"github":     "github.md",
	"gitlab":     "gitlab.md",
	"aws":        "aws.md",
	"eks":        "eks.md",
	"gcp":        "gcp.md",
	"gke":        "gke.md",
	"azure":      "azure.md",
	"aks":        "aks.md",
	"kubernetes": "kubernetes-self-managed.md",
}

func TestEveryConnectorHasADocFile(t *testing.T) {
	t.Parallel()

	// Test runs from the package dir (internal/auth); docs/connectors is at the
	// repo root, two directories up.
	dir := filepath.Join("..", "..", "docs", "connectors")

	for id, file := range connectorDocs {
		path := filepath.Join(dir, file)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("connector %q expects guide docs/connectors/%s, but it is missing (%v)", id, file, err)
		}
	}
}
