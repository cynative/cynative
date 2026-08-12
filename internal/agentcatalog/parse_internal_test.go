package agentcatalog_test

import (
	"errors"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/cynative/cynative/internal/agentcatalog"
)

// TestSoleDescriptionValue_DefensiveShapes drives the document-shape branch that
// no real agent file can reach: Parse always hands soleDescriptionValue a
// DocumentNode with exactly one child, so this is the only way to cover it.
func TestSoleDescriptionValue_DefensiveShapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  *yaml.Node
	}{
		{
			name: "not a document node",
			doc:  &yaml.Node{Kind: yaml.MappingNode}, //nolint:exhaustruct // only Kind matters.
		},
		{
			name: "document with no content",
			doc:  &yaml.Node{Kind: yaml.DocumentNode}, //nolint:exhaustruct // empty Content is the case.
		},
		{
			name: "document with two children",
			doc: &yaml.Node{ //nolint:exhaustruct // only Kind and Content matter.
				Kind: yaml.DocumentNode,
				Content: []*yaml.Node{
					{Kind: yaml.MappingNode}, //nolint:exhaustruct // only Kind matters.
					{Kind: yaml.MappingNode}, //nolint:exhaustruct // only Kind matters.
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := agentcatalog.SoleDescriptionValue(tc.doc)
			if !errors.Is(err, agentcatalog.ErrAgentInvalid) {
				t.Fatalf("SoleDescriptionValue() error = %v, want ErrAgentInvalid", err)
			}
		})
	}
}
