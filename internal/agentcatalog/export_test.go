package agentcatalog

import "gopkg.in/yaml.v3"

// SoleDescriptionValue exposes soleDescriptionValue so tests can drive its
// defensive document-shape check with a hand-built node.
//
// That check is unreachable through Parse: splitFrontmatter hands the decoder a
// document that always yields a DocumentNode with exactly one child, and an
// empty document is caught earlier as [io.EOF]. Function wrappers are used here
// rather than var aliases so no //nolint:gochecknoglobals is needed.
func SoleDescriptionValue(doc *yaml.Node) (*yaml.Node, error) {
	return soleDescriptionValue(doc)
}
