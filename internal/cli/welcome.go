package cli

import (
	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/ui"
)

// connectorMeta maps the available inventory views to the agent's per-connector
// identity/posture metadata, keyed by connector name (errored connectors omitted).
func connectorMeta(views []ui.ConnectorView) map[string]agent.ConnectorMeta {
	meta := make(map[string]agent.ConnectorMeta, len(views))
	for _, v := range views {
		if v.State == ui.ConnectorError {
			continue
		}
		meta[v.Name] = agent.ConnectorMeta{Identity: v.Identity, Posture: v.Posture}
	}

	return meta
}
