package cli

import (
	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/auth"
	"github.com/cynative/cynative/internal/ui"
)

// connectorMeta maps available inventory views to per-connector prompt metadata,
// keyed by connector name (errored connectors omitted). For an available parent
// whose view folds a managed K8s connector (Managed != ""), it also synthesizes a
// meta entry for that managed connector from its configured cluster_role — so the
// agent prompt carries the managed connector's access ceiling even though it has
// no own inventory line. managedClusterRoles maps managed connector name → its
// configured cluster_role (e.g. {"eks": "view"}).
func connectorMeta(views []ui.ConnectorView, managedClusterRoles map[string]string) map[string]agent.ConnectorMeta {
	meta := make(map[string]agent.ConnectorMeta, len(views))
	for _, v := range views {
		if v.State == ui.ConnectorError {
			continue
		}
		meta[v.Name] = agent.ConnectorMeta{Identity: v.Identity, Posture: v.Posture}
		if v.Managed != "" {
			if cr, ok := managedClusterRoles[v.Managed]; ok {
				meta[v.Managed] = agent.ConnectorMeta{Identity: v.Identity, Posture: auth.ManagedK8sPosture(cr)}
			}
		}
	}

	return meta
}
