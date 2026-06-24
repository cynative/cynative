package k8s

import (
	"encoding/json"
	"fmt"
)

// clusterRole is the minimal shape we decode from a ClusterRole API response.
type clusterRole struct {
	Kind  string `json:"kind"`
	Rules []struct {
		APIGroups     []string `json:"apiGroups"`
		Resources     []string `json:"resources"`
		ResourceNames []string `json:"resourceNames"`
		Verbs         []string `json:"verbs"`
	} `json:"rules"`
}

// ParseClusterRoleRules decodes a ClusterRole JSON body (as returned by the
// Kubernetes API) into PolicyRules. It rejects non-ClusterRole payloads (e.g. a
// Status error) and empty rule sets so a bogus response is never cached as a
// valid (allow-nothing-but-real) policy — both fail closed via ErrUnclassifiable.
func ParseClusterRoleRules(data []byte) ([]PolicyRule, error) {
	var cr clusterRole
	if err := json.Unmarshal(data, &cr); err != nil {
		return nil, fmt.Errorf("%w: decode clusterrole: %w", ErrUnclassifiable, err)
	}

	if cr.Kind != "ClusterRole" {
		return nil, fmt.Errorf("%w: response kind %q is not ClusterRole", ErrUnclassifiable, cr.Kind)
	}

	if len(cr.Rules) == 0 {
		return nil, fmt.Errorf("%w: clusterrole has no rules", ErrUnclassifiable)
	}

	rules := make([]PolicyRule, 0, len(cr.Rules))
	for _, r := range cr.Rules {
		rules = append(rules, PolicyRule{
			APIGroups:     r.APIGroups,
			Resources:     r.Resources,
			ResourceNames: r.ResourceNames,
			Verbs:         r.Verbs,
		})
	}

	return rules, nil
}
