package cli

import (
	"testing"

	"github.com/cynative/cynative/internal/agent"
	"github.com/cynative/cynative/internal/ui"
)

func TestConnectorMeta(t *testing.T) {
	t.Parallel()

	views := []ui.ConnectorView{
		{State: ui.ConnectorOK, Name: "github", Posture: "read-only", Identity: "@octocat"},
		{State: ui.ConnectorWarn, Name: "aws", Posture: "SecurityAudit", Identity: "123 · user/x"},
		{State: ui.ConnectorError, Name: "gcp", Posture: "no usable credentials", Identity: ""},
	}

	meta := connectorMeta(views, nil)

	if len(meta) != 2 {
		t.Fatalf("len(meta) = %d, want 2 (error view omitted)", len(meta))
	}
	if got, want := meta["github"], (agent.ConnectorMeta{Identity: "@octocat", Posture: "read-only"}); got != want {
		t.Errorf("github meta = %+v, want %+v", got, want)
	}
	if got, want := meta["aws"], (agent.ConnectorMeta{Identity: "123 · user/x", Posture: "SecurityAudit"}); got != want {
		t.Errorf("aws meta = %+v, want %+v", got, want)
	}
	if _, ok := meta["gcp"]; ok {
		t.Errorf("errored connector gcp must be omitted, got %+v", meta["gcp"])
	}
}

func TestConnectorMeta_Empty(t *testing.T) {
	t.Parallel()

	if meta := connectorMeta(nil, nil); len(meta) != 0 {
		t.Errorf("connectorMeta(nil, nil) = %+v, want empty", meta)
	}
}

func TestConnectorMeta_ManagedK8s(t *testing.T) {
	t.Parallel()

	views := []ui.ConnectorView{
		{
			State:    ui.ConnectorOK,
			Name:     "aws",
			Posture:  "access=default(read-only) · enforced=client · policy=x",
			Identity: "123",
			Managed:  "eks",
		},
	}
	meta := connectorMeta(views, map[string]string{"eks": "view"})

	got, ok := meta["eks"]
	if !ok {
		t.Fatalf("expected an eks meta entry")
	}
	if got.Posture != "access=default(read-only) · enforced=client · cluster role=view" {
		t.Errorf("eks posture = %q", got.Posture)
	}
}
