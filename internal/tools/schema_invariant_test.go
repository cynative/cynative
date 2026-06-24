package tools_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/cynative/cynative/internal/redact"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

// TestToolSchemas_ContainNoSecretShapedContent pins the §5.4 invariant: tool
// schemas (Desc + Params) are static cynative-authored text and are NOT redacted
// at egress, so they must never contain secret-shaped content. If a future tool
// embeds a token-shaped string in its schema, redact.Redact changes the rendered
// text and this test fails.
func TestToolSchemas_ContainNoSecretShapedContent(t *testing.T) {
	t.Parallel()

	httpTool, err := tools.NewHTTPRequestTool(nil)
	if err != nil {
		t.Fatalf("NewHTTPRequestTool: %v", err)
	}
	codeTool, err := tools.NewCodeExecutionTool([]schema.InvokableTool{httpTool}, nil, 1, nil)
	if err != nil {
		t.Fatalf("NewCodeExecutionTool: %v", err)
	}

	r := redact.New()
	for _, tool := range []schema.InvokableTool{httpTool, codeTool} {
		info, infoErr := tool.Info(context.Background())
		if infoErr != nil {
			t.Fatalf("Info: %v", infoErr)
		}

		rendered := info.Desc
		if info.Params != nil {
			b, marshalErr := json.Marshal(info.Params)
			if marshalErr != nil {
				t.Fatalf("marshal params for %s: %v", info.Name, marshalErr)
			}
			rendered += string(b)
		}

		if got := r.Redact(rendered); got != rendered {
			t.Errorf("tool %q schema contains secret-shaped content (redaction changed it):\nbefore: %s\nafter:  %s",
				info.Name, rendered, got)
		}
	}
}
