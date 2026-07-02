package tools_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cynative/cynative/internal/audit"
	"github.com/cynative/cynative/internal/schema"
	"github.com/cynative/cynative/internal/tools"
)

// fakeTool is a configurable schema.InvokableTool used to drive every branch of
// the approval decorator and to observe whether the inner tool ran.
type fakeTool struct {
	name string
	ret  string

	ran     bool
	gotArgs string
}

// Info reports the configured name.
func (f *fakeTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: f.name, Desc: "", Params: nil}
}

// Run records that it ran and the arguments it received.
func (f *fakeTool) Run(_ context.Context, argumentsInJSON string) (string, error) {
	f.ran = true
	f.gotArgs = argumentsInJSON

	return f.ret, nil
}

// countingTool counts how many times it ran; safe for concurrent Run.
type countingTool struct{ calls *atomic.Int64 }

func (countingTool) Info() *schema.ToolInfo {
	return &schema.ToolInfo{Name: "code_execution", Desc: "", Params: nil}
}

func (c countingTool) Run(context.Context, string) (string, error) {
	c.calls.Add(1)

	return "ok", nil
}

func TestApprovalToolApproveRunsInner(t *testing.T) {
	t.Parallel()

	inner := &fakeTool{name: "echo", ret: "echoed", ran: false, gotArgs: ""}

	var gotName, gotArgs, gotStyle string

	var gotGranted bool

	at := tools.NewApprovalTool(inner, func(n, a, s string, granted bool) tools.Decision {
		gotName, gotArgs, gotStyle, gotGranted = n, a, s, granted

		return tools.ApproveOnce
	}, "dark")

	out, err := at.Run(context.Background(), `{"x":1}`)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != "echoed" || !inner.ran {
		t.Errorf("out=%q ran=%v", out, inner.ran)
	}

	if inner.gotArgs != `{"x":1}` {
		t.Errorf("inner received args %q, want %q", inner.gotArgs, `{"x":1}`)
	}

	if gotName != "echo" || gotArgs != `{"x":1}` || gotStyle != "dark" {
		t.Errorf("prompter got %q %q %q", gotName, gotArgs, gotStyle)
	}

	if gotGranted {
		t.Error("alreadyGranted should be false on first call")
	}
}

func TestApprovalToolDenyReturnsDeniedMessage(t *testing.T) {
	t.Parallel()

	inner := &fakeTool{name: "echo", ret: "echoed", ran: false, gotArgs: ""}
	at := tools.NewApprovalTool(inner, func(string, string, string, bool) tools.Decision { return tools.Deny }, "dark")

	out, err := at.Run(context.Background(), "{}")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if out != tools.DeniedMessage {
		t.Errorf("out=%q want DeniedMessage", out)
	}

	if inner.ran {
		t.Error("inner ran despite denial")
	}
}

func TestApprovalToolInfoDelegates(t *testing.T) {
	t.Parallel()

	inner := &fakeTool{name: "echo", ret: "", ran: false, gotArgs: ""}
	at := tools.NewApprovalTool(inner, func(string, string, string, bool) tools.Decision {
		return tools.ApproveOnce
	}, "dark")

	info := at.Info()
	if info.Name != "echo" {
		t.Errorf("info=%+v", info)
	}
}

func TestApprovalTool_RecordsDecisionOnContext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		decision     tools.Decision
		wantApproved bool
		wantOut      string
	}{
		{"approve-once", tools.ApproveOnce, true, "ok"},
		{"approve-session", tools.ApproveSession, true, "ok"},
		{"deny", tools.Deny, false, tools.DeniedMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			inner := &fakeTool{name: "http_request", ret: "ok", ran: false, gotArgs: ""}
			at := tools.NewApprovalTool(inner, func(string, string, string, bool) tools.Decision {
				return tc.decision
			}, "notty")
			ctx, dec := audit.WithDecision(context.Background())
			out, err := at.Run(ctx, `{}`)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if !dec.Decided || dec.Approved != tc.wantApproved || dec.Session {
				t.Errorf("decision = %+v want approved=%v session=false", dec, tc.wantApproved)
			}
			if out != tc.wantOut {
				t.Errorf("out = %q want %q", out, tc.wantOut)
			}
		})
	}
}

func TestApprovalTool_SessionGrant_RecordsProvenance(t *testing.T) {
	t.Parallel()

	inner := &fakeTool{name: "code_execution", ret: "ok", ran: false, gotArgs: ""}
	at := tools.NewApprovalTool(inner, func(string, string, string, bool) tools.Decision {
		return tools.ApproveSession
	}, "notty")

	ctx1, dec1 := audit.WithDecision(context.Background())
	if _, err := at.Run(ctx1, "{}"); err != nil {
		t.Fatalf("Run #1: %v", err)
	}
	if !dec1.Decided || !dec1.Approved || dec1.Session {
		t.Errorf("decision #1 = %+v, want approved with Session=false", dec1)
	}

	ctx2, dec2 := audit.WithDecision(context.Background())
	if _, err := at.Run(ctx2, "{}"); err != nil {
		t.Fatalf("Run #2: %v", err)
	}
	if !dec2.Decided || !dec2.Approved || !dec2.Session {
		t.Errorf("decision #2 = %+v, want approved with Session=true", dec2)
	}
}

func TestApprovalTool_GrantIsPerToolInstance(t *testing.T) {
	t.Parallel()

	mk := func(name string, seen *[]bool) schema.InvokableTool {
		inner := &fakeTool{name: name, ret: "ok", ran: false, gotArgs: ""}

		return tools.NewApprovalTool(inner, func(_, _, _ string, granted bool) tools.Decision {
			*seen = append(*seen, granted)

			return tools.ApproveSession
		}, "notty")
	}

	var seenA, seenB []bool
	toolA := mk("code_execution", &seenA)
	toolB := mk("http_request", &seenB)

	if _, err := toolA.Run(context.Background(), "{}"); err != nil {
		t.Fatalf("toolA #1: %v", err)
	}
	if _, err := toolA.Run(context.Background(), "{}"); err != nil {
		t.Fatalf("toolA #2: %v", err)
	}
	if _, err := toolB.Run(context.Background(), "{}"); err != nil {
		t.Fatalf("toolB #1: %v", err)
	}

	if len(seenA) != 2 || seenA[0] || !seenA[1] {
		t.Errorf("toolA alreadyGranted = %v, want [false true]", seenA)
	}
	if len(seenB) != 1 || seenB[0] {
		t.Errorf("toolB alreadyGranted = %v, want [false]", seenB)
	}
}

func TestApprovalTool_ConcurrentRunsAfterGrant_NoRace(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	at := tools.NewApprovalTool(countingTool{calls: &calls}, func(string, string, string, bool) tools.Decision {
		return tools.ApproveSession
	}, "notty")

	if _, err := at.Run(context.Background(), "{}"); err != nil {
		t.Fatalf("seed Run: %v", err)
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_, _ = at.Run(context.Background(), "{}")
		})
	}
	wg.Wait()

	if calls.Load() != 51 {
		t.Errorf("inner ran %d times, want 51", calls.Load())
	}
}
