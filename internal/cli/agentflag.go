package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cynative/cynative/internal/agentcatalog"
	"github.com/cynative/cynative/internal/audit"
)

// agentSelection is the agent chosen for a run, carried alongside the composed
// task so runResearch can render provenance and stamp the audit log without
// re-resolving anything.
type agentSelection struct {
	Def agentcatalog.Definition
}

// provenance returns the audit stamp for this selection. The digest is over the
// exact raw file bytes; the body is never logged.
func (s *agentSelection) provenance() audit.AgentProvenance {
	sum := sha256.Sum256(s.Def.Raw)

	return audit.AgentProvenance{
		Name:   s.Def.Name,
		Source: s.Def.Source.String(),
		SHA256: hex.EncodeToString(sum[:]),
	}
}

// runRequest is what runRoot hands to deps.run.
//
// INVARIANT: Task is ALWAYS the final text passed to Agent.Run. When Agent is
// non-nil, Task is already Compose(Agent.Def, joinedInput); when Agent is nil,
// Task is joinTask's output unchanged. runResearch consumes Task verbatim and
// never re-composes, and reads Agent only for the provenance line and the audit
// stamp. Without this invariant an implementation could carry raw text here and
// compose later, which would look correct and quietly double-compose.
type runRequest struct {
	Task  string
	Agent *agentSelection
}

// buildRunRequest composes the final task. It is the single place composition
// happens, which is what makes the Task invariant enforceable.
func buildRunRequest(userInstruction string, def *agentcatalog.Definition) runRequest {
	if def == nil {
		return runRequest{Task: userInstruction, Agent: nil}
	}

	return runRequest{
		Task:  agentcatalog.Compose(*def, userInstruction),
		Agent: &agentSelection{Def: *def},
	}
}

// renderAgentProvenance writes the one-time startup line naming the agent and
// the file it came from, so the operator can see which file won before the run
// begins. Values are sanitized: a project-local agent can come from a repository
// the operator did not write.
//
// It goes in the startup block on stderr rather than the metrics footer (whose
// schema is operational counters) or the connector inventory (which represents
// credential readiness).
func renderAgentProvenance(w io.Writer, sel *agentSelection) {
	if sel == nil {
		return
	}

	fmt.Fprintf(w, "  Agent: %s  [%s: %s]\n",
		sanitizeInline(sel.Def.Name),
		sanitizeInline(sel.Def.Source.String()),
		sanitizeInline(sel.Def.Path),
	)
}

// selectAgent validates and resolves the --agent value. It returns a no-op
// cleanup when no agent was named, so the caller can defer unconditionally.
func (d *deps) selectAgent() (*agentcatalog.Definition, func(), error) {
	noop := func() {}

	if !d.agentFlagChanged {
		return nil, noop, nil
	}

	if err := agentcatalog.ValidName(d.agentName); err != nil {
		return nil, noop, err
	}

	catalog, cleanup, err := d.openAgentCatalog()
	if err != nil {
		return nil, noop, sanitizeErr(fmt.Errorf("open agent sources: %w", err))
	}

	def, err := catalog.Resolve(d.agentName)
	if err != nil {
		// Annotate BEFORE cleanup. cleanup closes the catalog's *os.Root
		// handles, and annotateResolveError enumerates names through them, so
		// releasing first makes that enumeration fail and silently drops the
		// "available agents" list that a not-found error exists to provide.
		annotated := annotateResolveError(err, catalog)

		cleanup()

		return nil, noop, sanitizeErr(annotated)
	}

	return &def, cleanup, nil
}

// annotateResolveError appends the available agent names to a not-found error,
// so the operator sees what they could have typed instead.
func annotateResolveError(err error, catalog *agentcatalog.Catalog) error {
	if !errors.Is(err, agentcatalog.ErrAgentNotFound) {
		return err
	}

	names, nerr := catalog.Names()
	if nerr != nil || len(names) == 0 {
		return err
	}

	return fmt.Errorf("%w; available agents: %s", err, strings.Join(names, ", "))
}
