# Agents

An agent is a markdown file that supplies the prompt for a run. It turns a
recurring investigation into an artifact you can version and review, instead of
a block of text pasted at the call site.

```bash
cynative -p --agent aws-public-data-stores "AWS account ID 12814983572854 only"   # with a task
cynative -p --agent aws-public-data-stores                    # without
cynative --agent aws-public-data-stores                       # seeds an interactive session
```

`--agent` composes with `-p`, `--auto-approve`, `--verbose`, `--config` and
piped stdin.

## The file format

```markdown
---
description: Finds publicly accessible data stores in an AWS account.
---
Check S3, RDS snapshots, EBS snapshots and public AMIs for exposure.
Report each finding with the resource ARN and how it is reachable.
```

The filename is the agent name, so `public-exposure.md` runs as
`--agent public-exposure`.

**Names** are lowercase kebab-case: 1 to 64 bytes of `a-z`, `0-9` and `-`, not
starting or ending with a hyphen. Windows reserved device names (`con`, `nul`,
`com1`…) are rejected on every platform so behaviour does not differ by OS.

**Frontmatter is required and strict.** It must be exactly one YAML mapping
whose only key is `description`, a single-line non-empty string of at most 256
bytes. Single-line is enforced against Unicode line and paragraph separators
(U+2028, U+2029) as well as ordinary control characters, since a renderer that
honours them would let a description break out of its `agents list` row. Unknown
keys, duplicate keys, aliases, merge keys, custom tags and multiple documents
are all rejected.

That strictness is deliberate. A frontmatter key cynative does not understand,
such as a `model:` or `tools:` override, fails loudly rather than being silently
ignored, so a file written against a newer version cannot appear to work while
doing nothing.

**The body** is everything after the closing `---` line, preserved byte for
byte. It must not be blank. Whole files are capped at 64 KiB.

A `---` line *after* the closing fence is body content, not a second
frontmatter block.

## Where agents come from

Two sources, searched in order, first match wins:

| Precedence | Source | Location |
| --- | --- | --- |
| 1 | user | `~/.cynative/agents/` |
| 2 | built-in | embedded in the binary |

To add your own agents, create the directory and write markdown files in it. Cynative will not create it for you:

```bash
mkdir -p ~/.cynative/agents
```

`--config` does not move it.

### Shadowing

A user agent takes precedence over a built-in of the same name, and
`cynative agents list` marks the loser:

```
NAME    DESCRIPTION                 SOURCE   STATUS
alpha   Your copy of alpha.         user     active
alpha   The built-in alpha.         builtin  shadowed by user
beta    A built-in agent.           builtin  active
broken                              user     invalid (blocking)
```

A file that is found but unusable — malformed, unreadable, oversized, a symlink,
or not a regular file — is `invalid (blocking)`. It still *claims* the name, so
nothing else answers to it and the run fails with an error naming the file.
Resolution never falls through to the built-in in that case: a typo in your own
agent must fail loudly rather than silently run a different one that happens to
share the name.

There is no way to address a built-in that a user agent shadows. Rename your
file.

## What the model receives

The prompt is three labelled sections in fixed order:

```
agent description:
<the description from the frontmatter>

user instruction:
<your task, if you passed one>

agent instructions:
<the body, verbatim>
```

The `user instruction:` section is omitted entirely when you pass no task. The
system prompt is unchanged: an agent is a named prompt, not a persona, so
cynative's scope, halt-and-ask and read-only rules apply exactly as they always
do.

### Piped input

Piping works as it always has, with one adjustment: when an agent is selected,
piped stdin is always treated as untrusted data and fenced in
`<piped_input>` tags, even with no positional task.

```bash
cat findings.json | cynative -p --agent triage-findings
```

Without an agent, bare piped stdin is your task. With one, the agent file is
already supplying the instruction, so the piped bytes are data to analyse rather
than orders to follow.

### Interactive sessions

`cynative --agent X` runs the agent as the first turn and then opens a normal
follow-up session. It does not re-apply the agent to every turn; the first turn
stays in the conversation history, so the model keeps the context.

The greeting shown for a bare interactive session is skipped, because the agent
is a seed task.

One limitation worth knowing: if the first turn is interrupted, stopped by the
token budget, or hits the iteration limit, nothing is recorded in history, so a
follow-up turn has no memory of the agent's instructions. Re-run the agent. This
is how a typed task behaves too.

Sub-agents spawned by the `task` tool do not inherit the agent body. They start
with a clean context by design; the supervising model puts what they need into
the task description.

## Inspecting agents

```bash
cynative agents list          # every agent, with source and status
cynative agents show <name>   # the exact file --agent <name> would run
```

`agents show` writes the file bytes to stdout and the source path to stderr, so
this copies a built-in you want to customize:

```bash
cynative agents show aws-public-data-stores > ~/.cynative/agents/my-version.md
```

Neither command reads your configuration or touches credentials, so both work on
a fresh install before cynative is configured. `--agent` and `agents show` both
support shell completion for agent names.

## Trust
Agents come only from your own home directory and the binary, so an agent is
something you installed. Selection is always explicit by name: the model cannot
introduce an agent or choose one on its own.

An agent only supplies text. Approvals, connector authorization and the
read-only ceilings are enforced by cynative when each tool call runs. An
agent cannot reach anything your credentials do not already allow.

Every run prints which file it used:

```
Agent: aws-public-data-stores  [user: /home/you/.cynative/agents/aws-public-data-stores.md]
```

`cynative agents list` shows the same information ahead of time, and every
audited tool call records the agent's name, source and file digest.
