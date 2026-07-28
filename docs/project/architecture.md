# Architecture

Single static Go binary, no server, no external state.

## Components

- **CLI** - interactive session or `-p` single-task mode.
- **Agent loop** - drives the model, bounded by iteration and token limits.
- **Tools** - `http_request`, `code_execution`, `verify_findings`.
- **Action gate** - resolves each call to its required IAM actions and
  authorizes against a read-only policy before credentials are attached.
  Fails closed.
- **Network layer** - pins each request host to its mapped service and
  region, verifies the resolved IP before connect.
- **JS sandbox** - runs model-written scripts with no network, filesystem
  or package access. Only exposed tools are reachable.
- **Connectors** - AWS, GCP, Azure, Kubernetes, GitHub, GitLab. Use the
  credentials already in the shell, no credential store.
- **Audit log** - append-only JSONL, fail-closed.

## Flow

Model decides: answer, or call a tool. Every call crosses the action
gate - denials return an error to the model and the loop continues.
Allowed calls go through the network layer to the provider, get logged,
and the result feeds back in. Repeat until the model answers or a bound
trips (`max_iterations`, `max_total_tokens`, `max_consecutive_failures`).

`code_execution` runs many calls inside one iteration. `verify_findings`
and sub-agents nest their own loops under the same gate and budget.
