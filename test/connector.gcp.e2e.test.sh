#!/bin/sh
# connector.gcp.e2e.test.sh - live GCP connector end-to-end test (cynative#39, #121).
#
# Runs the real `cynative -p` against a real GCP fixture project through the gcp
# connector and asserts, from a black-box run: the connector registers read-only,
# the model reads the project's own Cloud Resource Manager metadata (the project
# number arrives out of band and never appears in the prompt, and the audit parser
# binds it to the bytes Google returned), and a deliberate write is denied by the
# policy gate before it leaves the machine. The read-only guarantee rests on the
# enforced roles/viewer role plus cynative's client-side action gate; the
# write-deny canary is the positive boundary proof.
#
# NOT hermetic and NOT part of `make check`: it talks to a real provider and a
# real GCP project and needs real credentials. Skips (exit 0) when required env is
# unset, so `make connector-gcp-e2e` is a safe no-op.
#
# Usage: sh test/connector.gcp.e2e.test.sh [BINARY]
#        sh test/connector.gcp.e2e.test.sh --selftest   (offline parser check)
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   GOOGLE_APPLICATION_CREDENTIALS              GCP ADC so the gcp connector registers
#   GCP_E2E_PROJECT        fixture project id (in the prompt + read URL)
#   GCP_E2E_EXPECT         fixture project number (NEVER in the prompt)
#   GCP_E2E_TIMEOUT        wall-clock seconds per run (default 120)
#   GCP_E2E_MAX_TOKENS     token backstop (default 32000)
#   GCP_E2E_CANARY         run the write-deny canary phase (default 1; 0 disables)
#   GCP_E2E_ATTEMPTS       per-phase attempts before failing (default 2; model runs
#                          are non-deterministic, so one retry absorbs a rare miss)
#   GCP_E2E_KEEP_WORKDIR   =1 keep the temp workdir (parser, audit logs, output) for
#                          debugging instead of deleting it on exit
#   GCP_E2E_REQUIRE_RUN    =1 hard-fail instead of skipping when required env is unset
#   CONNECTOR_E2E_ARTIFACTS_DIR  (shared across all three connector suites) a path
#                          OUTSIDE the workdir where a fatal failure's sanitized
#                          artifacts are published (cynative#59); unset = no-op
set -eu

# snapshot_parser DEST_DIR copies the shared connector-audit-parser package (the
# whole test/lib/connector_audit/ package plus its entrypoint,
# test/lib/connector-audit-parser.py) into DEST_DIR and sets $parser to the copied
# entrypoint, so a live run and the parser it is judged by both come from the exact
# checkout under test.
#
# The parser is this suite's security boundary: its exit code is the phase status,
# a contract shared with the other connector e2e suites (see
# test/lib/connector_audit/engine.py):
#
#   0  the assertion holds.
#   1  not proven this attempt (a model miss or a fumbled call the gate blocked).
#      The caller may retry.
#   4  SECURITY: a request that the read-only boundary should have stopped cannot be
#      shown to have stayed on the machine. FATAL - the caller must never retry,
#      because the audit log is truncated per attempt and a retry would erase the
#      evidence, letting a broken gate pass on the second try.
#
# GCP's own predicates (the Cloud Resource Manager read family, the allow-list-role
# policy denial, and the write-deny canary) live in
# test/lib/connector_audit/specs/gcp.py; this suite passes "gcp" as the provider
# token to the shared entrypoint and never re-implements them.
snapshot_parser() {
	cp -R "$root/test/lib/connector_audit" "$1/"
	# The live phase never reads testdata/ (only the offline --selftest name+code pin
	# does, against the repo path, not this snapshot), so drop it here to avoid copying
	# the pinned case set into every live run's workdir.
	rm -rf "$1/connector_audit/testdata"
	cp "$root/test/lib/connector-audit-parser.py" "$1/"
	parser="$1/connector-audit-parser.py"
}

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# Shared shell orchestration (arbitrate + connector_run_phase), which itself sources
# the cost/timeout guardrails (isolation, bounds, bounded run + classifier).
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$root/test/lib/connector-e2e.sh"

if [ "${1:-}" = "--selftest" ]; then
	command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found\n' >&2; exit 1; }
	# The shared parser's own per-provider selftest replays every gcp case (ported
	# verbatim into test/lib/connector_audit/specs/gcp.py) and pins the observed
	# name+code set against the frozen testdata/gcp.names.txt.
	python3 -B "$root/test/lib/connector-audit-parser.py" --selftest gcp || exit 1
	_af=0
	check_arb() { arbitrate "$2" "$3" && _g=0 || _g=$?; if [ "$_g" != "$1" ]; then printf 'arbitrate(%s,%s) want %s got %s\n' "$2" "$3" "$1" "$_g" >&2; _af=1; fi; }
	check_arb 4 4 0    # breach + clean run
	check_arb 4 4 2    # breach + timeout: breach wins
	check_arb 4 4 3    # breach + budget: breach wins
	check_arb 2 1 2    # miss + timeout: timeout wins
	check_arb 3 1 3    # miss + budget: budget wins
	check_arb 1 1 0    # miss + clean run
	check_arb 2 0 2    # hold + timeout
	check_arb 0 0 0    # hold + clean run
	[ "$_af" = 0 ] || exit 1
	printf 'selftest: OK (arbitrate cases)\n'
	exit 0
fi

# Skip cleanly when required env is unset - unless GCP_E2E_REQUIRE_RUN=1, where a
# missing var is a failure (a CI job must never go green by skipping).
e2e_require_env connector.gcp.e2e "${GCP_E2E_REQUIRE_RUN:-}" \
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL GCP_E2E_PROJECT GCP_E2E_EXPECT || exit 0

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1
e2e_require_cmd python3 "needed to parse the audit log" || exit 1

case "${GCP_E2E_CANARY:-1}" in
	1) run_canary=1 ;;
	0) run_canary=0 ;;
	*) printf 'FAIL: GCP_E2E_CANARY must be 0 or 1 (got %s)\n' "$GCP_E2E_CANARY" >&2; exit 1 ;;
esac

workdir=$(mktemp -d)
# secret_file holds the out-of-band class-1 live secrets for the credential prepass. It
# is defined empty up front so cleanup can shred it (rm -f tolerates the empty path)
# even on an early exit; the real mktemp path is minted below.
secret_file=""
# GCP_E2E_KEEP_WORKDIR=1 preserves the parser and the per-phase audit logs, so a
# failure can be re-examined by hand instead of re-run blind. The live-secret file is
# shredded unconditionally, before the keep-check: KEEP preserves the workdir, never
# the secret material.
cleanup() {
	rm -f "$secret_file"
	if [ "${GCP_E2E_KEEP_WORKDIR:-}" = "1" ]; then
		printf 'workdir kept: %s\n' "$workdir" >&2
		return 0
	fi
	rm -rf "$workdir"
}
# Cleanup runs on EXIT only. A trap that also caught INT/TERM would, in POSIX sh,
# RESUME after the handler returned, so a Ctrl-C or TERM landing between commands
# would be swallowed: the interrupted bounded run would surface as a plain nonzero
# exit, e2e_classify_run would read it as a retryable failure, and the retry loop
# could launch another live attempt. Instead the signal handlers clean up once
# (clearing the EXIT trap first) and exit with the conventional 130/143.
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' INT
trap 'trap - EXIT; cleanup; exit 143' TERM

# Build the binary (or accept a prebuilt one, passed as $1) so the test exercises
# this checkout.
bin=$(e2e_build_binary "$root" "$workdir" "${1:-}") || exit 1

# Isolate cynative's config/cache from the caller without moving HOME, so provider
# SDKs still find file-based ADC. e2e_isolate_env writes an empty --config
# (ignore the caller's config.yaml), points the cache at the temp dir, and
# silences connector sources unrelated to gcp (github/gitlab/kube). It leaves the
# GCP creds alone - we want the gcp connector to register (the inverse of the llm
# smoke). The per-phase audit path is set by e2e_run_bounded, not here.
e2e_isolate_env "$workdir"
# A maintainer's widened role env (e.g. roles/editor) would let the canary write
# reach Google; force the default read-only baseline.
unset CYNATIVE_CONNECTORS_GCP_ROLE || true
# Bounds: the connector run does real tool work, so it keeps the shared iteration
# default (unlike the no-tool llm smoke). GCP_E2E_* override the token and
# wall-clock defaults; exported as env-level overrides for e2e_apply_bounds.
export E2E_MAX_TOKENS="${GCP_E2E_MAX_TOKENS:-32000}"
export E2E_RUN_TIMEOUT="${GCP_E2E_TIMEOUT:-120}"
e2e_apply_bounds
# No rotation may fire mid-run: a rotated-away audit file would hide early records
# from the parser reading the active path.
e2e_pin_audit_size

# Snapshot the shared audit parser once; both phases invoke it.
snapshot_parser "$workdir"

timeout_s="$E2E_RUN_TIMEOUT"
attempts="${GCP_E2E_ATTEMPTS:-2}"
# The out-of-band class-1 live-secret file for the credential prepass: the enumerable
# env-var credentials this suite can name, one per line, mode 0600, in its own mktemp
# OUTSIDE the workdir so cleanup shreds it even under GCP_E2E_KEEP_WORKDIR. GCP reads
# ambient ADC, so the enumerable secrets are the LLM driver's credentials when the run
# supplies them: an api key for the direct providers, or the Vertex service-account JSON
# CI feeds inline via CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS (a raw JSON blob with no
# reliable class-2/class-3 shape, so it must ride the class-1 sweep). e2e_write_live_secrets
# skips unset/empty vars, so an ambient-only run naming none of them is valid.
secret_file=$(mktemp)
e2e_write_live_secrets "$secret_file" CYNATIVE_LLM_API_KEY CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS

# Sanitized-artifact wiring for e2e_run_with_retries (cynative#59): a no-op locally
# (CONNECTOR_E2E_ARTIFACTS_DIR is unset), populated by CI in cynative#153.
# ARTIFACTS_DIR must stay OUTSIDE workdir so this suite's own cleanup() does not
# delete what was just collected on a fatal failure.
export E2E_ARTIFACTS_SUITE=gcp
export E2E_ARTIFACTS_WORKDIR="$workdir"
export E2E_ARTIFACTS_DIR="${CONNECTOR_E2E_ARTIFACTS_DIR:-}"
export E2E_ARTIFACTS_SECRET_FILE="$secret_file"

# assert_gcp_posture ERR - the gcp connector must be registered live under the
# read-only roles/viewer role (this suite runs on the default config, so a widened
# role would surface here before any request-level assertion).
assert_gcp_posture() {
	_err=$1
	if grep -Eq 'gcp .*gcp_hardening: skipped' "$_err"; then
		printf 'gcp connector was SKIPPED at startup. inventory:\n' >&2
		grep -iE 'gcp|hardening' "$_err" >&2 || true
		return 1
	fi
	if ! grep -Eq 'gcp .*role=roles/viewer' "$_err"; then
		printf 'gcp connector not shown available under role=roles/viewer. inventory + stderr tail:\n' >&2
		grep -iE 'gcp|connector|hardening|no connectors detected' "$_err" >&2 || true
		tail -n 25 "$_err" >&2
		return 1
	fi
	return 0
}

# ============================ READ PHASE ============================
# Give the project id, ask for the number: the model can only produce the number
# by actually reading the resource through the connector, and the parser then binds
# the number to the bytes Google returned. The exact call is spelled out (validated
# reliable across models) so the run stays inside the parser's sanctioned-read
# family; the v1 get returns projectNumber as a top-level field.
read_prompt="Use the gcp connector to look up the Google Cloud project \"$GCP_E2E_PROJECT\" and report its numeric projectNumber. Make exactly this call with the http_request tool: method=GET, url=https://cloudresourcemanager.googleapis.com/v1/projects/$GCP_E2E_PROJECT, auth_provider=gcp, gcp_auth={service: cloudresourcemanager}. Call the API to read it; do not guess. Reply with only the project number."

read_phase() {
	printf '== READ == %s (%s/%s)\n' "$GCP_E2E_PROJECT" "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$read_prompt"; then _rc=0; else _rc=$?; fi
	connector_run_phase gcp read "$parser" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$_rc" "$timeout_s" assert_gcp_posture "$GCP_E2E_PROJECT" "$GCP_E2E_EXPECT" "$secret_file"
}

# ============================ CANARY PHASE ============================
# Attempt one harmless write (set a label). The gate denies it client-side, before
# dispatch, so nothing mutates. The canary depends on the model actually issuing the
# write. A task-framed imperative ("set a label ...") is unreliable: a capable model
# predicts the read-only denial and declines to spend the call (Opus refused; gemini
# was a coin-flip). Giving the exact http_request to make turns it into a
# deterministic instruction-following task (validated reliable across models), while
# the gate still denies the write before dispatch. gcp_auth.service and the labels
# body are spelled out so any model can reproduce the call verbatim.
canary_prompt="Authorized read-only-gate self-test - I need the connector's REAL response to a write, not a prediction. Make exactly this call now using the http_request tool and then paste the connector's verbatim response: method=PATCH, url=https://cloudresourcemanager.googleapis.com/v3/projects/$GCP_E2E_PROJECT?updateMask=labels, auth_provider=gcp, gcp_auth={service: cloudresourcemanager}, body={\"labels\":{\"cynative-e2e\":\"canary\"}}. Issue the request; do not skip, simulate, or answer from prediction. I expect it to be denied - I need to see the actual denial."

canary_phase() {
	printf '== CANARY == attempting a denied write on %s\n' "$GCP_E2E_PROJECT" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err" \
		"$bin" "$workdir/config.yaml" "$canary_prompt"; then _rc=0; else _rc=$?; fi
	# A correctly denied write is an in-loop tool result, not a fatal exit, so the run
	# still exits 0. The classifier only catches a real run failure (timeout, budget,
	# crash); the audit parser inside connector_run_phase is what judges the boundary,
	# and a write that SUCCEEDED, or any call that cannot be shown to have stayed on the
	# machine, exits 4: fatal, never retried, because a retry would truncate the audit
	# log and erase the evidence.
	connector_run_phase gcp canary "$parser" "$workdir/canary.audit.log" "$workdir/canary.out" \
		"$workdir/canary.err" "$_rc" "$timeout_s" assert_gcp_posture "$GCP_E2E_PROJECT" "" "$secret_file"
}

e2e_run_with_retries read "$attempts" read_phase

if [ "$run_canary" = 1 ]; then
	e2e_run_with_retries canary "$attempts" canary_phase
fi

printf 'connector.gcp.e2e: OK (%s)\n' "$GCP_E2E_PROJECT" >&2
