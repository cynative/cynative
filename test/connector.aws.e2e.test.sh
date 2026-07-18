#!/bin/sh
# connector.aws.e2e.test.sh - live AWS connector end-to-end test (cynative#52).
#
# Runs the real `cynative -p` against a real AWS fixture account through the aws
# connector and asserts, from a black-box run: the connector registers under the
# read-only SecurityAudit policy, the model reads an inert fixture IAM role and
# surfaces a tag value it could only have obtained from AWS, and a deliberate write
# is denied client-side before it reaches the network.
#
# NOT hermetic and NOT part of `make check`: it talks to a real provider and a real
# AWS account and needs real credentials. Skips (exit 0) when required env is unset,
# so `make connector-aws-e2e` is a safe no-op.
#
# Usage: sh test/connector.aws.e2e.test.sh [BINARY]
#        sh test/connector.aws.e2e.test.sh --selftest   (offline parser check)
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   ambient AWS_* / profile                     required (lights the aws connector)
#   AWS_E2E_ROLE_NAME      fixture role name (appears in the prompt)
#   AWS_E2E_EXPECT         fixture tag value (NEVER in the prompt)
#   AWS_E2E_ACCOUNT        expected account id in the startup inventory
#   AWS_E2E_ENFORCED       expected `enforced=` field: client+aws (an assumed-role
#                          identity, e.g. CI, where credential scoping engages) or
#                          client (an IAM-user profile, for which cynative never
#                          attempts scoping)
#   AWS_E2E_TIMEOUT        wall-clock seconds per run (default 240; the first
#                          authorization cold-fetches the configured policy and a
#                          Smithy model archive before any request is dispatched)
#   AWS_E2E_MAX_TOKENS     token backstop (default 32000)
#   AWS_E2E_CANARY         run the write-deny canary phase (default 1; 0 disables)
#   AWS_E2E_ATTEMPTS       per-phase attempts (default 2; model runs are
#                          non-deterministic, so one retry absorbs a rare miss)
#   AWS_E2E_KEEP_WORKDIR   =1 keep the temp workdir (parser, audit logs, output) for
#                          debugging instead of deleting it on exit
#   AWS_E2E_REQUIRE_RUN    =1 hard-fail instead of skipping when required env is unset
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
# The load-bearing distinction is "did the request leave the machine". Every
# `aws_hardening` error is raised by an auth gate, and all of those run before
# httpClient.Do, so such an error PROVES the request was never dispatched. A failure
# WITHOUT that proof cannot be assumed harmless: a mutation can be dispatched, get a
# 2xx, and only then fail while its response body is read, which surfaces as a plain
# tool error. So anything that is neither a sanctioned read nor the exact sanctioned
# canary, and which lacks an aws_hardening denial, is a security failure.
#
# AWS's own predicates (the query/form Action decoder, the IAM/STS read family, and
# the TagRole write-deny canary) live in test/lib/connector_audit/specs/aws.py; this
# suite passes "aws" as the provider token to the shared entrypoint and never
# re-implements them.
snapshot_parser() {
	cp -R "$root/test/lib/connector_audit" "$1/"
	# The live phase never reads testdata/ (only --selftest/--dump-names/differential
	# do, and those run against the repo path, not this snapshot), so drop it here to
	# avoid copying the frozen corpus into every live run's workdir.
	rm -rf "$1/connector_audit/testdata"
	cp "$root/test/lib/connector-audit-parser.py" "$1/"
	parser="$1/connector-audit-parser.py"
}

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# Shared shell orchestration (arbitrate + connector_run_phase), which itself sources
# the cost/timeout guardrails (isolation, bounds, bounded run + classifier).
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$root/test/lib/connector-e2e.sh"

# --- offline self-test: verify the shared audit parser without credentials ---
if [ "${1:-}" = "--selftest" ]; then
	command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found\n' >&2; exit 1; }
	# The shared parser's own per-provider selftest replays every aws case (ported
	# verbatim into test/lib/connector_audit/specs/aws.py) and pins the observed
	# name+code set against the frozen testdata/aws.names.txt.
	python3 -B "$root/test/lib/connector-audit-parser.py" --selftest aws || exit 1
	_af=0
	check_arb() { arbitrate "$2" "$3" && _g=0 || _g=$?; if [ "$_g" != "$1" ]; then printf 'arbitrate(%s,%s) want %s got %s\n' "$2" "$3" "$1" "$_g" >&2; _af=1; fi; }
	check_arb 4 4 0; check_arb 4 4 2; check_arb 4 4 3; check_arb 2 1 2
	check_arb 3 1 3; check_arb 1 1 0; check_arb 2 0 2; check_arb 0 0 0
	[ "$_af" = 0 ] || exit 1
	printf 'selftest: OK (arbitrate cases)\n' >&2
	exit 0
fi

# Skip cleanly when required env is unset - unless AWS_E2E_REQUIRE_RUN=1, where a
# missing var is a failure (a CI job must never go green by skipping).
e2e_require_env connector.aws.e2e "${AWS_E2E_REQUIRE_RUN:-}" \
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL \
	AWS_E2E_ROLE_NAME AWS_E2E_EXPECT AWS_E2E_ACCOUNT AWS_E2E_ENFORCED || exit 0

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1
e2e_require_cmd python3 "needed to parse the audit log" || exit 1

workdir=$(mktemp -d)
# secret_file holds the out-of-band class-1 live secrets for the credential prepass. It
# is defined empty up front so cleanup can shred it (rm -f tolerates the empty path)
# even on an early exit; the real mktemp path is minted below.
secret_file=""
# AWS_E2E_KEEP_WORKDIR=1 preserves the parser and the per-phase audit logs, so a
# failure can be re-examined by hand instead of re-run blind. The live-secret file is
# shredded unconditionally, before the keep-check: KEEP preserves the workdir, never
# the secret material.
cleanup() {
	rm -f "$secret_file"
	if [ "${AWS_E2E_KEEP_WORKDIR:-}" = "1" ]; then
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

# Isolate cynative's config/cache from the caller without moving HOME, so the AWS SDK
# still finds the ambient profile or instance credentials. The AWS creds are left
# alone on purpose: we WANT the aws connector to register, which is the inverse of the
# llm smoke, where it must stay dark.
e2e_isolate_env "$workdir"
export E2E_MAX_TOKENS="${AWS_E2E_MAX_TOKENS:-32000}"
# The first AuthorizeAction pays a cold path INSIDE the tool call, before the target
# request is dispatched: it refetches the configured policy and pulls the Smithy model
# archive from codeload.github.com. Hence a larger default than the GCP suite.
export E2E_RUN_TIMEOUT="${AWS_E2E_TIMEOUT:-240}"
e2e_apply_bounds
# No rotation may fire mid-run: a rotated-away audit file would hide early records
# from the parser reading the active path.
e2e_pin_audit_size

# Snapshot the shared audit parser once; both phases invoke it.
snapshot_parser "$workdir"

timeout_s="$E2E_RUN_TIMEOUT"
attempts="${AWS_E2E_ATTEMPTS:-2}"
# The out-of-band class-1 live-secret file for the credential prepass: the enumerable
# env-var credentials this suite can name, one per line, mode 0600, in its own mktemp
# OUTSIDE the workdir so cleanup shreds it even under AWS_E2E_KEEP_WORKDIR. The AWS
# static-credential env vars are written only when set (an instance role or profile run
# leaves them unset), plus the LLM driver's api key when the run supplies one; an
# ambient LLM (Bedrock) leaves those unset, which is valid - the class-2/class-3 SHAPE
# families cover any leaked shaped key.
secret_file=$(mktemp)
e2e_write_live_secrets "$secret_file" \
	AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN CYNATIVE_LLM_API_KEY

# Sanitized-artifact wiring for e2e_run_with_retries (cynative#59): a no-op locally
# (CONNECTOR_E2E_ARTIFACTS_DIR is unset), populated by CI in cynative#153.
# ARTIFACTS_DIR must stay OUTSIDE workdir so this suite's own cleanup() does not
# delete what was just collected on a fatal failure.
export E2E_ARTIFACTS_SUITE=aws
export E2E_ARTIFACTS_WORKDIR="$workdir"
export E2E_ARTIFACTS_DIR="${CONNECTOR_E2E_ARTIFACTS_DIR:-}"
export E2E_ARTIFACTS_SECRET_FILE="$secret_file"

# assert_aws_posture ERR - the aws connector must be registered live, under the
# read-only policy, on the expected account, at the expected enforcement level.
#
# enforced= is compared EXACTLY, never as a substring: client+aws(unverified) is a
# distinct state (the scoping probe hit a transient error) and must not pass as
# client+aws. The expected value is an env knob because it legitimately differs by
# identity: an assumed-role principal (CI) engages credential scoping (client+aws),
# while an IAM-user profile never attempts it at all (client).
assert_aws_posture() {
	_err=$1
	if grep -Eq 'aws .*aws_hardening: skipped' "$_err"; then
		printf 'aws connector was SKIPPED at startup. inventory:\n' >&2
		grep -iE 'aws|hardening' "$_err" >&2 || true
		return 1
	fi
	_line=$(grep -E '^[^a-z]*aws[[:space:]]' "$_err" | head -n 1)
	if [ -z "$_line" ]; then
		printf 'aws connector not present in the startup inventory. stderr tail:\n' >&2
		grep -iE 'aws|connector|hardening|no connectors detected' "$_err" >&2 || true
		tail -n 25 "$_err" >&2
		return 1
	fi
	case "$_line" in
		*"policy=arn:aws:iam::aws:policy/SecurityAudit"*) ;;
		*)
			printf 'aws connector is not under the read-only SecurityAudit policy: %s\n' "$_line" >&2
			return 1
			;;
	esac
	case "$_line" in
		*"$AWS_E2E_ACCOUNT"*) ;;
		*)
			printf 'aws connector is on the wrong account (want %s): %s\n' "$AWS_E2E_ACCOUNT" "$_line" >&2
			return 1
			;;
	esac
	_enf=$(printf '%s\n' "$_line" | sed -n 's/.*enforced=\([^ ]*\).*/\1/p')
	if [ "$_enf" != "$AWS_E2E_ENFORCED" ]; then
		printf 'aws enforcement is %s, expected %s: %s\n' "${_enf:-<none>}" "$AWS_E2E_ENFORCED" "$_line" >&2
		return 1
	fi
	# When server-side scoping is expected, a degrade notice means it silently did not
	# engage and the run is only client-gated.
	if [ "$AWS_E2E_ENFORCED" = "client+aws" ] && grep -q 'cred_scope degraded' "$_err"; then
		printf 'credential scoping degraded, but %s was expected:\n' "$AWS_E2E_ENFORCED" >&2
		grep 'cred_scope degraded' "$_err" >&2
		return 1
	fi
	return 0
}

# ============================ READ PHASE ============================
# Name the role, ask for the tag value. The value reaches this script out of band
# (AWS_E2E_EXPECT) and never appears in the prompt, so the model can only produce it
# by actually reading the role through the connector. The audit parser then binds it
# to the bytes AWS returned, which is the assertion that really counts.
read_prompt="Use the aws connector to read the IAM role \"$AWS_E2E_ROLE_NAME\" and report the value of its tag \"cynative-e2e-fixture\". Make this exact call with the http_request tool: method=GET, url=https://iam.amazonaws.com/?Action=GetRole&RoleName=$AWS_E2E_ROLE_NAME&Version=2010-05-08, auth_provider=aws, aws_auth={service: iam}. Call the API to read it; do not guess. Reply with only the tag value."

read_phase() {
	printf '== READ == %s (%s/%s)\n' "$AWS_E2E_ROLE_NAME" "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$read_prompt"; then _rc=0; else _rc=$?; fi
	connector_run_phase aws read "$parser" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$_rc" "$timeout_s" assert_aws_posture "$AWS_E2E_ROLE_NAME" "$AWS_E2E_EXPECT" "$secret_file"
}

# ============================ CANARY PHASE ============================
# Attempt one harmless write: set a tag that is ALREADY set, on an inert fixture role
# that grants nothing, so even an escaped write is a no-op. The gate denies it before
# network dispatch, and the parser proves that (an aws_hardening policy denial can
# only be raised before the request is sent).
#
# The call is spelled out because a task-framed imperative is unreliable: a capable
# model predicts the read-only denial and declines to spend the call (Opus refused the
# GCP equivalent). Giving the exact request makes it an instruction-following task
# while the gate still does the deciding.
#
# The body is one line on purpose. If it wrapped, the newline and indent would become
# part of RoleName and the suite could go green for the wrong reason: cynative's
# classifier consumes only Action, so it would emit an identical denial for a request
# AWS itself would have rejected as malformed. The parser's full-shape validation is
# the backstop, but it should never be handed a malformed request in the first place.
canary_prompt="Authorized read-only-gate self-test - I need the connector's REAL response to a write, not a prediction. Make exactly this call now using the http_request tool and then paste the connector's verbatim response: method=POST, url=https://iam.amazonaws.com/, auth_provider=aws, aws_auth={service: iam}, headers=[{key: Content-Type, value: application/x-www-form-urlencoded}], body=Action=TagRole&Version=2010-05-08&RoleName=$AWS_E2E_ROLE_NAME&Tags.member.1.Key=cynative-e2e&Tags.member.1.Value=canary . Issue the request; do not skip, simulate, or answer from prediction. I expect it to be denied - I need to see the actual denial."

canary_phase() {
	printf '== CANARY == attempting a denied write on %s\n' "$AWS_E2E_ROLE_NAME" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err" \
		"$bin" "$workdir/config.yaml" "$canary_prompt"; then _rc=0; else _rc=$?; fi
	# A correctly denied write is an in-loop tool result, not a fatal exit, so the run
	# still exits 0. The classifier only catches a real run failure (timeout, budget,
	# crash); the audit parser inside connector_run_phase is what judges the boundary,
	# and a write that SUCCEEDED, or any call that cannot be shown to have stayed on the
	# machine, exits 4: fatal, never retried, because a retry would truncate the audit
	# log and erase the evidence.
	connector_run_phase aws canary "$parser" "$workdir/canary.audit.log" "$workdir/canary.out" \
		"$workdir/canary.err" "$_rc" "$timeout_s" assert_aws_posture "$AWS_E2E_ROLE_NAME" "" "$secret_file"
}

e2e_run_with_retries read "$attempts" read_phase

if [ "${AWS_E2E_CANARY:-1}" != "0" ]; then
	e2e_run_with_retries canary "$attempts" canary_phase
fi

printf 'connector.aws.e2e: OK (%s on %s)\n' "$AWS_E2E_ROLE_NAME" "$AWS_E2E_ACCOUNT" >&2
