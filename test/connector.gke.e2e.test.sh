#!/bin/sh
# connector.gke.e2e.test.sh - live GKE connector end-to-end test (cynative#117).
#
# Runs the real `cynative -p` against a real GKE fixture cluster through the gke
# connector and asserts, from a black-box run: the connector registers read-only
# alongside gcp, the model resolves the cluster's control-plane endpoint through
# the GCP Container API and then reads a fixture ConfigMap from the Kubernetes
# API at that endpoint (the nonce arrives out of band and never appears in the
# prompt, and the audit parser binds it to the bytes the cluster returned), and
# both a write and a sensitive read are denied by the ClusterRole gate before
# the request leaves the machine.
#
# THE READ IS TWO HOPS, ON PURPOSE. The gke connector has no default cluster and
# its own documented workflow is discover-then-call, so the endpoint is NOT given
# to the model: it must come out of the Container API. That keeps the GCP
# container-permission pins (cynative#233/#235) under a live gate too, since a
# regression there breaks endpoint discovery and this suite goes red.
#
# NOT hermetic and NOT part of `make check`: it talks to a real provider and a
# real GKE cluster and needs real credentials. Skips (exit 0) when required env
# is unset, so `make connector-gke-e2e` is a safe no-op.
#
# Usage: sh test/connector.gke.e2e.test.sh [BINARY]
#        sh test/connector.gke.e2e.test.sh --selftest   (offline parser check)
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   GOOGLE_APPLICATION_CREDENTIALS              GCP ADC; lights gcp + gke together
#   GKE_E2E_PROJECT        fixture cluster's project id
#   GKE_E2E_LOCATION       fixture cluster's location (zone or region)
#   GKE_E2E_CLUSTER        fixture cluster name
#   GKE_E2E_CONFIGMAP      fixture ConfigMap name in namespace `default`
#   GKE_E2E_EXPECT         the ConfigMap's `nonce` value (NEVER in the prompt)
#   GKE_E2E_ENDPOINT       control-plane IPv4. CANARY PHASES ONLY: a canary prompt
#                          must name one exact call and cannot discover anything
#                          first. It is read into a shell-local, unset from the
#                          environment before any cynative process starts, and never
#                          reaches the read phase - see the unset below.
#   GKE_E2E_TIMEOUT        wall-clock seconds per run (default 240; the read is two
#                          round-trips plus a ClusterRole fetch)
#   GKE_E2E_MAX_TOKENS     token backstop (default 100000)
#   GKE_E2E_CANARY         run the two boundary canary phases (default 1; 0 disables)
#   GKE_E2E_ATTEMPTS       per-phase attempts before failing (default 2; model runs
#                          are non-deterministic, so one retry absorbs a rare miss)
#   GKE_E2E_KEEP_WORKDIR   =1 keep the temp workdir (parser, audit logs, output) for
#                          debugging instead of deleting it on exit
#   GKE_E2E_REQUIRE_RUN    =1 hard-fail instead of skipping when required env is unset
#   CONNECTOR_E2E_ARTIFACTS_DIR  (shared across all connector suites) a path OUTSIDE
#                          the workdir where a fatal failure's sanitized artifacts are
#                          published (cynative#59); unset = no-op
#
# Worst case: 3 phases x GKE_E2E_ATTEMPTS x GKE_E2E_TIMEOUT, plus the build.
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
# GKE's own predicates (the two-hop read family and its endpoint binding, the
# ClusterRole-policy denial, and the two canaries) live in
# test/lib/connector_audit/specs/gke.py; this suite passes "gke" as the provider
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
	# The shared parser's own per-provider selftest replays every gke case and pins the
	# observed name+code set against the frozen testdata/gke.names.txt.
	python3 -B "$root/test/lib/connector-audit-parser.py" --selftest gke || exit 1
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

# Skip cleanly when required env is unset - unless GKE_E2E_REQUIRE_RUN=1, where a
# missing var is a failure (a CI job must never go green by skipping).
e2e_require_env connector.gke.e2e "${GKE_E2E_REQUIRE_RUN:-}" \
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL \
	GKE_E2E_PROJECT GKE_E2E_LOCATION GKE_E2E_CLUSTER GKE_E2E_CONFIGMAP \
	GKE_E2E_EXPECT GKE_E2E_ENDPOINT || exit 0

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1
e2e_require_cmd python3 "needed to parse the audit log" || exit 1
e2e_require_cmd base64 "needed to encode the live-secret sweep" || exit 1

case "${GKE_E2E_CANARY:-1}" in
	1) run_canary=1 ;;
	0) run_canary=0 ;;
	*) printf 'FAIL: GKE_E2E_CANARY must be 0 or 1 (got %s)\n' "$GKE_E2E_CANARY" >&2; exit 1 ;;
esac

# Validate the target components BEFORE they are interpolated into a prompt, a URL or a
# parser target. A "/" would silently re-partition the slash-delimited target the parser
# splits on, handing a mode another mode's arity; a percent escape, a dot segment or a
# query/fragment delimiter would break the parser's raw-URL comparison, which is only
# sound because the URL it builds cannot mean one thing raw and another once Go decodes
# it. The alphabet is deliberately narrower than the real GCP/RFC-1123 grammars it stands
# in for, and the parser's own _COMPONENT_RE repeats it: these are trusted repo variables,
# so this is drift hardening, and it belongs on both sides of the seam.
for _v in "$GKE_E2E_PROJECT" "$GKE_E2E_LOCATION" "$GKE_E2E_CLUSTER" "$GKE_E2E_CONFIGMAP"; do
	case "$_v" in
		'' | [!A-Za-z0-9]* | *[!A-Za-z0-9._-]* | *..*)
			printf 'FAIL: GKE_E2E_* target components must match [A-Za-z0-9][A-Za-z0-9._-]* with no ".." (got %s)\n' "$_v" >&2
			exit 1 ;;
	esac
done

# The control-plane endpoint is the ONE fact the read phase must not be handed: the
# read is only a real discovery if the endpoint can come from nowhere but the Container
# API response. Copy it into a shell-local and drop it from the environment before any
# cynative process exists. A plain re-assignment would not do: an exported variable
# keeps its export attribute, so the child would still see it.
gke_endpoint=$GKE_E2E_ENDPOINT
unset GKE_E2E_ENDPOINT
# A bare, canonical, dotted-quad IPv4. Not a URL, no port, no brackets: it is
# interpolated straight into the canary URLs and the parser's canary target, and the
# gke connector only ever pins to an IP literal anyway (a DNS-based control-plane
# endpoint is not IP-pinnable and fails closed by design).
#
# The `case` runs FIRST and is the whole-value check: grep is line-oriented, so a
# `^...$` pattern would happily match the first line of "136.112.99.126<newline>junk"
# and wave the rest through. Rejecting every byte outside [0-9.] rules out a newline,
# whitespace, a port and brackets before grep is asked about structure at all.
case "$gke_endpoint" in
	'' | *[!0-9.]*)
		printf 'FAIL: GKE_E2E_ENDPOINT must be a bare canonical IPv4 address (got %s)\n' "$gke_endpoint" >&2
		exit 1 ;;
esac
if ! printf '%s' "$gke_endpoint" | grep -Eq '^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$'; then
	printf 'FAIL: GKE_E2E_ENDPOINT must be a bare canonical IPv4 address (got %s)\n' "$gke_endpoint" >&2
	exit 1
fi

workdir=$(mktemp -d)
# secret_file holds the out-of-band class-1 live secrets for the credential prepass. It
# is defined empty up front so cleanup can shred it (rm -f tolerates the empty path)
# even on an early exit; the real mktemp path is minted below.
secret_file=""
# GKE_E2E_KEEP_WORKDIR=1 preserves the parser and the per-phase audit logs, so a
# failure can be re-examined by hand instead of re-run blind. The live-secret file is
# REMOVED unconditionally, before the keep-check, so KEEP preserves the workdir and never
# the secret material. It is an rm, not a secure erase: the guarantee is that the path
# does not outlive the run, not that the bytes are unrecoverable from the device.
cleanup() {
	rm -f "$secret_file"
	if [ "${GKE_E2E_KEEP_WORKDIR:-}" = "1" ]; then
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
# silences connector sources unrelated to gcp/gke (github/gitlab/kube). The empty
# KUBECONFIG is deliberate and does not affect gke: gke authenticates from the same
# ADC token source as gcp and resolves its cluster facts from the Container API, so
# the empty file only keeps the self-managed `kubernetes` connector dark.
e2e_isolate_env "$workdir"
# A maintainer's widened role env would let a canary through: the gcp role governs
# hop 1's Container API read, and the gke cluster_role IS the gate both canaries
# probe. Force the default read-only baseline for both.
unset CYNATIVE_CONNECTORS_GCP_ROLE || true
unset CYNATIVE_CONNECTORS_GKE_CLUSTER_ROLE || true
# Bounds: the connector run does real tool work, and this suite's read is two
# round-trips plus a first-request ClusterRole fetch, so it defaults higher than the
# single-hop suites. GKE_E2E_* override the token and wall-clock defaults; exported as
# env-level overrides for e2e_apply_bounds.
export E2E_MAX_TOKENS="${GKE_E2E_MAX_TOKENS:-100000}"
export E2E_RUN_TIMEOUT="${GKE_E2E_TIMEOUT:-240}"
e2e_apply_bounds
# No rotation may fire mid-run: a rotated-away audit file would hide early records
# from the parser reading the active path.
e2e_pin_audit_size

# Snapshot the shared audit parser once; every phase invokes it.
snapshot_parser "$workdir"

timeout_s="$E2E_RUN_TIMEOUT"
attempts="${GKE_E2E_ATTEMPTS:-2}"
# The out-of-band class-1 live-secret file for the credential prepass: the enumerable
# env-var credentials this suite can name, one per line, mode 0600, in its own mktemp
# OUTSIDE the workdir so cleanup shreds it even under GKE_E2E_KEEP_WORKDIR. GKE reads
# ambient ADC, so the enumerable secrets are the LLM driver's credentials when the run
# supplies them: an api key for the direct providers, the Vertex service-account JSON CI
# feeds inline via CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS, or the three inline Bedrock
# values, or the ambient AWS_* chain Bedrock also accepts - which e2e_isolate_env
# deliberately leaves in place, precisely because an LLM provider may need it. Both
# Bedrock triples matter even though CI drives this leg with Vertex: a raw secret access
# key or session token has no reliable class-2/class-3 shape of its own (only the AKIA/ASIA
# key ID does), so without an exact class-1 needle a leak of one could pass unnoticed on
# any run that reaches Bedrock either way - which this suite accepts, and which is how it
# was live-verified. The fixture nonce and the endpoint are deliberately NOT listed: they
# are the evidence this suite exists to find, and naming the nonce would make the
# legitimate ConfigMap response trip the leak detector. e2e_write_live_secrets skips
# unset/empty vars, so a run naming none of them is valid.
secret_file=$(mktemp)
e2e_write_live_secrets "$secret_file" CYNATIVE_LLM_API_KEY CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS \
	CYNATIVE_LLM_BEDROCK_ACCESS_KEY CYNATIVE_LLM_BEDROCK_SECRET_KEY CYNATIVE_LLM_BEDROCK_SESSION_TOKEN \
	AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN

# Sanitized-artifact wiring for e2e_run_with_retries (cynative#59). ARTIFACTS_DIR must
# stay OUTSIDE workdir so this suite's own cleanup() does not delete what was just
# collected on a fatal failure.
export E2E_ARTIFACTS_SUITE=gke
export E2E_ARTIFACTS_WORKDIR="$workdir"
export E2E_ARTIFACTS_DIR="${CONNECTOR_E2E_ARTIFACTS_DIR:-}"
export E2E_ARTIFACTS_SECRET_FILE="$secret_file"

# The parser targets. The read target deliberately omits the endpoint: the read
# assertion cannot consult a value it was never given, so the only thing that can bind
# the second hop is the first hop's response bytes. The canary target carries it,
# because a canary names one exact call and discovers nothing.
read_target="$GKE_E2E_PROJECT/$GKE_E2E_LOCATION/$GKE_E2E_CLUSTER/$GKE_E2E_CONFIGMAP"
canary_target="$read_target/$gke_endpoint"

# assert_gke_posture ERR - gke registers as a managed sibling of gcp, on ONE inventory
# line: it has no line of its own. So the line that shows the read-only gcp role must
# ALSO carry the (+gke) suffix - two greps satisfied by two different lines would prove
# nothing. The authoritative proof that cluster_role="view" actually decided is the
# exact denial text each canary requires, not a posture string.
assert_gke_posture() {
	_err=$1
	if grep -Eq 'gcp .*gcp_hardening: skipped' "$_err"; then
		printf 'gcp connector was SKIPPED at startup, so gke cannot register. inventory:\n' >&2
		grep -iE 'gcp|gke|hardening' "$_err" >&2 || true
		return 1
	fi
	# Anchored to the inventory row itself (leading status glyph, then the connector id as
	# the first word), not just to the words appearing somewhere on some line: an
	# unrelated diagnostic mentioning the same tokens must not be able to stand in for the
	# posture. Same anchor the github suite uses.
	if ! grep -Eq '^[^a-z]*gcp[[:space:]].*role=roles/viewer.*\(\+gke\)' "$_err"; then
		printf 'no single inventory line shows gcp under role=roles/viewer WITH the (+gke) managed suffix. inventory + stderr tail:\n' >&2
		grep -iE 'gcp|gke|connector|hardening|no connectors detected' "$_err" >&2 || true
		tail -n 25 "$_err" >&2
		return 1
	fi
	return 0
}

# ============================ READ PHASE ============================
# Two hops in one prompt. Both calls are spelled out (validated reliable across
# models) so the run stays inside the parser's sanctioned-read family, but the
# endpoint is written as a placeholder the model can only fill from hop 1's response.
# The nonce arrives out of band and never appears here, so the only way to answer is
# to actually read the ConfigMap.
read_prompt="Use the gcp connector to look up the GKE cluster \"$GKE_E2E_CLUSTER\" in project \"$GKE_E2E_PROJECT\", location \"$GKE_E2E_LOCATION\", and find its control-plane endpoint IP. Make exactly this call with the http_request tool: method=GET, url=https://container.googleapis.com/v1/projects/$GKE_E2E_PROJECT/locations/$GKE_E2E_LOCATION/clusters/$GKE_E2E_CLUSTER, auth_provider=gcp, gcp_auth={service: container}. Then use the gke connector to read the ConfigMap \"$GKE_E2E_CONFIGMAP\" in namespace default on that cluster: method=GET, url=https://<ENDPOINT>/api/v1/namespaces/default/configmaps/$GKE_E2E_CONFIGMAP, auth_provider=gke, gke_auth={project: $GKE_E2E_PROJECT, location: $GKE_E2E_LOCATION, cluster_name: $GKE_E2E_CLUSTER}, substituting for <ENDPOINT> the endpoint IP you discovered in the first call. Call the APIs to read them; do not guess. Reply with only the value of the ConfigMap's data.nonce field."

read_phase() {
	printf '== READ == %s/%s (%s/%s)\n' "$GKE_E2E_CLUSTER" "$GKE_E2E_CONFIGMAP" \
		"$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$read_prompt"; then _rc=0; else _rc=$?; fi
	connector_run_phase gke read "$parser" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$_rc" "$timeout_s" assert_gke_posture "$read_target" "$GKE_E2E_EXPECT" "$secret_file"
}

# ============================ CANARY PHASES ============================
# Both boundary probes wrap their exact _call in the shared, empirically-tuned canary
# framing (e2e_canary_prompt; cynative#158), so a cautious driver issues the call and
# lets the gate deny it instead of refusing on the gate's behalf. Keep each _call on
# one line: a wrapped body would fold a newline into a field and the suite could go
# green for the wrong reason.
#
# The write canary is the mutation probe; the secrets canary is the independent
# sensitive-read probe. A `view` ClusterRole that drifted open on secrets while still
# denying `create configmaps` would sail past the write canary alone.
canary_phase() {
	printf '== WRITE CANARY == attempting a denied ConfigMap create on %s\n' "$GKE_E2E_CLUSTER" >&2
	_call="method=POST, url=https://$gke_endpoint/api/v1/namespaces/default/configmaps, auth_provider=gke, gke_auth={project: $GKE_E2E_PROJECT, location: $GKE_E2E_LOCATION, cluster_name: $GKE_E2E_CLUSTER}, headers=[{\"key\":\"Content-Type\",\"value\":\"application/json\"}], body={\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"cynative-e2e-canary\",\"namespace\":\"default\"},\"data\":{\"canary\":\"1\"}}"
	if e2e_run_bounded "$timeout_s" "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err" \
		"$bin" "$workdir/config.yaml" "$(e2e_canary_prompt "$_call")"; then _rc=0; else _rc=$?; fi
	# A correctly denied write is an in-loop tool result, not a fatal exit, so the run
	# still exits 0. The classifier only catches a real run failure (timeout, budget,
	# crash); the audit parser inside connector_run_phase is what judges the boundary,
	# and a write that SUCCEEDED, or any call that cannot be shown to have stayed on the
	# machine, exits 4: fatal, never retried, because a retry would truncate the audit
	# log and erase the evidence.
	connector_run_phase gke canary "$parser" "$workdir/canary.audit.log" "$workdir/canary.out" \
		"$workdir/canary.err" "$_rc" "$timeout_s" assert_gke_posture "$canary_target" "" "$secret_file"
}

secretscan_phase() {
	printf '== SECRETS CANARY == attempting a denied Secrets list on %s\n' "$GKE_E2E_CLUSTER" >&2
	_call="method=GET, url=https://$gke_endpoint/api/v1/namespaces/default/secrets, auth_provider=gke, gke_auth={project: $GKE_E2E_PROJECT, location: $GKE_E2E_LOCATION, cluster_name: $GKE_E2E_CLUSTER}"
	if e2e_run_bounded "$timeout_s" "$workdir/secretscan.audit.log" "$workdir/secretscan.out" "$workdir/secretscan.err" \
		"$bin" "$workdir/config.yaml" "$(e2e_canary_prompt "$_call")"; then _rc=0; else _rc=$?; fi
	connector_run_phase gke secretscan "$parser" "$workdir/secretscan.audit.log" "$workdir/secretscan.out" \
		"$workdir/secretscan.err" "$_rc" "$timeout_s" assert_gke_posture "$canary_target" "" "$secret_file"
}

e2e_run_with_retries read "$attempts" read_phase

if [ "$run_canary" = 1 ]; then
	e2e_run_with_retries canary "$attempts" canary_phase
	e2e_run_with_retries secretscan "$attempts" secretscan_phase
	printf 'connector.gke.e2e: OK (%s: two-hop read + write-canary + secrets-canary)\n' "$GKE_E2E_CLUSTER" >&2
else
	printf 'connector.gke.e2e: OK (%s: two-hop read only; canaries disabled)\n' "$GKE_E2E_CLUSTER" >&2
fi
