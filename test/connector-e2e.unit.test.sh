#!/bin/sh
# connector-e2e.unit.test.sh - offline unit tests for the shared connector e2e shell
# orchestration library (test/lib/connector-e2e.sh, cynative#152).
#
# Hermetic: no network, no credentials, no cynative build, no live parser. It sources
# the library (which itself sources e2e-guardrails.sh) and exercises the pure
# `arbitrate` arbiter and the `connector_run_phase` driver against python3 stub
# parsers and stub posture callbacks, plus `e2e_pin_audit_size`. Run by `make sh-test`
# alongside the e2e-guardrails unit tests.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck source=test/lib/connector-e2e.sh
. "$here/lib/connector-e2e.sh"

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

# mkparser TD NAME CODE - write a python3 stub parser to TD/NAME that records its argv
# (sys.argv[1:], newline-joined, no trailing newline) into TD/argv and exits CODE.
mkparser() {
	printf 'import sys\nopen("%s","w").write("\\n".join(sys.argv[1:]))\nsys.exit(%s)\n' "$1/argv" "$3" > "$1/$2"
}

# mkposture TD - write an executable posture-callback stub to TD/posture that touches
# TD/posture_ran when invoked (and otherwise exits 0), so a case can assert whether
# connector_run_phase ran it.
mkposture() {
	printf '#!/bin/sh\n: > "%s/posture_ran"\n' "$1" > "$1/posture"
	chmod +x "$1/posture"
}

# runrc ARGS... - invoke connector_run_phase, printing its exit code without tripping
# set -e on the intentional non-zero returns.
runrc() {
	if connector_run_phase "$@" >/dev/null 2>&1; then echo 0; else echo $?; fi
}

# ---- arbitrate: the 8 rows ported from the suites' former --selftest -----------
if (
	_af=0
	check_arb() { arbitrate "$2" "$3" && _g=0 || _g=$?; if [ "$_g" != "$1" ]; then _af=1; fi; }
	check_arb 4 4 0 # breach + clean run
	check_arb 4 4 2 # breach + timeout: breach wins
	check_arb 4 4 3 # breach + budget: breach wins
	check_arb 2 1 2 # miss + timeout: timeout wins
	check_arb 3 1 3 # miss + budget: budget wins
	check_arb 1 1 0 # miss + clean run
	check_arb 2 0 2 # hold + timeout
	check_arb 0 0 0 # hold + clean run
	[ "$_af" = 0 ] || exit 1
); then pass "arbitrate: all 8 rows (breach/miss/hold x clean/timeout/budget)"; else fail "arbitrate"; fi

# ---- connector_run_phase: a security breach (4) short-circuits, posture suppressed --
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	mkparser "$td" p_breach.py 4
	mkposture "$td"
	: > "$td/out"; : > "$td/err"; : > "$td/audit"
	[ "$(runrc gcp read "$td/p_breach.py" "$td/audit" "$td/out" "$td/err" 0 60 "$td/posture" proj expect '')" -eq 4 ] || exit 1
	[ ! -e "$td/posture_ran" ] || exit 1
); then pass "connector_run_phase: a breach (parser exit 4) returns 4 and never runs the posture callback"; else fail "connector_run_phase breach"; fi

# ---- connector_run_phase: any abnormal parser exit normalizes to 4 -------------
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	mkparser "$td" p_two.py 2
	mkparser "$td" p_onetwentysix.py 126
	mkposture "$td"
	: > "$td/out"; : > "$td/err"; : > "$td/audit"
	[ "$(runrc gcp read "$td/p_two.py" "$td/audit" "$td/out" "$td/err" 0 60 "$td/posture" proj expect '')" -eq 4 ] || exit 1
	[ "$(runrc gcp read "$td/p_onetwentysix.py" "$td/audit" "$td/out" "$td/err" 0 60 "$td/posture" proj expect '')" -eq 4 ] || exit 1
	[ "$(runrc gcp read "$td/does-not-exist.py" "$td/audit" "$td/out" "$td/err" 0 60 "$td/posture" proj expect '')" -eq 4 ] || exit 1
	[ ! -e "$td/posture_ran" ] || exit 1
); then pass "connector_run_phase: parser exit 2/126/a missing parser path all normalize to 4"; else fail "connector_run_phase normalize"; fi

# ---- connector_run_phase: a retryable miss (1) plus a timeout (2) -> 2 wins ----
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	mkparser "$td" p_miss.py 1
	mkposture "$td"
	: > "$td/out"; : > "$td/err"; : > "$td/audit"
	[ "$(runrc gcp read "$td/p_miss.py" "$td/audit" "$td/out" "$td/err" 124 60 "$td/posture" proj expect '')" -eq 2 ] || exit 1
	[ ! -e "$td/posture_ran" ] || exit 1
); then pass "connector_run_phase: a miss (1) plus a classifier timeout (rc 124) arbitrates to 2"; else fail "connector_run_phase timeout-dominance"; fi

# ---- connector_run_phase: a clean parser (0) + clean classify runs the posture fn --
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	mkparser "$td" p_clean.py 0
	mkposture "$td"
	printf 'footer: 3 tool calls\n' > "$td/err"
	: > "$td/out"; : > "$td/audit"
	[ "$(runrc gcp canary "$td/p_clean.py" "$td/audit" "$td/out" "$td/err" 0 60 "$td/posture" proj expect '')" -eq 0 ] || exit 1
	[ -e "$td/posture_ran" ] || exit 1
); then pass "connector_run_phase: a clean parser + clean classify runs the posture callback"; else fail "connector_run_phase clean-run"; fi

# ---- connector_run_phase: argv fidelity - PROVIDER MODE AUDIT TARGET first --------
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	mkparser "$td" p_argv.py 0
	mkposture "$td"
	printf 'footer: 1 tool call\n' > "$td/err"
	printf 'expect-marker\n' > "$td/out"
	: > "$td/audit"
	connector_run_phase myprovider read "$td/p_argv.py" "$td/audit" "$td/out" "$td/err" 0 60 "$td/posture" mytarget expect-marker '' >/dev/null 2>&1 || true
	content=$(cat "$td/argv")
	want=$(printf '%s\n%s\n%s\n%s' myprovider read "$td/audit" mytarget)
	case "$content" in
		"$want"*) ;;
		*) exit 1 ;;
	esac
); then pass "connector_run_phase: argv starts with PROVIDER MODE AUDIT TARGET"; else fail "connector_run_phase argv fidelity"; fi

# ---- e2e_pin_audit_size ---------------------------------------------------------
if (
	unset CYNATIVE_AUDIT_MAX_SIZE_MB CYNATIVE_AUDIT_RETENTION_DAYS CYNATIVE_AUDIT_COMPRESS 2>/dev/null || true
	e2e_pin_audit_size
	[ "$CYNATIVE_AUDIT_MAX_SIZE_MB" = "4096" ] || exit 1
	[ "$CYNATIVE_AUDIT_RETENTION_DAYS" = "3650" ] || exit 1
	[ "$CYNATIVE_AUDIT_COMPRESS" = "false" ] || exit 1
); then pass "e2e_pin_audit_size exports a rotation-free audit configuration"; else fail "e2e_pin_audit_size"; fi

# ---- e2e_collect_artifacts (cynative#59) -----------------------------------------
# Sanitized-artifact collection reuses the shared parser's class-2/class-3 regex
# families (test/lib/connector_audit/engine.py), so it needs python3 - the same
# dependency `make sh-test` already asserts before running this file.
command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found\n' >&2; exit 1; }

# ---- e2e_collect_artifacts: sanitized artifacts, raw workdir left untouched, ----
# ---- no audit log published, meta.txt present, artifacts dir outside workdir ----
if (
	wd=$(mktemp -d)
	ad=$(mktemp -d)
	trap 'rm -rf "$wd" "$ad"' EXIT
	live_secret="s3cr3t-live-value-abcdef0123"
	sf=$(mktemp)
	{ printf '%s' "$live_secret" | base64 | tr -d '\n'; printf '\n'; } > "$sf"  # base64, matching e2e_write_live_secrets
	# A fake class-2 secret SHAPE (AWS's own documented example access key id; never a
	# real credential) that has nothing to do with the live-secret file.
	shape="AKIAIOSFODNN7EXAMPLE"
	printf 'reading with key %s now\n' "$shape" > "$wd/read.out"
	# The exact class-1 live-secret value, as --auto-approve would print a raw tool-call
	# argument to stderr.
	printf 'stderr noise\ntool call arg leaked: %s\nmore noise\n' "$live_secret" > "$wd/read.err"
	# A raw audit log carrying a credential in its (verbatim, approval-gated) arguments -
	# this must never be copied into the published artifacts at all.
	printf '{"tool":"http_request","arguments":"{\\"headers\\":[{\\"key\\":\\"Authorization\\",\\"value\\":\\"Bearer %s\\"}]}"}\n' \
		"$live_secret" > "$wd/read.audit.log"

	e2e_collect_artifacts myread "$wd" "$ad" "$sf" || exit 1

	# (a) the class-2 shape is scrubbed from the sanitized read.out.
	grep -q "$shape" "$ad/myread/read.out" && exit 1
	grep -q 'REDACTED' "$ad/myread/read.out" || exit 1
	# (b) the exact class-1 live secret is scrubbed from the sanitized read.err.
	grep -q "$live_secret" "$ad/myread/read.err" && exit 1
	grep -q 'REDACTED' "$ad/myread/read.err" || exit 1
	# (c) the raw workdir files are untouched (the secret bytes are still there).
	grep -q "$shape" "$wd/read.out" || exit 1
	grep -q "$live_secret" "$wd/read.err" || exit 1
	# (d) no *.audit.log anywhere under the artifacts dir.
	[ ! -e "$ad/myread/read.audit.log" ] || exit 1
	find "$ad" -name '*.audit.log' 2>/dev/null | grep -q . && exit 1
	# (e) meta.txt exists and names only the suite/fixture identifiers, never the
	# secret bytes.
	[ -e "$ad/myread/meta.txt" ] || exit 1
	grep -q "$live_secret" "$ad/myread/meta.txt" && exit 1
	# (f) the artifacts dir is outside the workdir.
	case "$ad" in "$wd"/*) exit 1 ;; esac
); then pass "e2e_collect_artifacts: sanitized artifacts, raw workdir untouched, no audit.log, meta.txt, outside workdir"; else fail "e2e_collect_artifacts"; fi

# ---- e2e_collect_artifacts: a live secret in a NON-CANONICAL percent-encoding is --
# ---- scrubbed (cynative#152 F1). The literal + quote_plus() canonical passes cannot --
# ---- remove a secret whose bytes are over-encoded (here 'c' -> %63): unquote_plus ----
# ---- restores it, but neither the literal value nor its quote_plus() form is present. --
# ---- The decoded-line backstop must drop the whole line so no reversibly-encoded ----
# ---- secret survives into the published artifact. -------------------------------
if (
	wd=$(mktemp -d)
	ad=$(mktemp -d)
	trap 'rm -rf "$wd" "$ad"' EXIT
	live_secret="abcdef012345live-xyz"
	sf=$(mktemp)
	{ printf '%s' "$live_secret" | base64 | tr -d '\n'; printf '\n'; } > "$sf"  # base64, matching e2e_write_live_secrets
	# The same secret bytes reversibly hidden behind a non-canonical percent-encoding
	# (over-encoding the 'c' as %63). quote_plus() leaves this all-safe value unchanged,
	# so the literal + canonical passes have no form to match; only the decoded backstop
	# can catch it. No credential-named key/colon/equals, so class-2/class-3 stay silent.
	encoded="ab%63def012345live-xyz"
	printf 'noise line\nleaked here %s trailing\nmore noise\n' "$encoded" > "$wd/read.err"
	printf 'benign %%2Fhome value\n' > "$wd/read.out"

	e2e_collect_artifacts myread "$wd" "$ad" "$sf" || exit 1

	# (a) neither the decoded secret nor its encoded form survives in the artifact.
	grep -q "$live_secret" "$ad/myread/read.err" && exit 1
	grep -q "$encoded" "$ad/myread/read.err" && exit 1
	# (b) the strongest assertion: unquote_plus of the whole scrubbed file reveals no
	# secret bytes - no reversible encoding slipped through.
	python3 - "$ad/myread/read.err" "$live_secret" <<'PY' || exit 1
import sys, urllib.parse
data = open(sys.argv[1], encoding="utf-8", errors="replace").read()
sys.exit(1 if sys.argv[2] in urllib.parse.unquote_plus(data) else 0)
PY
	# (c) no over-redaction: a benign percent-encoded line (a path, not a secret) is kept.
	grep -q 'benign' "$ad/myread/read.out" || exit 1
	# (d) the raw workdir file is untouched (the encoded secret bytes are still there).
	grep -q "$encoded" "$wd/read.err" || exit 1
); then pass "e2e_collect_artifacts: a live secret in a non-canonical percent-encoding is scrubbed"; else fail "e2e_collect_artifacts non-canonical encoding"; fi

# ---- e2e_collect_artifacts: a no-op when ARTIFACTS_DIR is empty -----------------
if (
	wd=$(mktemp -d)
	trap 'rm -rf "$wd"' EXIT
	printf 'hello\n' > "$wd/read.out"
	e2e_collect_artifacts myread "$wd" "" "" || exit 1
	# Nothing besides the seeded file exists in the workdir: no stray directory was
	# created from concatenating an empty ARTIFACTS_DIR with the suite name.
	[ "$(find "$wd" -mindepth 1 | wc -l)" -eq 1 ] || exit 1
); then pass "e2e_collect_artifacts: a no-op when ARTIFACTS_DIR is empty"; else fail "e2e_collect_artifacts no-op"; fi

# ---- e2e_run_with_retries: fires the collection before a fatal exit (cynative#59) --
# The phase callback is defined at top level (not inside the `if (...)` subshell)
# because it is invoked indirectly, by name, and ShellCheck only resolves that
# reference at top level (SC2329), mirroring test/e2e-guardrails.unit.test.sh.
unit_security_wired() { return 4; }

if (
	wd=$(mktemp -d)
	ad=$(mktemp -d)
	trap 'rm -rf "$wd" "$ad"' EXIT
	printf 'answer text\n' > "$wd/read.out"
	printf 'sdk log\n' > "$wd/read.err"
	export E2E_ARTIFACTS_SUITE=wired
	export E2E_ARTIFACTS_WORKDIR="$wd"
	export E2E_ARTIFACTS_DIR="$ad"
	export E2E_ARTIFACTS_SECRET_FILE=""
	if ( e2e_run_with_retries wired 1 unit_security_wired >/dev/null 2>&1 ); then exit 1; fi
	[ -e "$ad/wired/read.out" ] || exit 1
	[ -e "$ad/wired/meta.txt" ] || exit 1
	unset E2E_ARTIFACTS_SUITE E2E_ARTIFACTS_WORKDIR E2E_ARTIFACTS_DIR E2E_ARTIFACTS_SECRET_FILE
); then pass "e2e_run_with_retries: collects sanitized artifacts before its fatal exit on a security failure"; else fail "e2e_run_with_retries artifact wiring"; fi

# ---- e2e_write_live_secrets: base64 one line per value, multi-line preserved ----
# Each value is base64-encoded onto one line, so a multi-line credential (a JSON key
# blob) stays a single class-1 needle instead of splitting into per-line needles ("{",
# a project id) that false-positive against any audit legitimately containing them.
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	SINGLE="ghp_singleLineToken1234567890abcdef"
	MULTI=$(printf '{\n  "project_id": "cynative-cli-ci",\n  "token_url": "https://sts.googleapis.com/v1/token"\n}')
	export SINGLE MULTI
	e2e_write_live_secrets "$td/secrets" SINGLE MULTI
	[ "$(wc -l < "$td/secrets")" -eq 2 ] || exit 1          # one base64 line per value
	grep -Fq 'cynative-cli-ci' "$td/secrets" && exit 1      # raw fragments never appear
	grep -Fqx '{' "$td/secrets" && exit 1
	# each line base64-decodes back to its EXACT value; the multi-line one is preserved whole
	[ "$(sed -n 1p "$td/secrets" | base64 -d)" = "$SINGLE" ] || exit 1
	[ "$(sed -n 2p "$td/secrets" | base64 -d)" = "$MULTI" ] || exit 1
	unset SINGLE MULTI
); then pass "e2e_write_live_secrets: base64-encodes each value, preserving a multi-line secret as one needle"; else fail "e2e_write_live_secrets base64"; fi

# ---- e2e_write_live_secrets: fail closed when base64 is unavailable -------------
# POSIX sh has no pipefail, so a missing base64 would let the encode pipeline succeed and
# write a blank line that drops the secret from the class-1 sweep. The function must
# refuse (non-zero) instead of silently omitting the secret.
if (
	td=$(mktemp -d)
	trap 'rm -rf "$td"' EXIT
	X="a-real-secret-value"
	export X
	rc=0
	# Run with base64 off PATH inside its own subshell so the outer cleanup keeps its PATH.
	# shellcheck disable=SC2123  # intentional: emptying PATH is how we hide base64 here.
	( PATH=/nonexistent-dir-xyz; e2e_write_live_secrets "$td/out" X >/dev/null 2>&1 ) || rc=$?
	[ "$rc" -ne 0 ] || exit 1
	unset X
); then pass "e2e_write_live_secrets: fails closed when base64 is unavailable"; else fail "e2e_write_live_secrets base64 guard"; fi

if [ "$fails" -ne 0 ]; then
	printf 'connector-e2e.unit: %d case(s) FAILED\n' "$fails" >&2
	exit 1
fi
printf 'connector-e2e.unit: OK\n' >&2
