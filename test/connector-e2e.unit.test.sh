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

if [ "$fails" -ne 0 ]; then
	printf 'connector-e2e.unit: %d case(s) FAILED\n' "$fails" >&2
	exit 1
fi
printf 'connector-e2e.unit: OK\n' >&2
