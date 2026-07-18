# shellcheck shell=sh
# connector-e2e.sh - shared shell orchestration for the live connector e2e suites
# (cynative#152), extracted from the three suites' near-identical `arbitrate` +
# `run_phase` (added in cynative#39/#52/#53). Sourced, never executed: it defines
# helpers and has no side effects at source time beyond pulling in the shared cost/
# timeout guardrails (test/lib/e2e-guardrails.sh), which every caller here needs
# anyway.
#
# Every caller of this file lives directly in test/ (the three connector suites plus
# this library's own unit test), so `dirname "$0"` at source time always resolves to
# test/ - the same $0-relative trick the suites already use to find `root`/`here`.
#
# Phase-status contract, shared with test/lib/e2e-guardrails.sh and
# test/lib/connector_audit/engine.py:
#   0  the phase's assertions hold.
#   1  not proven this attempt (a model miss or a fumbled call the gate blocked).
#      Retryable.
#   2  the run timed out.
#   3  the token budget was hit. FATAL, never retried.
#   4  a SECURITY assertion failed: a request the read-only boundary should have
#      stopped was dispatched, or a write succeeded, or the audit parser itself
#      exited abnormally. FATAL, and never retried.
_connector_e2e_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$_connector_e2e_dir/lib/e2e-guardrails.sh"

# arbitrate PARSER_RC CLASSIFY_RC -> final phase status. Pure (no guardrail library
# calls), so an offline caller can exercise it directly. A security breach (4)
# dominates even a timeout or budget hit; otherwise a nonzero classifier (2 timeout /
# 3 budget / 1 error) wins; else the parser's own 0 (hold) or 1 (miss).
arbitrate() {
	if [ "$1" = 4 ]; then return 4; fi
	if [ "$2" != 0 ]; then return "$2"; fi
	return "$1"
}

# connector_run_phase PROVIDER MODE PARSER AUDIT OUT ERR RC TIMEOUT POSTURE_FN TARGET
# EXPECT_VALUE LIVE_SECRET_FILE -> phase status. Every argument is explicit (no
# caller-global `rc`, no eval, no callback command-strings): POSTURE_FN and, at
# invocation time, EXPECT_VALUE are plain values the shell resolves as an ordinary
# command/argument, never interpreted as source text.
#
# Runs the shared audit parser (PARSER) as the security boundary: its exit code is
# normalized to the 0/1/4 contract (any abnormal exit, e.g. a usage error or a missing
# parser path, becomes 4) BEFORE anything else runs, and a 4 short-circuits before the
# run classifier and every soft gate below - nothing may suppress or delay a security
# failure. Only once the parser holds (0/1) does the run classifier (RC/OUT/ERR/
# TIMEOUT) get consulted and the two arbitrated. A clean arbitration (0) then runs the
# connector-specific posture check (POSTURE_FN), the generic tool-called assertion, and
# (read mode only) checks EXPECT_VALUE landed in OUT.
connector_run_phase() {
	_provider=$1
	_mode=$2
	_parser=$3
	_audit=$4
	_out=$5
	_err=$6
	_rc=$7
	_timeout=$8
	_posture_fn=$9
	shift 9
	_target=$1
	_expect=$2
	_secret_file=$3

	if [ -n "$_secret_file" ]; then
		if python3 -B "$_parser" "$_provider" "$_mode" "$_audit" "$_target" "$_expect" \
			--live-secrets "$_secret_file"; then
			_p=0
		else
			_p=$?
		fi
	else
		if python3 -B "$_parser" "$_provider" "$_mode" "$_audit" "$_target" "$_expect"; then
			_p=0
		else
			_p=$?
		fi
	fi
	# The parser can abnormally exit in ways its own 0/1/4 contract never would (a
	# usage error exits 2, a missing/unreadable parser exits 2, a signal or crash
	# exits something else): normalize any code outside 0/1/4 to 4 so an abnormal
	# exit is never mistaken for a retryable miss.
	case "$_p" in 0 | 1 | 4) ;; *) _p=4 ;; esac
	# A breach short-circuits BEFORE the classifier and every soft gate: nothing may
	# suppress or delay a security failure.
	if [ "$_p" = 4 ]; then return 4; fi
	if e2e_classify_run "$_rc" "$_out" "$_err" "$_timeout"; then _c=0; else _c=$?; fi
	arbitrate "$_p" "$_c"
	_s=$?
	if [ "$_s" != 0 ]; then return "$_s"; fi
	# Parser held and no timeout/budget: run the connector-specific posture check,
	# then the generic diagnostic, retryable environment gates.
	"$_posture_fn" "$_err" || return 1
	e2e_assert_tool_called "$_err" || return 1
	if [ "$_mode" = read ] && ! grep -Fq "$_expect" "$_out"; then
		printf 'read: expected value not found in the answer (no real read?). stdout tail:\n' >&2
		tail -n 20 "$_out" >&2
		return 1
	fi
	return 0
}

# e2e_pin_audit_size - export a rotation-free audit configuration so no lumberjack
# rotation fires during a bounded run. A mid-run rotation would rename the active audit
# file the running suite is about to read, and the parser's own rotated-sibling sweep
# (test/lib/connector_audit/engine.py load_records) is the fail-closed backstop for the
# case where one slips through anyway. Idempotent; runs in the current shell (it
# exports), so do NOT call it via command substitution.
e2e_pin_audit_size() {
	export CYNATIVE_AUDIT_MAX_SIZE_MB=4096
	export CYNATIVE_AUDIT_RETENTION_DAYS=3650
	export CYNATIVE_AUDIT_COMPRESS=false
}
