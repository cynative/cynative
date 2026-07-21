#!/bin/sh
# Unit tests for scripts/ci/connector-e2e-contract.sh, the invocation contract of the
# consolidated connector e2e gate. Offline and hermetic.
#
# The contract is what stops a caller weakening the release gate: every workflow_call is
# the full gate, so a call that tries to narrow the roster must be rejected outright.
set -eu

script=scripts/ci/connector-e2e-contract.sh
fails=0

SHA=0123456789abcdef0123456789abcdef01234567
CALLER=cynative/cynative/.github/workflows/release.yaml@refs/heads/main
SELF=cynative/cynative/.github/workflows/connector-e2e.yaml@refs/heads/main

out=$(mktemp)
err=$(mktemp)
cleanup() { rm -f "$out" "$err"; }
trap cleanup EXIT

# run_release CALL_REF SELECTOR [REPOSITORY] [CALLER_WORKFLOW_REF]
# Exports the reusable-call shape in a subshell. Every variable is assigned separately
# and exported by name: building an env list and expanding it unquoted would word-split
# CONNECTORS, and `env` would then treat its second word as the command to run.
run_release() {
	(
		REPOSITORY=${3:-cynative/cynative}
		EXPECTED_REPOSITORY=cynative/cynative
		EVENT=push
		CALLER_WORKFLOW_REF=${4:-$CALLER}
		JOB_WORKFLOW_REF=$SELF
		EXPECTED_CALLER=$CALLER
		CONNECTORS='gcp aws github'
		CALL_REF=$1
		SELECTOR=$2
		export REPOSITORY EXPECTED_REPOSITORY EVENT CALLER_WORKFLOW_REF \
			JOB_WORKFLOW_REF EXPECTED_CALLER CONNECTORS CALL_REF SELECTOR
		sh "$script"
	)
}

# run_dispatch SELECTOR [TRIGGER_SHA] [EVENT] [CALL_REF]
run_dispatch() {
	(
		REPOSITORY=cynative/cynative
		EXPECTED_REPOSITORY=cynative/cynative
		EVENT=${3:-workflow_dispatch}
		CALLER_WORKFLOW_REF=$SELF
		JOB_WORKFLOW_REF=$SELF
		EXPECTED_CALLER=$CALLER
		CONNECTORS='gcp aws github'
		TRIGGER_SHA=${2:-$SHA}
		CALL_REF=${4:-}
		SELECTOR=$1
		export REPOSITORY EXPECTED_REPOSITORY EVENT CALLER_WORKFLOW_REF \
			JOB_WORKFLOW_REF EXPECTED_CALLER CONNECTORS TRIGGER_SHA CALL_REF SELECTOR
		sh "$script"
	)
}

# expect_status WANT DESC CMD... - runs the remaining args as a command.
expect_status() {
	_want=$1
	_desc=$2
	shift 2
	if "$@" >"$out" 2>"$err"; then
		_got=0
	else
		_got=$?
	fi
	if [ "$_want" != "$_got" ]; then
		printf 'FAIL: %s (want exit %s, got %s)\n' "$_desc" "$_want" "$_got" >&2
		sed 's/^/  /' "$err" >&2
		fails=1
	fi
}

# expect_field FIELD WANT DESC CMD... - runs and compares one emitted line.
expect_field() {
	_field=$1
	_want=$2
	_desc=$3
	shift 3
	if ! "$@" >"$out" 2>"$err"; then
		printf 'FAIL: %s (script exited non-zero)\n' "$_desc" >&2
		sed 's/^/  /' "$err" >&2
		fails=1
		return
	fi
	_got=$(sed -n "s/^${_field}=//p" "$out")
	if [ "$_want" != "$_got" ]; then
		printf 'FAIL: %s (%s want "%s", got "%s")\n' "$_desc" "$_field" "$_want" "$_got" >&2
		fails=1
	fi
}

# ---- release path (workflow_call) ----------------------------------------
expect_field mode release "release call yields mode=release" run_release "$SHA" ""
expect_field selector "" "release call has an empty selector" run_release "$SHA" ""
expect_field checkout_sha "$SHA" "release call checks out the passed ref" run_release "$SHA" ""

# A caller must not be able to narrow the gate.
expect_status 1 "release call carrying a selector is rejected" run_release "$SHA" gcp
# A non-SHA ref must be rejected, so the gate can never test the wrong revision.
expect_status 1 "release call with a branch ref is rejected" run_release main ""
expect_status 1 "release call with a short SHA is rejected" run_release 0123456 ""
expect_status 1 "release call with an empty ref is rejected" run_release "" ""
# An unexpected caller workflow must be rejected.
expect_status 1 "unexpected caller workflow is rejected" \
	run_release "$SHA" "" cynative/cynative \
	cynative/cynative/.github/workflows/evil.yaml@refs/heads/main
# A foreign repository must never get past the contract.
expect_status 1 "foreign repository is rejected" \
	run_release "$SHA" "" attacker/fork

# ---- dispatch path -------------------------------------------------------
expect_field mode manual "dispatch yields mode=manual" run_dispatch all
# "all" normalizes to an empty selector, meaning no filter.
expect_field selector "" "dispatch selector all normalizes to empty" run_dispatch all
expect_field selector gcp "dispatch selector gcp is preserved" run_dispatch gcp
expect_field checkout_sha "$SHA" "dispatch checks out the triggering SHA" run_dispatch all

# An unknown connector must fail closed rather than silently matching nothing.
expect_status 1 "unknown dispatch selector is rejected" run_dispatch azure
expect_status 1 "empty dispatch selector is rejected" run_dispatch ""
# A dispatch must not carry a call ref, and a non-dispatch event is a shape we never
# produce on the direct path.
expect_status 1 "dispatch carrying a call ref is rejected" run_dispatch all "$SHA" workflow_dispatch "$SHA"
expect_status 1 "non-dispatch event on the direct path is rejected" run_dispatch all "$SHA" pull_request
expect_status 1 "dispatch with a non-SHA trigger is rejected" run_dispatch all notasha

[ "$fails" = 0 ] || exit 1
printf 'OK: connector-e2e-contract unit tests\n'
