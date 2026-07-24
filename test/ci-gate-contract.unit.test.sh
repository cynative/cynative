#!/bin/sh
# Unit tests for scripts/ci/ci-gate-contract.sh, the invocation contract shared by the
# consolidated connector e2e gate and the live LLM gate. Offline and hermetic.
#
# The contract is what stops a caller weakening the release gate: every workflow_call is
# the full gate, so a call that tries to narrow the roster must be rejected outright.
set -eu

script=scripts/ci/ci-gate-contract.sh
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
# SELECTORS, and `env` would then treat its second word as the command to run.
run_release() {
	(
		REPOSITORY=${3:-cynative/cynative}
		EXPECTED_REPOSITORY=cynative/cynative
		EVENT=push
		CALLER_WORKFLOW_REF=${4:-$CALLER}
		JOB_WORKFLOW_REF=$SELF
		EXPECTED_CALLER=$CALLER
		# No-colon form: an explicitly-set empty override (a case testing an empty
		# allowlist or policy) must survive, and only a truly unset variable should
		# fall back to the wrapper's default. The colon form treats empty the same
		# as unset and would silently discard that override.
		# shellcheck disable=SC2030  # intentional: this resolves a per-call override
		# read from the parent shell into a copy local to this subshell, which is then
		# exported into the script invocation below, not back out to the caller.
		SELECTORS="${SELECTORS-gcp aws github}"
		# shellcheck disable=SC2030  # same as SELECTORS above.
		DISPATCH_POLICY="${DISPATCH_POLICY-filtered}"
		CALL_REF=$1
		SELECTOR=$2
		export REPOSITORY EXPECTED_REPOSITORY EVENT CALLER_WORKFLOW_REF \
			JOB_WORKFLOW_REF EXPECTED_CALLER SELECTORS DISPATCH_POLICY CALL_REF SELECTOR
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
		# No-colon form: an explicitly-set empty override (a case testing an empty
		# allowlist or policy) must survive, and only a truly unset variable should
		# fall back to the wrapper's default. The colon form treats empty the same
		# as unset and would silently discard that override.
		# shellcheck disable=SC2030,SC2031  # intentional, see run_release above: this
		# is a fresh, independent override read for this call, not a continuation of
		# any other subshell's local state.
		SELECTORS="${SELECTORS-gcp aws github}"
		# shellcheck disable=SC2030,SC2031  # same as SELECTORS above.
		DISPATCH_POLICY="${DISPATCH_POLICY-filtered}"
		TRIGGER_SHA=${2:-$SHA}
		CALL_REF=${4:-}
		SELECTOR=$1
		export REPOSITORY EXPECTED_REPOSITORY EVENT CALLER_WORKFLOW_REF \
			JOB_WORKFLOW_REF EXPECTED_CALLER SELECTORS DISPATCH_POLICY TRIGGER_SHA \
			CALL_REF SELECTOR
		sh "$script"
	)
}

# run_dispatch_unset_policy - the dispatch shape with DISPATCH_POLICY truly UNSET (not
# merely empty). The wrappers above default it via ${DISPATCH_POLICY-filtered}, so no
# wrapper-driven case can ever exercise unset; this composes the env by hand and
# unsets the variable immediately before the script runs. The script's own
# ${DISPATCH_POLICY:-} resolves unset to empty, which the policy case rejects like
# any other unknown value.
run_dispatch_unset_policy() {
	(
		REPOSITORY=cynative/cynative
		EXPECTED_REPOSITORY=cynative/cynative
		EVENT=workflow_dispatch
		CALLER_WORKFLOW_REF=$SELF
		JOB_WORKFLOW_REF=$SELF
		EXPECTED_CALLER=$CALLER
		# shellcheck disable=SC2030  # intentional, see run_release above: this
		# subshell-local assignment composes the isolated env for this one
		# invocation and is never meant to propagate back to the caller.
		SELECTORS='gcp aws github'
		TRIGGER_SHA=$SHA
		CALL_REF=
		SELECTOR=gcp
		export REPOSITORY EXPECTED_REPOSITORY EVENT CALLER_WORKFLOW_REF \
			JOB_WORKFLOW_REF EXPECTED_CALLER SELECTORS TRIGGER_SHA CALL_REF SELECTOR
		unset DISPATCH_POLICY
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

# ---- DISPATCH_POLICY ------------------------------------------------------
# DISPATCH_POLICY and SELECTORS are overridden per case via exported shell variables
# rather than a `VAR=val run_dispatch ...` prefix: expect_status/expect_field run their
# own command and need it passed explicitly, so the override has to be visible to the
# wrappers' subshell through the environment instead. Both wrappers default to
# "filtered"/'gcp aws github' when unset, which is why cases above this line that never
# touch these two variables are unaffected.
# shellcheck disable=SC2031  # intentional: this export is the parent script's own
# override mechanism for the run_dispatch/run_release calls below, not a read-back of
# either wrapper's local subshell state.
export DISPATCH_POLICY SELECTORS

# full-only is the LLM gate's policy: a direct dispatch must not carry a selector at
# all. The LLM workflow declares no dispatch inputs, so this is trivially satisfied
# today; asserting it means adding an input later fails closed instead of silently
# narrowing the roster. SELECTORS is empty on this path, which is why the script must
# not require it globally.
DISPATCH_POLICY=full-only
SELECTORS=''
expect_status 0 'full-only dispatch with no selector is accepted' run_dispatch ''
expect_field mode manual 'full-only dispatch yields mode=manual' run_dispatch ''
expect_field selector '' 'full-only dispatch has an empty selector' run_dispatch ''

expect_status 1 'full-only dispatch carrying a selector is rejected' run_dispatch gcp

# filtered is the connector gate's policy: a direct dispatch MUST carry a selector from
# the allowlist. The connector workflow's input is required with default all, so an
# empty value means the input was tampered with or removed.
DISPATCH_POLICY=filtered
SELECTORS='gcp aws github'
expect_status 1 'filtered dispatch with an empty selector is rejected' run_dispatch ''
expect_status 1 'filtered dispatch with an unknown selector is rejected' run_dispatch nope
expect_status 0 'filtered dispatch with a known selector is accepted' run_dispatch gcp
expect_field selector gcp 'filtered dispatch selector gcp is preserved' run_dispatch gcp

# A filtered gate with no allowlist would accept nothing but must say so plainly
# rather than rejecting every selector as unknown. "all" is the case that actually
# proves this guard does something: without it, the allowlist loop below only ever
# iterates over the literal "all", so SELECTOR=all would match trivially and a
# filtered gate with no configured allowlist would silently run every leg.
SELECTORS=''
expect_status 1 'filtered gate with an empty SELECTORS allowlist is rejected' run_dispatch gcp
expect_status 1 'filtered gate with an empty SELECTORS allowlist rejects "all" too' \
	run_dispatch all
SELECTORS='gcp aws github'

# An unrecognised policy must hard-fail rather than fall through to either behaviour,
# so a typo cannot silently pick the permissive one.
DISPATCH_POLICY=bogus-policy
expect_status 1 'unknown DISPATCH_POLICY is rejected' run_dispatch gcp

DISPATCH_POLICY=''
expect_status 1 'empty DISPATCH_POLICY is rejected' run_dispatch gcp

expect_status 1 'an unset DISPATCH_POLICY is rejected' run_dispatch_unset_policy

# A workflow_call may never carry a selector under EITHER policy.
DISPATCH_POLICY=filtered
expect_status 1 'filtered workflow_call carrying a selector is rejected' \
	run_release aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa gcp

DISPATCH_POLICY=full-only
SELECTORS=''
expect_status 1 'full-only workflow_call carrying a selector is rejected' \
	run_release aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa gcp

unset DISPATCH_POLICY SELECTORS

[ "$fails" = 0 ] || exit 1
printf 'OK: ci-gate-contract unit tests\n'
