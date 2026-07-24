#!/bin/sh
# ci-gate-contract.sh - validate how a release-gate workflow was invoked and emit the
# resolved contract. Shared by every gate built on this contract (today: the connector
# e2e gate and the live LLM gate); each gate picks a DISPATCH_POLICY that fits its own
# selector shape.
#
# A called reusable workflow sees the CALLER's github context, so github.event_name is
# "push" on the release path and cannot identify it. The discriminator is structural:
# github.workflow_ref names the caller's workflow file, job.workflow_ref names the file
# defining the current job. Equal means a direct dispatch, different means a reusable
# call.
#
# Every workflow_call is the full gate. There is no gate input and no way for a caller
# to narrow the roster: a call carrying a selector is rejected outright, under either
# policy.
#
# DISPATCH_POLICY controls what a direct (workflow_dispatch) invocation may carry:
#   filtered  - a selector is required and must be a member of the SELECTORS allowlist
#               (or the literal "all"). This is the connector gate's policy: it has
#               named legs, and a dispatch may run one leg or all of them.
#   full-only - a selector must not be present at all. This is for a gate with no
#               selectable legs, so a selector input added later fails closed instead
#               of silently narrowing the roster.
#
# Emits three lines on stdout for the caller to append to GITHUB_OUTPUT:
#   mode=release|manual
#   selector=<leg, or empty meaning every leg>
#   checkout_sha=<40 hex>
set -eu
# set -f for the whole script: nothing here wants globbing, and the allowlist loop
# below deliberately word-splits $SELECTORS unquoted, so -f keeps a glob character in
# a selector token literal instead of expanding it against the working directory.
set -f

die() {
	printf '::error::gate contract: %s\n' "$*" >&2
	exit 1
}

# is_sha - a checked-out revision must be an exact 40-hex commit, never a branch name,
# so the gate can never test a revision other than the one it was asked about.
is_sha() {
	case "$1" in
	*[!0-9a-f]* | '') return 1 ;;
	esac
	[ "${#1}" -eq 40 ]
}

: "${REPOSITORY:?REPOSITORY is required}"
: "${EXPECTED_REPOSITORY:?EXPECTED_REPOSITORY is required}"
: "${EVENT:?EVENT is required}"
: "${CALLER_WORKFLOW_REF:?CALLER_WORKFLOW_REF is required}"
: "${JOB_WORKFLOW_REF:?JOB_WORKFLOW_REF is required}"
: "${EXPECTED_CALLER:?EXPECTED_CALLER is required}"
CALL_REF=${CALL_REF:-}
TRIGGER_SHA=${TRIGGER_SHA:-}
SELECTOR=${SELECTOR:-}
SELECTORS=${SELECTORS:-}
# Deliberately not `: "${DISPATCH_POLICY:?...}"`: POSIX ${:?} treats an empty value
# the same as unset, which would exit 2 straight out of parameter expansion instead of
# the uniform die()-driven exit 1 every other rejection in this script produces. An
# empty or unset value falls through the case below to the same "unknown" rejection an
# invalid one gets.
DISPATCH_POLICY=${DISPATCH_POLICY:-}

# An unrecognised, empty, or unset policy must hard-fail rather than fall through to
# either behaviour, so a typo (or a caller that forgot to set it) cannot silently pick
# the permissive one. Validated before any branching so a bad value can never reach
# either path below.
case "$DISPATCH_POLICY" in
filtered | full-only) ;;
*) die "unknown DISPATCH_POLICY '$DISPATCH_POLICY'" ;;
esac

# These are PUBLIC reusable workflows, so any public repository may call them. Cloud
# trust policies would still refuse to mint credentials, but this guard is what makes
# "a fork never reaches the credential step" true rather than merely survivable.
[ "$REPOSITORY" = "$EXPECTED_REPOSITORY" ] ||
	die "foreign caller repository $REPOSITORY"

if [ "$CALLER_WORKFLOW_REF" != "$JOB_WORKFLOW_REF" ]; then
	[ "$CALLER_WORKFLOW_REF" = "$EXPECTED_CALLER" ] ||
		die "unexpected reusable-workflow caller $CALLER_WORKFLOW_REF"
	[ -z "$SELECTOR" ] ||
		die "a workflow_call must not carry a selector"
	is_sha "$CALL_REF" ||
		die "call ref is not a 40-hex SHA"
	mode=release
	selector=
	checkout_sha=$CALL_REF
else
	[ "$EVENT" = workflow_dispatch ] ||
		die "direct invocation must be workflow_dispatch, got $EVENT"
	[ -z "$CALL_REF" ] ||
		die "a direct dispatch must not carry a call ref"
	if [ "$DISPATCH_POLICY" = full-only ]; then
		# The workflow declares no selector input at all, so a non-empty value means
		# one was added without updating this contract.
		[ -z "$SELECTOR" ] ||
			die "a full-only dispatch must not carry a selector, got '$SELECTOR'"
		selector=
	else
		[ -n "$SELECTORS" ] ||
			die "a filtered gate must declare a non-empty SELECTORS allowlist"
		# Explicit if rather than `[ ... ] && _known=1`: the && form's exit status
		# under `set -e` is a POSIX subtlety, and this is a security-critical
		# allowlist.
		_known=0
		for _c in all $SELECTORS; do
			if [ "$_c" = "$SELECTOR" ]; then
				_known=1
			fi
		done
		[ "$_known" = 1 ] || die "unknown selector '$SELECTOR'"
		# "all" is the no-filter form, normalized to empty so downstream comparisons
		# have exactly one representation of "run every leg".
		if [ "$SELECTOR" = all ]; then
			selector=
		else
			selector=$SELECTOR
		fi
	fi
	is_sha "$TRIGGER_SHA" ||
		die "triggering SHA is not a 40-hex SHA"
	mode=manual
	checkout_sha=$TRIGGER_SHA
fi

printf 'mode=%s\n' "$mode"
printf 'selector=%s\n' "$selector"
printf 'checkout_sha=%s\n' "$checkout_sha"
