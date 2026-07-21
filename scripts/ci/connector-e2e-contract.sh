#!/bin/sh
# connector-e2e-contract.sh - validate how connector-e2e.yaml was invoked and emit
# the resolved contract.
#
# A called reusable workflow sees the CALLER's github context, so github.event_name is
# "push" on the release path and cannot identify it. The discriminator is structural:
# github.workflow_ref names the caller's workflow file, job.workflow_ref names the file
# defining the current job. Equal means a direct dispatch, different means a reusable
# call.
#
# Every workflow_call is the full release gate. There is no gate input and no way for a
# caller to narrow the roster: a call carrying a selector is rejected outright.
#
# Emits three lines on stdout for the caller to append to GITHUB_OUTPUT:
#   mode=release|manual
#   selector=<connector, or empty meaning every connector>
#   checkout_sha=<40 hex>
set -eu

die() {
	printf '::error::connector-e2e contract: %s\n' "$*" >&2
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
: "${CONNECTORS:?CONNECTORS is required}"
CALL_REF=${CALL_REF:-}
TRIGGER_SHA=${TRIGGER_SHA:-}
SELECTOR=${SELECTOR:-}

# These are PUBLIC reusable workflows, so any public repository may call them. Cloud
# trust policies would still refuse to mint credentials, but this guard is what makes
# "a fork never reaches the credential step" true rather than merely survivable.
[ "$REPOSITORY" = "$EXPECTED_REPOSITORY" ] ||
	die "foreign caller repository $REPOSITORY"

if [ "$CALLER_WORKFLOW_REF" != "$JOB_WORKFLOW_REF" ]; then
	[ "$CALLER_WORKFLOW_REF" = "$EXPECTED_CALLER" ] ||
		die "unexpected reusable-workflow caller $CALLER_WORKFLOW_REF"
	[ -z "$SELECTOR" ] ||
		die "a workflow_call must not carry a connector selector"
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
	# Explicit if rather than `[ ... ] && _known=1`: the && form's exit status under
	# `set -e` is a POSIX subtlety, and this is a security-critical allowlist.
	_known=0
	for _c in all $CONNECTORS; do
		if [ "$_c" = "$SELECTOR" ]; then
			_known=1
		fi
	done
	[ "$_known" = 1 ] || die "unknown connector selector '$SELECTOR'"
	is_sha "$TRIGGER_SHA" ||
		die "triggering SHA is not a 40-hex SHA"
	mode=manual
	# "all" is the no-filter form, normalized to empty so downstream comparisons have
	# exactly one representation of "run every connector".
	if [ "$SELECTOR" = all ]; then
		selector=
	else
		selector=$SELECTOR
	fi
	checkout_sha=$TRIGGER_SHA
fi

printf 'mode=%s\n' "$mode"
printf 'selector=%s\n' "$selector"
printf 'checkout_sha=%s\n' "$checkout_sha"
