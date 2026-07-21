#!/bin/sh
# connector-e2e-gate-assert.sh - the fail-closed fan-in of the connector e2e gate.
#
# Why this exists: GitHub reports a conditionally SKIPPED job as SUCCESS to its caller.
# A run concludes success when at least one job succeeded and none failed, so a gate
# whose live jobs all skipped while a cheap setup job passed is GREEN. publish's
# `result == 'success'` check alone would therefore be satisfied by a gate that tested
# nothing. This script turns that silence into a hard failure.
#
# It also closes the roster hole that consolidation introduces. A deleted matrix row
# produces no leg and therefore no sentinel, so the family job stays green with one
# fewer connector tested. Requiring a per-connector proof makes that visible.
#
# Inputs (env):
#   SELECTOR - empty means every connector; otherwise the single selected connector.
#   ROSTER   - space-separated connector:family pairs, a static literal in the workflow.
#   RESULTS  - newline-separated family=result pairs from the needs context.
#   PROOFS   - newline-separated connector=proof pairs from the family job outputs.
set -eu

: "${ROSTER:?ROSTER is required}"
: "${RESULTS:?RESULTS is required}"
SELECTOR=${SELECTOR:-}
PROOFS=${PROOFS:-}

fails=0

fail() {
	printf '::error::connector-e2e gate: %s\n' "$*" >&2
	fails=1
}

# lookup HAYSTACK KEY - echo the value of KEY= in a newline-separated key=value list.
lookup() {
	printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1
}

# has_key HAYSTACK KEY - true when KEY= appears at all, so a missing family is
# distinguishable from one whose result is empty.
has_key() {
	printf '%s\n' "$1" | grep -q "^$2="
}

for pair in $ROSTER; do
	connector=${pair%%:*}
	family=${pair##*:}

	if [ -z "$SELECTOR" ] || [ "$SELECTOR" = "$connector" ]; then
		selected=1
	else
		selected=0
	fi

	if ! has_key "$RESULTS" "$family"; then
		fail "family $family is missing from the results, so connector $connector was never gated"
		continue
	fi

	result=$(lookup "$RESULTS" "$family")
	proof=$(lookup "$PROOFS" "$connector")

	if [ "$selected" = 1 ]; then
		# needs.<job>.result is one of success, failure, cancelled, skipped. Testing
		# anything looser than an exact success admits two of the three bad states.
		[ "$result" = success ] ||
			fail "family $family must be exactly success, got '${result:-<empty>}'"
		[ "$proof" = success ] ||
			fail "connector $connector produced no success proof (got '${proof:-<empty>}'), so its leg did not run"
	else
		case "$result" in
		success | skipped) ;;
		*) fail "excluded family $family must be success or skipped, got '$result'" ;;
		esac
		[ -z "$proof" ] ||
			fail "connector $connector was excluded by the filter but produced a proof, so the filter leaked"
	fi
done

[ "$fails" = 0 ] || exit 1

if [ -z "$SELECTOR" ]; then
	printf 'OK: every connector in the roster ran and passed.\n'
else
	printf 'OK: connector %s ran and passed; the rest were excluded by an explicit dispatch filter.\n' "$SELECTOR"
fi
