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
# It also closes a second roster hole: ROSTER, RESULTS, and PROOFS are hand-maintained
# alongside the workflow's needs: list, and nothing binds them together. If a family job
# is added to needs but ROSTER is not updated to match (or the other way around), that
# connector can go silently ungated while the gate stays green. NEEDS_JSON carries the
# actual dependency set (toJSON(needs), which cannot be forged by forgetting to edit a
# second place) so this script cross-checks it against ROSTER before trusting either.
#
# Inputs (env):
#   SELECTOR   - empty means every connector; otherwise the single selected connector.
#   ROSTER     - space-separated connector:family pairs, a static literal in the workflow.
#   RESULTS    - newline-separated family=result pairs from the needs context.
#   PROOFS     - newline-separated connector=proof pairs from the family job outputs.
#   NEEDS_JSON - JSON object from toJSON(needs); its top-level keys are the jobs this
#                job actually depends on.
set -eu

: "${ROSTER:?ROSTER is required}"
: "${RESULTS:?RESULTS is required}"
: "${NEEDS_JSON:?NEEDS_JSON is required}"
SELECTOR=${SELECTOR:-}
PROOFS=${PROOFS:-}

fails=0

fail() {
	printf '::error::connector-e2e gate: %s\n' "$*" >&2
	fails=1
}

# contains_word HAYSTACK WORD - true if WORD appears as a whole space-separated token in
# HAYSTACK. Padding both sides with spaces turns a plain substring test into a
# word-boundary test, so "gcp" does not match inside "gcp-wif".
contains_word() {
	case " $1 " in
	*" $2 "*) return 0 ;;
	*) return 1 ;;
	esac
}

# lookup HAYSTACK KEY - echo the value of the sole "KEY=" line in a newline-separated
# key=value list. Matches KEY literally (a case pattern, never a sed/grep regex), so a
# regex metacharacter in KEY cannot wildcard onto an unrelated line. Returns 1 when KEY
# is absent. Fails closed with exit 2 (after naming the duplicate on stderr) when KEY
# appears more than once: a caller that only saw the first of two conflicting lines
# would silently agree with whichever one happened to come first.
lookup() {
	_val=
	_n=0
	while IFS= read -r _line || [ -n "$_line" ]; do
		case "$_line" in
		"$2="*)
			_val=${_line#"$2="}
			_n=$((_n + 1))
			;;
		esac
	done <<EOF
$1
EOF
	if [ "$_n" -gt 1 ]; then
		printf '::error::connector-e2e gate: duplicate key %s\n' "$2" >&2
		return 2
	fi
	[ "$_n" -eq 1 ] || return 1
	printf '%s' "$_val"
}

# ---- roster / job-graph cross-check ---------------------------------------
# FAMILIES is the set of jobs this job actually depends on (minus the always-present
# prepare); ROSTER_FAMILIES is what the hand-maintained ROSTER claims to cover. They
# must be the same set in both directions, or a connector can go silently ungated.
if families_from_needs=$(python3 -c '
import json
import os
import sys

try:
    needs = json.loads(os.environ["NEEDS_JSON"])
except (KeyError, ValueError):
    sys.exit(1)
if not isinstance(needs, dict) or not needs:
    sys.exit(1)
families = sorted(key for key in needs if key != "prepare")
print(" ".join(families))
'); then
	needs_parse_ok=1
else
	needs_parse_ok=0
	families_from_needs=
	fail "NEEDS_JSON is missing, empty, or not a JSON object; cannot verify ROSTER against the actual job graph"
fi

roster_families=
for pair in $ROSTER; do
	family=${pair##*:}
	contains_word "$roster_families" "$family" || roster_families="$roster_families $family"
done

if [ "$needs_parse_ok" -eq 1 ]; then
	for family in $families_from_needs; do
		contains_word "$roster_families" "$family" ||
			fail "family '$family' is a dependency in needs but missing from ROSTER, so it would never be gated"
	done
	for family in $roster_families; do
		contains_word "$families_from_needs" "$family" ||
			fail "family '$family' is in ROSTER but nothing in needs depends on it"
	done
fi

for pair in $ROSTER; do
	connector=${pair%%:*}
	family=${pair##*:}

	if [ -z "$SELECTOR" ] || [ "$SELECTOR" = "$connector" ]; then
		selected=1
	else
		selected=0
	fi

	if result=$(lookup "$RESULTS" "$family"); then
		:
	else
		rc=$?
		if [ "$rc" -eq 2 ]; then
			fails=1
		else
			fail "family $family is missing from the results, so connector $connector was never gated"
		fi
		continue
	fi

	if proof=$(lookup "$PROOFS" "$connector"); then
		:
	else
		rc=$?
		if [ "$rc" -eq 2 ]; then
			fails=1
			continue
		fi
		proof=
	fi

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
