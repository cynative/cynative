#!/bin/sh
# ci-gate-assert.sh - the fail-closed fan-in shared by the connector e2e gate and the
# live LLM gate.
#
# Why this exists: GitHub reports a conditionally SKIPPED job as SUCCESS to its caller.
# A run concludes success when at least one job succeeded and none failed, so a gate
# whose live jobs all skipped while a cheap setup job passed is GREEN. publish's
# `result == 'success'` check alone would therefore be satisfied by a gate that tested
# nothing. This script turns that silence into a hard failure.
#
# It also closes the roster hole that consolidation introduces. A deleted matrix row
# produces no leg and therefore no sentinel, so the family job stays green with one
# fewer leg tested. Requiring a per-leg proof makes that visible.
#
# It also closes a second roster hole: ROSTER, JOBS, RESULTS, and PROOFS are
# hand-maintained alongside the workflow's needs: list, and nothing binds them
# together. If a job is added to needs but JOBS is not updated to match (or the other
# way around), that leg can go silently ungated while the gate stays green. NEEDS_JSON
# carries the actual dependency set (toJSON(needs), which cannot be forged by
# forgetting to edit a second place) so this script cross-checks it against JOBS before
# trusting either.
#
# Some families are served by TWO mutually exclusive physical jobs rather than one (the
# live LLM gate's api-key family runs as either api-key-release or api-key-manual,
# never both). ROSTER stays a logical leg:family list; JOBS separately says which
# physical job:family:policy triples exist and which policy is active for MODE. Exactly
# one job per family must be active in a given mode, and PROOFS is keyed job.leg so a
# proof from the inactive job of a family can never satisfy the active one.
#
# Inputs (env):
#   SELECTOR   - empty means every leg; otherwise the single selected leg.
#   ROSTER     - space-separated leg:family pairs, a static literal in the workflow.
#                family is the logical family a leg belongs to.
#   JOBS       - space-separated job:family:policy triples, a static literal in the
#                workflow. policy is always, release, or manual; MODE selects the one
#                job per family that is active.
#   MODE       - release or manual, from the invocation contract's mode output.
#   RESULTS    - newline-separated job=result pairs from the needs context, keyed by
#                physical job.
#   PROOFS     - newline-separated job.leg=proof pairs from the job outputs, keyed by
#                physical job and leg.
#   NEEDS_JSON - JSON object from toJSON(needs); its top-level keys are the jobs this
#                job actually depends on.
set -eu

: "${ROSTER:?ROSTER is required}"
: "${JOBS:?JOBS is required}"
: "${RESULTS:?RESULTS is required}"
: "${NEEDS_JSON:?NEEDS_JSON is required}"
SELECTOR=${SELECTOR:-}
PROOFS=${PROOFS:-}

# MODE=${MODE-}, NOT ${MODE:-release} or : "${MODE:?...}": either colon form would
# treat an empty MODE the same as unset, either silently defaulting it or failing
# closed with exit 2 before the case below ever sees it. An empty MODE must reach and
# fail the case below (exit 1), the same as any other invalid value.
MODE=${MODE-}
case "$MODE" in
release | manual) ;;
*) printf '::error::gate: unknown MODE %s\n' "${MODE:-<empty>}" >&2; exit 1 ;;
esac

fails=0

fail() {
	printf '::error::gate: %s\n' "$*" >&2
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
		printf '::error::gate: duplicate key %s\n' "$2" >&2
		return 2
	fi
	[ "$_n" -eq 1 ] || return 1
	printf '%s' "$_val"
}

# ---- physical job policy --------------------------------------------------
# JOBS is job:family:policy. A policy of `always` runs on both paths; `release` and
# `manual` run only on the matching MODE. Exactly one job per family must be active,
# and every inactive job must report exactly `skipped`.
all_jobs=
for triple in $JOBS; do
	job=${triple%%:*}
	rest=${triple#*:}
	family=${rest%%:*}
	policy=${rest##*:}
	# Exact-reconstruction arity check: with four or more fields the three extractions
	# above no longer cover the whole token, and an empty field survives
	# reconstruction, so both are rejected explicitly rather than trusting the parse.
	if [ "$job:$family:$policy" != "$triple" ] ||
		[ -z "$job" ] || [ -z "$family" ] || [ -z "$policy" ]; then
		fail "JOBS entry '$triple' is not job:family:policy"
		continue
	fi
	case "$policy" in
	always | release | manual) ;;
	*) fail "job '$job' has unknown policy '$policy'" ;;
	esac
	contains_word "$all_jobs" "$job" && fail "job '$job' is listed twice in JOBS"
	all_jobs="$all_jobs $job"
done

# ROSTER entries have the same silent-swallow hazard as JOBS triples: leg takes the
# first field and family the last, so a middle field or an empty half vanishes.
for pair in $ROSTER; do
	leg=${pair%%:*}
	family=${pair##*:}
	if [ "$leg:$family" != "$pair" ] || [ -z "$leg" ] || [ -z "$family" ]; then
		fail "ROSTER entry '$pair' is not leg:family"
	fi
done

# active_job_for FAMILY - echo the sole job active in this mode, or return 1.
active_job_for() {
	_found=
	_n=0
	for _triple in $JOBS; do
		_job=${_triple%%:*}
		_rest=${_triple#*:}
		_family=${_rest%%:*}
		_policy=${_rest##*:}
		[ "$_family" = "$1" ] || continue
		if [ "$_policy" = always ] || [ "$_policy" = "$MODE" ]; then
			_found=$_job
			_n=$((_n + 1))
		fi
	done
	[ "$_n" -eq 1 ] || return 1
	printf '%s' "$_found"
}

# ---- roster / job-graph cross-check ---------------------------------------
# jobs_from_needs is the set of jobs this job actually depends on (minus the
# always-present prepare); all_jobs is what the hand-maintained JOBS claims to cover.
# They must be the same set in both directions, or a job can go silently ungated.
#
# Residual: this check can only compare needs against JOBS, so a job added to neither is
# still invisible and still ungated. needs is the anchor because it is the actual
# dependency graph, so needs must list every job for this check to be exhaustive.
if jobs_from_needs=$(python3 -c '
import json
import os
import sys

try:
    needs = json.loads(os.environ["NEEDS_JSON"])
except (KeyError, ValueError):
    sys.exit(1)
if not isinstance(needs, dict) or not needs:
    sys.exit(1)
jobs = sorted(key for key in needs if key != "prepare")
print(" ".join(jobs))
'); then
	needs_parse_ok=1
else
	needs_parse_ok=0
	jobs_from_needs=
	fail "NEEDS_JSON is missing, empty, or not a JSON object; cannot verify JOBS against the actual job graph"
fi

if [ "$needs_parse_ok" -eq 1 ]; then
	# jobs_from_needs is a deliberately space-separated word list meant to be split on
	# iteration, so it is intentionally unquoted here; set -f disables globbing for the
	# duration so a job name containing a glob character expands to nothing but itself,
	# never to filenames in the working directory.
	set -f
	for job in $jobs_from_needs; do
		contains_word "$all_jobs" "$job" ||
			fail "job '$job' is a dependency in needs but missing from JOBS, so it would never be gated"
	done
	set +f
	for job in $all_jobs; do
		contains_word "$jobs_from_needs" "$job" ||
			fail "job '$job' is in JOBS but nothing in needs depends on it"
	done
fi

# ---- family coupling ------------------------------------------------------
# Every family named in JOBS must be gated by at least one ROSTER leg, and every family
# a ROSTER leg names must have a job in JOBS. Together with the JOBS/needs comparison
# above, this leaves no job that is real but ungated.
roster_families=
for pair in $ROSTER; do
	family=${pair##*:}
	contains_word "$roster_families" "$family" || roster_families="$roster_families $family"
done

job_families=
for triple in $JOBS; do
	rest=${triple#*:}
	family=${rest%%:*}
	contains_word "$job_families" "$family" || job_families="$job_families $family"
done

for family in $job_families; do
	contains_word "$roster_families" "$family" ||
		fail "family '$family' has jobs in JOBS but no leg in ROSTER, so those jobs are never gated"
done
for family in $roster_families; do
	contains_word "$job_families" "$family" ||
		fail "family '$family' is named by a ROSTER leg but has no job in JOBS"
done

# Every job that is NOT active in this mode must be exactly skipped. A success there
# means a job ran on a path it was never meant to run on (for the LLM gate, that the
# reviewer-gated environment was reached from a release run, or the reverse).
for triple in $JOBS; do
	job=${triple%%:*}
	rest=${triple#*:}
	policy=${rest##*:}
	[ "$policy" = always ] || [ "$policy" = "$MODE" ] && continue
	if result=$(lookup "$RESULTS" "$job"); then
		[ "$result" = skipped ] ||
			fail "job $job is inactive in $MODE mode and must be exactly skipped, got '${result:-<empty>}'"
	else
		fail "job $job is missing from the results"
	fi
done

for pair in $ROSTER; do
	leg=${pair%%:*}
	family=${pair##*:}

	if [ -z "$SELECTOR" ] || [ "$SELECTOR" = "$leg" ]; then
		selected=1
	else
		selected=0
	fi

	if job=$(active_job_for "$family"); then
		:
	else
		fail "family $family has no single active job in $MODE mode, so leg $leg was never gated"
		continue
	fi

	if result=$(lookup "$RESULTS" "$job"); then
		:
	else
		rc=$?
		if [ "$rc" -eq 2 ]; then
			fails=1
		else
			fail "job $job is missing from the results, so leg $leg was never gated"
		fi
		continue
	fi

	if proof=$(lookup "$PROOFS" "$job.$leg"); then
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
			fail "job $job must be exactly success, got '${result:-<empty>}'"
		[ "$proof" = success ] ||
			fail "leg $leg produced no success proof (got '${proof:-<empty>}'), so its leg did not run"
	else
		case "$result" in
		success | skipped) ;;
		*) fail "excluded job $job must be success or skipped, got '$result'" ;;
		esac
		[ -z "$proof" ] ||
			fail "leg $leg was excluded by the filter but produced a proof, so the filter leaked"
	fi
done

[ "$fails" = 0 ] || exit 1

if [ -z "$SELECTOR" ]; then
	printf 'OK: every leg in the roster ran and passed.\n'
else
	printf 'OK: leg %s ran and passed; the rest were excluded by an explicit dispatch filter.\n' "$SELECTOR"
fi
