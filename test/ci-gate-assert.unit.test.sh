#!/bin/sh
# Unit tests for scripts/ci/ci-gate-assert.sh, the fail-closed fan-in shared by the
# connector e2e gate and the live LLM gate. Offline and hermetic.
#
# This is the assertion that makes a gate real: GitHub surfaces a conditionally skipped
# job as Success, so publish's `result == 'success'` alone would be satisfied by a gate
# that ran nothing.
set -eu

script=scripts/ci/ci-gate-assert.sh
fails=0

ROSTER='gcp:gcp-wif aws:aws-oidc github:github-app'
JOBS='gcp-wif:gcp-wif:always aws-oidc:aws-oidc:always github-app:github-app:always'

# needs_json JOBS - build a NEEDS_JSON (the toJSON(needs) shape) whose keys are every
# physical job plus the always-present prepare. The union across modes, never the
# active-mode subset: an inactive job is still a real dependency.
needs_json() {
	_out='{"prepare":{"result":"success"}'
	for _triple in $1; do
		_job=${_triple%%:*}
		_out="$_out,\"$_job\":{\"result\":\"success\"}"
	done
	printf '%s}' "$_out"
}
NEEDS_JSON_DEFAULT=$(needs_json "$JOBS")

# case_ WANT DESC SELECTOR RESULTS PROOFS [ROSTER] [NEEDS_JSON] [JOBS] [MODE] [STDERR_SUBSTR]
case_() {
	_want=$1
	_desc=$2
	_roster=${6:-$ROSTER}
	_jobs=${8:-$JOBS}
	# `${9-release}`, NOT `${9:-release}`: the colon form substitutes the default for an
	# EMPTY argument too, which would silently rewrite the explicit empty-MODE test into
	# a release-mode one and make it pass for the wrong reason.
	_mode=${9-release}
	_needs=${7-$NEEDS_JSON_DEFAULT}
	# Optional literal stderr substring. Some guards share their exit code with later,
	# unrelated failures (removing the guard still exits 1 via a different message), so
	# the exit status alone cannot pin them; the diagnostic is the distinguishing
	# signal.
	_stderr=${10-}
	# Capture the REAL exit status, never a collapsed 0/1: the retained empty-NEEDS_JSON
	# case asserts exit 2, and flattening every nonzero to 1 would turn it into a false
	# pass. `|| _got=$?` rather than a bare if/else so the distinction survives.
	_got=0
	( SELECTOR="$3" ROSTER="$_roster" RESULTS="$4" PROOFS="$5" \
		NEEDS_JSON="$_needs" JOBS="$_jobs" MODE="$_mode" \
		sh "$script" >/tmp/ga_out 2>/tmp/ga_err ) || _got=$?
	if [ "$_got" != "$_want" ]; then
		printf 'FAIL %s (want exit %s, got %s)\n' "$_desc" "$_want" "$_got"
		sed 's/^/       /' /tmp/ga_err
		fails=1
	elif [ -n "$_stderr" ] && ! grep -F -q -- "$_stderr" /tmp/ga_err; then
		printf 'FAIL %s (stderr does not contain "%s")\n' "$_desc" "$_stderr"
		sed 's/^/       /' /tmp/ga_err
		fails=1
	else
		printf 'ok   %s\n' "$_desc"
	fi
}

ALL_OK='gcp-wif=success
aws-oidc=success
github-app=success'
ALL_PROOF='gcp-wif.gcp=success
aws-oidc.aws=success
github-app.github=success'

# ---- the happy release path ----------------------------------------------
case_ 0 "full roster all green passes" "" "$ALL_OK" "$ALL_PROOF"

# ---- the fail-open shapes this script exists to catch ---------------------
# A family that skipped reports success to the caller; it must not pass here.
case_ 1 "a skipped family on the full path fails" "" 'gcp-wif=skipped
aws-oidc=success
github-app=success' "$ALL_PROOF"

# A dropped matrix row leaves the family green but emits no proof.
case_ 1 "a missing proof fails even when the family is green" "" "$ALL_OK" 'gcp-wif.gcp=success
aws-oidc.aws=success
github-app.github='

# A cancelled family must block, not wave through.
case_ 1 "a cancelled family fails" "" 'gcp-wif=cancelled
aws-oidc=success
github-app=success' "$ALL_PROOF"

case_ 1 "a failed family fails" "" 'gcp-wif=failure
aws-oidc=success
github-app=success' "$ALL_PROOF"

# A proof that is present but not exactly "success" must not pass.
case_ 1 "a non-success proof value fails" "" "$ALL_OK" 'gcp-wif.gcp=skipped
aws-oidc.aws=success
github-app.github=success'

# A connector absent from RESULTS entirely (family job deleted from needs).
case_ 1 "a family missing from the results fails" "" 'aws-oidc=success
github-app=success' "$ALL_PROOF"

# ---- the filtered dispatch path ------------------------------------------
# Only gcp selected: its family must be green with a proof, the others must be skipped.
case_ 0 "filtered dispatch passes with the others skipped" gcp 'gcp-wif=success
aws-oidc=skipped
github-app=skipped' 'gcp-wif.gcp=success
aws-oidc.aws=
github-app.github='

# An unselected family that ran anyway means the filter leaked.
case_ 1 "an unselected connector emitting a proof fails" gcp 'gcp-wif=success
aws-oidc=success
github-app=skipped' 'gcp-wif.gcp=success
aws-oidc.aws=success
github-app.github='

# The selected family must still be exactly success.
case_ 1 "filtered dispatch with the selected family skipped fails" gcp 'gcp-wif=skipped
aws-oidc=skipped
github-app=skipped' 'gcp-wif.gcp=
aws-oidc.aws=
github-app.github='

# The selected connector must still produce its proof.
case_ 1 "filtered dispatch with no proof from the selected leg fails" gcp 'gcp-wif=success
aws-oidc=skipped
github-app=skipped' 'gcp-wif.gcp=
aws-oidc.aws=
github-app.github='

# ---- duplicate-key and metacharacter safety --------------------------------
# A script whose whole purpose is fail-closed must not agree with a result it only
# partly read. A duplicate key must be a hard failure, not a silent first-match. Both
# duplicate lines below agree ("success"), so a lookup that merely tolerated the
# duplicate (rather than rejecting it) would let this whole case pass; only an
# explicit duplicate check catches it.
case_ 1 "a duplicated family key in RESULTS fails" "" 'gcp-wif=success
gcp-wif=success
aws-oidc=success
github-app=success' "$ALL_PROOF"

case_ 1 "a duplicated connector key in PROOFS fails" "" "$ALL_OK" 'gcp-wif.gcp=success
gcp-wif.gcp=success
aws-oidc.aws=success
github-app.github=success'

# The same physical job listed under two different families must be rejected by the
# duplicate-JOBS guard itself. The families differ, so a guard loosened to dedupe on
# the (job, family) pair rather than the job name alone would wave this through.
case_ 1 "a job listed under two families in JOBS fails" "" "$ALL_OK" "$ALL_PROOF" \
	"$ROSTER" "$NEEDS_JSON_DEFAULT" \
	'gcp-wif:gcp-wif:always gcp-wif:aws-oidc:always github-app:github-app:always' \
	release "is listed twice in JOBS"

# A job name containing a shell glob character must match only its own literal line in
# lookup(), never wildcard onto an unrelated one. JOBS/ROSTER/needs all declare the same
# metacharacter-bearing family so the job reaches lookup() at all (a mismatched shape
# dies earlier, at family coupling or active_job_for, without ever calling lookup()).
# The decoy line "gcpXXXwif=success" does not literally start with "gcp*wif=", so a
# correct literal-match lookup() ignores it and this case passes. A lookup() whose case
# pattern loses its quoting treats the "*" in the key as a real wildcard, so the pattern
# matches both the decoy line and the real one, lookup() reports a duplicate key, and
# the case flips to a failure.
META_JOBS='gcp*wif:gcp*wif:always'
META_ROSTER='meta:gcp*wif'
case_ 0 "a metacharacter-bearing key reaches lookup and matches only its literal line" "" \
	'gcpXXXwif=success
gcp*wif=success' 'gcp*wif.meta=success' \
	"$META_ROSTER" "$(needs_json "$META_JOBS")" "$META_JOBS"

# ---- roster vs job-graph cross-check ---------------------------------------
# needs is the actual dependency graph (toJSON(needs)); JOBS is a hand-maintained
# parallel list. Nothing else binds them, so a job added to one and forgotten in the
# other must fail closed rather than silently leave a leg ungated.
NEEDS_EXTRA_FAMILY='{"prepare":{"result":"success"},"gcp-wif":{"result":"success"},
"aws-oidc":{"result":"success"},"github-app":{"result":"success"},
"gitlab-token":{"result":"success"}}'
case_ 1 "a family in needs but missing from ROSTER fails" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" "$NEEDS_EXTRA_FAMILY"

NEEDS_MISSING_FAMILY='{"prepare":{"result":"success"},"gcp-wif":{"result":"success"},
"aws-oidc":{"result":"success"}}'
case_ 1 "a family in ROSTER but missing from needs fails" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" "$NEEDS_MISSING_FAMILY"

# contains_word must match whole tokens, not substrings. A plain substring test (e.g. a
# case pattern of *"$2"* with no space padding) would let "aws" silently match inside
# "aws-oidc" and pass both directions below; that is the exact false pass this pair of
# cases pins shut.
NEEDS_SUBSTRING_OF_ROSTER='{"prepare":{"result":"success"},"gcp-wif":{"result":"success"},
"aws-oidc":{"result":"success"},"github-app":{"result":"success"},"aws":{"result":"success"}}'
case_ 1 "a needs family that is a strict substring of a ROSTER family fails" "" \
	"$ALL_OK" "$ALL_PROOF" "$ROSTER" "$NEEDS_SUBSTRING_OF_ROSTER"

# NOTE this does not exercise contains_word's word-boundary safety: JOBS has no "aws"
# family at all (only "aws-oidc"), so the extra "awsx" leg below is rejected by
# active_job_for's exact-string family compare (zero matching JOBS triples) regardless
# of whether contains_word's word-boundary padding holds. The substring property itself
# is pinned above by "a needs family that is a strict substring of a ROSTER family
# fails". This case still pins a real property: a ROSTER leg naming a family with no
# JOBS entry is rejected, just not via contains_word.
ROSTER_ORPHAN_FAMILY='gcp:gcp-wif aws:aws-oidc github:github-app awsx:aws'
case_ 1 "a ROSTER leg naming a family absent from JOBS fails" "" \
	'gcp-wif=success
aws-oidc=success
github-app=success
aws=success' \
	'gcp-wif.gcp=success
aws-oidc.aws=success
github-app.github=success
aws.awsx=success' \
	"$ROSTER_ORPHAN_FAMILY" "$NEEDS_JSON_DEFAULT"

case_ 1 "malformed NEEDS_JSON fails" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" 'not json'

case_ 1 "a NEEDS_JSON that is valid JSON but not an object fails" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" '["prepare"]'

# A NEEDS_JSON that is a JSON ARRAY of exactly the job names is the case only the type
# guard can catch: iterating a list yields the same job set as iterating a dict's
# keys, so with the isinstance check removed the downstream JOBS/needs cross-check
# would pass and the whole run would go green. (The not-an-object case above still
# documents the general shape, but its exit 1 also arises downstream, so it cannot
# pin the guard by itself.)
case_ 1 "a NEEDS_JSON array of the job names fails on the type guard" "" "$ALL_OK" "$ALL_PROOF" \
	"$ROSTER" '["aws-oidc","gcp-wif","github-app"]' "$JOBS" release \
	"NEEDS_JSON is missing, empty, or not a JSON object"

# An empty JSON object means toJSON(needs) saw no dependencies at all. Removing the
# `or not needs` half still exits 1 via the downstream cross-check, so the case pins
# the guard's own diagnostic, not just the exit code.
case_ 1 "an empty NEEDS_JSON object fails on the type guard" "" "$ALL_OK" "$ALL_PROOF" \
	"$ROSTER" '{}' "$JOBS" release \
	"NEEDS_JSON is missing, empty, or not a JSON object"

# NEEDS_JSON is a required env var (a fatal shell parameter-expansion error, exit 2),
# so an empty value fails closed before the cross-check even runs.
case_ 2 "an empty NEEDS_JSON fails closed" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" ""

case_ 0 "matching needs and ROSTER still passes" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" "$NEEDS_JSON_DEFAULT"

# ---- MODE validation ------------------------------------------------------
# PROOFS must be job-qualified ($ALL_PROOF), not the bare family form: every job here
# is policy "always", so a bare-keyed PROOFS would still fail (on a missing proof)
# even with the MODE case removed, and the test would never pin MODE at all.
case_ 1 'unknown MODE is rejected' '' "$ALL_OK" "$ALL_PROOF" \
	"$ROSTER" "$NEEDS_JSON_DEFAULT" "$JOBS" 'bogus'
case_ 1 'empty MODE is rejected' '' "$ALL_OK" "$ALL_PROOF" \
	"$ROSTER" "$NEEDS_JSON_DEFAULT" "$JOBS" ''

# ---- two mutually exclusive jobs serving one family -----------------------
# This is the LLM gate's api-key shape: the same two logical legs are carried by
# api-key-release and api-key-manual, exactly one of which runs per mode.
LLM_ROSTER='vertex-notool:gcp-wif vertex-tools:gcp-wif bedrock-notool:aws-oidc bedrock-tools:aws-oidc openai-tools:api-key anthropic-tools:api-key'
LLM_JOBS='gcp-wif:gcp-wif:always aws-oidc:aws-oidc:always api-key-release:api-key:release api-key-manual:api-key:manual'
LLM_NEEDS=$(needs_json "$LLM_JOBS")
# Job-qualified. Both api-key jobs are listed; the script must pick the one the mode
# says is active, never whichever is non-empty.
LLM_PROOFS='gcp-wif.vertex-notool=success
gcp-wif.vertex-tools=success
aws-oidc.bedrock-notool=success
aws-oidc.bedrock-tools=success
api-key-release.openai-tools=success
api-key-release.anthropic-tools=success'
LLM_PROOFS_MANUAL='gcp-wif.vertex-notool=success
gcp-wif.vertex-tools=success
aws-oidc.bedrock-notool=success
aws-oidc.bedrock-tools=success
api-key-manual.openai-tools=success
api-key-manual.anthropic-tools=success'
# Proofs for both api-key jobs. Needed only by "a family with two active jobs for this
# mode is rejected": that case must fail on the active-job count itself, not on a
# missing api-key-manual proof, so both jobs need a proof present.
LLM_PROOFS_BOTH='gcp-wif.vertex-notool=success
gcp-wif.vertex-tools=success
aws-oidc.bedrock-notool=success
aws-oidc.bedrock-tools=success
api-key-release.openai-tools=success
api-key-release.anthropic-tools=success
api-key-manual.openai-tools=success
api-key-manual.anthropic-tools=success'

case_ 0 'release mode: release job success, manual job skipped' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success
api-key-manual=skipped' \
	"$LLM_PROOFS" "$LLM_ROSTER" "$LLM_NEEDS" "$LLM_JOBS" 'release'

case_ 0 'manual mode: manual job success, release job skipped' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=skipped
api-key-manual=success' \
	"$LLM_PROOFS_MANUAL" "$LLM_ROSTER" "$LLM_NEEDS" "$LLM_JOBS" 'manual'

# The crossed-proof case: this is why proofs are job-qualified. In release mode a proof
# emitted by the manual job must NOT satisfy the release leg, even though the leg id
# matches and the release job reports success.
case_ 1 'release mode: a proof from the manual job does not satisfy a release leg' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success
api-key-manual=skipped' \
	"$LLM_PROOFS_MANUAL" "$LLM_ROSTER" "$LLM_NEEDS" "$LLM_JOBS" 'release'

case_ 1 'release mode: the active api-key job skipped is a failure' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=skipped
api-key-manual=skipped' \
	"$LLM_PROOFS" "$LLM_ROSTER" "$LLM_NEEDS" "$LLM_JOBS" 'release'

case_ 1 'release mode: the inactive api-key job must be skipped, not success' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success
api-key-manual=success' \
	"$LLM_PROOFS" "$LLM_ROSTER" "$LLM_NEEDS" "$LLM_JOBS" 'release'

case_ 1 'release mode: the inactive api-key job failing is a failure' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success
api-key-manual=failure' \
	"$LLM_PROOFS" "$LLM_ROSTER" "$LLM_NEEDS" "$LLM_JOBS" 'release'

# An inactive job that vanishes from RESULTS entirely (not merely non-skipped) must be
# caught by the inactive-job loop's own missing-key branch: every other check in this
# fixture is green, so nothing else reports it.
case_ 1 'an inactive job missing from RESULTS fails' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success' \
	"$LLM_PROOFS" "$LLM_ROSTER" "$LLM_NEEDS" "$LLM_JOBS" 'release' \
	'job api-key-manual is missing from the results'

# NOTE the PROOFS argument is present. Omitting it shifts every later argument by one,
# which silently supplies a different JOBS/MODE than the case name claims.
# The api-key family here has NO job whose policy is active in release mode, so the
# family cannot be resolved at all.
case_ 1 'a family with no active job for this mode is rejected' '' \
	'gcp-wif=success
aws-oidc=success
api-key-manual=skipped' \
	"$LLM_PROOFS" "$LLM_ROSTER" \
	'{"prepare":{"result":"success"},"gcp-wif":{"result":"success"},"aws-oidc":{"result":"success"},"api-key-manual":{"result":"skipped"}}' \
	'gcp-wif:gcp-wif:always aws-oidc:aws-oidc:always api-key-manual:api-key:manual' \
	'release'

# Both jobs need a real proof ($LLM_PROOFS_BOTH, not $LLM_PROOFS): with only the
# release job's proof present, a count check loosened to "at least one" still picks a
# job (the loop's last match, api-key-manual) and then fails on ITS missing proof, so
# the case would still pass for the wrong reason and never pin the count itself.
case_ 1 'a family with two active jobs for this mode is rejected' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success
api-key-manual=success' \
	"$LLM_PROOFS_BOTH" "$LLM_ROSTER" "$LLM_NEEDS" \
	'gcp-wif:gcp-wif:always aws-oidc:aws-oidc:always api-key-release:api-key:always api-key-manual:api-key:always' \
	'release'

# api-key-manual's policy is "always" (not "manual") and its RESULTS/PROOFS are the
# active, successful leg, so it resolves cleanly and contributes no failure of its own.
# api-key-release keeps the unknown policy but reports "skipped" (what the inactive-job
# loop demands of any job that policy resolution does not recognize as active), so that
# loop raises nothing either. With both of those neutralized, the only remaining
# failure path is the policy validation itself. Reusing $LLM_PROOFS or $LLM_NEEDS here
# would leave a real, independent failure standing (a missing manual-job proof, or an
# unresolved active job), so this case builds its own consistent inputs instead.
case_ 1 'unknown job policy is rejected' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=skipped
api-key-manual=success' \
	"$LLM_PROOFS_MANUAL" "$LLM_ROSTER" "$LLM_NEEDS" \
	'gcp-wif:gcp-wif:always aws-oidc:aws-oidc:always api-key-release:api-key:sometimes api-key-manual:api-key:always' \
	'release'

# ---- family coupling between JOBS and ROSTER -------------------------------
# Every family named in JOBS must be gated by at least one ROSTER leg, and every family
# a ROSTER leg names must have a job in JOBS ("a ROSTER leg naming a family absent from
# JOBS fails", above, already pins that second direction). Without the first direction,
# a job can be real (present in JOBS, active for the mode, a genuine dependency in
# needs) yet belong to a family no ROSTER leg names, so no per-leg check ever looks at
# it and it can report skipped, or anything else, without blocking the gate.
JOBS_ORPHAN_FAMILY="$JOBS orphan-job:orphan-family:always"
case_ 1 'a JOBS family with no ROSTER leg fails' '' \
	"$ALL_OK
orphan-job=success" "$ALL_PROOF" \
	"$ROSTER" "$(needs_json "$JOBS_ORPHAN_FAMILY")" "$JOBS_ORPHAN_FAMILY"

# ---- NEEDS_JSON is the union across modes, not the active subset ----------
case_ 1 'a job in JOBS but absent from needs is rejected' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success
api-key-manual=skipped' \
	"$LLM_PROOFS" "$LLM_ROSTER" \
	'{"prepare":{"result":"success"},"gcp-wif":{"result":"success"},"aws-oidc":{"result":"success"},"api-key-release":{"result":"success"}}' \
	"$LLM_JOBS" 'release'

case_ 1 'a job in needs but absent from JOBS is rejected' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success
api-key-manual=skipped' \
	"$LLM_PROOFS" "$LLM_ROSTER" \
	'{"prepare":{"result":"success"},"gcp-wif":{"result":"success"},"aws-oidc":{"result":"success"},"api-key-release":{"result":"success"},"api-key-manual":{"result":"skipped"},"stowaway":{"result":"success"}}' \
	"$LLM_JOBS" 'release'

# ---- a missing leg proof still fails, with two jobs per family ------------
case_ 1 'a leg with no proof fails even when its job succeeded' '' \
	'gcp-wif=success
aws-oidc=success
api-key-release=success
api-key-manual=skipped' \
	'gcp-wif.vertex-notool=success
gcp-wif.vertex-tools=success
aws-oidc.bedrock-notool=success
aws-oidc.bedrock-tools=success
api-key-release.openai-tools=success' \
	"$LLM_ROSTER" "$LLM_NEEDS" "$LLM_JOBS" 'release'

rm -f /tmp/ga_out /tmp/ga_err
[ "$fails" = 0 ] || exit 1
printf 'OK: ci-gate-assert unit tests\n'
