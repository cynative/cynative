#!/bin/sh
# Unit tests for scripts/ci/connector-e2e-gate-assert.sh, the fail-closed fan-in of the
# consolidated connector e2e gate. Offline and hermetic.
#
# This is the assertion that makes the gate real: GitHub reports a conditionally skipped
# job as SUCCESS to its caller, so publish's `result == 'success'` alone would be
# satisfied by a gate that ran nothing.
set -eu

script=scripts/ci/connector-e2e-gate-assert.sh
fails=0

ROSTER='gcp:gcp-wif aws:aws-oidc github:github-app'

# needs_json ROSTER - build a NEEDS_JSON (the toJSON(needs) shape) whose family keys
# match ROSTER's family names exactly, plus the always-present prepare. Used as the
# default so most cases exercise only the thing they name, not the roster/needs
# cross-check; the cross-check's own tests build NEEDS_JSON by hand instead.
needs_json() {
	_out='{"prepare":{"result":"success"}'
	for _pair in $1; do
		_family=${_pair##*:}
		_out="$_out,\"$_family\":{\"result\":\"success\"}"
	done
	printf '%s}' "$_out"
}
NEEDS_JSON_DEFAULT=$(needs_json "$ROSTER")

# case_ WANT DESC SELECTOR RESULTS PROOFS [ROSTER] [NEEDS_JSON]
# ROSTER defaults to the shared roster above; pass it to exercise a roster with a
# connector or family name the shared one does not have. NEEDS_JSON defaults to a set
# matching that roster; pass it (including an empty string) to exercise the roster/needs
# cross-check itself.
case_() {
	_want=$1
	_desc=$2
	_roster=${6:-$ROSTER}
	_needs=${7-$NEEDS_JSON_DEFAULT}
	if ( SELECTOR="$3" ROSTER="$_roster" RESULTS="$4" PROOFS="$5" NEEDS_JSON="$_needs" \
		sh "$script" >/tmp/ga_out 2>/tmp/ga_err ); then
		_got=0
	else
		_got=$?
	fi
	if [ "$_want" != "$_got" ]; then
		printf 'FAIL: %s (want exit %s, got %s)\n' "$_desc" "$_want" "$_got" >&2
		cat /tmp/ga_err >&2
		fails=1
	fi
}

ALL_OK='gcp-wif=success
aws-oidc=success
github-app=success'
ALL_PROOF='gcp=success
aws=success
github=success'

# ---- the happy release path ----------------------------------------------
case_ 0 "full roster all green passes" "" "$ALL_OK" "$ALL_PROOF"

# ---- the fail-open shapes this script exists to catch ---------------------
# A family that skipped reports success to the caller; it must not pass here.
case_ 1 "a skipped family on the full path fails" "" 'gcp-wif=skipped
aws-oidc=success
github-app=success' "$ALL_PROOF"

# A dropped matrix row leaves the family green but emits no proof.
case_ 1 "a missing proof fails even when the family is green" "" "$ALL_OK" 'gcp=success
aws=success
github='

# A cancelled family must block, not wave through.
case_ 1 "a cancelled family fails" "" 'gcp-wif=cancelled
aws-oidc=success
github-app=success' "$ALL_PROOF"

case_ 1 "a failed family fails" "" 'gcp-wif=failure
aws-oidc=success
github-app=success' "$ALL_PROOF"

# A proof that is present but not exactly "success" must not pass.
case_ 1 "a non-success proof value fails" "" "$ALL_OK" 'gcp=skipped
aws=success
github=success'

# A connector absent from RESULTS entirely (family job deleted from needs).
case_ 1 "a family missing from the results fails" "" 'aws-oidc=success
github-app=success' "$ALL_PROOF"

# ---- the filtered dispatch path ------------------------------------------
# Only gcp selected: its family must be green with a proof, the others must be skipped.
case_ 0 "filtered dispatch passes with the others skipped" gcp 'gcp-wif=success
aws-oidc=skipped
github-app=skipped' 'gcp=success
aws=
github='

# An unselected family that ran anyway means the filter leaked.
case_ 1 "an unselected connector emitting a proof fails" gcp 'gcp-wif=success
aws-oidc=success
github-app=skipped' 'gcp=success
aws=success
github='

# The selected family must still be exactly success.
case_ 1 "filtered dispatch with the selected family skipped fails" gcp 'gcp-wif=skipped
aws-oidc=skipped
github-app=skipped' 'gcp=
aws=
github='

# The selected connector must still produce its proof.
case_ 1 "filtered dispatch with no proof from the selected leg fails" gcp 'gcp-wif=success
aws-oidc=skipped
github-app=skipped' 'gcp=
aws=
github='

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

case_ 1 "a duplicated connector key in PROOFS fails" "" "$ALL_OK" 'gcp=success
gcp=success
aws=success
github=success'

# A family name containing a regex metacharacter must match only its own literal
# line, never wildcard onto an unrelated one (a "gcp.wif" family must not match a
# "gcpXwif=success" line, which a sed/grep regex built from the key would allow).
META_ROSTER='gcp:gcp.wif aws:aws-oidc github:github-app'
case_ 1 "a metacharacter family name does not wildcard-match a different line" "" 'gcpXwif=success
aws-oidc=success
github-app=success' "$ALL_PROOF" "$META_ROSTER" "$(needs_json "$META_ROSTER")"

# ---- roster vs job-graph cross-check ---------------------------------------
# needs is the actual dependency graph (toJSON(needs)); ROSTER is a hand-maintained
# parallel list. Nothing else binds them, so a family added to one and forgotten in the
# other must fail closed rather than silently leave a connector ungated.
NEEDS_EXTRA_FAMILY='{"prepare":{"result":"success"},"gcp-wif":{"result":"success"},
"aws-oidc":{"result":"success"},"github-app":{"result":"success"},
"gitlab-token":{"result":"success"}}'
case_ 1 "a family in needs but missing from ROSTER fails" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" "$NEEDS_EXTRA_FAMILY"

NEEDS_MISSING_FAMILY='{"prepare":{"result":"success"},"gcp-wif":{"result":"success"},
"aws-oidc":{"result":"success"}}'
case_ 1 "a family in ROSTER but missing from needs fails" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" "$NEEDS_MISSING_FAMILY"

case_ 1 "malformed NEEDS_JSON fails" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" 'not json'

case_ 1 "a NEEDS_JSON that is valid JSON but not an object fails" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" '["prepare"]'

# NEEDS_JSON is a required env var (a fatal shell parameter-expansion error, exit 2),
# so an empty value fails closed before the cross-check even runs.
case_ 2 "an empty NEEDS_JSON fails closed" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" ""

case_ 0 "matching needs and ROSTER still passes" "" "$ALL_OK" "$ALL_PROOF" "$ROSTER" "$NEEDS_JSON_DEFAULT"

rm -f /tmp/ga_out /tmp/ga_err
[ "$fails" = 0 ] || exit 1
printf 'OK: connector-e2e-gate-assert unit tests\n'
