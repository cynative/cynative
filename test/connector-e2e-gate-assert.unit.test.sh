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

# case_ WANT DESC SELECTOR RESULTS PROOFS
case_() {
	_want=$1
	_desc=$2
	if ( SELECTOR="$3" ROSTER="$ROSTER" RESULTS="$4" PROOFS="$5" \
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

rm -f /tmp/ga_out /tmp/ga_err
[ "$fails" = 0 ] || exit 1
printf 'OK: connector-e2e-gate-assert unit tests\n'
