#!/bin/sh
# release-signing.unit.test.sh - offline contract pins for the release signing path
# (cynative#180). Hermetic: reads tracked source files only, no network, no cosign.
#
# The contract spans four files and nothing else checks it: .goreleaser.yaml decides what
# gets signed and what the asset is called, scripts/release/assert-assets.sh decides
# whether that asset is admitted to the draft, .github/workflows/release.yaml mints the
# OIDC token and verifies the result, and the Makefile's snapshot target is what keeps
# local builds out of the signing path. Any drift between them fails for the FIRST time
# during a live release, so pin each half here. Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)

goreleaser="$root/.goreleaser.yaml"
assert="$root/scripts/release/assert-assets.sh"
release="$root/.github/workflows/release.yaml"
makefile="$root/Makefile"

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

for f in "$goreleaser" "$assert" "$release" "$makefile"; do
	[ -f "$f" ] || { printf 'FAIL: %s not found\n' "$f" >&2; exit 1; }
done

# ---- .goreleaser.yaml: exactly one signs stanza, with the pinned shape -------------
signs_count=$(grep -cE '^signs:' "$goreleaser" || true)
if [ "$signs_count" -eq 1 ]; then
	pass "exactly one live signs: stanza in .goreleaser.yaml"
else
	fail "expected exactly 1 live signs: stanza in .goreleaser.yaml, found $signs_count"
fi

# Scope every field check to the stanza itself: a whole-file grep would be satisfied by
# a comment or an unrelated block. The stanza runs to the next top-level key.
block=$(awk '/^signs:/{f=1;next} f && /^[a-z]/{f=0} f' "$goreleaser")

check_block() { # pattern description
	n=$(printf '%s\n' "$block" | grep -cE "$1" || true)
	if [ "$n" -eq 1 ]; then pass "$2"; else fail "$2 (found $n matches)"; fi
}

check_block '^[[:space:]]+- cmd: cosign$'                               'signs stanza runs cosign'
check_block '^[[:space:]]+artifacts: checksum$'                         'signs stanza signs the checksum manifest'
check_block '^[[:space:]]+signature: "\$\{artifact\}\.sigstore\.json"$' 'signs stanza names the bundle .sigstore.json'
check_block '^[[:space:]]+- sign-blob$'                                 'signs stanza uses sign-blob'
check_block '^[[:space:]]+- "--bundle=\$\{signature\}"$'                'signs stanza writes the configured bundle path'
check_block '^[[:space:]]+- "--yes"$'                                   'signs stanza is non-interactive'
check_block '^[[:space:]]+- "\$\{artifact\}"$'                          'signs stanza signs the artifact'

# A `certificate:` field would emit a second artifact that assert-assets.sh does not
# admit, so the release would fail closed on a surplus asset. Keep it absent.
if printf '%s\n' "$block" | grep -qE '^[[:space:]]+certificate:'; then
	fail "signs stanza must not set certificate: (the bundle carries the cert; a cert artifact is not admitted by the asset gate)"
else
	pass "signs stanza sets no certificate: field"
fi

# ---- assert-assets.sh: the admitted type set is exactly Archive+Checksum+Signature --
# Exact whole-line match on the live filter, counted. A substring grep would also be
# satisfied by a commented-out decoy, and a whole-file scan for "Certificate" would match
# the header comment that explains why Certificate is excluded. The behavioural proof
# that Binary and Certificate stay excluded is the golden fixture in
# test/assert-assets.unit.test.sh; this pin is only about the live filter line.
filter_count=$(grep -cxF '    | select(.type == "Archive" or .type == "Checksum" or .type == "Signature")' "$assert" || true)
if [ "$filter_count" -eq 1 ]; then
	pass "assert-assets.sh admits exactly Archive, Checksum and Signature"
else
	fail "assert-assets.sh's generate filter must be exactly Archive, Checksum and Signature (found $filter_count exact matches) - otherwise the signature is surplus on the draft, or a type nothing signs is admitted"
fi

# ---- Makefile: snapshot skips signing ---------------------------------------------
if grep -qxF '	go tool goreleaser release --snapshot --clean --skip=sign' "$makefile"; then
	pass "make snapshot skips signing (no OIDC token locally)"
else
	fail "make snapshot must pass --skip=sign - keyless signing needs a GitHub Actions OIDC token, so a local snapshot (and the install-e2e that shells out to it) would fail"
fi

# ---- release.yaml: the production run must NOT skip signing ------------------------
# Strip comments first: a commented-out decoy invocation would otherwise satisfy the
# locator. Require exactly one live invocation so a second, skipping one cannot hide.
prod=$(sed 's/#.*//' "$release" | grep -E 'go tool goreleaser release' || true)
prod_count=$(printf '%s' "$prod" | grep -c . || true)
if [ "$prod_count" -ne 1 ]; then
	fail "expected exactly one live goreleaser invocation in release.yaml, found $prod_count"
elif printf '%s\n' "$prod" | grep -q -- '--skip=sign'; then
	fail "the production goreleaser invocation must not pass --skip=sign - that would publish an unsigned release that still passes every other gate"
else
	pass "the production goreleaser invocation signs"
fi

# ---- release.yaml: OIDC permission and the guarded steps ---------------------------
# Scope to the release job: a whole-file grep would latch onto another job's block. The
# scan resets at every job header, so a missing block fails below rather than borrowing
# a later job's permissions.
job=$(awk '/^  [A-Za-z0-9_-]+:$/{injob=($0=="  release:")} injob' "$release")

for perm in 'contents: read' 'id-token: write'; do
	if printf '%s\n' "$job" | grep -qxF "      ${perm}"; then
		pass "release job grants ${perm}"
	else
		fail "release job must grant ${perm} - a job-level permissions block replaces the workflow-level one, so both have to be stated"
	fi
done

# Both signing steps must carry the release-created guard. Without it they run on every
# ordinary push to main, where the checkout is skipped: the bootstrap would have no
# Makefile to read and the verification no dist/ to verify.
guard="if: \${{ steps.release-please.outputs.release_created == 'true' }}"
for step in 'Bootstrap pinned cosign' 'Verify the release signature'; do
	# Exactly one step of each name: the guard scan reads the FIRST occurrence, so a
	# guarded copy plus an unguarded duplicate would otherwise pass.
	step_count=$(grep -cxF "      - name: $step" "$release" || true)
	if [ "$step_count" -ne 1 ]; then
		fail "expected exactly one step named '$step' in release.yaml, found $step_count"
		continue
	fi
	# Scope to this step's own block, then require the guard at step level (exactly
	# eight spaces) anywhere inside it. Scoping stops a neighbouring step's guard from
	# satisfying the check, while not requiring the guard to be the very next line, so
	# a comment between `- name:` and `if:` is not a spurious failure. The eight-space
	# anchor is what keeps the same text inside a `run:` block, which is indented
	# deeper, from counting.
	step_block=$(awk -v s="      - name: $step" \
		'$0==s{f=1;next} f && /^      - name: /{f=0} f' "$release")
	if printf '%s\n' "$step_block" | grep -qxF "        $guard"; then
		pass "step '$step' carries the release-created guard"
	else
		fail "step '$step' must carry the release-created guard, or it runs on every ordinary push to main where the checkout is skipped"
	fi
done

# ---- release.yaml: the verification step's own contract ----------------------------
# Scoped to the step, not the whole file: a permissive identity regexp, a dropped
# certificate flag, or verification deleted entirely while the bundle path survives in a
# comment would all keep a whole-file grep green. The step runs to the next step.
verify_step=$(awk '/^      - name: Verify the release signature$/{f=1;next} f && /^      - name: /{f=0} f' "$release")

# `--` before the pattern: most of these start with a dash, which grep would otherwise
# read as its own option.
check_verify() { # substring description
	if printf '%s\n' "$verify_step" | grep -qF -- "$1"; then
		pass "$2"
	else
		fail "$2 - missing from the 'Verify the release signature' step"
	fi
}

# shellcheck disable=SC2016 # The literal ${COSIGN_*} spellings are exactly what is
# being pinned in the workflow; expanding them here would defeat the check.
check_verify 'cosign verify-blob dist/checksums.txt' \
	'verification runs cosign verify-blob on the checksum manifest'
# shellcheck disable=SC2016 # As above: pinning the literal workflow text.
check_verify '--bundle dist/checksums.txt.sigstore.json' \
	'verification names the bundle it verifies'
# shellcheck disable=SC2016 # As above: pinning the literal workflow text.
check_verify '--certificate-identity "${COSIGN_IDENTITY}"' \
	'verification pins an exact certificate identity'
# shellcheck disable=SC2016 # As above: pinning the literal workflow text.
check_verify '--certificate-oidc-issuer "${COSIGN_ISSUER}"' \
	'verification pins the OIDC issuer'
check_verify 'COSIGN_IDENTITY: https://github.com/cynative/cynative/.github/workflows/release.yaml@refs/heads/main' \
	'the pinned identity is this workflow on main'
check_verify 'COSIGN_ISSUER: https://token.actions.githubusercontent.com' \
	'the pinned issuer is GitHub Actions'

if printf '%s\n' "$verify_step" | grep -q -- '--certificate-identity-regexp'; then
	fail "verification must pin an exact --certificate-identity, never a regexp - a permissive pattern would accept a signature minted by any workflow in the repo"
else
	pass "verification does not fall back to an identity regexp"
fi

[ "$fails" -eq 0 ] || { printf '%d failure(s)\n' "$fails" >&2; exit 1; }
printf 'OK: release signing contract pins\n'
