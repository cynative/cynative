#!/bin/sh
# Unit tests for scripts/release/retrigger.sh, the release-pipeline re-trigger. Offline
# and hermetic: a stub gh on PATH stands in for every API call, so no test can reach
# GitHub.
#
# What matters here is that the script fails closed. A re-trigger that silently does
# nothing (bad repo argument, missing token, a dispatch the API rejected) would leave an
# operator believing recovery is under way while the draft sits untouched.
# shellcheck disable=SC2030,SC2031
set -eu

script=scripts/release/retrigger.sh
fails=0

bindir=$(mktemp -d)
out=$(mktemp)
err=$(mktemp)
cleanup() { rm -rf "$bindir" "$out" "$err"; }
trap cleanup EXIT

# write_gh BODY - install a stub gh whose behaviour is BODY.
write_gh() {
	printf '#!/bin/sh\n%s\n' "$1" >"$bindir/gh"
	chmod +x "$bindir/gh"
}

# run ARGS... - run the script with the stub gh first on PATH.
run() {
	(
		PATH="$bindir:$PATH"
		# Colon form, so an ambient GH_TOKEN= (empty, not unset) still gets the
		# stub. The no-colon form would preserve the empty value and the script
		# would exit on its own token check before reaching the stub gh, failing
		# a test that is supposed to be hermetic.
		GH_TOKEN=${GH_TOKEN:-stub-token}
		export PATH GH_TOKEN
		bash "$script" "$@"
	)
}

check() {
	if [ "$1" = "$2" ]; then
		printf '  ok: %s\n' "$3"
	else
		printf 'FAIL: %s (expected exit %s, got %s)\n' "$3" "$2" "$1" >&2
		sed 's/^/    stderr: /' "$err" >&2
		fails=$((fails + 1))
	fi
}

# A dispatch the API accepts is the success path.
write_gh 'exit 0'
run cynative/cynative >"$out" 2>"$err" && rc=0 || rc=$?
check "$rc" 0 "accepted dispatch exits 0"
if ! grep -q 'release-retry' "$out"; then
	printf 'FAIL: success output does not name the release-retry event type\n' >&2
	fails=$((fails + 1))
fi

# A rejected dispatch must fail, never report success.
write_gh 'echo "{\"message\":\"Not Found\"}" >&2; exit 1'
run cynative/cynative >"$out" 2>"$err" && rc=0 || rc=$?
check "$rc" 1 "rejected dispatch exits 1"

# A missing repo argument is a usage error, not a dispatch against an empty repo.
write_gh 'exit 0'
run >"$out" 2>"$err" && rc=0 || rc=$?
check "$rc" 1 "missing repo argument exits 1"

# A repo argument that is not owner/name is rejected before any API call: a bare name
# would otherwise POST to a path gh resolves against the current directory's remote.
write_gh 'exit 0'
run cynative >"$out" 2>"$err" && rc=0 || rc=$?
check "$rc" 1 "repo argument without a slash exits 1"

# No GH_TOKEN means no dispatch: failing here is clearer than a gh auth error.
write_gh 'exit 0'
(
	PATH="$bindir:$PATH"
	unset GH_TOKEN
	export PATH
	bash "$script" cynative/cynative
) >"$out" 2>"$err" && rc=0 || rc=$?
check "$rc" 1 "missing GH_TOKEN exits 1"

if [ "$fails" -ne 0 ]; then
	printf 'FAIL: %s retrigger.sh unit test(s) failed\n' "$fails" >&2
	exit 1
fi
printf 'OK: retrigger.sh unit tests\n'
