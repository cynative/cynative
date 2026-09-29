#!/bin/sh
# dependabot-auto-merge.unit.test.sh - offline unit tests for the "Resolve
# Dependabot PR" step (the gate that decides whether the App token is minted)
# and the "Merge Dependabot PR" step (the pinned direct merge) of
# .github/workflows/dependabot-auto-merge.yaml.
#
# Hermetic: no network, no credentials. Each step's `run:` block is extracted
# from the workflow and executed against a fake `gh` that serves canned API
# responses and applies the caller's --jq filter with the real jq, so the shell
# and the jq predicates under test are the ones the workflow runs. Requires jq.
# DEPENDABOT_AUTOMERGE_WORKFLOW points the test at another copy of the workflow.
# Run by `make sh-test`.
set -eu

here=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/.." && pwd)
workflow="${DEPENDABOT_AUTOMERGE_WORKFLOW:-$root/.github/workflows/dependabot-auto-merge.yaml}"

fails=0
pass() { printf 'ok: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; fails=$((fails + 1)); }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"

# extract_step <step name> <out file>: the `run:` block of that step, dedented.
extract_step() {
  awk -v name="$1" '
    index($0, "- name: " name) { in_step = 1; next }
    in_step && /^        run: \|$/ { in_run = 1; next }
    in_run && /^          / { sub(/^          /, ""); print; next }
    in_run { exit }
  ' "$workflow" > "$2"
  if [ ! -s "$2" ]; then
    printf 'FAIL: could not extract the "%s" step\n' "$1" >&2
    exit 1
  fi
}
extract_step "Resolve Dependabot PR" "$tmp/step.sh"
extract_step "Merge Dependabot PR" "$tmp/merge.sh"

# Fake sleep: the retry delay must not slow the test.
printf '#!/bin/sh\nexit 0\n' > "$tmp/bin/sleep"
chmod +x "$tmp/bin/sleep"

# Fake gh: `gh api <path> [--paginate] [--jq <filter>]`, answered from $FIX.
# commits.json is an array of pages of commits, served as compare responses
# ({total_commits, commits}). Like the real gh, --paginate runs the filter over
# every page and without it only the first page is fetched.
cat > "$tmp/bin/gh" <<'EOF_GH'
#!/bin/sh
if [ "$1" = pr ]; then
  # gh pr merge <args>: record the call, answer from merge.results (line N for
  # call N, the last line once they run out): "ok" or "fail:<message>".
  printf '%s\n' "$*" >> "$FIX/merge.calls"
  n=$(wc -l < "$FIX/merge.calls" | tr -d ' ')
  total=$(wc -l < "$FIX/merge.results" | tr -d ' ')
  [ "$n" -le "$total" ] || n=$total
  result=$(sed -n "${n}p" "$FIX/merge.results")
  case "$result" in
    ok) echo "merged"; exit 0 ;;
    *) echo "${result#fail:}" >&2; exit 1 ;;
  esac
fi
path=""
filter=""
paginate=""
shift
while [ "$#" -gt 0 ]; do
  case "$1" in
    --jq) filter=$2; shift 2 ;;
    --paginate) paginate=1; shift ;;
    *) path=$1; shift ;;
  esac
done
case "$path" in
  */commits/*/pulls) file=$FIX/pulls.json ;;
  */compare/main...aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) file=$FIX/commits.json ;;
  */pulls/*) file=$FIX/pr.json ;;
  *) echo "unexpected gh path: $path" >&2; exit 1 ;;
esac
if [ "$file" = "$FIX/commits.json" ]; then
  if [ -n "$paginate" ]; then
    jq -c --slurpfile t "$FIX/total.json" '.[] | {total_commits: $t[0], commits: .}' "$file"
  else
    jq -c --slurpfile t "$FIX/total.json" '.[0] | {total_commits: $t[0], commits: .}' "$file"
  fi | while IFS= read -r page; do
    printf '%s\n' "$page" | jq -r "$filter"
  done
else
  jq -r "$filter" "$file"
fi
EOF_GH
chmod +x "$tmp/bin/gh"

sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

# dependabot commit: author dependabot[bot], committer web-flow, verified.
dep='{"sha":"1111111111111111","author":{"login":"dependabot[bot]"},"committer":{"login":"web-flow"},"commit":{"verification":{"verified":true}}}'

# run_case <name> <commit pages json> <total_commits> <pulls-json>; sets out and log.
run_case() {
  fix="$tmp/fix.$1"
  mkdir "$fix"
  printf '%s\n' "$4" > "$fix/pulls.json"
  printf '%s\n' "$2" > "$fix/commits.json"
  printf '%s\n' "$3" > "$fix/total.json"
  : > "$fix/out"
  PATH="$tmp/bin:$PATH" FIX="$fix" GITHUB_OUTPUT="$fix/out" \
    GITHUB_REPOSITORY=cynative/cynative HEAD_SHA="$sha" GH_TOKEN=x \
    bash -c "$(cat "$tmp/step.sh")" > "$fix/log" 2>&1 || {
      fail "$1: step exited non-zero"
      cat "$fix/log" >&2
    }
  out=$(cat "$fix/out")
  log=$(cat "$fix/log")
}

# expect_out <description> <expected out>: compare the step's output file.
expect_out() {
  if [ "$out" = "$2" ]; then
    pass "$1"
  else
    fail "$1: out=[$out] log=[$log]"
  fi
}

open_pr="[{\"number\":7,\"state\":\"open\",\"base\":{\"ref\":\"main\"},\"user\":{\"login\":\"dependabot[bot]\"},\"head\":{\"sha\":\"$sha\",\"repo\":{\"full_name\":\"cynative/cynative\"}}}]"

run_case clean "[[$dep]]" 1 "$open_pr"
expect_out "pure Dependabot PR goes on to merge" "number=7"

run_case two "[[$dep],[$dep]]" 2 "$open_pr"
expect_out "Dependabot commits across two pages go on to merge" "number=7"

human='{"sha":"2222222222222222","author":{"login":"someone"},"committer":{"login":"someone"},"commit":{"verification":{"verified":false}}}'
run_case mixed "[[$dep],[$human]]" 2 "$open_pr"
expect_out "a human commit on the second page does not go on to merge" ""
case "$log" in *"2222222 author=someone committer=someone verified=false"*"not merging"*|*"not merging"*"2222222 author=someone"*) pass "the skip names the offending commit" ;; *) fail "skip log: [$log]" ;; esac

unverified='{"sha":"3333333333333333","author":{"login":"dependabot[bot]"},"committer":{"login":"web-flow"},"commit":{"verification":{"verified":false}}}'
run_case unverified "[[$unverified]]" 1 "$open_pr"
expect_out "an unverified Dependabot-looking commit does not go on to merge" ""

selfsigned='{"sha":"4444444444444444","author":{"login":"dependabot[bot]"},"committer":{"login":"someone"},"commit":{"verification":{"verified":true}}}'
run_case committer "[[$selfsigned]]" 1 "$open_pr"
expect_out "a commit not committed by GitHub does not go on to merge" ""

nologin='{"sha":"5555555555555555","author":null,"committer":{"login":"web-flow"},"commit":{"verification":{"verified":true}}}'
run_case nologin "[[$nologin]]" 1 "$open_pr"
expect_out "a commit with no linked author does not go on to merge" ""

run_case truncated "[[$dep]]" 3 "$open_pr"
expect_out "an incomplete commit listing does not go on to merge" ""
case "$log" in *"listed 1 of 3"*) pass "the skip reports the counts" ;; *) fail "count log: [$log]" ;; esac

run_case nopr "[[$dep]]" 1 '[]'
expect_out "no matching PR does not go on to merge" ""
case "$log" in *"nothing to do"*) pass "no matching PR logs and stops" ;; *) fail "no PR log: [$log]" ;; esac

human_pr=$(printf '%s' "$open_pr" | sed 's/"dependabot\[bot\]"/"someone"/')
run_case humanpr "[[$dep]]" 1 "$human_pr"
expect_out "a human-authored PR does not go on to merge" ""

# run_merge <name> <pr.json> <results...>: run the Merge step; sets rc, calls, log.
run_merge() {
  fix="$tmp/fix.$1"
  mkdir "$fix"
  printf '%s\n' "$2" > "$fix/pr.json"
  shift 2
  printf '%s\n' "$@" > "$fix/merge.results"
  : > "$fix/merge.calls"
  rc=0
  PATH="$tmp/bin:$PATH" FIX="$fix" GITHUB_REPOSITORY=cynative/cynative \
    HEAD_SHA="$sha" PR_NUMBER=7 GH_TOKEN=x \
    bash -c "$(cat "$tmp/merge.sh")" > "$fix/log" 2>&1 || rc=$?
  calls=$(wc -l < "$fix/merge.calls" | tr -d ' ')
  log=$(cat "$fix/log")
}

# expect <description> <condition result>: pass when the condition held.
expect() {
  if [ "$2" = 1 ]; then pass "$1"; else fail "$1: rc=$rc calls=$calls log=[$log]"; fi
}

clean_pr="{\"merged\":false,\"head\":{\"sha\":\"$sha\"},\"mergeable_state\":\"clean\"}"

run_merge merged "$clean_pr" ok
expect "merges once at the tested SHA" "$([ "$rc" = 0 ] && [ "$calls" = 1 ] && echo 1 || echo 0)"
pinned=0
if grep -q -- "--squash --match-head-commit $sha" "$tmp/fix.merged/merge.calls" &&
  ! grep -q -- "--auto" "$tmp/fix.merged/merge.calls"; then
  pinned=1
fi
expect "the merge is direct, squashed and pinned" "$pinned"

moved_pr="{\"merged\":false,\"head\":{\"sha\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"},\"mergeable_state\":\"clean\"}"
run_merge moved "$moved_pr" "fail:Head branch was modified"
expect "a moved head is not retried and exits cleanly" "$([ "$rc" = 0 ] && [ "$calls" = 1 ] && echo 1 || echo 0)"
case "$log" in *"Head moved to bbbb"*) pass "a moved head is logged" ;; *) fail "moved log: [$log]" ;; esac

behind_pr="{\"merged\":false,\"head\":{\"sha\":\"$sha\"},\"mergeable_state\":\"behind\"}"
run_merge behind "$behind_pr" "fail:Head branch is out of date"
expect "a branch behind main is not retried and exits cleanly" "$([ "$rc" = 0 ] && [ "$calls" = 1 ] && echo 1 || echo 0)"
case "$log" in *"behind main"*) pass "a behind branch is logged" ;; *) fail "behind log: [$log]" ;; esac

run_merge transient "$clean_pr" "fail:HTTP 502" ok
expect "a transient error is retried and then merges" "$([ "$rc" = 0 ] && [ "$calls" = 2 ] && echo 1 || echo 0)"

run_merge persistent "$clean_pr" "fail:HTTP 502"
max_attempts=$(sed -n 's/^attempts=\([0-9][0-9]*\)$/\1/p' "$tmp/merge.sh")
expect "a persistent error stops after $max_attempts attempts and fails the job" "$([ "$rc" = 1 ] && [ "$calls" = "$max_attempts" ] && echo 1 || echo 0)"

merged_pr="{\"merged\":true,\"head\":{\"sha\":\"$sha\"},\"mergeable_state\":\"unknown\"}"
run_merge already "$merged_pr" "fail:Pull request is already merged"
expect "an already merged PR is not retried" "$([ "$rc" = 0 ] && [ "$calls" = 1 ] && echo 1 || echo 0)"

if [ "$fails" -ne 0 ]; then
  printf '%s dependabot-auto-merge unit test(s) failed\n' "$fails" >&2
  exit 1
fi
printf 'OK: dependabot-auto-merge unit tests\n'
