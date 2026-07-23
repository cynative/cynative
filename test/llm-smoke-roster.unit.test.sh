#!/bin/sh
# Unit tests for the live LLM gate's leg roster. Offline and hermetic.
#
# This replaces internal/llm/livellm_manifest_test.go, which validated the deleted JSON
# manifest under `Lint & Test`. A static matrix has no schema, so without this the first
# time a bad roster is noticed is a release run.
#
# It is deliberately a GOLDEN, not a relational check. Comparing the workflow's matrix
# rows against the workflow's own ROSTER string would pass if a whole family were deleted
# from both, and the remaining legs would still emit gate_sha. The canonical roster below
# is the independent anchor.
#
# It pins each row's full tuple INCLUDING its owning job, not just the leg id: flipping
# vertex-notool to the tools suite keeps its id, family, live success, and proof while
# silently dropping the connector-dark tripwire, and repointing openai-tools at Anthropic
# yields two Anthropic calls, zero OpenAI calls, and a green gate. Job attribution is
# what makes the release/manual parity check real: without it, two OpenAI rows in one API
# job and two Anthropic rows in the other satisfy an aggregate multiset while violating
# parity outright.
set -eu

workflow=.github/workflows/llm-smoke.yaml
fails=0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# job|leg|family|suite|provider|model_var, one line per PHYSICAL matrix row. The api-key
# legs appear once under api-key-release and once under api-key-manual.
cat >"$tmp/expected" <<'EOF'
api-key-manual|anthropic-tools|api-key|llm-tools-smoke|anthropic|CYNATIVE_CLI_CI_ANTHROPIC_MODEL
api-key-manual|openai-tools|api-key|llm-tools-smoke|openai|CYNATIVE_CLI_CI_OPENAI_MODEL
api-key-release|anthropic-tools|api-key|llm-tools-smoke|anthropic|CYNATIVE_CLI_CI_ANTHROPIC_MODEL
api-key-release|openai-tools|api-key|llm-tools-smoke|openai|CYNATIVE_CLI_CI_OPENAI_MODEL
aws-oidc|bedrock-notool|aws-oidc|llm-smoke|bedrock|CYNATIVE_CLI_CI_BEDROCK_MODEL
aws-oidc|bedrock-tools|aws-oidc|llm-tools-smoke|bedrock|CYNATIVE_CLI_CI_BEDROCK_MODEL
gcp-wif|vertex-notool|gcp-wif|llm-smoke|vertex|CYNATIVE_CLI_CI_VERTEX_MODEL
gcp-wif|vertex-tools|gcp-wif|llm-tools-smoke|vertex|CYNATIVE_CLI_CI_VERTEX_MODEL
EOF

# Extract the rows the workflow actually declares, attributing each to its enclosing job.
# Strict by design: the parser only accepts the canonical block shape, so a reformatted
# or reordered row fails loudly rather than being silently reinterpreted.
#
# It also asserts each row's OPERATIONAL model expression equals `${{ vars.<model_var> }}`
# for that row's own model_var. Pinning model_var alone would leave the diagnostic label
# canonical while the consumed expression pointed elsewhere.
python3 - "$workflow" >"$tmp/actual" <<'PY'
import re
import sys

lines = open(sys.argv[1]).read().splitlines()

# Job headers sit at exactly two spaces of indentation, but only inside the top-level
# `jobs:` block. `on:` has children (workflow_call, workflow_dispatch) at that same
# two-space indentation, and without the in_jobs gate they would be misread as jobs.
top_re = re.compile(r"^(\S.*):\s*$")
job_re = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
row_keys = ("leg", "family", "suite", "provider", "model_var", "model")

rows = []
problems = []
job = None
in_jobs = False
i = 0
declared = 0
while i < len(lines):
    tm = top_re.match(lines[i])
    if tm:
        in_jobs = tm.group(1) == "jobs"
        i += 1
        continue
    if in_jobs:
        m = job_re.match(lines[i])
        if m:
            job = m.group(1)
            i += 1
            continue
    if re.match(r"^\s*- leg:", lines[i]):
        declared += 1
        block = lines[i:i + len(row_keys)]
        vals = {}
        ok = len(block) == len(row_keys)
        if ok:
            for key, line in zip(row_keys, block):
                km = re.match(r"^\s*-?\s*%s:\s*(.+?)\s*$" % re.escape(key), line)
                if not km:
                    ok = False
                    break
                vals[key] = km.group(1)
        if not ok:
            problems.append("row near line %d is not leg/family/suite/provider/model_var/model in order" % (i + 1))
            i += len(row_keys)
        else:
            want_model = "${{ vars.%s }}" % vals["model_var"]
            if vals["model"] != want_model:
                problems.append(
                    "leg %s consumes model %r but its model_var says it should consume %r"
                    % (vals["leg"], vals["model"], want_model)
                )
            rows.append("|".join([job or "<no-job>"] + [vals[k] for k in row_keys[:-1]]))
            i += len(row_keys)
            # The six known keys share one indentation level inside the row's mapping.
            # Anything else at that same indentation before the next row, job, or dedent
            # is a key the fixed-width window above would otherwise step over silently.
            indent_m = re.match(r"^(\s*)family:", block[1])
            indent = indent_m.group(1) if indent_m else None
            if indent is not None:
                while i < len(lines):
                    sm = re.match(r"^%s([A-Za-z0-9_-]+):" % re.escape(indent), lines[i])
                    if not sm:
                        break
                    problems.append(
                        "leg %s has an unexpected key %r" % (vals["leg"], sm.group(1))
                    )
                    i += 1
        continue
    i += 1

if declared != len(rows) or problems:
    for p in problems:
        sys.stderr.write("  %s\n" % p)
    sys.stderr.write("  declared rows=%d parsed rows=%d\n" % (declared, len(rows)))
    sys.exit(1)

print("\n".join(sorted(rows)))
PY

LC_ALL=C sort -o "$tmp/expected" "$tmp/expected"
LC_ALL=C sort -o "$tmp/actual" "$tmp/actual"

# Sorted comparison, so row order is free but the MULTISET is pinned. A set comparison
# would not catch a duplicated row.
if cmp -s "$tmp/expected" "$tmp/actual"; then
	printf 'ok   llm-smoke roster matches the canonical roster (8 rows, 6 legs)\n'
else
	printf 'FAIL: llm-smoke.yaml roster does not match the canonical roster.\n'
	printf '  only in canonical:\n'
	comm -23 "$tmp/expected" "$tmp/actual" | sed 's/^/    /'
	printf '  only in workflow:\n'
	comm -13 "$tmp/expected" "$tmp/actual" | sed 's/^/    /'
	fails=1
fi

# Release/manual parity, job-qualified: strip the job column from each api-key job's rows
# and require the two sets to be identical. Comparing them separately is what catches an
# uneven split that an aggregate multiset would wave through.
grep '^api-key-release|' "$tmp/actual" | cut -d'|' -f2- | LC_ALL=C sort >"$tmp/api_release"
grep '^api-key-manual|' "$tmp/actual" | cut -d'|' -f2- | LC_ALL=C sort >"$tmp/api_manual"
if ! cmp -s "$tmp/api_release" "$tmp/api_manual"; then
	printf 'FAIL: the api-key release and manual jobs must carry identical legs.\n'
	diff "$tmp/api_release" "$tmp/api_manual" | sed 's/^/    /' || true
	fails=1
fi

if [ "$fails" = 0 ]; then
	printf 'OK: llm-smoke-roster\n'
else
	exit 1
fi
