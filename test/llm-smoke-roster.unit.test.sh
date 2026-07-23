#!/bin/sh
# Unit tests for the live LLM gate's static contract in llm-smoke.yaml. Offline and
# hermetic. Three layers, all anchored to the one canonical roster below:
#
#   1. The matrix rows: each physical row's full job/leg/family/suite/provider/
#      model-variable tuple, plus release/manual parity for the api-key jobs.
#   2. The gate-assert fan-in: the ROSTER/JOBS/PROOFS literals are derived from the
#      canonical rows plus the job->policy map and compared as sorted multisets, so a
#      leg dropped from the fan-in (invisible to the runtime checks: the remaining
#      legs still pass) fails here instead of going silently ungated.
#   3. The smoke steps' operational seam: SUITE/provider/model must be consumed from
#      the matrix and the canonical suite dispatcher must be present, so a row field
#      cannot degrade into an unused label and the connector-dark tripwire cannot be
#      disabled while the rows stay green.
#
# It is deliberately a GOLDEN, not a relational check. Comparing the workflow's matrix
# rows against the workflow's own ROSTER string would pass if a whole family were
# deleted from both. The canonical roster is the independent anchor; the policy map is
# part of that anchor (policies are not derivable from the matrix).
#
# Rows pin the full tuple INCLUDING the owning job: flipping vertex-notool to the
# tools suite keeps its id/family/proof while dropping the connector-dark tripwire,
# and repointing openai-tools at Anthropic yields two Anthropic calls and a green
# gate. Job attribution is what makes the release/manual parity check real.
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
python3 - "$workflow" "$tmp/expected" >"$tmp/actual" <<'PY'
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

# ---- gate-assert fan-in literals -------------------------------------------
# The canonical rows (argv[2]) are the anchor; the gate-assert env's ROSTER, JOBS,
# and PROOFS are DERIVED from them plus this job->policy map and compared as sorted
# multisets. The map is part of the anchor: policies are not derivable from the
# matrix. A leg dropped from the fan-in is invisible to the runtime checks (the
# remaining legs still pass), which is exactly why these literals need a golden.
policy_map = {
    "gcp-wif": "always",
    "aws-oidc": "always",
    "api-key-release": "release",
    "api-key-manual": "manual",
}

canonical = []
for raw in open(sys.argv[2]).read().splitlines():
    if raw.strip():
        canonical.append(raw.split("|"))
for parts in canonical:
    if len(parts) != 6:
        problems.append(
            "canonical row %r is not job|leg|family|suite|provider|model_var" % "|".join(parts)
        )

# Derivation self-guards: a stale policy map or an ambiguous family mapping must fail
# the golden itself, not silently derive a wrong expectation.
canonical_jobs = sorted({parts[0] for parts in canonical})
if sorted(policy_map) != canonical_jobs:
    problems.append(
        "policy map keys %s do not equal the canonical job set %s"
        % (sorted(policy_map), canonical_jobs)
    )
for what, idx in (("job", 0), ("leg", 1)):
    fams = {}
    for parts in canonical:
        fams.setdefault(parts[idx], set()).add(parts[2])
    for name, seen in sorted(fams.items()):
        if len(seen) != 1:
            problems.append("%s %s maps to multiple families %s" % (what, name, sorted(seen)))

want_roster = sorted({parts[1] + ":" + parts[2] for parts in canonical})
want_jobs = sorted(
    {parts[0] + ":" + parts[2] + ":" + policy_map.get(parts[0], "<unmapped>") for parts in canonical}
)
want_proofs = sorted(
    parts[0] + "." + parts[1] + "=${{ needs." + parts[0]
    + ".outputs.proof_" + parts[1].replace("-", "_") + " }}"
    for parts in canonical
)

def job_slice(name):
    start = None
    for i, line in enumerate(lines):
        if line == "  %s:" % name:
            start = i + 1
            break
    if start is None:
        problems.append("job %s not found in the workflow" % name)
        return []
    end = len(lines)
    for i in range(start, len(lines)):
        if re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[i]) or re.match(r"^\S", lines[i]):
            end = i
            break
    return lines[start:end]

def scalars(chunk, key):
    out = []
    for line in chunk:
        m = re.match(r"^\s*%s:\s*(.+?)\s*$" % re.escape(key), line)
        if m:
            out.append(m.group(1))
    return out

def block(chunk, key):
    out = []
    starts = [i for i, l in enumerate(chunk) if re.match(r"^\s*%s:\s*\|\s*$" % re.escape(key), l)]
    if len(starts) != 1:
        problems.append("expected exactly one %s block in gate-assert, found %d" % (key, len(starts)))
        return out
    indent = len(chunk[starts[0]]) - len(chunk[starts[0]].lstrip())
    for l in chunk[starts[0] + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) <= indent:
            break
        if l.strip():
            out.append(l.strip())
    return out

ga = job_slice("gate-assert")
got_roster = scalars(ga, "ROSTER")
got_jobs = scalars(ga, "JOBS")
if len(got_roster) != 1:
    problems.append("expected exactly one ROSTER scalar in gate-assert, found %d" % len(got_roster))
if len(got_jobs) != 1:
    problems.append("expected exactly one JOBS scalar in gate-assert, found %d" % len(got_jobs))
got_proofs = block(ga, "PROOFS")

if got_roster and sorted(got_roster[0].split()) != want_roster:
    problems.append(
        "gate-assert ROSTER %s does not match the derived %s"
        % (sorted(got_roster[0].split()), want_roster)
    )
if got_jobs and sorted(got_jobs[0].split()) != want_jobs:
    problems.append(
        "gate-assert JOBS %s does not match the derived %s"
        % (sorted(got_jobs[0].split()), want_jobs)
    )
if sorted(got_proofs) != want_proofs:
    problems.append(
        "gate-assert PROOFS do not match the derived lines:\n    got  %s\n    want %s"
        % (sorted(got_proofs), want_proofs)
    )

# ---- per-job smoke-step operational seam -----------------------------------
# The rows pin what the matrix DECLARES; these pin what the smoke step CONSUMES. A
# SUITE hardcoded to llm-tools-smoke would keep every row green while silently
# disabling the connector-dark tripwire, and an unbound provider/model would reduce
# canonical row fields to unused labels.
SMOKE_ENV_PINS = {
    "SMOKE_REQUIRE_RUN": '"1"',
    "SUITE": "${{ matrix.suite }}",
    "CYNATIVE_LLM_PROVIDER": "${{ matrix.provider }}",
    "CYNATIVE_LLM_MODEL": "${{ matrix.model }}",
}
DISPATCHER = [
    'case "$SUITE" in',
    'llm-smoke) export SMOKE_REQUIRE_NO_CONNECTORS=1; exec make llm-smoke ;;',
    'llm-tools-smoke) unset SMOKE_REQUIRE_NO_CONNECTORS; exec make llm-tools-smoke ;;',
    '*) echo "::error::unknown suite: $SUITE" >&2; exit 1 ;;',
    'esac',
]

def norm(line):
    return " ".join(line.split())

def check_smoke(jobname):
    chunk = job_slice(jobname)
    smoke = [i for i, l in enumerate(chunk) if norm(l) == "id: smoke"]
    if len(smoke) != 1:
        problems.append(
            "job %s must have exactly one id: smoke step, found %d" % (jobname, len(smoke))
        )
        return
    j = smoke[0]
    while j < len(chunk) and norm(chunk[j]) != "env:":
        j += 1
    if j == len(chunk):
        problems.append("job %s smoke step has no env block" % jobname)
        return
    env_indent = len(chunk[j]) - len(chunk[j].lstrip())
    env = {}
    j += 1
    while j < len(chunk):
        l = chunk[j]
        if l.strip() and (len(l) - len(l.lstrip())) <= env_indent:
            break
        m = re.match(r"^\s*([A-Za-z0-9_]+):\s*(.*?)\s*$", l)
        if m and not l.lstrip().startswith("#"):
            if m.group(1) in env:
                problems.append("job %s smoke env declares %s twice" % (jobname, m.group(1)))
            env[m.group(1)] = m.group(2)
        j += 1
    for key, want in sorted(SMOKE_ENV_PINS.items()):
        if env.get(key) != want:
            problems.append(
                "job %s smoke env %s is %r, want %r" % (jobname, key, env.get(key), want)
            )
    while j < len(chunk) and norm(chunk[j]) != "run: |":
        j += 1
    if j == len(chunk):
        problems.append("job %s smoke step has no run block" % jobname)
        return
    run_indent = len(chunk[j]) - len(chunk[j].lstrip())
    body = []
    for l in chunk[j + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) <= run_indent:
            break
        if l.strip():
            body.append(norm(l))
    for k in range(len(body) - len(DISPATCHER) + 1):
        if body[k:k + len(DISPATCHER)] == DISPATCHER:
            break
    else:
        problems.append("job %s smoke run block lacks the canonical suite dispatcher" % jobname)

for jobname in canonical_jobs:
    check_smoke(jobname)

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
	printf 'OK: llm-smoke-roster (rows + fan-in literals + smoke seam)\n'
else
	exit 1
fi
