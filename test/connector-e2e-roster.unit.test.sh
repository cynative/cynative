#!/bin/sh
# Unit tests for the live connector gate's static contract in connector-e2e.yaml.
# Offline and hermetic. Modelled on test/llm-smoke-roster.unit.test.sh (cynative#190) and
# added with the GKE leg (cynative#117), which is what made the gap urgent: a connector is
# only gated if it appears in BOTH the job topology and the fan-in, and nothing checked
# that the two agree with anything outside the workflow.
#
# THE HOLE THIS CLOSES. The runtime checks are internally consistent by construction: the
# sentinel proves its own leg ran, and gate-assert proves every connector in ROSTER
# produced a proof. Delete a matrix row AND its ROSTER entry together and both still pass
# - the remaining legs are green, the fan-in asks for nothing more, and the connector is
# silently ungated on the pre-publish release path. EXPECTED_TOTAL does not help: it is a
# literal in the same file, edited in the same breath.
#
# So this is a GOLDEN, not a relational check. The canonical roster below is an
# independent anchor: it is never derived from the workflow, and every assertion is made
# against it. Four layers:
#
#   1. Job topology: each matrix job's rows (connector + timeout) and fail-fast, and the
#      static github leg, which is a real job rather than a one-row matrix and would be
#      invisible to a matrix-only parser.
#   2. Selection: SELECTORS, the dispatch choice list, and each job's own `if:`
#      membership, spelled as exact equality (never contains(), which is substring
#      matching: contains('gcp gke', 'gk') is true).
#   3. The fan-in: ROSTER/JOBS/PROOFS and gate-assert's `needs`, all derived from the
#      canonical rows and compared as sorted multisets.
#   4. The operational seam: each leg's `*_REQUIRE_RUN: "1"` and `*_CANARY: "1"`, its
#      proof output and sentinel arm, and the `make connector-<c>-e2e` invocation. A leg
#      whose REQUIRE_RUN went missing skips green on a renamed variable, and one whose
#      CANARY went to 0 would prove a read while never probing the boundary at all.
set -eu

workflow=.github/workflows/connector-e2e.yaml
fails=0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# job|connector|kind|timeout, one line per LOGICAL connector leg. `kind` is matrix or
# static: github is a genuine singleton job, not a one-row matrix, and the difference
# changes which assertions apply (a static job has no strategy, no matrix.connector, and
# no EXPECTED_TOTAL). Timeouts are part of the anchor because a leg silently dropped to a
# 1-minute cap would fail on the release path only.
cat >"$tmp/expected" <<'EOF'
aws-oidc|aws|matrix|25
gcp-wif|gcp|matrix|20
gcp-wif|gke|matrix|30
github-app|github|static|35
EOF

python3 - "$workflow" "$tmp/expected" >"$tmp/actual" <<'PY'
import re
import sys

with open(sys.argv[1], encoding="utf-8") as workflow_file:
    lines = workflow_file.read().splitlines()

problems = []

canonical = []
with open(sys.argv[2], encoding="utf-8") as canonical_file:
    for raw in canonical_file.read().splitlines():
        if raw.strip():
            canonical.append(raw.split("|"))
for parts in canonical:
    if len(parts) != 4:
        problems.append("canonical row %r is not job|connector|kind|timeout" % "|".join(parts))
    elif parts[2] not in ("matrix", "static"):
        problems.append("canonical row %r has an unknown kind %r" % ("|".join(parts), parts[2]))

CONNECTORS = sorted(parts[1] for parts in canonical)
JOBS = sorted({parts[0] for parts in canonical})
BY_JOB = {}
for parts in canonical:
    BY_JOB.setdefault(parts[0], []).append(parts)
# A job is matrix or static as a whole; a mixed one would make every per-kind assertion
# below ambiguous rather than wrong, so catch it here.
for job, rows in sorted(BY_JOB.items()):
    if len({r[2] for r in rows}) != 1:
        problems.append("job %s mixes matrix and static legs" % job)


def job_slice(name):
    """The lines of one top-level job, exclusive of the next job header."""
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
    """Every `key: value` in chunk, comments excluded."""
    out = []
    for line in chunk:
        if line.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*%s:\s*(.+?)\s*$" % re.escape(key), line)
        if m:
            out.append(m.group(1))
    return out


def block(chunk, key):
    """The lines of a single `key: |` literal block."""
    out = []
    starts = [i for i, l in enumerate(chunk)
              if re.match(r"^\s*%s:\s*\|\s*$" % re.escape(key), l)]
    if len(starts) != 1:
        problems.append("expected exactly one %s block, found %d" % (key, len(starts)))
        return out
    indent = len(chunk[starts[0]]) - len(chunk[starts[0]].lstrip())
    for l in chunk[starts[0] + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) <= indent:
            break
        if l.strip():
            out.append(l.strip())
    return out


def folded(chunk, key):
    """A `key: >-` folded scalar, joined into one line."""
    starts = [i for i, l in enumerate(chunk) if re.match(r"^\s*%s:\s*>-\s*$" % re.escape(key), l)]
    if len(starts) != 1:
        return None
    indent = len(chunk[starts[0]]) - len(chunk[starts[0]].lstrip())
    parts = []
    for l in chunk[starts[0] + 1:]:
        if l.strip() and (len(l) - len(l.lstrip())) <= indent:
            break
        if l.strip():
            parts.append(l.strip())
    return " ".join(parts)


def step_env(chunk, step_id):
    """The env mapping of the step whose `id:` is step_id."""
    ids = [i for i, l in enumerate(chunk) if " ".join(l.split()) == "id: %s" % step_id]
    if len(ids) != 1:
        problems.append("expected exactly one `id: %s` step, found %d" % (step_id, len(ids)))
        return {}
    j = ids[0]
    while j < len(chunk) and " ".join(chunk[j].split()) != "env:":
        j += 1
    if j == len(chunk):
        return {}
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
                problems.append("step %s declares env %s twice" % (step_id, m.group(1)))
            env[m.group(1)] = m.group(2)
        j += 1
    return env


# ---- 1. job topology --------------------------------------------------------
rows = []
for job in JOBS:
    chunk = job_slice(job)
    kind = BY_JOB[job][0][2]
    if kind == "matrix":
        if "false" not in scalars(chunk, "fail-fast"):
            problems.append("job %s must set fail-fast: false so one red leg cannot mask another"
                            % job)
        # Each `- connector: X` row is followed by its own `timeout: N`.
        declared = []
        for i, l in enumerate(chunk):
            m = re.match(r"^\s*-\s*connector:\s*(\S+)\s*$", l)
            if not m:
                continue
            timeout = None
            for follow in chunk[i + 1:]:
                if re.match(r"^\s*-\s*connector:", follow):
                    break
                tm = re.match(r"^\s*timeout:\s*(\d+)\s*$", follow)
                if tm:
                    timeout = tm.group(1)
                    break
            if timeout is None:
                problems.append("job %s row %s declares no timeout" % (job, m.group(1)))
                continue
            declared.append((m.group(1), timeout))
        if len(declared) != len(set(declared)):
            problems.append("job %s declares a duplicate matrix row" % job)
        for connector, timeout in declared:
            rows.append("%s|%s|matrix|%s" % (job, connector, timeout))
        # EXPECTED_TOTAL must equal this job's realized leg count, or strategy.job-total
        # cannot catch an added or dropped row.
        totals = scalars(chunk, "EXPECTED_TOTAL")
        want_total = '"%d"' % len(BY_JOB[job])
        if totals != [want_total]:
            problems.append("job %s EXPECTED_TOTAL is %r, want exactly [%r]" % (job, totals, want_total))
        if scalars(chunk, "CONNECTOR") != ["${{ matrix.connector }}"] * 2:
            problems.append("job %s must bind CONNECTOR: ${{ matrix.connector }} in both the "
                            "e2e and sentinel steps, so a row field cannot become an unused label"
                            % job)
        if 'make "connector-${CONNECTOR}-e2e"' not in "\n".join(chunk):
            problems.append("job %s does not invoke make \"connector-${CONNECTOR}-e2e\"" % job)
    else:
        if scalars(chunk, "strategy"):
            problems.append("job %s is canonically static but declares a strategy" % job)
        connector = BY_JOB[job][0][1]
        if "make connector-%s-e2e" % connector not in "\n".join(chunk):
            problems.append("job %s does not invoke make connector-%s-e2e" % (job, connector))
        timeouts = scalars(chunk, "timeout-minutes")
        rows.append("%s|%s|static|%s" % (job, connector, timeouts[0] if timeouts else "<none>"))

    # ---- 2. selection: the job's own membership test ------------------------
    cond = folded(chunk, "if") or ""
    if "contains(" in cond:
        problems.append("job %s uses contains() in its if:, which is SUBSTRING matching; use "
                        "exact selector equality" % job)
    if "github.repository == 'cynative/cynative'" not in cond:
        problems.append("job %s lost its repository guard, the defense that keeps a fork off "
                        "the credential steps" % job)
    for parts in BY_JOB[job]:
        want = "needs.prepare.outputs.selector == '%s'" % parts[1]
        if want not in cond:
            problems.append("job %s if: does not admit its own connector %s (want %r)"
                            % (job, parts[1], want))

    # ---- 4. the operational seam -------------------------------------------
    outputs = scalars(chunk, "proof_%s" % BY_JOB[job][0][1])
    del outputs
    for parts in BY_JOB[job]:
        connector = parts[1]
        want_out = "${{ steps.sentinel.outputs.proof_%s }}" % connector
        if want_out not in scalars(chunk, "proof_%s" % connector):
            problems.append("job %s does not declare output proof_%s from the sentinel"
                            % (job, connector))
        if kind == "matrix":
            arm = "%s) key=proof_%s ;;" % (connector, connector)
            if arm not in [" ".join(l.split()) for l in chunk]:
                problems.append("job %s sentinel has no allowlist arm %r" % (job, arm))
        else:
            if "proof_%s=success" % connector not in "\n".join(chunk):
                problems.append("job %s sentinel does not emit proof_%s=success" % (job, connector))
    env = step_env(chunk, "e2e")
    for parts in BY_JOB[job]:
        prefix = "GH" if parts[1] == "github" else parts[1].upper()
        for suffix in ("REQUIRE_RUN", "CANARY"):
            key = "%s_E2E_%s" % (prefix, suffix)
            if env.get(key) != '"1"':
                problems.append("job %s e2e env %s is %r, want '\"1\"' (a missing REQUIRE_RUN "
                                "skips green; a CANARY other than 1 leaves the boundary unprobed)"
                                % (job, key, env.get(key)))

# ---- 2. selection: the global selector vocabulary ---------------------------
prep = job_slice("prepare")
selectors = scalars(prep, "SELECTORS")
if len(selectors) != 1 or sorted(selectors[0].split()) != CONNECTORS:
    problems.append("prepare SELECTORS %r does not equal the canonical connector set %s"
                    % (selectors, CONNECTORS))
options = [l for l in lines if re.match(r"^\s*options:\s*\[", l)]
if len(options) != 1:
    problems.append("expected exactly one workflow_dispatch options list, found %d" % len(options))
else:
    got = [o.strip() for o in options[0].split("[", 1)[1].rstrip("]").split(",")]
    want = ["all"] + CONNECTORS
    if sorted(got) != sorted(want) or got[0] != "all":
        problems.append("workflow_dispatch options %s do not equal %s" % (got, want))

# ---- 3. the fan-in ----------------------------------------------------------
ga = job_slice("gate-assert")
want_roster = sorted("%s:%s" % (parts[1], parts[0]) for parts in canonical)
want_jobs = sorted("%s:%s:always" % (job, job) for job in JOBS)
want_proofs = sorted(
    "%s.%s=${{ needs.%s.outputs.proof_%s }}" % (parts[0], parts[1], parts[0], parts[1])
    for parts in canonical
)
want_results = sorted("%s=${{ needs.%s.result }}" % (job, job) for job in JOBS)

got_roster = scalars(ga, "ROSTER")
got_jobs = scalars(ga, "JOBS")
if len(got_roster) != 1 or sorted(got_roster[0].split()) != want_roster:
    problems.append("gate-assert ROSTER %r does not match the derived %s" % (got_roster, want_roster))
if len(got_jobs) != 1 or sorted(got_jobs[0].split()) != want_jobs:
    problems.append("gate-assert JOBS %r does not match the derived %s" % (got_jobs, want_jobs))
if sorted(block(ga, "PROOFS")) != want_proofs:
    problems.append("gate-assert PROOFS do not match the derived lines:\n    got  %s\n    want %s"
                    % (sorted(block(ga, "PROOFS")), want_proofs))
if sorted(block(ga, "RESULTS")) != want_results:
    problems.append("gate-assert RESULTS do not match the derived lines:\n    got  %s\n    want %s"
                    % (sorted(block(ga, "RESULTS")), want_results))

# gate-assert's `needs` is what the runtime cross-check compares ROSTER against, so a job
# missing from it makes the whole family invisible rather than red.
needs = [l for l in ga if re.match(r"^\s*needs:\s*\[", l)]
if len(needs) != 1:
    problems.append("expected exactly one gate-assert needs list, found %d" % len(needs))
else:
    got_needs = sorted(n.strip() for n in needs[0].split("[", 1)[1].rstrip("]").split(","))
    if got_needs != sorted(["prepare"] + JOBS):
        problems.append("gate-assert needs %s does not equal %s"
                        % (got_needs, sorted(["prepare"] + JOBS)))
# Bare always(), zero conjuncts: any conjunct reopens the skip-is-success hole.
if "    if: ${{ always() }}" not in ga:
    problems.append("gate-assert must run under a bare `if: ${{ always() }}` with no conjuncts")

if problems:
    for p in problems:
        sys.stderr.write("  %s\n" % p)
    sys.exit(1)

print("\n".join(sorted(rows)))
PY

LC_ALL=C sort -o "$tmp/expected" "$tmp/expected"
LC_ALL=C sort -o "$tmp/actual" "$tmp/actual"

# Sorted comparison, so declaration order is free but the MULTISET is pinned. A set
# comparison would not catch a duplicated row.
if cmp -s "$tmp/expected" "$tmp/actual"; then
	printf 'ok   connector-e2e roster matches the canonical roster (4 legs, 3 jobs)\n'
else
	printf 'FAIL: connector-e2e.yaml roster does not match the canonical roster.\n'
	printf '  only in canonical:\n'
	comm -23 "$tmp/expected" "$tmp/actual" | sed 's/^/    /'
	printf '  only in workflow:\n'
	comm -13 "$tmp/expected" "$tmp/actual" | sed 's/^/    /'
	fails=1
fi

if [ "$fails" = 0 ]; then
	printf 'OK: connector-e2e-roster (topology + selection + fan-in + operational seam)\n'
else
	exit 1
fi
