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
#   3. The fan-in: ROSTER/JOBS/PROOFS/RESULTS and gate-assert's `needs`, all derived from
#      the canonical rows and compared as sorted multisets.
#   4. The two EXECUTABLE seams, which are what turn the roster into evidence. Every
#      literal above is inert unless something runs the suite and something evaluates the
#      fan-in, so both invocations are pinned as the COMPLETE comment-stripped body of the
#      owning step's `run:` - `make connector-<c>-e2e` in `id: e2e`, and
#      `sh scripts/ci/ci-gate-assert.sh &&` guarding the gate_sha emission in `id: assert`.
#      Membership is not enough: a body that merely CONTAINS the command proves nothing
#      about execution, since `if false; then make ...; fi` succeeds, mints a proof and
#      greens the gate. Also each leg's `*_REQUIRE_RUN` and `*_CANARY` forcing.
#
# THE WORKFLOW IS PARSED WITH PyYAML, NOT LINE BY LINE. Every check here asks a structural
# question - which key belongs to which step - and a line scanner cannot answer that
# safely: a decoy `env:`/`run:` block nested inside a multiline `name:` scalar is valid
# YAML that a text search reads as the step's own keys while Actions uses the real sibling
# keys below it. Parsing gives the same tree Actions sees, so a decoy is just a string.
# The loader clears PyYAML's YAML 1.1 implicit resolvers for the same reason
# scripts/ci/check-llm-smoke-secrets.py does: otherwise `on:` resolves to the boolean True
# and stops being addressable as the key it was written as.
set -eu

workflow=.github/workflows/connector-e2e.yaml
fails=0

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

# job|connector|kind|timeout|extra, one line per LOGICAL connector leg.
#
# `kind` is matrix or static: github is a genuine singleton job, not a one-row matrix, and
# the difference changes which assertions apply (a static job has no strategy, no
# matrix.connector, and no EXPECTED_TOTAL). Timeouts are part of the anchor because a leg
# silently dropped to a 1-minute cap would fail on the release path only. `extra` is the
# row's remaining matrix keys as k=v pairs, or `-` for none: aws-oidc carries
# output_env_credentials=true, which is what puts AWS_* in the environment so the aws
# connector registers, and the github leg sets the INVERSE to keep it dark. The workflow
# calls that inversion easy to copy wrongly, so it is pinned rather than tolerated.
cat >"$tmp/expected" <<'EOF'
aws-oidc|aws|matrix|25|output_env_credentials=true
gcp-wif|gcp|matrix|20|-
gcp-wif|gke|matrix|30|-
github-app|github|static|35|-
EOF

python3 - "$workflow" "$tmp/expected" >"$tmp/actual" <<'PY'
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("  PyYAML not found - needed to parse the workflow (apt: python3-yaml, "
                     "pip: PyYAML)\n")
    sys.exit(1)


class PlainStringLoader(yaml.SafeLoader):
    """Leaves every plain scalar as the string it was written as, so `on:` stays the key
    `on` instead of resolving to the YAML 1.1 boolean True."""


PlainStringLoader.yaml_implicit_resolvers = {}

with open(sys.argv[1], encoding="utf-8") as workflow_file:
    wf = yaml.load(workflow_file.read(), Loader=PlainStringLoader)  # noqa: S506 - SafeLoader subclass

problems = []

canonical = []
with open(sys.argv[2], encoding="utf-8") as canonical_file:
    for raw in canonical_file.read().splitlines():
        if raw.strip():
            canonical.append(raw.split("|"))
for parts in canonical:
    if len(parts) != 5:
        problems.append("canonical row %r is not job|connector|kind|timeout|extra" % "|".join(parts))
    elif parts[2] not in ("matrix", "static"):
        problems.append("canonical row %r has an unknown kind %r" % ("|".join(parts), parts[2]))

CONNECTORS = sorted(parts[1] for parts in canonical)
JOBS = sorted({parts[0] for parts in canonical})
BY_JOB = {}
for parts in canonical:
    BY_JOB.setdefault(parts[0], []).append(parts)
# A job is matrix or static as a whole; a mixed one would make every per-kind assertion
# below ambiguous rather than wrong, so catch it here.
for job, job_rows in sorted(BY_JOB.items()):
    if len({r[2] for r in job_rows}) != 1:
        problems.append("job %s mixes matrix and static legs" % job)

# The COMPLETE comment-stripped run body of each executable seam, as an independent
# literal. Whole-body equality, never membership: a body that merely CONTAINS the command
# proves nothing about execution, and every membership check has the same shape of bypass -
#
#     if false; then
#       make "connector-${CONNECTOR}-e2e"
#     fi
#
# succeeds, mints a proof and greens the release gate while containing the line verbatim.
# The same applies to gate-assert: checking the script call and the gate_sha printf
# separately would accept `sh ...ci-gate-assert.sh && true` followed by an unconditional
# printf, which emits the gate's proof even when the assertion failed. Only the exact
# sequence pins the `&&` relationship between them.
#
# The cost is that any real edit to these four bodies must update this table too. That is
# the intent: these are the lines that turn every other literal in this file from a
# declaration into evidence.
# The full normalized `if` of every credential-bearing job and of the two steps that
# decide whether a leg runs and whether it may mint a proof. Whole-expression equality for
# the same reason as EXPECTED_RUN: a substring check for the repository guard survives
# appending `|| true`, which neutralizes the one defense that keeps a fork off the
# credential steps while every checked fragment stays present.
#
# Scope is deliberate: the conditions pinned here are the ones that can let a leg mint a
# proof it did not earn. Other step conditions (the preflight's, which carries the same
# selection expression) are not pinned, because loosening one can only make a run fail on
# a variable it does not need - noisy, never green.
EXPECTED_IF = {
    ("gcp-wif", None): ("github.repository == 'cynative/cynative' && "
                        "needs.prepare.result == 'success' && "
                        "(needs.prepare.outputs.selector == '' || "
                        "needs.prepare.outputs.selector == 'gcp' || "
                        "needs.prepare.outputs.selector == 'gke')"),
    ("aws-oidc", None): ("github.repository == 'cynative/cynative' && "
                         "needs.prepare.result == 'success' && "
                         "(needs.prepare.outputs.selector == '' || "
                         "needs.prepare.outputs.selector == 'aws')"),
    ("github-app", None): ("github.repository == 'cynative/cynative' && "
                           "needs.prepare.result == 'success' && "
                           "(needs.prepare.outputs.selector == '' || "
                           "needs.prepare.outputs.selector == 'github')"),
    # A matrix leg is selected on the STEP, because a job-level if cannot read matrix.
    ("gcp-wif", "e2e"): ("${{ needs.prepare.outputs.selector == '' || "
                         "needs.prepare.outputs.selector == matrix.connector }}"),
    ("aws-oidc", "e2e"): ("${{ needs.prepare.outputs.selector == '' || "
                          "needs.prepare.outputs.selector == matrix.connector }}"),
    ("github-app", "e2e"): "",
    ("gcp-wif", "sentinel"): ("${{ always() && (needs.prepare.outputs.selector == '' || "
                              "needs.prepare.outputs.selector == matrix.connector) }}"),
    ("aws-oidc", "sentinel"): ("${{ always() && (needs.prepare.outputs.selector == '' || "
                               "needs.prepare.outputs.selector == matrix.connector) }}"),
    ("github-app", "sentinel"): "${{ always() }}",
    ("gate-assert", None): "${{ always() }}",
}

EXPECTED_RUN = {
    ("gcp-wif", "e2e"): [
        'export GOOGLE_APPLICATION_CREDENTIALS="$CREDS_FILE"',
        'CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS="$(cat "$CREDS_FILE")"',
        "export CYNATIVE_LLM_VERTEX_AUTH_CREDENTIALS",
        'make "connector-${CONNECTOR}-e2e"',
    ],
    ("aws-oidc", "e2e"): ['make "connector-${CONNECTOR}-e2e"'],
    ("github-app", "e2e"): ["make connector-github-e2e"],
    ("gate-assert", "assert"): [
        "sh scripts/ci/ci-gate-assert.sh &&",
        "printf 'gate_sha=%s\\n' \"$CHECKOUT_SHA\" >>\"$GITHUB_OUTPUT\"",
    ],
    # The sentinel is the third executable seam. Pinned whole: dropping only its
    # E2E_OUTCOME check, while keeping the case arms and the proof emission, lets a leg
    # that never ran still mint its proof - and every arm-by-arm check would still pass.
    ("gcp-wif", "sentinel"): [
        'if [ "$ACTUAL_TOTAL" != "$EXPECTED_TOTAL" ]; then',
        'echo "::error::gcp-wif realized $ACTUAL_TOTAL legs, expected $EXPECTED_TOTAL: a matrix row was added or dropped"',
        "exit 1",
        "fi",
        'if [ "$E2E_OUTCOME" != success ]; then',
        'echo "::error::connector $CONNECTOR e2e outcome=$E2E_OUTCOME"',
        "exit 1",
        "fi",
        'case "$CONNECTOR" in',
        "gcp) key=proof_gcp ;;",
        "gke) key=proof_gke ;;",
        '*) echo "::error::connector $CONNECTOR is not in the gcp-wif allowlist"; exit 1 ;;',
        "esac",
        "printf '%s=success\\n' \"$key\" >>\"$GITHUB_OUTPUT\"",
    ],
    ("aws-oidc", "sentinel"): [
        'if [ "$ACTUAL_TOTAL" != "$EXPECTED_TOTAL" ]; then',
        'echo "::error::aws-oidc realized $ACTUAL_TOTAL legs, expected $EXPECTED_TOTAL: a matrix row was added or dropped"',
        "exit 1",
        "fi",
        'if [ "$E2E_OUTCOME" != success ]; then',
        'echo "::error::connector $CONNECTOR e2e outcome=$E2E_OUTCOME"',
        "exit 1",
        "fi",
        'case "$CONNECTOR" in',
        "aws) key=proof_aws ;;",
        '*) echo "::error::connector $CONNECTOR is not in the aws-oidc allowlist"; exit 1 ;;',
        "esac",
        "printf '%s=success\\n' \"$key\" >>\"$GITHUB_OUTPUT\"",
    ],
    ("github-app", "sentinel"): [
        'if [ "$E2E_OUTCOME" != success ]; then',
        'echo "::error::connector github e2e outcome=$E2E_OUTCOME"',
        "exit 1",
        "fi",
        "printf 'proof_github=success\\n' >>\"$GITHUB_OUTPUT\"",
    ],
}


def job_of(name):
    j = (wf.get("jobs") or {}).get(name)
    if not isinstance(j, dict):
        problems.append("job %s is missing from the workflow" % name)
        return {}
    return j


def step_of(job_name, step_id):
    """The ONE step of `job_name` whose `id` is step_id, from the parsed tree. Any other
    count is a broken workflow, never a silently-picked first match."""
    steps = [s for s in (job_of(job_name).get("steps") or [])
             if isinstance(s, dict) and s.get("id") == step_id]
    if len(steps) != 1:
        problems.append("job %s must have exactly one step with id: %s, found %d"
                        % (job_name, step_id, len(steps)))
        return {}
    return steps[0]


def step_env(job_name, step_id):
    env = step_of(job_name, step_id).get("env")
    return env if isinstance(env, dict) else {}


def run_body(job_name, step_id):
    """The step's `run:` as a list of normalized, non-comment, non-blank lines."""
    body = step_of(job_name, step_id).get("run")
    if not isinstance(body, str):
        return []
    out = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            out.append(" ".join(stripped.split()))
    return out


def check_run(job_name, step_id):
    want = EXPECTED_RUN.get((job_name, step_id))
    if want is None:
        problems.append("no expected run body is pinned for %s/%s" % (job_name, step_id))
        return
    got = run_body(job_name, step_id)
    if got != want:
        problems.append("job %s step %s run body is not the pinned sequence:\n"
                        "    got  %s\n    want %s" % (job_name, step_id, got, want))


def check_if(job_name, step_id):
    """Whole-expression equality against EXPECTED_IF. step_id None means the job's own
    condition."""
    key = (job_name, step_id)
    if key not in EXPECTED_IF:
        problems.append("no expected if: is pinned for %s/%s" % (job_name, step_id))
        return
    node = job_of(job_name) if step_id is None else step_of(job_name, step_id)
    got = " ".join(str(node.get("if") or "").split())
    if got != EXPECTED_IF[key]:
        problems.append("job %s %s if: is not the pinned expression:\n    got  %r\n    want %r"
                        % (job_name, "job-level" if step_id is None else "step " + step_id,
                           got, EXPECTED_IF[key]))


# ---- 1. job topology --------------------------------------------------------
rows = []
for job in JOBS:
    spec = job_of(job)
    kind = BY_JOB[job][0][2]
    if kind == "matrix":
        strategy = spec.get("strategy") or {}
        if strategy.get("fail-fast") != "false":
            problems.append("job %s must set fail-fast: false so one red leg cannot mask "
                            "another (got %r)" % (job, strategy.get("fail-fast")))
        include = (strategy.get("matrix") or {}).get("include") or []
        declared = []
        for row in include:
            if not isinstance(row, dict) or "connector" not in row or "timeout" not in row:
                problems.append("job %s has a matrix row without connector+timeout: %r" % (job, row))
                continue
            extra = ",".join("%s=%s" % (k, row[k]) for k in sorted(row)
                             if k not in ("connector", "timeout")) or "-"
            declared.append((row["connector"], str(row["timeout"]), extra))
        if len(declared) != len(set(declared)):
            problems.append("job %s declares a duplicate matrix row" % job)
        for connector, timeout, extra in declared:
            rows.append("%s|%s|matrix|%s|%s" % (job, connector, timeout, extra))
        # EXPECTED_TOTAL must equal this job's realized leg count, or strategy.job-total
        # cannot catch an added or dropped row.
        want_total = str(len(BY_JOB[job]))
        got_total = step_env(job, "sentinel").get("EXPECTED_TOTAL")
        if got_total != want_total:
            problems.append("job %s sentinel EXPECTED_TOTAL is %r, want %r"
                            % (job, got_total, want_total))
        # Checked per step: other steps legitimately bind CONNECTOR too (the preflight
        # dispatches its per-fixture checks on it), so a count would pin how many of them
        # exist rather than the two that matter.
        for step_id in ("e2e", "sentinel"):
            if step_env(job, step_id).get("CONNECTOR") != "${{ matrix.connector }}":
                problems.append("job %s step %s must bind CONNECTOR: ${{ matrix.connector }}, "
                                "so a row field cannot become an unused label" % (job, step_id))
    else:
        if spec.get("strategy"):
            problems.append("job %s is canonically static but declares a strategy" % job)
        rows.append("%s|%s|static|%s|-"
                    % (job, BY_JOB[job][0][1], str(spec.get("timeout-minutes"))))
    check_run(job, "e2e")

    # ---- 2. selection: the job's and its steps' own conditions --------------
    # Whole-expression equality, not substring membership: the repository guard is the one
    # defense that keeps a fork off the credential steps, and appending `|| true` leaves
    # every fragment a substring check looks for exactly where it was. The pinned strings
    # are also what carry the "exact equality, never contains()" rule, since contains() is
    # substring matching and contains('gcp gke', 'gk') is true.
    for step_id in (None, "e2e", "sentinel"):
        check_if(job, step_id)

    # ---- 4. the operational seam -------------------------------------------
    outputs = spec.get("outputs") or {}
    want_outputs = {"proof_%s" % parts[1]: "${{ steps.sentinel.outputs.proof_%s }}" % parts[1]
                    for parts in BY_JOB[job]}
    if outputs != want_outputs:
        problems.append("job %s outputs are %r, want exactly %r (matrix outputs sharing one "
                        "name race; distinct names combine)" % (job, outputs, want_outputs))
    # The sentinel's allowlist arms, its E2E_OUTCOME check and its proof emission are all
    # inside the body pinned here, so no separate per-arm assertion is needed - and a
    # per-arm one would miss the removal of the outcome check that guards them.
    check_run(job, "sentinel")
    if step_env(job, "sentinel").get("E2E_OUTCOME") != "${{ steps.e2e.outcome }}":
        problems.append("job %s sentinel must bind E2E_OUTCOME to steps.e2e.OUTCOME - "
                        "outcome is the value before continue-on-error, so it catches a "
                        "skipped, tolerated or renamed e2e step where conclusion would not"
                        % job)
    env = step_env(job, "e2e")
    for parts in BY_JOB[job]:
        prefix = "GH" if parts[1] == "github" else parts[1].upper()
        for suffix in ("REQUIRE_RUN", "CANARY"):
            key = "%s_E2E_%s" % (prefix, suffix)
            if str(env.get(key)) != "1":
                problems.append("job %s e2e env %s is %r, want \"1\" (a missing REQUIRE_RUN "
                                "skips green; a CANARY other than 1 leaves the boundary "
                                "unprobed)" % (job, key, env.get(key)))

# ---- 2. selection: the global selector vocabulary ---------------------------
selectors = step_env("prepare", "contract").get("SELECTORS")
if not isinstance(selectors, str) or sorted(selectors.split()) != CONNECTORS:
    problems.append("prepare SELECTORS %r does not equal the canonical connector set %s"
                    % (selectors, CONNECTORS))
triggers = wf.get("on")
options = (((triggers or {}).get("workflow_dispatch") or {}).get("inputs") or {}) \
    .get("connector", {}).get("options")
if not isinstance(options, list) or options[:1] != ["all"] or sorted(options) != sorted(["all"] + CONNECTORS):
    problems.append("workflow_dispatch connector options %r do not equal %s with 'all' first"
                    % (options, ["all"] + CONNECTORS))

# ---- 3. the fan-in ----------------------------------------------------------
ga_env = step_env("gate-assert", "assert")
want_roster = sorted("%s:%s" % (parts[1], parts[0]) for parts in canonical)
want_jobs = sorted("%s:%s:always" % (job, job) for job in JOBS)
want_proofs = sorted(
    "%s.%s=${{ needs.%s.outputs.proof_%s }}" % (parts[0], parts[1], parts[0], parts[1])
    for parts in canonical
)
want_results = sorted("%s=${{ needs.%s.result }}" % (job, job) for job in JOBS)


def lines_of(value):
    return sorted(l.strip() for l in str(value or "").splitlines() if l.strip())


if sorted(str(ga_env.get("ROSTER") or "").split()) != want_roster:
    problems.append("gate-assert ROSTER %r does not match the derived %s"
                    % (ga_env.get("ROSTER"), want_roster))
if sorted(str(ga_env.get("JOBS") or "").split()) != want_jobs:
    problems.append("gate-assert JOBS %r does not match the derived %s"
                    % (ga_env.get("JOBS"), want_jobs))
if lines_of(ga_env.get("PROOFS")) != want_proofs:
    problems.append("gate-assert PROOFS do not match the derived lines:\n    got  %s\n    want %s"
                    % (lines_of(ga_env.get("PROOFS")), want_proofs))
if lines_of(ga_env.get("RESULTS")) != want_results:
    problems.append("gate-assert RESULTS do not match the derived lines:\n    got  %s\n    want %s"
                    % (lines_of(ga_env.get("RESULTS")), want_results))

# gate-assert's `needs` is what the runtime cross-check compares ROSTER against, so a job
# missing from it makes the whole family invisible rather than red.
ga = job_of("gate-assert")
got_needs = sorted(ga.get("needs") or [])
if got_needs != sorted(["prepare"] + JOBS):
    problems.append("gate-assert needs %s does not equal %s"
                    % (got_needs, sorted(["prepare"] + JOBS)))
# Bare always(), zero conjuncts: any conjunct reopens the skip-is-success hole.
check_if("gate-assert", None)
# The fan-in literals are only evidence if something evaluates them, and gate_sha is only
# evidence if it cannot be emitted without that evaluation succeeding.
check_run("gate-assert", "assert")

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
