#!/bin/sh
# connector.aws.e2e.test.sh - live AWS connector end-to-end test (cynative#52).
#
# Runs the real `cynative -p` against a real AWS fixture account through the aws
# connector and asserts, from a black-box run: the connector registers under the
# read-only SecurityAudit policy, the model reads an inert fixture IAM role and
# surfaces a tag value it could only have obtained from AWS, and a deliberate write
# is denied client-side before it reaches the network.
#
# NOT hermetic and NOT part of `make check`: it talks to a real provider and a real
# AWS account and needs real credentials. Skips (exit 0) when required env is unset,
# so `make connector-aws-e2e` is a safe no-op.
#
# Usage: sh test/connector.aws.e2e.test.sh [BINARY]
#        sh test/connector.aws.e2e.test.sh --selftest   (offline parser check)
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   ambient AWS_* / profile                     required (lights the aws connector)
#   AWS_E2E_ROLE_NAME      fixture role name (appears in the prompt)
#   AWS_E2E_EXPECT         fixture tag value (NEVER in the prompt)
#   AWS_E2E_ACCOUNT        expected account id in the startup inventory
#   AWS_E2E_ENFORCED       expected `enforced=` field: client+aws (an assumed-role
#                          identity, e.g. CI, where credential scoping engages) or
#                          client (an IAM-user profile, for which cynative never
#                          attempts scoping)
#   AWS_E2E_TIMEOUT        wall-clock seconds per run (default 240; the first
#                          authorization cold-fetches the configured policy and a
#                          Smithy model archive before any request is dispatched)
#   AWS_E2E_MAX_TOKENS     token backstop (default 32000)
#   AWS_E2E_CANARY         run the write-deny canary phase (default 1; 0 disables)
#   AWS_E2E_ATTEMPTS       per-phase attempts (default 2; model runs are
#                          non-deterministic, so one retry absorbs a rare miss)
#   AWS_E2E_KEEP_WORKDIR   =1 keep the temp workdir (parser, audit logs, output) for
#                          debugging instead of deleting it on exit
#   AWS_E2E_REQUIRE_RUN    =1 hard-fail instead of skipping when required env is unset
set -eu

# write_parser writes the embedded python3 audit parser to $1.
#
# The parser is the security boundary of this suite, so it is deliberately paranoid.
# Its exit codes feed the shared phase-status contract in test/lib/e2e-guardrails.sh:
#
#   0  the assertion holds.
#   1  not proven this attempt (a model miss or a fumbled call the gate blocked).
#      The caller may retry.
#   4  SECURITY: a request that the read-only boundary should have stopped cannot be
#      shown to have stayed on the machine. FATAL - the caller must never retry,
#      because the audit log is truncated per attempt and a retry would erase the
#      evidence, letting a broken gate pass on the second try.
#
# The load-bearing distinction is "did the request leave the machine". Every
# `aws_hardening` error is raised by an auth gate, and all of those run before
# httpClient.Do, so such an error PROVES the request was never dispatched. A failure
# WITHOUT that proof cannot be assumed harmless: a mutation can be dispatched, get a
# 2xx, and only then fail while its response body is read, which surfaces as a plain
# tool error. So anything that is neither a sanctioned read nor the exact sanctioned
# canary, and which lacks an aws_hardening denial, is a security failure.
write_parser() {
	cat >"$1" <<'PY'
import json
import re
import sys
from urllib.parse import parse_qs, urlparse

NOT_PROVEN = 1
SECURITY = 4

MARKER = "cynative-e2e"
FIXTURE_TAG_KEY = "cynative-e2e-fixture"
IAM_HOST = "iam.amazonaws.com"
STS_HOST = "sts.amazonaws.com"
CANARY_URL = "https://iam.amazonaws.com/"
CANARY_VERSION = "2010-05-08"
FORM_CT = "application/x-www-form-urlencoded"
# Any aws_hardening error proves a pre-dispatch block: every gate that raises one
# runs before the request is sent.
BLOCKED = "aws_hardening"
WRAP_DIRECT = "Error executing tool: auth: authorize action for provider aws: "
WRAP_SANDBOX = "auth: authorize action for provider aws: "
# The policy-gate denial (internal/auth/aws ErrPolicyDenied):
#   aws_hardening: action denied by policy: [<perms>] denied by policy <arn>
# The bracketed list is Go's %v of a []string, and the policy ARN is an operator
# config value (not fixed in this suite), so the match is structural: the fullmatch
# pins the gate's exact prefix/suffix shape, and the canary check then requires the
# write's own action to be IN the list.
DENIAL_RE = re.compile(
    r"aws_hardening: action denied by policy: \[([^][]*)\] denied by policy \S+"
)
# Reads the model may legitimately make. Anything else is either the one sanctioned
# canary or a failure.
READ_ACTIONS = {"GetRole", "ListRoleTags", "ListRoles", "GetCallerIdentity"}
# Reads that actually return the role's tags. ListRoles cannot be the witness: AWS
# omits tags from it.
TAG_READS = {"GetRole", "ListRoleTags"}
CANARY_FORM_KEYS = {"Action", "Version", "RoleName", "Tags.member.1.Key", "Tags.member.1.Value"}


class DuplicateKeyError(ValueError):
    """Raised by the object hook on a duplicate JSON key. Distinct from a plain
    JSONDecodeError so a duplicate key is ALWAYS fatal, even on the final line."""


def die(msg, code=NOT_PROVEN):
    print(msg)
    sys.exit(code)


def insecure(msg):
    die("SECURITY: " + msg, SECURITY)


def _no_dup_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise DuplicateKeyError("duplicate key %r" % k)
        d[k] = v
    return d


def _loads(s):
    """json.loads with duplicate-key rejection. DuplicateKeyError propagates."""
    return json.loads(s, object_pairs_hook=_no_dup_keys)


def load_records(path):
    """Every JSON object record in the audit log, attempt and result phases alike
    (both are needed to pair a call).

    Fails closed on almost everything: an unreadable or missing file, non-UTF-8
    bytes, a duplicate JSON key (even on the final line - a repeated key is
    ambiguous, never a mere write artifact), and a malformed line anywhere but the
    last. A single malformed FINAL physical line is tolerated: it is a probable
    kill-during-write artifact, and every record that DID fully parse is still swept
    below, so tolerating it can never hide a breach, only a genuine evidence gap,
    which then surfaces as a retryable "not proven" from the caller.
    """
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError as e:
        insecure("audit: cannot read %s: %s" % (path, e))
    except UnicodeDecodeError:
        insecure("audit: log is not valid UTF-8 - failing closed")
    lines = raw.splitlines()
    recs = []
    for n, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rec = _loads(stripped)
        except DuplicateKeyError:
            insecure("duplicate JSON key at line %d - failing closed" % n)
        except ValueError:
            if n == len(lines):
                # A single malformed FINAL line is tolerated; every record that DID
                # parse is still classified below.
                continue
            insecure("malformed JSONL at line %d (not final) - failing closed" % n)
        if not isinstance(rec, dict):
            insecure("line %d is not a JSON object - failing closed" % n)
        recs.append(rec)
    return recs


def http_records(recs):
    return [r for r in recs if r.get("tool") == "http_request"]


def type_strict_eq(a, b):
    """Equality that treats bool and int as distinct types (Python's == does not:
    False == 0), so an attempt/result pair that swapped one for the other is caught
    rather than waved through as agreeing."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(type_strict_eq(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(type_strict_eq(x, y) for x, y in zip(a, b))
    return a == b


def index_calls(recs):
    """Ordered list of (key, {attempt, result}) for every http_request call, keyed by
    (session_id, run_id, call_id). A missing id component, an unknown phase, an
    orphan or duplicate record, a result preceding its attempt, or an attempt/result
    pair that disagrees on arguments is a breach: the pairing itself cannot be
    trusted, so nothing downstream may rely on it.
    """
    calls = {}
    order = []
    for r in http_records(recs):
        key = (r.get("session_id"), r.get("run_id"), r.get("call_id"))
        if not all(isinstance(k, str) and k for k in key):
            insecure("http_request record with an empty id tuple: %r" % (key,))
        slot = calls.get(key)
        if slot is None:
            slot = {}
            calls[key] = slot
            order.append(key)
        phase = r.get("phase")
        if phase == "attempt":
            if "attempt" in slot:
                insecure("duplicate attempt for %r" % (key,))
            if "result" in slot:
                insecure("result precedes attempt for %r" % (key,))
            slot["attempt"] = r
        elif phase == "result":
            if "attempt" not in slot:
                insecure("result without a preceding attempt for %r" % (key,))
            if "result" in slot:
                insecure("duplicate result for %r" % (key,))
            slot["result"] = r
        else:
            insecure("http_request record with unknown phase %r" % (phase,))
    out = []
    for k in order:
        slot = calls[k]
        a, res = slot.get("attempt"), slot.get("result")
        if a is not None and res is not None and not type_strict_eq(args_of(a), args_of(res)):
            insecure("attempt/result arguments disagree for %r" % (k,))
        out.append((k, slot))
    return out


def _fold_keys(d, what):
    """Mirror Go's case-insensitive JSON field matching: the transport decodes the
    raw arguments with encoding/json, which binds e.g. "HEADERS" to the headers field
    or "Method" to method, so the parser must see the same view or a miscased key could
    add wire behavior invisible to the allow-list sweep. A case-fold collision is
    ambiguous (which value Go bound is decoder-internal), so it fails closed."""
    out = {}
    for k, v in d.items():
        f = k.casefold() if isinstance(k, str) else k
        if f in out:
            insecure("case-folded duplicate key %r in %s - failing closed" % (k, what))
        out[f] = v
    return out


def args_of(rec):
    a = rec.get("arguments")
    if isinstance(a, str):
        try:
            a = json.loads(a)
        except ValueError:
            die("audit: unparseable http_request arguments")
    if not isinstance(a, dict):
        return {}
    return _fold_keys(a, "http_request arguments")


def aws_service_of(a):
    """The aws_auth.service claim, folded the way Go binds it (aws_auth is a struct, so
    "Service"/"SERVICE" bind to the Service field), or None when absent."""
    g = a.get("aws_auth")
    return _fold_keys(g, "aws_auth").get("service") if isinstance(g, dict) else None


def result_of(rec):
    r = rec.get("result")
    return r if isinstance(r, str) else ""


def result_json(rec):
    """The sandbox path records StructuredRun's JSON as a STRING, so `result` needs a
    second decode. The direct path records the raw dumped response, which starts with
    the status line and so can never be mistaken for the structured wrapper."""
    try:
        obj = json.loads(result_of(rec))
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def status_of(rec):
    """The HTTP status, from either result encoding, or None when the request never
    produced a response. There is no status field on the audit record, and
    outcome == ok only means "below 400", which includes 3xx.

    type(x) is int, not isinstance: isinstance(True, int) is True in Python, so an
    isinstance check would let a JSON bool masquerade as a status code."""
    obj = result_json(rec)
    if obj is not None and type(obj.get("status")) is int:
        return obj["status"]
    # Anchor on the protocol version, not a literal HTTP/2.0 (HTTP/1.1 is a legal
    # negotiation and the dump preserves whatever was negotiated), and require a
    # boundary after the 3-digit status so "HTTP/1.1 2000" cannot be read as 200.
    m = re.match(r"HTTP/[0-9.]+\s+([0-9]{3})(?![0-9])", result_of(rec))
    return int(m.group(1)) if m else None


def body_of(rec):
    """(body, truncated). The direct path dumps status line + headers + body, so the
    headers must be cut off: a tag value appearing only in a response header would
    otherwise satisfy a body assertion.

    Fail-closed on the structured path: a missing/non-false truncated flag, a
    non-string body, or a non-int status counts as truncated/invalid - a witness needs
    proof the body arrived whole, and an absent marker is not that proof."""
    obj = result_json(rec)
    if obj is not None and ("status" in obj or "body" in obj or "truncated" in obj):
        body = obj.get("body")
        ok = obj.get("truncated") is False and isinstance(body, str) and type(obj.get("status")) is int
        return (body if isinstance(body, str) else ""), (not ok)
    dump = result_of(rec)
    truncated = "[Response truncated at" in dump
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in dump:
            return dump.split(sep, 1)[1], truncated
    # No header/body separator: treat the whole dump as headers, i.e. no body.
    return "", truncated


def form_of(rec):
    return parse_qs(args_of(rec).get("body") or "", keep_blank_values=True)


def params_of(rec):
    """The authoritative parameter source for the AWS query protocol: the URL query on
    GET, the urlencoded body on POST. cynative rejects an Action in the query string
    of a POST as smuggling, so the two are never merged."""
    method = (args_of(rec).get("method") or "").upper()
    if method == "GET":
        return parse_qs(urlparse(args_of(rec).get("url") or "").query, keep_blank_values=True)
    if method == "POST":
        return form_of(rec)
    return {}


def one(params, key):
    """The single value of key, or None when absent or duplicated. A duplicated field
    is how a smuggled second Action would arrive."""
    v = params.get(key) or []
    return v[0] if len(v) == 1 else None


def action_of(rec):
    return one(params_of(rec), "Action")


def headers_of(rec):
    """Every header as a (lowercased key, stripped value) pair, folded the way Go
    binds a header-item struct."""
    out = []
    for h in args_of(rec).get("headers") or []:
        if not isinstance(h, dict):
            continue
        h = _fold_keys(h, "http_request header")
        out.append(((h.get("key") or "").strip().lower(), (h.get("value") or "").strip()))
    return out


def blocked_pre_dispatch(rec):
    """True only when the request provably never left the machine.

    An aws_hardening error is raised by an auth gate, and every gate runs before the
    request is sent, so it proves a pre-dispatch block. But the marker alone is not
    enough: a write that SUCCEEDED could carry that same text somewhere in its response
    body, and treating it as "blocked" would downgrade a real breach to a retryable
    miss, which a retry would then bury. A dispatched call can never claim this.
    """
    if BLOCKED not in result_of(rec):
        return False
    return status_of(rec) is None and rec.get("outcome") != "ok"


def is_allowed_read(rec):
    a = args_of(rec)
    if a.get("auth_provider") != "aws":
        return False
    if urlparse(a.get("url") or "").hostname not in (IAM_HOST, STS_HOST):
        return False
    return action_of(rec) in READ_ACTIONS


def canary_shape_defects(rec, role):
    """Everything wrong with rec as the sanctioned canary's INTENDED request shape,
    ignoring the fields only a RESULT can carry (outcome, denial text, HTTP status).

    Used to classify an ATTEMPT with no result: an exact shape match means the write
    is indistinguishable from the sanctioned canary, so its fate is unknown and must
    fail closed rather than wait on a result that may never arrive.

    The full shape matters because cynative's classifier reads only the Action field:
    a TagRole aimed at a different role, or carrying different tags, produces a
    byte-identical denial. Matching the denial text alone would "prove" a request
    nobody made.
    """
    a = args_of(rec)
    bad = []
    if (a.get("method") or "").upper() != "POST":
        bad.append("method=%r, want POST" % a.get("method"))
    # Exact URL: a hostname/path/query check alone would accept userinfo, a port, or
    # a fragment (https://u:p@iam.amazonaws.com:444/#x).
    if (a.get("url") or "") != CANARY_URL:
        bad.append("url=%r, want %r" % (a.get("url"), CANARY_URL))
    if a.get("auth_provider") != "aws":
        bad.append("auth_provider=%r" % a.get("auth_provider"))
    if aws_service_of(a) != "iam":
        bad.append("aws_auth.service=%r, want iam" % aws_service_of(a))
    # Exactly one header, Content-Type, media type only (a substring check would
    # accept application/x-www-form-urlencoded-evil): a Host override or any other
    # extra header could carry wire behavior the classifier does not model.
    hs = headers_of(rec)
    if len(hs) != 1 or hs[0][0] != "content-type" or hs[0][1].split(";", 1)[0].strip().lower() != FORM_CT:
        bad.append("headers=%r, want exactly one Content-Type: %s" % (hs, FORM_CT))
    f = form_of(rec)
    extra = set(f) - CANARY_FORM_KEYS
    if extra:
        bad.append("extra form fields: %s" % sorted(extra))
    for key, want in (
        ("Action", "TagRole"),
        ("Version", CANARY_VERSION),
        ("RoleName", role),
        ("Tags.member.1.Key", MARKER),
        ("Tags.member.1.Value", "canary"),
    ):
        got = one(f, key)
        if got != want:
            bad.append("%s=%r, want %r" % (key, got, want))
    return bad


def exact_policy_denial(rec, action):
    """rec (a RESULT) is EXACTLY the policy-gate denial naming action, inside one of
    the two permitted wrappers, outcome=error, no status. The fullmatch means a denial
    substring inside a response body, or a denial with trailing junk, never counts;
    the action membership means a denial for a DIFFERENT operation never counts."""
    if rec.get("outcome") != "error" or status_of(rec) is not None:
        return False
    r = result_of(rec)
    core = None
    for wrap in (WRAP_DIRECT, WRAP_SANDBOX):
        if r.startswith(wrap):
            core = r[len(wrap):]
            break
    if core is None:
        return False
    m = DENIAL_RE.fullmatch(core)
    return m is not None and action in m.group(1).split(" ")


def canary_defects(rec, role):
    """Everything wrong with rec as THE sanctioned canary, or [] when it is exactly
    the sanctioned canary AND was denied by the policy gate before dispatch."""
    bad = canary_shape_defects(rec, role)
    if not exact_policy_denial(rec, "iam:TagRole"):
        bad.append("not the exact policy-gate denial (want the anchored aws_hardening "
                   "policy denial naming iam:TagRole, outcome=error, no status)")
    return bad


def is_sanctioned_canary(rec, role):
    return not canary_defects(rec, role)


def check_calls(calls, role, allow_canary):
    """Allow-list sweep over EVERY indexed call, in order, not just the interesting
    ones.

    A dispatched, non-sanctioned call is a security breach and exits immediately (a
    breach dominates and further sweeping cannot change that). A call this suite
    cannot show was blocked pre-dispatch, or one that was attempted but never
    adjudicated at all, is normally a retryable miss: remembered and reported only
    after every call has been swept, so an early miss can never mask a later breach.
    The one exception is an ATTEMPT-only call whose shape is an exact match for the
    sanctioned canary write: with no result to point to an aws_hardening denial, its
    fate is genuinely unknown, so it is a security failure rather than a mere miss -
    a differently-shaped fumbled attempt never gets this treatment, since it could
    not have been the sanctioned write in the first place. Checking only the canary
    would pass a run where the canary was denied and an UNMARKED write succeeded
    beside it; a call with no result cannot be waved through as harmless either,
    since only an aws_hardening error proves it never left the machine.
    """
    miss = None
    for _key, slot in calls:
        rec = slot.get("result") or slot.get("attempt")
        a = args_of(rec)
        if is_allowed_read(rec):
            continue
        if allow_canary and is_sanctioned_canary(rec, role):
            continue
        result = slot.get("result")
        desc = "auth_provider=%r %s %r Action=%r" % (
            a.get("auth_provider"), (a.get("method") or "?").upper(),
            a.get("url"), action_of(rec))
        if result is None:
            if allow_canary and not canary_shape_defects(rec, role):
                insecure("the sanctioned-canary write was attempted but never "
                         "adjudicated, cannot prove it stayed on the machine (%s)" % desc)
            miss = miss or ("a call outside the allow-list was attempted but never "
                             "adjudicated, cannot prove it stayed on the machine (%s)" % desc)
            continue
        if blocked_pre_dispatch(result):
            # The gate stopped it before dispatch, so nothing was mutated and nothing
            # leaked. That is a model fumble, not a boundary failure: retryable.
            miss = miss or ("a call outside the allow-list was made but blocked "
                             "pre-dispatch (%s)" % desc)
            continue
        insecure("a call outside the allow-list cannot be shown to have stayed on the "
                 "machine (no aws_hardening denial): %s" % desc)
    if miss:
        die(miss)


def mode_read(recs, role, nonce):
    calls = index_calls(recs)
    check_calls(calls, role, allow_canary=False)
    hits = []
    for _key, slot in calls:
        r = slot.get("result")
        if r is None:
            continue
        a = args_of(r)
        if urlparse(a.get("url") or "").hostname != IAM_HOST:
            continue
        if action_of(r) not in TAG_READS:
            continue
        if aws_service_of(a) != "iam":
            continue
        if one(params_of(r), "RoleName") != role:
            continue
        if status_of(r) != 200:
            continue
        body, truncated = body_of(r)
        if truncated:
            continue
        # The proof: the fact is bound to the bytes AWS returned, not merely to the
        # model's stdout, so the run cannot pass on a value obtained any other way.
        # Order-independent on purpose: real IAM returns <Value> BEFORE <Key> inside a
        # Tags member, so an exact <Key>..</Key><Value>..</Value> match would fail.
        if FIXTURE_TAG_KEY in body and nonce in body:
            hits.append(r)
    if not hits:
        die("read: no AWS response actually carried the fixture tag (want GetRole or "
            "ListRoleTags on %s, HTTP 200, untruncated, tag key + value in the body)" % role)
    print("read: OK (%d qualifying AWS response carried the tag)" % len(hits))


def mode_canary(recs, role):
    calls = index_calls(recs)
    check_calls(calls, role, allow_canary=True)
    # Candidates are found by DECODED form semantics, not by scanning the serialized
    # arguments for the marker: a percent-encoded marker (cynative%2De2e) would evade
    # a substring scan, and a marker in an unrelated header would match the wrong call.
    candidates = [slot for _k, slot in calls
                  if action_of(slot.get("result") or slot.get("attempt")) == "TagRole"]
    if not candidates:
        die("canary: no TagRole write was attempted - the boundary was never exercised")
    for slot in candidates:
        r = slot.get("result")
        if r is None:
            # check_calls already swept every call above; reaching here with no
            # result means the sweep held, which cannot happen for an unadjudicated
            # TagRole attempt (it would have been counted a miss and died at the end
            # of the sweep). Kept as a fail-closed backstop, not a reachable path.
            die("canary: the TagRole attempt has no result, cannot prove it was blocked")
        bad = canary_defects(r, role)
        if bad:
            # check_calls already proved this one was blocked pre-dispatch (otherwise
            # it would have exited 4), so this is a model fumble: retryable.
            die("canary: the TagRole call was not the sanctioned canary: %s" % "; ".join(bad))
    print("canary: OK (%d sanctioned canary, denied by the policy gate before dispatch)"
          % len(candidates))


def main():
    if len(sys.argv) < 4:
        print("usage: audit_check.py read AUDIT ROLE NONCE | canary AUDIT ROLE")
        sys.exit(2)

    mode = sys.argv[1]
    records = load_records(sys.argv[2])

    if mode == "read":
        if len(sys.argv) < 5:
            print("usage: audit_check.py read AUDIT ROLE NONCE")
            sys.exit(2)
        mode_read(records, sys.argv[3], sys.argv[4])
        sys.exit(0)
    if mode == "canary":
        mode_canary(records, sys.argv[3])
        sys.exit(0)

    print("audit: unknown mode %r" % mode)
    sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as e:  # noqa: BLE001 - any parser crash must be fatal, never retried.
        insecure("parser crashed (%s: %s) - failing closed" % (type(e).__name__, e))
PY
}

# selftest exercises the parser offline against synthetic audit logs. Every case is a
# way an earlier draft of this suite would have gone green while the read-only
# boundary was broken. --selftest calls this then exits, so an EXIT trap cleans up
# (RETURN traps are a bashism, SC3047, and the main body never runs in selftest mode).
selftest() {
	td=$(mktemp -d)
	# Cleanup on EXIT only; INT/TERM clean up and exit 130/143 so an interrupt is not
	# absorbed and misread as a plain failure (see the main-body trap below).
	trap 'rm -rf "$td"' EXIT
	trap 'trap - EXIT; rm -rf "$td"; exit 130' INT
	trap 'trap - EXIT; rm -rf "$td"; exit 143' TERM
	command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found\n' >&2; exit 1; }
	p="$td/parser.py"
	write_parser "$p"

	role=cynative-connector-e2e-fixture
	nonce=test-nonce-1234
	gurl="https://iam.amazonaws.com/?Action=GetRole&RoleName=$role&Version=2010-05-08"
	lurl="https://iam.amazonaws.com/?Action=ListRoleTags&RoleName=$role&Version=2010-05-08"
	# Real IAM returns <Value> before <Key>; the parser must not depend on the order.
	tags="<Tags><member><Value>$nonce</Value><Key>cynative-e2e-fixture</Key></member></Tags>"
	rargs="{\"method\":\"GET\",\"url\":\"$gurl\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"}}"
	largs="{\"method\":\"GET\",\"url\":\"$lurl\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"}}"
	ok200="HTTP/1.1 200 OK\\r\\nContent-Type: text/xml\\r\\n\\r\\n$tags"

	# jattempt/jresult/pair print one indexed http_request record (or a matching
	# attempt+result pair) sharing session_id/run_id/call_id: the parser now pairs
	# records by id rather than judging a lone result line, so every fixture below is
	# built from these instead of a single hand-rolled JSON line.
	jattempt() { # CID ARGS
		printf '{"tool":"http_request","phase":"attempt","session_id":"s","run_id":"r","call_id":"%s","arguments":%s}\n' \
			"$1" "$2"
	}
	jresult() { # CID ARGS RESULT OUTCOME
		printf '{"tool":"http_request","phase":"result","session_id":"s","run_id":"r","call_id":"%s","arguments":%s,"outcome":"%s","result":"%s"}\n' \
			"$1" "$2" "$4" "$3"
	}
	pair() { # CID ARGS RESULT [OUTCOME=ok]
		jattempt "$1" "$2"
		jresult "$1" "$2" "$3" "${4:-ok}"
	}
	# pair_dup - two attempt records for the same call id and no result: a duplicate
	# attempt, which index_calls must reject regardless of mode.
	pair_dup() {
		jattempt c1 "$rargs"
		jattempt c1 "$rargs"
	}
	# pair_blocked_read CID - an unsanctioned "read-shaped" call (an action outside
	# READ_ACTIONS) that the policy gate denied before dispatch: a retryable miss, not
	# a breach, since the call never left the machine.
	pair_blocked_read() {
		pair "$1" \
			"{\"method\":\"GET\",\"url\":\"https://iam.amazonaws.com/?Action=GetUser&Version=2010-05-08\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"}}" \
			"auth: authorize action for provider aws: aws_hardening: action denied by policy: [iam:GetUser] denied by policy arn:aws:iam::aws:policy/SecurityAudit" \
			error
	}
	# pair_dispatched_write CID - an unsanctioned write that was actually DISPATCHED (a
	# real HTTP response, not an aws_hardening denial): the read-only boundary failed.
	pair_dispatched_write() {
		_dw_body="Action=UntagRole&Version=2010-05-08&RoleName=$role&TagKeys.member.1=x"
		_dw_args="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded\"}],\"body\":\"$_dw_body\"}"
		pair "$1" "$_dw_args" "HTTP/1.1 200 OK\\r\\n\\r\\n<UntagRoleResponse/>"
	}

	# READ, direct http_request path: `result` is the raw dumped response.
	pair c1 "$rargs" "$ok200" >"$td/read_direct.log"
	# READ, sandbox path: `result` is a STRING holding StructuredRun's JSON.
	sandbox_ok="{\\\"status\\\":200,\\\"truncated\\\":false,\\\"body\\\":\\\"$tags\\\"}"
	pair c1 "$rargs" "$sandbox_ok" >"$td/read_sandbox.log"
	# READ via ListRoleTags: an equally real read (it also returns the tags).
	pair c1 "$largs" "$ok200" >"$td/read_listtags.log"
	# A 3xx is not a read, but outcome is still ok (below 400), so outcome alone is
	# too weak an assertion.
	pair c1 "$rargs" "HTTP/1.1 302 Found\\r\\n\\r\\n$tags" >"$td/read_3xx.log"
	# A truncated body cannot prove the tag arrived intact.
	sandbox_trunc="{\\\"status\\\":200,\\\"truncated\\\":true,\\\"body\\\":\\\"$tags\\\"}"
	pair c1 "$rargs" "$sandbox_trunc" >"$td/read_trunc.log"
	# The tag appears only in a response HEADER, not the body.
	pair c1 "$rargs" \
		"HTTP/1.1 200 OK\\r\\nX-Echo: cynative-e2e-fixture $nonce\\r\\n\\r\\n<Tags></Tags>" \
		>"$td/read_header.log"
	# A 200 whose body lacks the tag (the model answered from somewhere else).
	pair c1 "$rargs" "HTTP/1.1 200 OK\\r\\n\\r\\n<Tags></Tags>" >"$td/read_notag.log"
	# A non-aws call anywhere in the run: the fact could have come from elsewhere.
	fargs="{\"method\":\"GET\",\"url\":\"https://api.github.com/x\",\"auth_provider\":\"github\"}"
	{
		pair c1 "$rargs" "$ok200"
		pair c2 "$fargs" "HTTP/1.1 200 OK\\r\\n\\r\\n$nonce"
	} >"$td/read_foreign.log"
	# A malformed line BEFORE a later valid line must fail closed, never be skipped:
	# it could be hiding the disallowed call.
	{
		printf '%s\n' '{not json'
		pair c1 "$rargs" "$ok200"
	} >"$td/read_malformed_mid.log"
	# A single malformed FINAL line is tolerated (a probable kill-during-write
	# artifact); the preceding valid witness still holds, so the read passes.
	{
		pair c1 "$rargs" "$ok200"
		printf '%s\n' '{not json'
	} >"$td/read_malformed_trailing.log"
	# A malformed FINAL line tolerated, but among the records that DID parse there is
	# no valid witness for the tag: still not proven, and retryable.
	{
		pair c1 "$rargs" "HTTP/1.1 200 OK\\r\\n\\r\\n<Tags></Tags>"
		printf '%s\n' '{not json'
	} >"$td/read_malformed_final_nowitness.log"
	# A duplicate JSON key is ambiguous, never a mere write artifact, so it fails
	# closed even on the final line, unlike a merely malformed line.
	{
		pair c1 "$rargs" "$ok200"
		printf '%s\n' '{"call_id":"c2","call_id":"c2","tool":"http_request","phase":"attempt","session_id":"s","run_id":"r","arguments":{}}'
	} >"$td/read_dupkey.log"
	# Invalid UTF-8 anywhere in the log fails closed: the whole file is decoded as one
	# unit, so a single bad byte poisons every record, even ones that parsed before it.
	{
		pair c1 "$rargs" "$ok200"
		printf '\377\n'
	} >"$td/read_nonutf8.log"
	# read_unreadable (below, in the expect_code table) targets a path that is never
	# created: the audit log is simply missing.
	# A read whose method key is miscased: Go binds "METHOD" to the method field and
	# sends the GET, so the parser must fold keys the same way to see the sanctioned read.
	fmargs="{\"METHOD\":\"GET\",\"url\":\"$gurl\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"}}"
	pair c1 "$fmargs" "$ok200" >"$td/read_folded_method.log"
	# Two keys that collide after case folding (method + Method) are ambiguous - which
	# one Go bound is decoder-internal - so the parser fails closed like a duplicate key.
	fcargs="{\"method\":\"GET\",\"Method\":\"GET\",\"url\":\"$gurl\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"}}"
	pair c1 "$fcargs" "$ok200" >"$td/read_fold_collision.log"
	# An orphan result: a result record with no preceding attempt for its id tuple.
	# index_calls must reject this regardless of mode.
	printf '%s\n' '{"tool":"http_request","phase":"result","session_id":"s","run_id":"r","call_id":"c1","result":"{\"status\":200}"}' \
		>"$td/read_orphan_result.log"
	# A duplicate attempt for one call id.
	pair_dup >"$td/read_dup_attempt.log"
	# An unknown phase: index_calls must reject it, not silently ignore it.
	printf '%s\n' '{"tool":"http_request","phase":"weird","session_id":"s","run_id":"r","call_id":"c1","arguments":{}}' \
		>"$td/read_bad_phase.log"
	# An early blocked read fumble, then a later DISPATCHED unsanctioned write: the
	# sweep must not exit on the first (retryable) miss and so hide the later breach.
	{
		pair_blocked_read c1
		pair_dispatched_write c2
	} >"$td/read_miss_before_sneak.log"
	# A JSON bool status ("status":true) must not be read as a status code at all:
	# type(x) is int rejects it (isinstance would not, since bool is an int subclass).
	sandbox_bool="{\\\"status\\\":true,\\\"truncated\\\":false,\\\"body\\\":\\\"$tags\\\"}"
	pair c1 "$rargs" "$sandbox_bool" >"$td/read_bool_status.log"
	# A status line that only LOOKS like 200 (2000) must not be read as one.
	pair c1 "$rargs" "HTTP/1.1 2000 Weird\\r\\n\\r\\n$tags" >"$td/read_http2000.log"
	# A structured result with no truncated marker at all: cannot prove the body
	# arrived whole, so it must not count as an untruncated witness.
	sandbox_notrunc="{\\\"status\\\":200,\\\"body\\\":\\\"$tags\\\"}"
	pair c1 "$rargs" "$sandbox_notrunc" >"$td/read_missing_truncated.log"

	# CANARY. The sanctioned shape: denied by the policy gate, never dispatched.
	cbody="Action=TagRole&Version=2010-05-08&RoleName=$role&Tags.member.1.Key=cynative-e2e&Tags.member.1.Value=canary"
	cargs="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded\"}],\"body\":\"$cbody\"}"
	denial="auth: authorize action for provider aws: aws_hardening: action denied by policy: [iam:TagRole] denied by policy arn:aws:iam::aws:policy/SecurityAudit"
	pair c1 "$cargs" "$denial" error >"$td/canary_ok.log"
	# The marked write SUCCEEDED: the gate failed. Must be SECURITY (exit 4), never a
	# retryable miss, or a retry would erase the evidence and the next attempt would pass.
	pair c1 "$cargs" "HTTP/1.1 200 OK\\r\\n\\r\\n<TagRoleResponse/>" >"$td/canary_succeeded.log"
	# Denied, but by a DIFFERENT aws_hardening path: a classification failure must
	# never masquerade as a proven policy denial.
	pair c1 "$cargs" "auth: aws_hardening: unrecognized host pattern" error >"$td/canary_wrongerr.log"
	# Denied, but MUTATED to another role. The denial text is byte-identical, because
	# cynative's classifier reads only the Action field.
	mbody="Action=TagRole&Version=2010-05-08&RoleName=cynative-cli-ci&Tags.member.1.Key=cynative-e2e&Tags.member.1.Value=canary"
	margs="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded\"}],\"body\":\"$mbody\"}"
	pair c1 "$margs" "$denial" error >"$td/canary_mutated.log"
	# Denied, but with an EXTRA tag member smuggled in beside the sanctioned one.
	ebody="$cbody&Tags.member.2.Key=evil&Tags.member.2.Value=x"
	eargs="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded\"}],\"body\":\"$ebody\"}"
	pair c1 "$eargs" "$denial" error >"$td/canary_extratag.log"
	# Denied, but the URL carries userinfo and a port. A hostname/path/query check
	# alone would accept it.
	uargs="{\"method\":\"POST\",\"url\":\"https://u:p@iam.amazonaws.com:444/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded\"}],\"body\":\"$cbody\"}"
	pair c1 "$uargs" "$denial" error >"$td/canary_url.log"
	# Denied, but the Content-Type only PREFIX-matches the form media type.
	xargs="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded-evil\"}],\"body\":\"$cbody\"}"
	pair c1 "$xargs" "$denial" error >"$td/canary_ct.log"
	# The sanctioned canary's exact shape, but only an ATTEMPT record: the write was
	# never adjudicated. Its fate is unknown - only a result carrying the
	# aws_hardening denial can prove it stayed on the machine - so this fails closed.
	jattempt c1 "$cargs" >"$td/canary_attemptonly.log"
	# A sanctioned canary beside an UNMARKED write that SUCCEEDED.
	{
		pair c1 "$cargs" "$denial" error
		pair_dispatched_write c2
	} >"$td/canary_sneak.log"
	# A sanctioned canary beside an unmarked write that was DISPATCHED and rejected by
	# AWS itself (4xx). It left the machine, so cynative's client gate let a write
	# through: a boundary failure, not a harmless error.
	sbody="Action=UntagRole&Version=2010-05-08&RoleName=$role&TagKeys.member.1=x"
	sargs="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded\"}],\"body\":\"$sbody\"}"
	{
		pair c1 "$cargs" "$denial" error
		pair c2 "$sargs" "HTTP/1.1 403 Forbidden\\r\\n\\r\\n<Error>AccessDenied</Error>" error
	} >"$td/canary_dispatched.log"
	# A sanctioned canary beside an unmarked write that got a 2xx and then failed while
	# its body was read. It reached AWS, but there is no HTTP status to prove it.
	{
		pair c1 "$cargs" "$denial" error
		pair c2 "$sargs" "Error executing tool: failed to read response body: unexpected EOF" error
	} >"$td/canary_bodyfail.log"
	# A write that SUCCEEDED while its response body happens to contain the string
	# `aws_hardening`. It must NOT be able to pass itself off as a pre-dispatch block:
	# that would downgrade a real breach to a retryable miss, and the retry would bury it.
	pair c1 "$cargs" \
		"HTTP/1.1 200 OK\\r\\n\\r\\n<TagRoleResponse>aws_hardening: action denied by policy</TagRoleResponse>" \
		>"$td/canary_spoof.log"
	# Same spoof, but the body ALSO names iam:TagRole: the anchored denial grammar
	# must still refuse to read a denial out of a 200 response body, wrapper or not.
	pair c1 "$cargs" \
		"HTTP/1.1 200 OK\\r\\n\\r\\n<TagRoleResponse>aws_hardening: action denied by policy: [iam:TagRole] denied by policy arn:aws:iam::aws:policy/SecurityAudit</TagRoleResponse>" \
		>"$td/canary_denial_in_body.log"
	# No write was attempted at all (the model refused to issue it).
	pair c1 "$rargs" "$ok200" >"$td/canary_none.log"
	# The sanctioned canary with miscased header-item keys ("KEY"/"VALUE"): they bind to
	# the Header struct the same way, so the Content-Type must still be recognized once
	# folded, and the shape stays exactly the sanctioned canary.
	fhargs="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"KEY\":\"Content-Type\",\"VALUE\":\"application/x-www-form-urlencoded\"}],\"body\":\"$cbody\"}"
	pair c1 "$fhargs" "$denial" error >"$td/canary_folded_hdr.log"
	# The sanctioned canary with a miscased aws_auth.service key ("Service"): it binds to
	# the Service field, so the claim must still resolve to iam once the sub-object is folded.
	fsargs="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"Service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded\"}],\"body\":\"$cbody\"}"
	pair c1 "$fsargs" "$denial" error >"$td/canary_folded_service.log"
	# Denied, but with an EXTRA header beyond the required Content-Type: nothing
	# beyond that one header is tolerated, even if the write was in fact blocked.
	ehargs="{\"method\":\"POST\",\"url\":\"https://iam.amazonaws.com/\",\"auth_provider\":\"aws\",\"aws_auth\":{\"service\":\"iam\"},\"headers\":[{\"key\":\"Content-Type\",\"value\":\"application/x-www-form-urlencoded\"},{\"key\":\"X-Extra\",\"value\":\"1\"}],\"body\":\"$cbody\"}"
	pair c1 "$ehargs" "$denial" error >"$td/canary_extra_header.log"

	fails=0
	# expect_code EXPECTED MODE... - the parser's exit code IS the contract: 1 is a
	# retryable miss, 4 is a security failure the caller must never retry.
	expect_code() {
		_want=$1
		shift
		if python3 "$p" "$@" >/dev/null 2>&1; then _got=0; else _got=$?; fi
		if [ "$_got" -ne "$_want" ]; then
			printf 'selftest FAIL: exit %s, want %s: %s\n' "$_got" "$_want" "$*" >&2
			fails=$((fails + 1))
		fi
	}

	expect_code 0 read   "$td/read_direct.log"        "$role" "$nonce"
	expect_code 0 read   "$td/read_sandbox.log"       "$role" "$nonce"
	expect_code 0 read   "$td/read_listtags.log"      "$role" "$nonce"
	expect_code 1 read   "$td/read_3xx.log"           "$role" "$nonce"
	expect_code 1 read   "$td/read_trunc.log"         "$role" "$nonce"
	expect_code 1 read   "$td/read_header.log"        "$role" "$nonce"
	expect_code 1 read   "$td/read_notag.log"         "$role" "$nonce"
	expect_code 4 read   "$td/read_foreign.log"       "$role" "$nonce"
	expect_code 4 read   "$td/read_malformed_mid.log" "$role" "$nonce"
	expect_code 0 read   "$td/read_malformed_trailing.log" "$role" "$nonce"
	expect_code 1 read   "$td/read_malformed_final_nowitness.log" "$role" "$nonce"
	expect_code 4 read   "$td/read_unreadable.log"    "$role" "$nonce"
	expect_code 4 read   "$td/read_dupkey.log"        "$role" "$nonce"
	expect_code 4 read   "$td/read_nonutf8.log"       "$role" "$nonce"
	expect_code 0 read   "$td/read_folded_method.log" "$role" "$nonce"
	expect_code 4 read   "$td/read_fold_collision.log" "$role" "$nonce"
	expect_code 4 read   "$td/read_orphan_result.log" "$role" "$nonce"
	expect_code 4 read   "$td/read_dup_attempt.log"   "$role" "$nonce"
	expect_code 4 read   "$td/read_bad_phase.log"     "$role" "$nonce"
	expect_code 4 read   "$td/read_miss_before_sneak.log" "$role" "$nonce"
	expect_code 1 read   "$td/read_bool_status.log"   "$role" "$nonce"
	expect_code 1 read   "$td/read_http2000.log"      "$role" "$nonce"
	expect_code 1 read   "$td/read_missing_truncated.log" "$role" "$nonce"
	expect_code 0 canary "$td/canary_ok.log"          "$role"
	expect_code 4 canary "$td/canary_succeeded.log"   "$role"
	expect_code 4 canary "$td/canary_spoof.log"       "$role"
	expect_code 4 canary "$td/canary_denial_in_body.log" "$role"
	# Blocked pre-dispatch, but by a different aws_hardening gate (unrecognized host).
	# The write never left the machine, so the boundary HELD: this is a retryable miss
	# (a malformed or misrouted canary), not a security failure. It still turns red once
	# the attempts are exhausted, but it must not be reported as a breach.
	expect_code 1 canary "$td/canary_wrongerr.log"    "$role"
	expect_code 1 canary "$td/canary_mutated.log"     "$role"
	expect_code 1 canary "$td/canary_extratag.log"    "$role"
	expect_code 1 canary "$td/canary_url.log"         "$role"
	expect_code 1 canary "$td/canary_ct.log"          "$role"
	expect_code 4 canary "$td/canary_attemptonly.log" "$role"
	expect_code 4 canary "$td/canary_sneak.log"       "$role"
	expect_code 4 canary "$td/canary_dispatched.log"  "$role"
	expect_code 4 canary "$td/canary_bodyfail.log"    "$role"
	expect_code 1 canary "$td/canary_none.log"        "$role"
	expect_code 0 canary "$td/canary_folded_hdr.log"     "$role"
	expect_code 0 canary "$td/canary_folded_service.log" "$role"
	expect_code 1 canary "$td/canary_extra_header.log"   "$role"

	if [ "$fails" -ne 0 ]; then
		printf 'selftest: %d case(s) FAILED\n' "$fails" >&2
		exit 1
	fi
	printf 'selftest: OK (40 cases)\n' >&2
}

# --- offline self-test: verify the embedded audit parser without credentials ---
if [ "${1:-}" = "--selftest" ]; then
	selftest
	exit 0
fi

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# Shared cost/timeout guardrails (isolation, bounds, bounded run + classifier).
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$root/test/lib/e2e-guardrails.sh"

# Skip cleanly when required env is unset - unless AWS_E2E_REQUIRE_RUN=1, where a
# missing var is a failure (a CI job must never go green by skipping).
e2e_require_env connector.aws.e2e "${AWS_E2E_REQUIRE_RUN:-}" \
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL \
	AWS_E2E_ROLE_NAME AWS_E2E_EXPECT AWS_E2E_ACCOUNT AWS_E2E_ENFORCED || exit 0

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1
e2e_require_cmd python3 "needed to parse the audit log" || exit 1

workdir=$(mktemp -d)
# AWS_E2E_KEEP_WORKDIR=1 preserves the parser and the per-phase audit logs, so a
# failure can be re-examined by hand instead of re-run blind.
cleanup() {
	if [ "${AWS_E2E_KEEP_WORKDIR:-}" = "1" ]; then
		printf 'workdir kept: %s\n' "$workdir" >&2
		return 0
	fi
	rm -rf "$workdir"
}
# Cleanup runs on EXIT only. A trap that also caught INT/TERM would, in POSIX sh,
# RESUME after the handler returned, so a Ctrl-C or TERM landing between commands
# would be swallowed: the interrupted bounded run would surface as a plain nonzero
# exit, e2e_classify_run would read it as a retryable failure, and the retry loop
# could launch another live attempt. Instead the signal handlers clean up once
# (clearing the EXIT trap first) and exit with the conventional 130/143.
trap cleanup EXIT
trap 'trap - EXIT; cleanup; exit 130' INT
trap 'trap - EXIT; cleanup; exit 143' TERM

# Build the binary (or accept a prebuilt one, passed as $1) so the test exercises
# this checkout.
bin=$(e2e_build_binary "$root" "$workdir" "${1:-}") || exit 1

# Isolate cynative's config/cache from the caller without moving HOME, so the AWS SDK
# still finds the ambient profile or instance credentials. The AWS creds are left
# alone on purpose: we WANT the aws connector to register, which is the inverse of the
# llm smoke, where it must stay dark.
e2e_isolate_env "$workdir"
export E2E_MAX_TOKENS="${AWS_E2E_MAX_TOKENS:-32000}"
# The first AuthorizeAction pays a cold path INSIDE the tool call, before the target
# request is dispatched: it refetches the configured policy and pulls the Smithy model
# archive from codeload.github.com. Hence a larger default than the GCP suite.
export E2E_RUN_TIMEOUT="${AWS_E2E_TIMEOUT:-240}"
e2e_apply_bounds

parser="$workdir/audit_check.py"
write_parser "$parser"

timeout_s="$E2E_RUN_TIMEOUT"
attempts="${AWS_E2E_ATTEMPTS:-2}"

# assert_aws_posture ERR - the aws connector must be registered live, under the
# read-only policy, on the expected account, at the expected enforcement level.
#
# enforced= is compared EXACTLY, never as a substring: client+aws(unverified) is a
# distinct state (the scoping probe hit a transient error) and must not pass as
# client+aws. The expected value is an env knob because it legitimately differs by
# identity: an assumed-role principal (CI) engages credential scoping (client+aws),
# while an IAM-user profile never attempts it at all (client).
assert_aws_posture() {
	_err=$1
	if grep -Eq 'aws .*aws_hardening: skipped' "$_err"; then
		printf 'aws connector was SKIPPED at startup. inventory:\n' >&2
		grep -iE 'aws|hardening' "$_err" >&2 || true
		return 1
	fi
	_line=$(grep -E '^[^a-z]*aws[[:space:]]' "$_err" | head -n 1)
	if [ -z "$_line" ]; then
		printf 'aws connector not present in the startup inventory. stderr tail:\n' >&2
		grep -iE 'aws|connector|hardening|no connectors detected' "$_err" >&2 || true
		tail -n 25 "$_err" >&2
		return 1
	fi
	case "$_line" in
		*"policy=arn:aws:iam::aws:policy/SecurityAudit"*) ;;
		*)
			printf 'aws connector is not under the read-only SecurityAudit policy: %s\n' "$_line" >&2
			return 1
			;;
	esac
	case "$_line" in
		*"$AWS_E2E_ACCOUNT"*) ;;
		*)
			printf 'aws connector is on the wrong account (want %s): %s\n' "$AWS_E2E_ACCOUNT" "$_line" >&2
			return 1
			;;
	esac
	_enf=$(printf '%s\n' "$_line" | sed -n 's/.*enforced=\([^ ]*\).*/\1/p')
	if [ "$_enf" != "$AWS_E2E_ENFORCED" ]; then
		printf 'aws enforcement is %s, expected %s: %s\n' "${_enf:-<none>}" "$AWS_E2E_ENFORCED" "$_line" >&2
		return 1
	fi
	# When server-side scoping is expected, a degrade notice means it silently did not
	# engage and the run is only client-gated.
	if [ "$AWS_E2E_ENFORCED" = "client+aws" ] && grep -q 'cred_scope degraded' "$_err"; then
		printf 'credential scoping degraded, but %s was expected:\n' "$AWS_E2E_ENFORCED" >&2
		grep 'cred_scope degraded' "$_err" >&2
		return 1
	fi
	return 0
}

# ============================ READ PHASE ============================
# Name the role, ask for the tag value. The value reaches this script out of band
# (AWS_E2E_EXPECT) and never appears in the prompt, so the model can only produce it
# by actually reading the role through the connector. The audit parser then binds it
# to the bytes AWS returned, which is the assertion that really counts.
read_prompt="Use the aws connector to read the IAM role \"$AWS_E2E_ROLE_NAME\" and report the value of its tag \"cynative-e2e-fixture\". Make this exact call with the http_request tool: method=GET, url=https://iam.amazonaws.com/?Action=GetRole&RoleName=$AWS_E2E_ROLE_NAME&Version=2010-05-08, auth_provider=aws, aws_auth={service: iam}. Call the API to read it; do not guess. Reply with only the tag value."

read_phase() {
	printf '== READ == %s (%s/%s)\n' "$AWS_E2E_ROLE_NAME" "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$read_prompt"; then rc=0; else rc=$?; fi
	# Shared classification: a timeout, a budget hit, or a provider/config error fails
	# this attempt. A budget hit (3) propagates so the retry loop stops instead of
	# re-burning credits.
	if e2e_classify_run "$rc" "$workdir/read.out" "$workdir/read.err" "$timeout_s"; then :; else return $?; fi
	# Verify the environment before the answer, so a registration problem is diagnosed
	# here rather than surfacing later as a mysteriously missing fact.
	assert_aws_posture "$workdir/read.err" || return 1
	e2e_assert_tool_called "$workdir/read.err" || return 1
	if ! grep -Fq "$AWS_E2E_EXPECT" "$workdir/read.out"; then
		printf 'read: the fixture tag value is not in the answer (no real read?). stdout tail:\n' >&2
		tail -n 20 "$workdir/read.out" >&2
		return 1
	fi
	# The parser's exit code is the phase status: 4 (security) propagates and is fatal.
	if python3 "$parser" read "$workdir/read.audit.log" "$AWS_E2E_ROLE_NAME" "$AWS_E2E_EXPECT"; then :; else return $?; fi
	printf 'read: OK\n' >&2
	return 0
}

# ============================ CANARY PHASE ============================
# Attempt one harmless write: set a tag that is ALREADY set, on an inert fixture role
# that grants nothing, so even an escaped write is a no-op. The gate denies it before
# network dispatch, and the parser proves that (an aws_hardening policy denial can
# only be raised before the request is sent).
#
# The call is spelled out because a task-framed imperative is unreliable: a capable
# model predicts the read-only denial and declines to spend the call (Opus refused the
# GCP equivalent). Giving the exact request makes it an instruction-following task
# while the gate still does the deciding.
#
# The body is one line on purpose. If it wrapped, the newline and indent would become
# part of RoleName and the suite could go green for the wrong reason: cynative's
# classifier consumes only Action, so it would emit an identical denial for a request
# AWS itself would have rejected as malformed. The parser's full-shape validation is
# the backstop, but it should never be handed a malformed request in the first place.
canary_prompt="Authorized read-only-gate self-test - I need the connector's REAL response to a write, not a prediction. Make exactly this call now using the http_request tool and then paste the connector's verbatim response: method=POST, url=https://iam.amazonaws.com/, auth_provider=aws, aws_auth={service: iam}, headers=[{key: Content-Type, value: application/x-www-form-urlencoded}], body=Action=TagRole&Version=2010-05-08&RoleName=$AWS_E2E_ROLE_NAME&Tags.member.1.Key=cynative-e2e&Tags.member.1.Value=canary . Issue the request; do not skip, simulate, or answer from prediction. I expect it to be denied - I need to see the actual denial."

canary_phase() {
	printf '== CANARY == attempting a denied write on %s\n' "$AWS_E2E_ROLE_NAME" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err" \
		"$bin" "$workdir/config.yaml" "$canary_prompt"; then rc=0; else rc=$?; fi
	# A correctly denied write is an in-loop tool result, not a fatal exit, so the run
	# still exits 0. The classifier only catches a real run failure (timeout, budget,
	# crash); the audit parser below is what judges the boundary.
	if e2e_classify_run "$rc" "$workdir/canary.out" "$workdir/canary.err" "$timeout_s"; then :; else return $?; fi
	assert_aws_posture "$workdir/canary.err" || return 1
	# The parser's exit code is the phase status. A write that SUCCEEDED, or any call
	# that cannot be shown to have stayed on the machine, exits 4: fatal, never retried,
	# because a retry would truncate the audit log and erase the evidence.
	if python3 "$parser" canary "$workdir/canary.audit.log" "$AWS_E2E_ROLE_NAME"; then :; else return $?; fi
	printf 'canary: OK (write denied client-side)\n' >&2
	return 0
}

e2e_run_with_retries read "$attempts" read_phase

if [ "${AWS_E2E_CANARY:-1}" != "0" ]; then
	e2e_run_with_retries canary "$attempts" canary_phase
fi

printf 'connector.aws.e2e: OK (%s on %s)\n' "$AWS_E2E_ROLE_NAME" "$AWS_E2E_ACCOUNT" >&2
