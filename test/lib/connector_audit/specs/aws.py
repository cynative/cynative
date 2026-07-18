#!/usr/bin/env python3
"""AWS connector e2e provider spec: the IAM/STS read family, the query-vs-form Action
decoder, the TagRole-write canary shape check, and the anchored policy-gate denial.

Ported verbatim from the pre-extraction embedded parser in
test/connector.aws.e2e.test.sh (cynative#152). The shared load/index/sweep machinery
this suite needed already lives in engine.py (ported from GCP, the strictest of the
three); this module supplies only the data and the pure predicate hooks
engine.ProviderSpec and engine.CanarySpec require."""
import json
import re
from urllib.parse import parse_qs

from connector_audit import engine

MARKER = "cynative-e2e"
FIXTURE_TAG_KEY = "cynative-e2e-fixture"
IAM_HOST = "iam.amazonaws.com"
STS_HOST = "sts.amazonaws.com"
CANARY_URL = "https://iam.amazonaws.com/"
CANARY_VERSION = "2010-05-08"
FORM_CT = "application/x-www-form-urlencoded"
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


def form_of(rec):
    return parse_qs(engine.args_of(rec).get("body") or "", keep_blank_values=True)


def params_of(rec):
    """The authoritative parameter source for the AWS query protocol: the URL query on
    GET, the urlencoded body on POST. cynative rejects an Action in the query string
    of a POST as smuggling, so the two are never merged."""
    a = engine.args_of(rec)
    method = (a.get("method") or "").upper()
    if method == "GET":
        return parse_qs(engine.parsed_url(a).query, keep_blank_values=True)
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


def aws_service_of(a):
    """args (already top-level fold-keyed by engine.args_of) may carry a nested
    aws_auth object whose OWN keys were never folded by args_of's shallow pass, so a
    miscased "SERVICE" would otherwise slip past. Re-fold aws_auth on its own."""
    g = a.get("aws_auth")
    return engine._fold_keys(g, "aws_auth").get("service") if isinstance(g, dict) else None


def sanctioned_read(rec, _target):
    """A read the model may legitimately make: an https call to IAM or STS, over the
    aws claim, decoding to one of the allow-listed read actions. Not role-scoped: any
    of these reads is fine regardless of which role/identity it names, mirroring the
    original suite (the narrower per-role, per-action witness proof lives in
    is_witness below)."""
    a = engine.args_of(rec)
    if a.get("auth_provider") != "aws":
        return False
    if engine.parsed_url(a).hostname not in (IAM_HOST, STS_HOST):
        return False
    return action_of(rec) in READ_ACTIONS


def blocked_pre_dispatch(rec):
    """rec (a RESULT) was provably never dispatched: an aws_hardening error is raised
    by an auth gate, and every gate runs before the request is sent - but the marker
    alone is not enough, since a write that SUCCEEDED could carry that same text
    somewhere in its response body. Requiring no recovered status and a non-ok
    outcome closes that gap."""
    if BLOCKED not in engine.result_of(rec):
        return False
    return engine.status_of(rec) is None and rec.get("outcome") != "ok"


def exact_policy_denial(rec, action):
    """rec (a RESULT) is EXACTLY the policy-gate denial naming action, inside one of
    the two permitted wrappers, outcome=error, no status. The fullmatch means a denial
    substring inside a response body, or a denial with trailing junk, never counts;
    the action membership means a denial for a DIFFERENT operation never counts."""
    if rec.get("outcome") != "error" or engine.status_of(rec) is not None:
        return False
    r = engine.result_of(rec)
    core = None
    for wrap in (WRAP_DIRECT, WRAP_SANDBOX):
        if r.startswith(wrap):
            core = r[len(wrap):]
            break
    if core is None:
        return False
    m = DENIAL_RE.fullmatch(core)
    return m is not None and action in m.group(1).split(" ")


def canary_shape_defects(rec, role):
    """Everything wrong with rec as the sanctioned canary's INTENDED request shape,
    ignoring the fields only a RESULT can carry (outcome, denial text, HTTP status).

    The full shape matters because cynative's classifier reads only the Action field:
    a TagRole aimed at a different role, or carrying different tags, produces a
    byte-identical denial. Matching the denial text alone would "prove" a request
    nobody made."""
    a = engine.args_of(rec)
    bad = []
    if (a.get("method") or "").upper() != "POST":
        bad.append("method=%r, want POST" % a.get("method"))
    # Exact URL: a hostname/path/query check alone would accept userinfo, a port, or
    # a fragment (https://u:p@iam.amazonaws.com:444/#x).
    if engine._str(a.get("url")) != CANARY_URL:
        bad.append("url=%r, want %r" % (a.get("url"), CANARY_URL))
    if a.get("auth_provider") != "aws":
        bad.append("auth_provider=%r" % a.get("auth_provider"))
    if aws_service_of(a) != "iam":
        bad.append("aws_auth.service=%r, want iam" % aws_service_of(a))
    # Exactly one header, Content-Type, media type only (a substring check would
    # accept application/x-www-form-urlencoded-evil): a Host override or any other
    # extra header could carry wire behavior the classifier does not model.
    hs = engine.headers_of(rec)
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


def canary_defects(rec, role):
    """Everything wrong with rec as THE sanctioned canary, or [] when it is exactly
    the sanctioned canary AND was denied by the policy gate before dispatch."""
    bad = canary_shape_defects(rec, role)
    if not exact_policy_denial(rec, "iam:TagRole"):
        bad.append("not the exact policy-gate denial (want the anchored aws_hardening "
                   "policy denial naming iam:TagRole, outcome=error, no status)")
    return bad


def is_canary_target(rec, _target):
    """A candidate for the TagRole canary, by decoded operation semantics (not a
    substring scan on the serialized arguments, which a percent-encoded marker could
    evade). Not role-scoped, mirroring the original suite: a TagRole aimed at the
    wrong role is still a candidate, and canary_defects is what flags the mismatch."""
    return action_of(rec) == "TagRole"


CANARY = engine.CanarySpec(
    mode="canary",
    label="canary",
    boundary="POST https://iam.amazonaws.com/ (Action=TagRole) write",
    is_target=is_canary_target,
    defects=canary_defects,
)


def is_witness(rec, target, expect):
    """rec already passed is_sanctioned_read (engine.run_read calls is_witness only for
    records that did). The remaining, narrower proof: an IAM tag-bearing read
    (ListRoles is excluded - AWS omits tags from it), scoped to the target role, an
    untruncated 200 whose body carries both the fixture tag key and expect (the tag
    value, fed out of band) - binding the fact to the bytes AWS returned. Order
    independent on purpose: real IAM returns <Value> before <Key> inside a Tags
    member."""
    a = engine.args_of(rec)
    if engine.parsed_url(a).hostname != IAM_HOST:
        return False
    if action_of(rec) not in TAG_READS:
        return False
    if aws_service_of(a) != "iam":
        return False
    if one(params_of(rec), "RoleName") != target:
        return False
    if engine.status_of(rec) != 200:
        return False
    body, truncated = engine.body_of(rec)
    if truncated:
        return False
    return FIXTURE_TAG_KEY in body and expect in body


# ---------------------------------------------------------------------------
# Selftest cases: every AWS case from the pre-extraction embedded parser's shell
# `selftest()`, verbatim (name, code, mode, lines, *rest). Replayed by
# engine._provider_selftest and pinned by name+code against testdata/aws.names.txt.
# ---------------------------------------------------------------------------


def _jline(cid, phase, args, **extra):
    r = {"session_id": "s", "run_id": "r", "call_id": cid, "tool": "http_request",
         "phase": phase, "arguments": args}
    r.update(extra)
    return json.dumps(r)


def _pair(cid, args, result, outcome="ok"):
    return [_jline(cid, "attempt", args),
            _jline(cid, "result", args, result=result, outcome=outcome)]


def _build_cases():
    role = "cynative-connector-e2e-fixture"
    nonce = "test-nonce-1234"
    gurl = "https://iam.amazonaws.com/?Action=GetRole&RoleName=%s&Version=2010-05-08" % role
    lurl = "https://iam.amazonaws.com/?Action=ListRoleTags&RoleName=%s&Version=2010-05-08" % role
    # Real IAM returns <Value> before <Key>; the parser must not depend on the order.
    tags = "<Tags><member><Value>%s</Value><Key>cynative-e2e-fixture</Key></member></Tags>" % nonce
    rargs = {"method": "GET", "url": gurl, "auth_provider": "aws", "aws_auth": {"service": "iam"}}
    largs = {"method": "GET", "url": lurl, "auth_provider": "aws", "aws_auth": {"service": "iam"}}
    ok200 = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n" + tags

    # A non-aws call anywhere in the run: the fact could have come from elsewhere.
    fargs = {"method": "GET", "url": "https://api.github.com/x", "auth_provider": "github"}

    # A read whose method key is miscased: Go binds "METHOD" to the method field and
    # sends the GET, so the parser must fold keys the same way to see the sanctioned
    # read.
    fmargs = {k: v for k, v in rargs.items() if k != "method"}
    fmargs["METHOD"] = "GET"
    # Two keys that collide after case folding (method + Method) are ambiguous - which
    # one Go bound is decoder-internal - so the parser fails closed like a duplicate
    # key.
    fcargs = {**rargs, "Method": "GET"}

    # An unsanctioned write that was actually DISPATCHED (a real HTTP response, not an
    # aws_hardening denial): the read-only boundary failed.
    dw_body = "Action=UntagRole&Version=2010-05-08&RoleName=%s&TagKeys.member.1=x" % role
    dw_args = {"method": "POST", "url": "https://iam.amazonaws.com/", "auth_provider": "aws",
               "aws_auth": {"service": "iam"},
               "headers": [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"}],
               "body": dw_body}
    dw_result = "HTTP/1.1 200 OK\r\n\r\n<UntagRoleResponse/>"

    # An unsanctioned "read-shaped" call (an action outside READ_ACTIONS) that the
    # policy gate denied before dispatch: a retryable miss, not a breach, since the
    # call never left the machine.
    blocked_read_args = {"method": "GET",
                         "url": "https://iam.amazonaws.com/?Action=GetUser&Version=2010-05-08",
                         "auth_provider": "aws", "aws_auth": {"service": "iam"}}
    blocked_read_denial = ("auth: authorize action for provider aws: aws_hardening: action denied "
                           "by policy: [iam:GetUser] denied by policy arn:aws:iam::aws:policy/SecurityAudit")

    # CANARY. The sanctioned shape: denied by the policy gate, never dispatched.
    cbody = ("Action=TagRole&Version=2010-05-08&RoleName=%s&Tags.member.1.Key=cynative-e2e"
             "&Tags.member.1.Value=canary" % role)
    cargs = {"method": "POST", "url": "https://iam.amazonaws.com/", "auth_provider": "aws",
             "aws_auth": {"service": "iam"},
             "headers": [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"}],
             "body": cbody}
    denial = ("auth: authorize action for provider aws: aws_hardening: action denied by policy: "
             "[iam:TagRole] denied by policy arn:aws:iam::aws:policy/SecurityAudit")

    # Denied, but MUTATED to another role. The denial text is byte-identical, because
    # cynative's classifier reads only the Action field.
    mbody = ("Action=TagRole&Version=2010-05-08&RoleName=cynative-cli-ci&Tags.member.1.Key=cynative-e2e"
             "&Tags.member.1.Value=canary")
    margs = {**cargs, "body": mbody}

    # Denied, but with an EXTRA tag member smuggled in beside the sanctioned one.
    ebody = cbody + "&Tags.member.2.Key=evil&Tags.member.2.Value=x"
    eargs = {**cargs, "body": ebody}

    # Denied, but the URL carries userinfo and a port. A hostname/path/query check
    # alone would accept it.
    uargs = {**cargs, "url": "https://u:p@iam.amazonaws.com:444/"}

    # Denied, but the Content-Type only PREFIX-matches the form media type.
    xargs = {**cargs, "headers": [{"key": "Content-Type", "value": "application/x-www-form-urlencoded-evil"}]}

    # The sanctioned canary with miscased header-item keys ("KEY"/"VALUE"): they bind
    # to the Header struct the same way, so the Content-Type must still be recognized
    # once folded, and the shape stays exactly the sanctioned canary.
    fhargs = {**cargs, "headers": [{"KEY": "Content-Type", "VALUE": "application/x-www-form-urlencoded"}]}
    # The sanctioned canary with a miscased aws_auth.service key ("Service"): it binds
    # to the Service field, so the claim must still resolve to iam once the
    # sub-object is folded.
    fsargs = {**cargs, "aws_auth": {"Service": "iam"}}
    # Denied, but with an EXTRA header beyond the required Content-Type: nothing
    # beyond that one header is tolerated, even if the write was in fact blocked.
    ehargs = {**cargs, "headers": [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"},
                                   {"key": "X-Extra", "value": "1"}]}

    # Invalid UTF-8 anywhere in the log fails closed: the whole file is decoded as one
    # unit, so a single bad byte poisons every record, even ones that parsed before it.
    nonutf8 = ("\n".join(_pair("c1", rargs, ok200)) + "\n").encode("utf-8") + b"\xff\n"

    return [
        # READ, direct http_request path: `result` is the raw dumped response.
        ("read_direct", 0, "read", _pair("c1", rargs, ok200), nonce),
        # READ, sandbox path: `result` is a STRING holding StructuredRun's JSON.
        ("read_sandbox", 0, "read", _pair("c1", rargs,
            json.dumps({"status": 200, "truncated": False, "body": tags})), nonce),
        # READ via ListRoleTags: an equally real read (it also returns the tags).
        ("read_listtags", 0, "read", _pair("c1", largs, ok200), nonce),
        # A 3xx is not a read, but outcome is still ok (below 400), so outcome alone
        # is too weak an assertion.
        ("read_3xx", 1, "read", _pair("c1", rargs, "HTTP/1.1 302 Found\r\n\r\n" + tags), nonce),
        # A truncated body cannot prove the tag arrived intact.
        ("read_trunc", 1, "read", _pair("c1", rargs,
            json.dumps({"status": 200, "truncated": True, "body": tags})), nonce),
        # The tag appears only in a response HEADER, not the body.
        ("read_header", 1, "read", _pair("c1", rargs,
            "HTTP/1.1 200 OK\r\nX-Echo: cynative-e2e-fixture " + nonce + "\r\n\r\n<Tags></Tags>"), nonce),
        # A 200 whose body lacks the tag (the model answered from somewhere else).
        ("read_notag", 1, "read", _pair("c1", rargs, "HTTP/1.1 200 OK\r\n\r\n<Tags></Tags>"), nonce),
        ("read_foreign", 4, "read", _pair("c1", rargs, ok200) +
            _pair("c2", fargs, "HTTP/1.1 200 OK\r\n\r\n" + nonce), nonce),
        # A malformed line BEFORE a later valid line must fail closed, never be
        # skipped: it could be hiding the disallowed call.
        ("read_malformed_mid", 4, "read", ["{not json"] + _pair("c1", rargs, ok200), nonce),
        # A single malformed FINAL line is tolerated (a probable kill-during-write
        # artifact); the preceding valid witness still holds, so the read passes.
        ("read_malformed_trailing", 0, "read", _pair("c1", rargs, ok200) + ["{not json"], nonce),
        # A malformed FINAL line tolerated, but among the records that DID parse
        # there is no valid witness for the tag: still not proven, and retryable.
        ("read_malformed_final_nowitness", 1, "read",
            _pair("c1", rargs, "HTTP/1.1 200 OK\r\n\r\n<Tags></Tags>") + ["{not json"], nonce),
        # The audit log itself is missing.
        ("read_unreadable", 4, "read", None, nonce),
        # A duplicate JSON key is ambiguous, never a mere write artifact, so it fails
        # closed even on the final line, unlike a merely malformed line.
        ("read_dupkey", 4, "read", _pair("c1", rargs, ok200) +
            ['{"call_id":"c2","call_id":"c2","tool":"http_request","phase":"attempt",'
             '"session_id":"s","run_id":"r","arguments":{}}'], nonce),
        ("read_nonutf8", 4, "read", nonutf8, nonce),
        ("read_folded_method", 0, "read", _pair("c1", fmargs, ok200), nonce),
        ("read_fold_collision", 4, "read", _pair("c1", fcargs, ok200), nonce),
        # An orphan result: a result record with no preceding attempt for its id
        # tuple. index_calls must reject this regardless of mode.
        ("read_orphan_result", 4, "read",
            [json.dumps({"tool": "http_request", "phase": "result", "session_id": "s",
                        "run_id": "r", "call_id": "c1", "result": json.dumps({"status": 200})})], nonce),
        # A duplicate attempt for one call id.
        ("read_dup_attempt", 4, "read", [_jline("c1", "attempt", rargs), _jline("c1", "attempt", rargs)], nonce),
        # An unknown phase: index_calls must reject it, not silently ignore it.
        ("read_bad_phase", 4, "read",
            [json.dumps({"tool": "http_request", "phase": "weird", "session_id": "s",
                        "run_id": "r", "call_id": "c1", "arguments": {}})], nonce),
        # An early blocked read fumble, then a later DISPATCHED unsanctioned write:
        # the sweep must not exit on the first (retryable) miss and so hide the later
        # breach.
        ("read_miss_before_sneak", 4, "read",
            _pair("c1", blocked_read_args, blocked_read_denial, outcome="error") +
            _pair("c2", dw_args, dw_result), nonce),
        # A JSON bool status ("status":true) must not be read as a status code at
        # all: type(x) is int rejects it (isinstance would not, since bool is an int
        # subclass).
        ("read_bool_status", 1, "read", _pair("c1", rargs,
            json.dumps({"status": True, "truncated": False, "body": tags})), nonce),
        # A status line that only LOOKS like 200 (2000) must not be read as one.
        ("read_http2000", 1, "read", _pair("c1", rargs, "HTTP/1.1 2000 Weird\r\n\r\n" + tags), nonce),
        # A structured result with no truncated marker at all: cannot prove the body
        # arrived whole, so it must not count as an untruncated witness.
        ("read_missing_truncated", 1, "read", _pair("c1", rargs,
            json.dumps({"status": 200, "body": tags})), nonce),
        ("canary_ok", 0, "canary", _pair("c1", cargs, denial, outcome="error")),
        # The marked write SUCCEEDED: the gate failed. Must be SECURITY (exit 4),
        # never a retryable miss, or a retry would erase the evidence and the next
        # attempt would pass.
        ("canary_succeeded", 4, "canary", _pair("c1", cargs, "HTTP/1.1 200 OK\r\n\r\n<TagRoleResponse/>")),
        # Denied, but by a DIFFERENT aws_hardening path: a classification failure
        # must never masquerade as a proven policy denial.
        ("canary_wrongerr", 1, "canary",
            _pair("c1", cargs, "auth: aws_hardening: unrecognized host pattern", outcome="error")),
        ("canary_mutated", 1, "canary", _pair("c1", margs, denial, outcome="error")),
        ("canary_extratag", 1, "canary", _pair("c1", eargs, denial, outcome="error")),
        ("canary_url", 1, "canary", _pair("c1", uargs, denial, outcome="error")),
        ("canary_ct", 1, "canary", _pair("c1", xargs, denial, outcome="error")),
        # The sanctioned canary's exact shape, but only an ATTEMPT record: the write
        # was never adjudicated. Its fate is unknown - only a result carrying the
        # aws_hardening denial can prove it stayed on the machine - so this fails
        # closed.
        ("canary_attemptonly", 4, "canary", [_jline("c1", "attempt", cargs)]),
        # A sanctioned canary beside an UNMARKED write that SUCCEEDED.
        ("canary_sneak", 4, "canary", _pair("c1", cargs, denial, outcome="error") +
            _pair("c2", dw_args, dw_result)),
        # A sanctioned canary beside an unmarked write that was DISPATCHED and
        # rejected by AWS itself (4xx). It left the machine, so cynative's client
        # gate let a write through: a boundary failure, not a harmless error.
        ("canary_dispatched", 4, "canary", _pair("c1", cargs, denial, outcome="error") +
            _pair("c2", dw_args, "HTTP/1.1 403 Forbidden\r\n\r\n<Error>AccessDenied</Error>", outcome="error")),
        # A sanctioned canary beside an unmarked write that got a 2xx and then failed
        # while its body was read. It reached AWS, but there is no HTTP status to
        # prove it.
        ("canary_bodyfail", 4, "canary", _pair("c1", cargs, denial, outcome="error") +
            _pair("c2", dw_args, "Error executing tool: failed to read response body: unexpected EOF",
                 outcome="error")),
        # A write that SUCCEEDED while its response body happens to contain the
        # string `aws_hardening`. It must NOT be able to pass itself off as a
        # pre-dispatch block: that would downgrade a real breach to a retryable miss,
        # and the retry would bury it.
        ("canary_spoof", 4, "canary", _pair("c1", cargs,
            "HTTP/1.1 200 OK\r\n\r\n<TagRoleResponse>aws_hardening: action denied by policy</TagRoleResponse>")),
        # Same spoof, but the body ALSO names iam:TagRole: the anchored denial
        # grammar must still refuse to read a denial out of a 200 response body,
        # wrapper or not.
        ("canary_denial_in_body", 4, "canary", _pair("c1", cargs,
            "HTTP/1.1 200 OK\r\n\r\n<TagRoleResponse>aws_hardening: action denied by policy: "
            "[iam:TagRole] denied by policy arn:aws:iam::aws:policy/SecurityAudit</TagRoleResponse>")),
        # No write was attempted at all (the model refused to issue it).
        ("canary_none", 1, "canary", _pair("c1", rargs, ok200)),
        ("canary_folded_hdr", 0, "canary", _pair("c1", fhargs, denial, outcome="error")),
        ("canary_folded_service", 0, "canary", _pair("c1", fsargs, denial, outcome="error")),
        ("canary_extra_header", 1, "canary", _pair("c1", ehargs, denial, outcome="error")),
    ]


SELFTEST_CASES = tuple(_build_cases())

SPEC = engine.ProviderSpec(
    name="aws",
    blocked_word=BLOCKED,
    read_mode="read",
    is_sanctioned_read=sanctioned_read,
    denial_matches=blocked_pre_dispatch,
    is_witness=is_witness,
    witness_hint=("read: no sanctioned aws response carried the fixture tag (want GetRole or "
                 "ListRoleTags on the role, HTTP 200, untruncated, the tag key and value in the "
                 "body) - retry"),
    canaries=(CANARY,),
    selftest_target="cynative-connector-e2e-fixture",
    selftest_cases=SELFTEST_CASES,
)
