#!/usr/bin/env python3
"""GitHub connector e2e provider spec: the private-repo read family, the exposure-ceiling
denial, and the two boundary canaries (a PATCH write, and a secret-scanning-alerts read
the exposure ceiling denies by default).

Ported verbatim from the pre-extraction embedded parser in
test/connector.github.e2e.test.sh (cynative#152). The shared load/index/sweep machinery
this suite needed already lives in engine.py (ported from GCP, the strictest of the three
suites); this module supplies only the data and the pure predicate hooks
engine.ProviderSpec and engine.CanarySpec require.

GitHub is the richest of the three: TWO canaries share one ProviderSpec (a write PATCH
and a secret-scanning-alerts read, each denied by the exposure ceiling before dispatch -
engine.ProviderSpec.canaries is already a tuple, so this needs no engine change beyond
listing both), and the read assertion carries a "public repo fails hard" rule on top of
the usual witness proof: if ANY sanctioned read observes the fixture repo as public, that
is itself a security failure, even when a separate, valid private witness is also
present. That rule lives in is_witness (engine.run_read calls it for every record that
already passed is_sanctioned_read): it calls engine.insecure(...) itself rather than
returning False, so one public sighting anywhere in the sweep is fatal regardless of
iteration order."""
import json

from connector_audit import engine

GITHUB_HOST = "api.github.com"
BLOCKED = "github_hardening"
WRAP_DIRECT = "Error executing tool: auth: authorize action for provider github: "
WRAP_SANDBOX = "auth: authorize action for provider github: "
WRITE_BODY = {"has_issues": False}


def sanctioned_read(rec, repo):
    """Exactly the sanctioned fixture read: GET the exact raw URL, github, no body, no
    query/fragment/userinfo/port, and NO request headers at all (GitHub honors a method
    override header, so a headered GET could be a write on the wire)."""
    a = engine.args_of(rec)
    u = engine.parsed_url(a)
    return (
        a.get("auth_provider") == "github"
        and (a.get("method") or "") == "GET"
        and engine._str(a.get("url")) == "https://api.github.com/repos/" + repo
        and not u.query and not u.fragment and not u.username and not u.password and u.port is None
        and not engine._str(a.get("body"))
        and not engine.headers_of(rec)
    )


def blocked_by_hardening(rec):
    """rec (a RESULT) was denied by some auth gate before dispatch: an exact wrapper
    prefix followed by github_hardening:, no recovered status, non-ok outcome. Proves
    nothing left the machine; does NOT prove WHICH gate fired."""
    if rec.get("outcome") == "ok" or engine.status_of(rec) is not None:
        return False
    r = engine.result_of(rec)
    for wrap in (WRAP_DIRECT, WRAP_SANDBOX):
        if r.startswith(wrap + BLOCKED + ":"):
            return True
    return False


def is_witness(rec, target, expect):
    """rec already passed is_sanctioned_read (engine.run_read calls is_witness only for
    records that did). First checks whether the fixture repo body is PUBLIC - that fails
    closed via engine.insecure(...) itself, so one public sighting anywhere in the sweep
    is fatal even when a separate, valid witness is also present (a public flip must
    never be hidden by a good record). Only then does it look for the actual witness
    shape: private, archived, issues disabled, an untruncated 200 whose description
    carries expect (the marker, fed out of band)."""
    if engine.status_of(rec) != 200:
        return False
    body, truncated = engine.body_of(rec)
    if truncated:
        return False
    try:
        doc = engine._loads(body)
    except ValueError:
        return False
    if not isinstance(doc, dict):
        return False
    if doc.get("full_name") == target and doc.get("private") is False:
        engine.insecure("read: the fixture repo is PUBLIC (private=false); a public 200 "
                         "cannot prove the connector injected the credential")
    desc = doc.get("description")
    return (doc.get("full_name") == target and doc.get("private") is True
            and doc.get("archived") is True and doc.get("has_issues") is False
            and isinstance(desc, str) and expect in desc)


def write_core(repo):
    return ('github_hardening: request exceeds configured exposure: '
            'PATCH /repos/%s needs write on "repos" (ceiling read)' % repo)


def secretscan_core(repo):
    return ('github_hardening: request exceeds configured exposure: '
            'GET /repos/%s/secret-scanning/alerts needs read on "secret-scanning" '
            '(ceiling none)' % repo)


def canary_url(repo, path):
    return "https://%s/repos/%s%s" % (GITHUB_HOST, repo, path)


def exact_ceiling_denial(rec, core):
    """rec (a RESULT) is EXACTLY the exposure-ceiling denial for core, inside one of the
    two permitted wrappers, outcome=error, no status. Exact equality: a denial substring
    inside a 200 body can never satisfy this."""
    if rec.get("outcome") != "error" or engine.status_of(rec) is not None:
        return False
    r = engine.result_of(rec)
    return r == WRAP_DIRECT + core or r == WRAP_SANDBOX + core


def _is_canary_target(rec, repo, method, path):
    a = engine.args_of(rec)
    u = engine.parsed_url(a)
    return ((a.get("method") or "") == method and u.hostname == GITHUB_HOST
             and u.path == "/repos/" + repo + path)


def _canary_defects(rec, repo, core, method, path, body_obj):
    """Everything wrong with rec as THE sanctioned canary, or [] when it is exactly the
    sanctioned request shape AND was denied by the exposure ceiling before dispatch. The
    full shape matters: cynative's classifier reads only method+path, so a request aimed
    elsewhere, or carrying a different body/headers, produces the SAME denial text -
    matching the denial alone would "prove" a request nobody made."""
    a = engine.args_of(rec)
    url = canary_url(repo, path)
    bad = []
    if (a.get("method") or "") != method:
        bad.append("method=%r, want %s" % (a.get("method"), method))
    if engine._str(a.get("url")) != url:
        bad.append("url=%r, want %r" % (a.get("url"), url))
    if a.get("auth_provider") != "github":
        bad.append("auth_provider=%r" % a.get("auth_provider"))
    hs = engine.headers_of(rec)
    if body_obj is not None:
        # Exactly one header, Content-Type: application/json. No Host, no Authorization,
        # no extras: an Authorization header would still get the exact ceiling denial
        # (AuthorizeAction precedes credential rejection), so the shape must be exact.
        if (len(hs) != 1 or hs[0][0] != "content-type"
                or hs[0][1].split(";", 1)[0].strip().lower() != "application/json"):
            bad.append("headers=%r, want exactly one Content-Type: application/json" % hs)
        try:
            got = engine._loads(engine._str(a.get("body")) or "null")
        except ValueError:
            got = None
        if not engine.type_strict_eq(got, body_obj):
            bad.append("body=%r, want %r (type-strict)" % (a.get("body"), body_obj))
    else:
        if hs:
            bad.append("unexpected headers %r, want none" % hs)
        if engine._str(a.get("body")):
            bad.append("unexpected body %r" % a.get("body"))
    if not exact_ceiling_denial(rec, core):
        bad.append("not the exact exposure denial (want %r, outcome=error, no status)" % core)
    return bad


def _write_is_target(rec, repo):
    return _is_canary_target(rec, repo, "PATCH", "")


def _write_defects(rec, repo):
    return _canary_defects(rec, repo, write_core(repo), "PATCH", "", WRITE_BODY)


def _secretscan_is_target(rec, repo):
    return _is_canary_target(rec, repo, "GET", "/secret-scanning/alerts")


def _secretscan_defects(rec, repo):
    return _canary_defects(rec, repo, secretscan_core(repo), "GET", "/secret-scanning/alerts", None)


CANARY_WRITE = engine.CanarySpec(
    mode="canary",
    label="canary",
    boundary="PATCH /repos/<repo> write",
    is_target=_write_is_target,
    defects=_write_defects,
)

CANARY_SECRETSCAN = engine.CanarySpec(
    mode="secretscan",
    label="secretscan",
    boundary="GET /repos/<repo>/secret-scanning/alerts read",
    is_target=_secretscan_is_target,
    defects=_secretscan_defects,
)


# ---------------------------------------------------------------------------
# Selftest cases: every GitHub case from the pre-extraction embedded parser's `_selftest`,
# verbatim (name, code, mode, lines, *rest). Replayed by engine._provider_selftest and
# pinned by name+code against testdata/github.names.txt.
# ---------------------------------------------------------------------------


def _jline(cid, phase, args, **extra):
    r = {"session_id": "s", "run_id": "r", "call_id": cid, "tool": "http_request",
         "phase": phase, "arguments": args}
    r.update(extra)
    return json.dumps(r)


def _sres(status, body, truncated=False):
    return json.dumps({"status": status, "statusText": str(status), "headers": [],
                       "body": body, "truncated": truncated})


def _pair(cid, args, result, outcome="ok"):
    return [_jline(cid, "attempt", args),
            _jline(cid, "result", args, result=result, outcome=outcome, decision="approved")]


def _build_cases():
    repo = "cynative/connector-e2e-fixture"
    mark = "driftwood-harbor-1731"
    url = "https://api.github.com/repos/" + repo
    ss_url = url + "/secret-scanning/alerts"

    read_args = {"method": "GET", "url": url, "auth_provider": "github"}
    ok_body = json.dumps({"full_name": repo, "private": True, "archived": True,
                          "has_issues": False, "description": "fixture - " + mark})
    write_args = {"method": "PATCH", "url": url, "auth_provider": "github",
                  "headers": [{"key": "Content-Type", "value": "application/json"}],
                  "body": '{"has_issues":false}'}
    wdenial = WRAP_DIRECT + write_core(repo)
    ss_args = {"method": "GET", "url": ss_url, "auth_provider": "github"}
    ssdenial = WRAP_DIRECT + secretscan_core(repo)

    return [
        ("read_ok", 0, "read", _pair("c1", read_args, _sres(200, ok_body)), mark),
        ("read_public", 4, "read", _pair("c1", read_args, _sres(200, json.dumps(
            {"full_name": repo, "private": False, "archived": True, "has_issues": False,
             "description": "x " + mark}))), mark),
        ("read_3xx", 1, "read", _pair("c1", read_args, _sres(302, "")), mark),
        ("read_trunc", 1, "read", _pair("c1", read_args, _sres(200, ok_body, truncated=True)), mark),
        ("read_foreign", 4, "read", _pair("c1", {"method": "GET", "url": "https://gitlab.com/api/v4/x",
                                                  "auth_provider": "gitlab"}, _sres(200, "{}")), mark),
        ("read_direct_ok", 0, "read", _pair("c1", read_args,
            "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + ok_body), mark),
        # A miscased headers key: Go binds "HEADERS" to the headers field and sends
        # them on the wire, so the parser must fold keys the same way or a smuggled
        # method-override on a "headerless" 200 read would pass the sweep.
        ("read_folded_headers", 4, "read", _pair("c1", {**read_args, "HEADERS":
            [{"key": "X-HTTP-Method-Override", "value": "PATCH"}]},
            _sres(200, ok_body)), mark),
        # Keys that collide after case folding are ambiguous (which one Go bound is
        # decoder-internal): fail closed like a duplicate key.
        ("read_fold_collision", 4, "read", _pair("c1", {**read_args, "Method": "GET"},
            _sres(200, ok_body)), mark),
        ("read_malformed_mid", 4, "read", ["{bad json", _jline("c1", "attempt", read_args)], mark),
        ("read_malformed_trailing", 0, "read", _pair("c1", read_args, _sres(200, ok_body)) + ["{partial"], mark),
        ("read_attemptonly", 1, "read", [_jline("c1", "attempt", read_args)], mark),
        ("read_orphan", 4, "read",
            [_jline("c1", "result", read_args, result=_sres(200, ok_body), outcome="ok")], mark),
        ("read_dup_result", 4, "read", _pair("c1", read_args, _sres(200, ok_body)) +
            [_jline("c1", "result", read_args, result=_sres(200, ok_body), outcome="ok")], mark),
        ("read_no_truncated", 1, "read",
            _pair("c1", read_args, json.dumps({"status": 200, "body": ok_body})), mark),
        ("read_nondict_args", 4, "read",
            ['{"session_id":"s","run_id":"r","call_id":"c1","tool":"http_request",'
             '"phase":"attempt","arguments":"x"}'], mark),
        ("index_unknown_phase", 4, "read", [_jline("c1", "attempt", read_args),
            _jline("c1", "weird", read_args, result=_sres(200, ok_body), outcome="ok")], mark),
        ("index_tuple_mismatch", 4, "read", [_jline("c1", "attempt", read_args),
            _jline("c1", "result", write_args, result=_sres(200, "{}"), outcome="ok")], mark),
        # A bool/int type collision between attempt and result args must NOT pass as
        # equal (False == 0 in plain Python); type-strict pairing makes it a breach.
        ("index_type_collision", 4, "read", [
            _jline("c1", "attempt", {**read_args, "timeout_seconds": False}),
            _jline("c1", "result", {**read_args, "timeout_seconds": 0},
                  result=_sres(200, ok_body), outcome="ok")], mark),
        ("dupkey_final", 4, "read", _pair("c1", read_args, _sres(200, ok_body)) +
            ['{"call_id":"c2","call_id":"c2","tool":"http_request","phase":"attempt",'
             '"session_id":"s","run_id":"r","arguments":{}}'], mark),
        ("canary_ok", 0, "canary", _pair("c1", write_args, wdenial, outcome="error")),
        # The marked write SUCCEEDED: the gate failed. Never retryable.
        ("canary_succeeded", 4, "canary", _pair("c1", write_args, _sres(200, "{}"))),
        # The denial text inside a 200 body must never pass itself off as a denial.
        ("canary_spoof", 4, "canary", _pair("c1", write_args, _sres(200, wdenial))),
        # Denied, but by a DIFFERENT github_hardening path: a classification failure
        # must never masquerade as a proven exposure denial.
        ("canary_wrongerr", 1, "canary", _pair("c1", write_args,
            WRAP_DIRECT + "github_hardening: cannot classify request", outcome="error")),
        # A miscased method key still IS the sanctioned canary once folded the way Go
        # decodes it (the wire saw a PATCH; the denial is the exposure ceiling's).
        ("canary_folded_method", 0, "canary", _pair("c1",
            {**{k: v for k, v in write_args.items() if k != "method"}, "Method": "PATCH"},
            wdenial, outcome="error")),
        # Miscased header-item keys ("KEY"/"VALUE") bind to the Header struct the same
        # way, so the sanctioned Content-Type must still be recognized once folded.
        ("canary_folded_hdr", 0, "canary", _pair("c1", {**write_args, "headers":
            [{"KEY": "Content-Type", "VALUE": "application/json"}]}, wdenial, outcome="error")),
        ("canary_ct", 1, "canary", _pair("c1", {**write_args, "headers":
            [{"key": "Content-Type", "value": "text/plain"}]}, wdenial, outcome="error")),
        ("canary_mutated", 1, "canary",
            _pair("c1", {**write_args, "body": '{"has_issues":true}'}, wdenial, outcome="error")),
        ("canary_intbody", 1, "canary",
            _pair("c1", {**write_args, "body": '{"has_issues":0}'}, wdenial, outcome="error")),
        # An Authorization header still gets the exact ceiling denial (AuthorizeAction
        # precedes credential rejection), but the sanctioned canary shape allows none.
        ("canary_authhdr", 1, "canary", _pair("c1", {**write_args, "headers":
            [{"key": "Content-Type", "value": "application/json"}, {"key": "Authorization", "value": "Bearer x"}]},
            wdenial, outcome="error")),
        # The write was attempted but never adjudicated: cannot prove it was blocked.
        ("canary_attemptonly", 4, "canary", [_jline("c1", "attempt", write_args)]),
        # The write was DISPATCHED and rejected by GitHub itself: it left the machine.
        ("canary_dispatched", 4, "canary",
            _pair("c1", write_args, "HTTP/2.0 403 Forbidden\r\n\r\n{}", outcome="error")),
        # A sanctioned canary beside an unmarked write that SUCCEEDED.
        ("canary_sneak", 4, "canary", _pair("c1", write_args, wdenial, outcome="error") +
            _pair("c2", {"method": "PUT", "url": url + "/topics", "auth_provider": "github", "body": "{}"},
                  _sres(200, "{}"))),
        # An early miss must not hide a later breach: the sweep sees every slot.
        ("miss_before_sneak", 4, "canary", _pair("cA", write_args,
            WRAP_DIRECT + "github_hardening: cannot classify request", outcome="error") +
            _pair("cB", {"method": "PUT", "url": url + "/topics", "auth_provider": "github", "body": "{}"},
                  _sres(200, "{}"))),
        ("foreign_attemptonly", 4, "canary", [_jline("c1", "attempt",
            {"method": "PATCH", "url": "https://gitlab.com/x", "auth_provider": "gitlab"})] +
            _pair("c2", write_args, wdenial, outcome="error")),
        ("secretscan_ok", 0, "secretscan", _pair("c1", ss_args, ssdenial, outcome="error")),
        # The marked secret-scanning read SUCCEEDED: the gate failed. Never retryable.
        ("secretscan_succeeded", 4, "secretscan", _pair("c1", ss_args, _sres(200, "[]"))),
        # The read was attempted but never adjudicated: cannot prove it was blocked.
        ("secretscan_attemptonly", 4, "secretscan", [_jline("c1", "attempt", ss_args)]),
        # An extra header on the sanctioned-shape read is not tolerated (the read canary
        # carries no headers at all).
        ("secretscan_hdr", 1, "secretscan", _pair("c1", {**ss_args, "headers":
            [{"key": "X-Foo", "value": "bar"}]}, ssdenial, outcome="error")),
        # A status line that only LOOKS like a status must not be read as one.
        ("status_boundary", 4, "secretscan", _pair("c1", ss_args, "HTTP/1.1 2000 Weird\r\n\r\n{}", outcome="error")),
    ]


SELFTEST_CASES = tuple(_build_cases())

SPEC = engine.ProviderSpec(
    name="github",
    blocked_word=BLOCKED,
    read_mode="read",
    is_sanctioned_read=sanctioned_read,
    denial_matches=blocked_by_hardening,
    is_witness=is_witness,
    witness_hint=("read: no sanctioned github 200 response carried the private fixture "
                  "marker (want GET https://api.github.com/repos/<repo>, HTTP 200, "
                  "untruncated, private+archived body with the marker in description) - retry"),
    canaries=(CANARY_WRITE, CANARY_SECRETSCAN),
    selftest_target="cynative/connector-e2e-fixture",
    selftest_cases=SELFTEST_CASES,
)
