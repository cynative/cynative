#!/usr/bin/env python3
"""GCP connector e2e provider spec: the Cloud Resource Manager read family, the
allow-list-role policy denial, and the single PATCH ?updateMask=labels canary.

Ported verbatim from the pre-extraction embedded parser in
test/connector.gcp.e2e.test.sh (cynative#152). GCP is the strictest of the three
suites, so the sweep/index/load machinery it needed now lives in engine.py; this
module supplies only the data and the pure predicate hooks engine.ProviderSpec and
engine.CanarySpec require."""
import json
import re

from connector_audit import engine

CRM_HOST = "cloudresourcemanager.googleapis.com"
SERVICE = "cloudresourcemanager"
ROLE = "roles/viewer"
CANARY_PERM = "resourcemanager.projects.update"
CANARY_BODY = {"labels": {"cynative-e2e": "canary"}}
BLOCKED = "gcp_hardening"
WRAP_DIRECT = "Error executing tool: auth: authorize action for provider gcp: "
WRAP_SANDBOX = "auth: authorize action for provider gcp: "
# The policy-gate denial (internal/auth/gcp ErrPermissionDenied):
#   gcp_hardening: permission not in allow-list role(s): [<perms>] not granted by role <role>
# The bracketed list is Go's %v of a sorted []string and has a live component (the
# iam-dataset write union), so the match is structural rather than byte-exact: the
# fullmatch pins the gate's exact prefix and suffix, and the canary check then
# requires the operation's own permission to be IN the list. Any other gcp_hardening
# error is a DIFFERENT gate (host pinning, claim mismatch, classifier miss) and
# proves nothing about the policy gate under test.
DENIAL_RE = re.compile(
    r"gcp_hardening: permission not in allow-list role\(s\): "
    r"\[([^][]*)\] not granted by role " + re.escape(ROLE)
)
# A pre-dispatch block can be raised by TWO gates with distinct wrappers: the action
# gate (auth: authorize action for provider gcp: ...) and the host gate (auth:
# authorize host "<host>" for provider gcp: ...). Both run before httpClient.Do.
# Anchored at the start of the result so denial text inside a response body can
# never match; the policy denial itself (DENIAL_RE) can only come from the action
# gate, so exact_policy_denial keeps the narrower wrapper set.
BLOCK_RE = re.compile(
    r"(?:Error executing tool: )?auth: authorize "
    r"(?:action for provider gcp|host \"[^\"]*\" for provider gcp): "
    + re.escape(BLOCKED) + ":")

READ_PATHS_FMT = ("/v1/projects/%s", "/v3/projects/%s", "/v1/projects", "/v3/projects",
                  "/v3/projects:search")


def gcp_service_of(args):
    """args (already top-level fold-keyed by engine.args_of) may carry a nested
    gcp_auth object whose OWN keys were never folded by args_of's shallow pass, so a
    miscased "SERVICE" would otherwise slip past. Re-fold gcp_auth on its own."""
    g = args.get("gcp_auth")
    return engine._fold_keys(g, "gcp_auth").get("service") if isinstance(g, dict) else None


def sanctioned_read(rec, project):
    """A read the model may legitimately make: an https GET to Cloud Resource Manager
    under the cloudresourcemanager claim, no body, NO request headers at all (Google
    honors X-HTTP-Method-Override, so a headered GET could be a write on the wire),
    no userinfo/port/fragment, and a path in the known read family - the fixture
    project's direct get (v1/v3) or a list/search (project id in the query). The
    prompt pins the v1 direct get; the family absorbs a model that reads another
    valid way without opening anything beyond CRM project reads."""
    a = engine.args_of(rec)
    u = engine.parsed_url(a)
    paths = tuple(p % project if "%s" in p else p for p in READ_PATHS_FMT)
    return (
        a.get("auth_provider") == "gcp"
        and gcp_service_of(a) == SERVICE
        and (a.get("method") or "").upper() == "GET"
        and u.scheme == "https" and u.hostname == CRM_HOST
        and not u.fragment and not u.username and not u.password and u.port is None
        and u.path in paths
        and not engine._str(a.get("body"))
        and not engine.headers_of(rec)
    )


def blocked_by_hardening(rec):
    """rec (a RESULT) was denied by some auth gate before dispatch: a known wrapper
    prefix followed by gcp_hardening:, no recovered status, non-ok outcome. Proves
    nothing left the machine; does NOT prove WHICH gate fired."""
    if rec.get("outcome") == "ok" or engine.status_of(rec) is not None:
        return False
    return BLOCK_RE.match(engine.result_of(rec)) is not None


def exact_policy_denial(rec, perm):
    """rec (a RESULT) is EXACTLY the allow-list-role policy denial naming perm, inside
    one of the two permitted wrappers, outcome=error, no status. The fullmatch means a
    denial substring inside a 200 body, or a denial with trailing junk, never counts;
    the perm membership means a denial for a DIFFERENT operation never counts."""
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
    return m is not None and perm in m.group(1).split(" ")


def is_witness(rec, target, expect):
    """rec already passed is_sanctioned_read (engine.run_read calls is_witness only for
    records that did). The remaining proof: the target project appears in the request
    URL (a list/search read must have filtered on it, not just landed in the read
    family), the response is an untruncated 200, and expect (the project number, fed
    out of band) is in the body - binding the number to the bytes Google returned."""
    if target not in engine._str(engine.args_of(rec).get("url")):
        return False
    if engine.status_of(rec) != 200:
        return False
    body, truncated = engine.body_of(rec)
    if truncated:
        return False
    return expect in body


def canary_url(project):
    return "https://%s/v3/projects/%s?updateMask=labels" % (CRM_HOST, project)


def is_canary_target(rec, project):
    a = engine.args_of(rec)
    u = engine.parsed_url(a)
    return ((a.get("method") or "").upper() == "PATCH" and u.hostname == CRM_HOST
             and u.path == "/v3/projects/" + project)


def canary_defects(rec, project):
    """Everything wrong with rec as THE sanctioned canary, or [] when it is exactly
    the sanctioned canary AND was denied by the policy gate before dispatch. The full
    shape matters: the policy gate classifies the operation, not its target labels,
    so a PATCH carrying a different body produces the same denial text, and matching
    the denial alone would "prove" a request nobody made."""
    a = engine.args_of(rec)
    bad = []
    if (a.get("method") or "").upper() != "PATCH":
        bad.append("method=%r, want PATCH" % a.get("method"))
    # Exact URL: a hostname/path check alone would accept userinfo, a port, a fragment,
    # or an extra query parameter (https://u:p@host:444/...?updateMask=labels&x=y).
    if engine._str(a.get("url")) != canary_url(project):
        bad.append("url=%r, want %r" % (a.get("url"), canary_url(project)))
    if a.get("auth_provider") != "gcp":
        bad.append("auth_provider=%r" % a.get("auth_provider"))
    if gcp_service_of(a) != SERVICE:
        bad.append("gcp_auth.service=%r, want %s" % (gcp_service_of(a), SERVICE))
    # The prompt names no headers, but models add a Content-Type for a JSON PATCH on
    # their own; tolerate exactly that one, nothing else (no Host override, no
    # Authorization, no method-override).
    hs = engine.headers_of(rec)
    if hs and (len(hs) != 1 or hs[0][0] != "content-type"
               or hs[0][1].split(";", 1)[0].strip().lower() != "application/json"):
        bad.append("headers=%r, want none or exactly one Content-Type: application/json" % hs)
    try:
        got = engine._loads(engine._str(a.get("body")) or "null")
    except ValueError:
        got = None
    if not engine.type_strict_eq(got, CANARY_BODY):
        bad.append("body=%r, want %r (type-strict)" % (a.get("body"), CANARY_BODY))
    if not exact_policy_denial(rec, CANARY_PERM):
        bad.append("not the exact policy-gate denial (want the allow-list-role denial "
                   "naming %s, outcome=error, no status)" % CANARY_PERM)
    return bad


CANARY = engine.CanarySpec(
    mode="canary",
    label="canary",
    boundary="PATCH .../v3/projects/<project>?updateMask=labels write",
    is_target=is_canary_target,
    defects=canary_defects,
)


# ---------------------------------------------------------------------------
# Selftest cases: every GCP case from the pre-extraction embedded parser, verbatim
# (name, code, mode, lines, *rest). Replayed by engine._provider_selftest and pinned
# by name+code against testdata/gcp.names.txt.
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
    project = "demo-proj"
    number = "123456789012"
    gurl = "https://cloudresourcemanager.googleapis.com/v1/projects/" + project
    curl = canary_url(project)

    gauth = {"service": "cloudresourcemanager"}
    read_args = {"method": "GET", "url": gurl, "auth_provider": "gcp", "gcp_auth": gauth}
    ok_body = json.dumps({"projectId": project, "projectNumber": number,
                                 "lifecycleState": "ACTIVE"})
    list_url = "https://cloudresourcemanager.googleapis.com/v1/projects?filter=name:" + project
    list_args = {"method": "GET", "url": list_url, "auth_provider": "gcp", "gcp_auth": gauth}
    list_body = json.dumps({"projects": [{"projectId": project, "projectNumber": number}]})
    write_args = {"method": "PATCH", "url": curl, "auth_provider": "gcp", "gcp_auth": gauth,
                  "headers": [{"key": "Content-Type", "value": "application/json"}],
                  "body": '{"labels":{"cynative-e2e":"canary"}}'}
    wdenial = (WRAP_DIRECT + "gcp_hardening: permission not in allow-list role(s): "
               "[resourcemanager.projects.update] not granted by role roles/viewer")
    # The same policy denial with the live iam-dataset write union widening the list.
    wdenial_union = (WRAP_DIRECT + "gcp_hardening: permission not in allow-list role(s): "
                     "[resourcemanager.projects.get resourcemanager.projects.update] "
                     "not granted by role roles/viewer")
    # Denials from DIFFERENT gates: blocked pre-dispatch, but not the gate under test.
    # The claim mismatch is raised by the HOST gate (its own wrapper); the classifier
    # miss is raised by the ACTION gate.
    hostdenial = ('Error executing tool: auth: authorize host '
                  '"cloudresourcemanager.googleapis.com" for provider gcp: '
                  'gcp_hardening: host does not match gcp_auth claim: x vs y')
    actiondenial = (WRAP_DIRECT + "gcp_hardening: cannot identify method from request: "
                    "no method matches PATCH /x")
    # The policy denial for a DIFFERENT operation's permission.
    otherperm = (WRAP_DIRECT + "gcp_hardening: permission not in allow-list role(s): "
                 "[resourcemanager.projects.delete] not granted by role roles/viewer")

    sneak_args = {"method": "POST",
                  "url": "https://cloudresourcemanager.googleapis.com/v1/projects/%s:setIamPolicy" % project,
                  "auth_provider": "gcp", "gcp_auth": gauth, "body": "{}"}

    return [
        ("read_ok", 0, "read", _pair("c1", read_args, _sres(200, ok_body)), number),
        ("read_direct_ok", 0, "read", _pair("c1", read_args,
            "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + ok_body), number),
        ("read_list_ok", 0, "read", _pair("c1", list_args, _sres(200, list_body)), number),
        ("read_3xx", 1, "read", _pair("c1", read_args, _sres(302, "")), number),
        ("read_trunc", 1, "read", _pair("c1", read_args, _sres(200, ok_body, truncated=True)), number),
        ("read_nonumber", 1, "read", _pair("c1", read_args, _sres(200, "{}")), number),
        # The number appears only in a response HEADER of the raw dump, not the body.
        ("read_header_only", 1, "read", _pair("c1", read_args,
            "HTTP/2.0 200 OK\r\nX-Echo: " + number + "\r\n\r\n{}"), number),
        # A sanctioned-shape GET smuggling a method override: Google would treat it as
        # a write on the wire, so a headered GET is never a sanctioned read.
        ("read_override_hdr", 4, "read", _pair("c1", {**read_args, "headers":
            [{"key": "X-HTTP-Method-Override", "value": "PATCH"}]}, _sres(200, ok_body)), number),
        # A wrong gcp_auth claim, denied by the host gate: blocked, so a retryable miss.
        ("read_wrong_claim", 1, "read", _pair("c1", {**read_args, "gcp_auth":
            {"service": "compute"}}, hostdenial, outcome="error"), number),
        # A miscased headers key: Go binds "HEADERS" to the headers field and sends
        # them on the wire, so the parser must fold keys the same way or a smuggled
        # method-override on a "headerless" 200 read would pass the sweep.
        ("read_folded_headers", 4, "read", _pair("c1", {**read_args, "HEADERS":
            [{"key": "X-HTTP-Method-Override", "value": "PATCH"}]},
            _sres(200, ok_body)), number),
        # Keys that collide after case folding are ambiguous (which one Go bound is
        # decoder-internal): fail closed like a duplicate key.
        ("read_fold_collision", 4, "read", _pair("c1", {**read_args, "Method": "GET"},
            _sres(200, ok_body)), number),
        ("read_foreign", 4, "read", _pair("c1", {"method": "GET",
            "url": "https://api.github.com/repos/x", "auth_provider": "github"},
            _sres(200, "{}")), number),
        ("read_malformed_mid", 4, "read", ["{bad json", _jline("c1", "attempt", read_args)], number),
        ("read_malformed_trailing", 0, "read",
            _pair("c1", read_args, _sres(200, ok_body)) + ["{partial"], number),
        ("read_attemptonly", 1, "read", [_jline("c1", "attempt", read_args)], number),
        ("read_orphan", 4, "read",
            [_jline("c1", "result", read_args, result=_sres(200, ok_body), outcome="ok")], number),
        ("read_dup_result", 4, "read", _pair("c1", read_args, _sres(200, ok_body)) +
            [_jline("c1", "result", read_args, result=_sres(200, ok_body), outcome="ok")], number),
        ("read_no_truncated", 1, "read",
            _pair("c1", read_args, json.dumps({"status": 200, "body": ok_body})), number),
        ("read_nondict_args", 4, "read",
            ['{"session_id":"s","run_id":"r","call_id":"c1","tool":"http_request",'
             '"phase":"attempt","arguments":"x"}'], number),
        ("index_unknown_phase", 4, "read", [_jline("c1", "attempt", read_args),
            _jline("c1", "weird", read_args, result=_sres(200, ok_body), outcome="ok")], number),
        ("index_tuple_mismatch", 4, "read", [_jline("c1", "attempt", read_args),
            _jline("c1", "result", write_args, result=_sres(200, "{}"), outcome="ok")], number),
        # A bool/int type collision between attempt and result args must NOT pass as
        # equal (False == 0 in plain Python); type-strict pairing makes it a breach.
        ("index_type_collision", 4, "read", [
            _jline("c1", "attempt", {**read_args, "timeout_seconds": False}),
            _jline("c1", "result", {**read_args, "timeout_seconds": 0},
                  result=_sres(200, ok_body), outcome="ok")], number),
        ("dupkey_final", 4, "read", _pair("c1", read_args, _sres(200, ok_body)) +
            ['{"call_id":"c2","call_id":"c2","tool":"http_request","phase":"attempt",'
             '"session_id":"s","run_id":"r","arguments":{}}'], number),
        ("canary_ok", 0, "canary", _pair("c1", write_args, wdenial, outcome="error")),
        ("canary_ok_union", 0, "canary", _pair("c1", write_args, wdenial_union, outcome="error")),
        ("canary_ok_noheaders", 0, "canary", _pair("c1",
            {k: v for k, v in write_args.items() if k != "headers"},
            wdenial, outcome="error")),
        # The marked write SUCCEEDED: the gate failed. Never retryable.
        ("canary_succeeded", 4, "canary", _pair("c1", write_args, _sres(200, "{}"))),
        # The denial text inside a 200 body must never pass itself off as a denial.
        ("canary_spoof", 4, "canary", _pair("c1", write_args, _sres(200, wdenial))),
        # Denied, but by a DIFFERENT gate: the policy gate under test was never
        # exercised. Blocked pre-dispatch, so retryable - never "proven denied".
        ("canary_wronggate_host", 1, "canary",
            _pair("c1", write_args, hostdenial, outcome="error")),
        ("canary_wronggate_action", 1, "canary",
            _pair("c1", write_args, actiondenial, outcome="error")),
        # A miscased method key still IS the sanctioned canary once folded the way
        # Go decodes it (the wire saw a PATCH; the denial is the policy gate's).
        ("canary_folded_method", 0, "canary", _pair("c1",
            {**{k: v for k, v in write_args.items() if k != "method"}, "Method": "PATCH"},
            wdenial, outcome="error")),
        # Denied by the policy gate, but for a different operation's permission.
        ("canary_otherperm", 1, "canary", _pair("c1", write_args, otherperm, outcome="error")),
        # Trailing junk after the denial: the fullmatch must reject it.
        ("canary_suffix", 1, "canary", _pair("c1", write_args, wdenial + " x", outcome="error")),
        ("canary_mutated", 1, "canary", _pair("c1",
            {**write_args, "body": '{"labels":{"cynative-e2e":"other"}}'},
            wdenial, outcome="error")),
        ("canary_extra_query", 1, "canary", _pair("c1",
            {**write_args, "url": curl + "&x=1"}, wdenial, outcome="error")),
        ("canary_ct", 1, "canary", _pair("c1", {**write_args, "headers":
            [{"key": "Content-Type", "value": "text/plain"}]}, wdenial, outcome="error")),
        ("canary_hostoverride", 1, "canary", _pair("c1", {**write_args, "headers":
            [{"key": "Content-Type", "value": "application/json"},
             {"key": "Host", "value": "evil.example"}]}, wdenial, outcome="error")),
        # The write was attempted but never adjudicated: cannot prove it was blocked.
        ("canary_attemptonly", 4, "canary", [_jline("c1", "attempt", write_args)]),
        # The write was DISPATCHED and rejected by Google itself: it left the machine.
        ("canary_dispatched", 4, "canary", _pair("c1", write_args,
            "HTTP/2.0 403 Forbidden\r\n\r\n{}", outcome="error")),
        # A status line that only LOOKS like a status must not be read as one.
        ("status_boundary", 4, "canary", _pair("c1", write_args,
            "HTTP/1.1 2000 Weird\r\n\r\n{}", outcome="error")),
        # A sanctioned canary beside an unmarked write that SUCCEEDED.
        ("canary_sneak", 4, "canary", _pair("c1", write_args, wdenial, outcome="error") +
            _pair("c2", sneak_args, _sres(200, "{}"))),
        # An early miss must not hide a later breach: the sweep sees every slot.
        ("miss_before_sneak", 4, "canary", _pair("cA", write_args, hostdenial, outcome="error") +
            _pair("cB", sneak_args, _sres(200, "{}"))),
        ("foreign_attemptonly", 4, "canary", [_jline("c1", "attempt",
            {"method": "PATCH", "url": "https://gitlab.com/x", "auth_provider": "gitlab"})] +
            _pair("c2", write_args, wdenial, outcome="error")),
        # No write was attempted at all (the model refused to issue it).
        ("canary_none", 1, "canary", _pair("c1", read_args, _sres(200, ok_body))),
    ]


SELFTEST_CASES = tuple(_build_cases())

SPEC = engine.ProviderSpec(
    name="gcp",
    blocked_word=BLOCKED,
    read_mode="read",
    is_sanctioned_read=sanctioned_read,
    denial_matches=blocked_by_hardening,
    is_witness=is_witness,
    witness_hint=("read: no sanctioned gcp 200 response carried the project number "
                  "(want a Cloud Resource Manager GET referencing the project, HTTP 200, "
                  "untruncated, the number in the body) - retry"),
    canaries=(CANARY,),
    selftest_target="demo-proj",
    selftest_cases=SELFTEST_CASES,
)
