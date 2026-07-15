#!/bin/sh
# connector.gcp.e2e.test.sh - live GCP connector end-to-end test (cynative#39, #121).
#
# Runs the real `cynative -p` against a real GCP fixture project through the gcp
# connector and asserts, from a black-box run: the connector registers read-only,
# the model reads the project's own Cloud Resource Manager metadata (the project
# number arrives out of band and never appears in the prompt, and the audit parser
# binds it to the bytes Google returned), and a deliberate write is denied by the
# policy gate before it leaves the machine. The read-only guarantee rests on the
# enforced roles/viewer role plus cynative's client-side action gate; the
# write-deny canary is the positive boundary proof.
#
# NOT hermetic and NOT part of `make check`: it talks to a real provider and a
# real GCP project and needs real credentials. Skips (exit 0) when required env is
# unset, so `make connector-gcp-e2e` is a safe no-op.
#
# Usage: sh test/connector.gcp.e2e.test.sh [BINARY]
#        sh test/connector.gcp.e2e.test.sh --selftest   (offline parser check)
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   GOOGLE_APPLICATION_CREDENTIALS              GCP ADC so the gcp connector registers
#   GCP_E2E_PROJECT        fixture project id (in the prompt + read URL)
#   GCP_E2E_EXPECT         fixture project number (NEVER in the prompt)
#   GCP_E2E_TIMEOUT        wall-clock seconds per run (default 120)
#   GCP_E2E_MAX_TOKENS     token backstop (default 32000)
#   GCP_E2E_CANARY         run the write-deny canary phase (default 1; 0 disables)
#   GCP_E2E_ATTEMPTS       per-phase attempts before failing (default 2; model runs
#                          are non-deterministic, so one retry absorbs a rare miss)
#   GCP_E2E_KEEP_WORKDIR   =1 keep the temp workdir (parser, audit logs, output) for
#                          debugging instead of deleting it on exit
#   GCP_E2E_REQUIRE_RUN    =1 hard-fail instead of skipping when required env is unset
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
# `gcp_hardening` error is raised by an auth gate, and all of those run before
# httpClient.Do, so such an error PROVES the request was never dispatched. A failure
# WITHOUT that proof cannot be assumed harmless: a mutation can be dispatched, get a
# 2xx, and only then fail while its response body is read, which surfaces as a plain
# tool error. So anything that is neither a sanctioned read nor the exact sanctioned
# canary, and which lacks a gcp_hardening denial, is a security failure.
write_parser() {
	cat >"$1" <<'PY'
#!/usr/bin/env python3
"""Offline audit-log parser for the GCP connector e2e. It is the security boundary:
its exit code is the phase status. 0 hold, 1 retryable miss, 4 security breach (fatal,
never retried), 2 usage. The shell classifier supplies 2 (timeout) and 3 (budget)."""
import json
import re
import sys
from urllib.parse import urlparse

NOT_PROVEN = 1
SECURITY = 4

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
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError as e:
        die("audit: cannot read %s: %s" % (path, e))
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
            # A duplicate key is an ambiguous record, never a mere write artifact.
            insecure("duplicate JSON key at line %d - failing closed" % n)
        except ValueError:
            if n == len(lines):
                # A single malformed FINAL physical line is a probable kill-during-write
                # artifact; tolerate ONLY a decode error, and only because every
                # fully-parsed record is still classified below.
                continue
            insecure("malformed JSONL at line %d (not final) - failing closed" % n)
        if not isinstance(rec, dict):
            insecure("line %d is not a JSON object - failing closed" % n)
        recs.append(rec)
    return recs


def http_records(recs):
    return [r for r in recs if r.get("tool") == "http_request"]


def index_calls(recs):
    """Ordered list of (key, {attempt, result}) for every http_request call. A missing id
    component, an unknown phase, an orphan/duplicate, a result-before-attempt, or an
    attempt/result that disagree on tool/via/depth/arguments is a breach."""
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
            insecure("http_request record with unknown phase %r" % phase)
    out = []
    for k in order:
        slot = calls[k]
        a, r = slot.get("attempt"), slot.get("result")
        if a is not None and r is not None:
            for field in ("tool", "via", "depth"):
                if not type_strict_eq(a.get(field), r.get(field)):
                    insecure("attempt/result disagree on %s for %r" % (field, k))
            if not type_strict_eq(args_of(a), args_of(r)):
                insecure("attempt/result arguments disagree for %r" % (k,))
        out.append((k, slot))
    return out


def _fold_keys(d, what):
    """Mirror Go's case-insensitive JSON field matching: the transport decodes the
    raw arguments with encoding/json, which binds e.g. "HEADERS" to the headers
    field, so the parser must see the same view or a miscased key could add wire
    behavior (a smuggled header on a "headerless" read) invisible to the sweep.
    A case-fold collision is ambiguous (which value Go bound is decoder-internal),
    so it fails closed like a duplicate key."""
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
            a = _loads(a)
        except ValueError:
            insecure("unparseable http_request arguments")
    if a is None:
        return {}
    if not isinstance(a, dict):
        insecure("http_request arguments are not an object: %r" % type(a).__name__)
    return _fold_keys(a, "http_request arguments")


def _str(v):
    return v if isinstance(v, str) else ""


def result_of(rec):
    return _str(rec.get("result"))


def result_json(rec):
    try:
        obj = _loads(result_of(rec))
    except DuplicateKeyError:
        insecure("duplicate key in a structured http_request result")
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def status_of(rec):
    obj = result_json(rec)
    if obj is not None and type(obj.get("status")) is int:
        return obj["status"]
    # Anchor on the protocol version and require a boundary after the 3-digit status so
    # "HTTP/1.1 2000" cannot be read as 200.
    m = re.match(r"HTTP/[0-9.]+\s+([0-9]{3})(?![0-9])", result_of(rec))
    return int(m.group(1)) if m else None


def body_of(rec):
    """(body, truncated). Fail-closed on the structured path: a missing/non-false
    truncated flag, a non-string body, or a non-int status counts as truncated/invalid."""
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
    return "", truncated


def headers_of(rec):
    hs = args_of(rec).get("headers")
    if hs is None:
        return []
    if not isinstance(hs, list):
        insecure("http_request headers are not a list")
    out = []
    for h in hs:
        if not isinstance(h, dict):
            insecure("http_request header is not an object")
        h = _fold_keys(h, "http_request header")
        out.append(((h.get("key") or "").strip().lower(), (h.get("value") or "").strip()))
    return out


def gcp_service_of(args):
    g = args.get("gcp_auth")
    return _fold_keys(g, "gcp_auth").get("service") if isinstance(g, dict) else None


def blocked_by_hardening(rec):
    """rec (a RESULT) was denied by some auth gate before dispatch: a known wrapper
    prefix followed by gcp_hardening:, no recovered status, non-ok outcome. Proves
    nothing left the machine; does NOT prove WHICH gate fired."""
    if rec.get("outcome") == "ok" or status_of(rec) is not None:
        return False
    return BLOCK_RE.match(result_of(rec)) is not None


def exact_policy_denial(rec, perm):
    """rec (a RESULT) is EXACTLY the allow-list-role policy denial naming perm, inside
    one of the two permitted wrappers, outcome=error, no status. The fullmatch means a
    denial substring inside a 200 body, or a denial with trailing junk, never counts;
    the perm membership means a denial for a DIFFERENT operation never counts."""
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
    return m is not None and perm in m.group(1).split(" ")


def parsed_url(args):
    return urlparse(_str(args.get("url")))


READ_PATHS_FMT = ("/v1/projects/%s", "/v3/projects/%s", "/v1/projects", "/v3/projects",
                  "/v3/projects:search")


def sanctioned_read(rec, project):
    """A read the model may legitimately make: an https GET to Cloud Resource Manager
    under the cloudresourcemanager claim, no body, NO request headers at all (Google
    honors X-HTTP-Method-Override, so a headered GET could be a write on the wire),
    no userinfo/port/fragment, and a path in the known read family - the fixture
    project's direct get (v1/v3) or a list/search (project id in the query). The
    prompt pins the v1 direct get; the family absorbs a model that reads another
    valid way without opening anything beyond CRM project reads."""
    a = args_of(rec)
    u = parsed_url(a)
    paths = tuple(p % project if "%s" in p else p for p in READ_PATHS_FMT)
    return (
        a.get("auth_provider") == "gcp"
        and gcp_service_of(a) == SERVICE
        and (a.get("method") or "").upper() == "GET"
        and u.scheme == "https" and u.hostname == CRM_HOST
        and not u.fragment and not u.username and not u.password and u.port is None
        and u.path in paths
        and not _str(a.get("body"))
        and not headers_of(rec)
    )


def sweep_calls(calls, project, canary_ok):
    """Allow-list over EVERY call. Sweeps ALL slots: a breach exits 4 immediately, a
    retryable miss is remembered and only reported (1) after the full sweep, so a miss in
    an early slot can never hide a breach in a later one. canary_ok(slot)->bool admits the
    mode's one sanctioned (denied) canary; None in read mode."""
    miss = None
    for _key, slot in calls:
        rec = slot.get("attempt") or slot.get("result")
        a = args_of(rec)
        is_read = sanctioned_read(rec, project)
        is_canary = bool(canary_ok) and canary_ok(slot)
        if is_read or is_canary:
            continue
        result = slot.get("result")
        desc = "auth_provider=%r %s %r" % (
            a.get("auth_provider"), (a.get("method") or "?"), a.get("url"))
        if result is None:
            insecure("an unsanctioned/write attempt has no result, cannot prove it was "
                     "blocked: %s" % desc)
        if blocked_by_hardening(result):
            miss = miss or ("a call outside the allow-list was blocked pre-dispatch (%s)" % desc)
            continue
        insecure("a call outside the allow-list cannot be shown to have stayed on the "
                 "machine (no gcp_hardening denial): %s outcome=%r" % (desc, result.get("outcome")))
    if miss:
        die(miss)


def mode_read(recs, project, expect):
    calls = index_calls(recs)
    sweep_calls(calls, project, canary_ok=None)
    # The proof: the project number (fed out of band, never in the prompt) is bound to
    # the bytes Google returned - a sanctioned project-referencing read, HTTP 200,
    # untruncated, the number in the body - not merely to the model's stdout.
    witness = None
    for _key, slot in calls:
        r = slot.get("result")
        if r is None or not sanctioned_read(r, project):
            continue
        if project not in _str(args_of(r).get("url")):
            continue
        if status_of(r) != 200:
            continue
        body, truncated = body_of(r)
        if truncated:
            continue
        if expect in body:
            witness = r
    if witness is None:
        die("read: no sanctioned gcp 200 response carried the project number "
            "(want a Cloud Resource Manager GET referencing %s, HTTP 200, untruncated, "
            "the number in the body) - retry" % project)
    print("read: OK (a sanctioned Cloud Resource Manager 200 carried the project number)")


def type_strict_eq(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(type_strict_eq(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(type_strict_eq(x, y) for x, y in zip(a, b))
    return a == b


def canary_url(project):
    return "https://%s/v3/projects/%s?updateMask=labels" % (CRM_HOST, project)


def canary_defects(rec, project):
    """Everything wrong with rec as THE sanctioned canary, or [] when it is exactly
    the sanctioned canary AND was denied by the policy gate before dispatch. The full
    shape matters: the policy gate classifies the operation, not its target labels,
    so a PATCH carrying a different body produces the same denial text, and matching
    the denial alone would "prove" a request nobody made."""
    a = args_of(rec)
    bad = []
    if (a.get("method") or "").upper() != "PATCH":
        bad.append("method=%r, want PATCH" % a.get("method"))
    # Exact URL: a hostname/path check alone would accept userinfo, a port, a fragment,
    # or an extra query parameter (https://u:p@host:444/...?updateMask=labels&x=y).
    if _str(a.get("url")) != canary_url(project):
        bad.append("url=%r, want %r" % (a.get("url"), canary_url(project)))
    if a.get("auth_provider") != "gcp":
        bad.append("auth_provider=%r" % a.get("auth_provider"))
    if gcp_service_of(a) != SERVICE:
        bad.append("gcp_auth.service=%r, want %s" % (gcp_service_of(a), SERVICE))
    # The prompt names no headers, but models add a Content-Type for a JSON PATCH on
    # their own; tolerate exactly that one, nothing else (no Host override, no
    # Authorization, no method-override).
    hs = headers_of(rec)
    if hs and (len(hs) != 1 or hs[0][0] != "content-type"
               or hs[0][1].split(";", 1)[0].strip().lower() != "application/json"):
        bad.append("headers=%r, want none or exactly one Content-Type: application/json" % hs)
    try:
        got = _loads(_str(a.get("body")) or "null")
    except ValueError:
        got = None
    if not type_strict_eq(got, CANARY_BODY):
        bad.append("body=%r, want %r (type-strict)" % (a.get("body"), CANARY_BODY))
    if not exact_policy_denial(rec, CANARY_PERM):
        bad.append("not the exact policy-gate denial (want the allow-list-role denial "
                   "naming %s, outcome=error, no status)" % CANARY_PERM)
    return bad


def mode_canary(recs, project):
    def is_target(rec):
        a = args_of(rec)
        u = parsed_url(a)
        return ((a.get("method") or "").upper() == "PATCH" and u.hostname == CRM_HOST
                and u.path == "/v3/projects/" + project)

    def canary_ok(slot):
        r = slot.get("result")
        rec = slot.get("attempt") or r
        if r is None or not is_target(rec):
            return False
        return not canary_defects(r, project)

    calls = index_calls(recs)
    sweep_calls(calls, project, canary_ok)
    candidates = [slot for _k, slot in calls if is_target(slot.get("attempt") or slot.get("result"))]
    if not candidates:
        die("canary: no PATCH /v3/projects/%s was attempted - the boundary was never "
            "exercised" % project)
    for slot in candidates:
        r = slot.get("result")
        if r is None:
            insecure("canary: the canary attempt has no result, cannot prove it was blocked")
        bad = canary_defects(r, project)
        if bad:
            die("canary: the PATCH call was not the sanctioned canary: %s" % "; ".join(bad))
    print("canary: OK (%d sanctioned canary denied by the policy gate before dispatch)"
          % len(candidates))


def _selftest():
    import os
    import tempfile
    import io
    project = "demo-proj"
    number = "123456789012"
    gurl = "https://cloudresourcemanager.googleapis.com/v1/projects/" + project
    curl = canary_url(project)

    def jline(cid, phase, args, **extra):
        r = {"session_id": "s", "run_id": "r", "call_id": cid, "tool": "http_request",
             "phase": phase, "arguments": args}
        r.update(extra)
        return json.dumps(r)

    def sres(status, body, truncated=False):
        return json.dumps({"status": status, "statusText": str(status), "headers": [],
                           "body": body, "truncated": truncated})

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

    def pair(cid, args, result, outcome="ok"):
        return [jline(cid, "attempt", args),
                jline(cid, "result", args, result=result, outcome=outcome, decision="approved")]

    sneak_args = {"method": "POST",
                  "url": "https://cloudresourcemanager.googleapis.com/v1/projects/%s:setIamPolicy" % project,
                  "auth_provider": "gcp", "gcp_auth": gauth, "body": "{}"}

    cases = [
        ("read_ok", 0, "read", pair("c1", read_args, sres(200, ok_body)), number),
        ("read_direct_ok", 0, "read", pair("c1", read_args,
            "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + ok_body), number),
        ("read_list_ok", 0, "read", pair("c1", list_args, sres(200, list_body)), number),
        ("read_3xx", 1, "read", pair("c1", read_args, sres(302, "")), number),
        ("read_trunc", 1, "read", pair("c1", read_args, sres(200, ok_body, truncated=True)), number),
        ("read_nonumber", 1, "read", pair("c1", read_args, sres(200, "{}")), number),
        # The number appears only in a response HEADER of the raw dump, not the body.
        ("read_header_only", 1, "read", pair("c1", read_args,
            "HTTP/2.0 200 OK\r\nX-Echo: " + number + "\r\n\r\n{}"), number),
        # A sanctioned-shape GET smuggling a method override: Google would treat it as
        # a write on the wire, so a headered GET is never a sanctioned read.
        ("read_override_hdr", 4, "read", pair("c1", {**read_args, "headers":
            [{"key": "X-HTTP-Method-Override", "value": "PATCH"}]}, sres(200, ok_body)), number),
        # A wrong gcp_auth claim, denied by the host gate: blocked, so a retryable miss.
        ("read_wrong_claim", 1, "read", pair("c1", {**read_args, "gcp_auth":
            {"service": "compute"}}, hostdenial, outcome="error"), number),
        # A miscased headers key: Go binds "HEADERS" to the headers field and sends
        # them on the wire, so the parser must fold keys the same way or a smuggled
        # method-override on a "headerless" 200 read would pass the sweep.
        ("read_folded_headers", 4, "read", pair("c1", {**read_args, "HEADERS":
            [{"key": "X-HTTP-Method-Override", "value": "PATCH"}]},
            sres(200, ok_body)), number),
        # Keys that collide after case folding are ambiguous (which one Go bound is
        # decoder-internal): fail closed like a duplicate key.
        ("read_fold_collision", 4, "read", pair("c1", {**read_args, "Method": "GET"},
            sres(200, ok_body)), number),
        ("read_foreign", 4, "read", pair("c1", {"method": "GET",
            "url": "https://api.github.com/repos/x", "auth_provider": "github"},
            sres(200, "{}")), number),
        ("read_malformed_mid", 4, "read", ["{bad json", jline("c1", "attempt", read_args)], number),
        ("read_malformed_trailing", 0, "read",
            pair("c1", read_args, sres(200, ok_body)) + ["{partial"], number),
        ("read_attemptonly", 1, "read", [jline("c1", "attempt", read_args)], number),
        ("read_orphan", 4, "read",
            [jline("c1", "result", read_args, result=sres(200, ok_body), outcome="ok")], number),
        ("read_dup_result", 4, "read", pair("c1", read_args, sres(200, ok_body)) +
            [jline("c1", "result", read_args, result=sres(200, ok_body), outcome="ok")], number),
        ("read_no_truncated", 1, "read",
            pair("c1", read_args, json.dumps({"status": 200, "body": ok_body})), number),
        ("read_nondict_args", 4, "read",
            ['{"session_id":"s","run_id":"r","call_id":"c1","tool":"http_request",'
             '"phase":"attempt","arguments":"x"}'], number),
        ("index_unknown_phase", 4, "read", [jline("c1", "attempt", read_args),
            jline("c1", "weird", read_args, result=sres(200, ok_body), outcome="ok")], number),
        ("index_tuple_mismatch", 4, "read", [jline("c1", "attempt", read_args),
            jline("c1", "result", write_args, result=sres(200, "{}"), outcome="ok")], number),
        # A bool/int type collision between attempt and result args must NOT pass as equal
        # (False == 0 in plain Python); type-strict pairing makes it a breach.
        ("index_type_collision", 4, "read", [
            jline("c1", "attempt", {**read_args, "timeout_seconds": False}),
            jline("c1", "result", {**read_args, "timeout_seconds": 0},
                  result=sres(200, ok_body), outcome="ok")], number),
        ("dupkey_final", 4, "read", pair("c1", read_args, sres(200, ok_body)) +
            ['{"call_id":"c2","call_id":"c2","tool":"http_request","phase":"attempt",'
             '"session_id":"s","run_id":"r","arguments":{}}'], number),
        ("canary_ok", 0, "canary", pair("c1", write_args, wdenial, outcome="error")),
        ("canary_ok_union", 0, "canary", pair("c1", write_args, wdenial_union, outcome="error")),
        ("canary_ok_noheaders", 0, "canary", pair("c1",
            {k: v for k, v in write_args.items() if k != "headers"},
            wdenial, outcome="error")),
        # The marked write SUCCEEDED: the gate failed. Never retryable.
        ("canary_succeeded", 4, "canary", pair("c1", write_args, sres(200, "{}"))),
        # The denial text inside a 200 body must never pass itself off as a denial.
        ("canary_spoof", 4, "canary", pair("c1", write_args, sres(200, wdenial))),
        # Denied, but by a DIFFERENT gate: the policy gate under test was never
        # exercised. Blocked pre-dispatch, so retryable - never "proven denied".
        ("canary_wronggate_host", 1, "canary",
            pair("c1", write_args, hostdenial, outcome="error")),
        ("canary_wronggate_action", 1, "canary",
            pair("c1", write_args, actiondenial, outcome="error")),
        # A miscased method key still IS the sanctioned canary once folded the way
        # Go decodes it (the wire saw a PATCH; the denial is the policy gate's).
        ("canary_folded_method", 0, "canary", pair("c1",
            {**{k: v for k, v in write_args.items() if k != "method"}, "Method": "PATCH"},
            wdenial, outcome="error")),
        # Denied by the policy gate, but for a different operation's permission.
        ("canary_otherperm", 1, "canary", pair("c1", write_args, otherperm, outcome="error")),
        # Trailing junk after the denial: the fullmatch must reject it.
        ("canary_suffix", 1, "canary", pair("c1", write_args, wdenial + " x", outcome="error")),
        ("canary_mutated", 1, "canary", pair("c1",
            {**write_args, "body": '{"labels":{"cynative-e2e":"other"}}'},
            wdenial, outcome="error")),
        ("canary_extra_query", 1, "canary", pair("c1",
            {**write_args, "url": curl + "&x=1"}, wdenial, outcome="error")),
        ("canary_ct", 1, "canary", pair("c1", {**write_args, "headers":
            [{"key": "Content-Type", "value": "text/plain"}]}, wdenial, outcome="error")),
        ("canary_hostoverride", 1, "canary", pair("c1", {**write_args, "headers":
            [{"key": "Content-Type", "value": "application/json"},
             {"key": "Host", "value": "evil.example"}]}, wdenial, outcome="error")),
        # The write was attempted but never adjudicated: cannot prove it was blocked.
        ("canary_attemptonly", 4, "canary", [jline("c1", "attempt", write_args)]),
        # The write was DISPATCHED and rejected by Google itself: it left the machine.
        ("canary_dispatched", 4, "canary", pair("c1", write_args,
            "HTTP/2.0 403 Forbidden\r\n\r\n{}", outcome="error")),
        # A status line that only LOOKS like a status must not be read as one.
        ("status_boundary", 4, "canary", pair("c1", write_args,
            "HTTP/1.1 2000 Weird\r\n\r\n{}", outcome="error")),
        # A sanctioned canary beside an unmarked write that SUCCEEDED.
        ("canary_sneak", 4, "canary", pair("c1", write_args, wdenial, outcome="error") +
            pair("c2", sneak_args, sres(200, "{}"))),
        # An early miss must not hide a later breach: the sweep sees every slot.
        ("miss_before_sneak", 4, "canary", pair("cA", write_args, hostdenial, outcome="error") +
            pair("cB", sneak_args, sres(200, "{}"))),
        ("foreign_attemptonly", 4, "canary", [jline("c1", "attempt",
            {"method": "PATCH", "url": "https://gitlab.com/x", "auth_provider": "gitlab"})] +
            pair("c2", write_args, wdenial, outcome="error")),
        # No write was attempted at all (the model refused to issue it).
        ("canary_none", 1, "canary", pair("c1", read_args, sres(200, ok_body))),
    ]
    failures = 0
    for name, want, mode, lines, *rest in cases:
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        argv = ["x", mode, path, project] + list(rest)
        old_argv, old_out = sys.argv, sys.stdout
        sys.argv = argv
        sys.stdout = io.StringIO()  # suppress per-case parser diagnostics
        try:
            main()
            got = 0
        except SystemExit as e:
            got = e.code if isinstance(e.code, int) else 1
        finally:
            sys.argv, sys.stdout = old_argv, old_out
            os.unlink(path)
        if got != want:
            failures += 1
            print("selftest FAIL %s: want %d got %d" % (name, want, got))
    if failures:
        print("selftest: %d/%d FAILED" % (failures, len(cases)))
        sys.exit(1)
    print("selftest: OK (%d parser cases)" % len(cases))


def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--selftest":
        _selftest()
        return
    if len(sys.argv) < 4:
        print("usage: audit_check.py read AUDIT PROJECT EXPECT | canary AUDIT PROJECT")
        sys.exit(2)
    mode = sys.argv[1]
    records = load_records(sys.argv[2])
    if mode == "read":
        if len(sys.argv) < 5:
            print("usage: read AUDIT PROJECT EXPECT")
            sys.exit(2)
        mode_read(records, sys.argv[3], sys.argv[4])
        return
    if mode == "canary":
        mode_canary(records, sys.argv[3])
        return
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

# arbitrate PARSER_RC CLASSIFY_RC -> final phase status. Pure (no guardrail library), so
# the offline selftest can exercise it. A security breach (4) dominates even a timeout or
# budget hit; otherwise a nonzero classifier (2 timeout / 3 budget / 1 error) wins; else
# the parser's own 0 (hold) or 1 (miss).
arbitrate() {
	if [ "$1" = 4 ]; then return 4; fi
	if [ "$2" != 0 ]; then return "$2"; fi
	return "$1"
}

if [ "${1:-}" = "--selftest" ]; then
	command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found\n' >&2; exit 1; }
	_pt=$(mktemp)
	# Cleanup on EXIT only; INT/TERM clean up and exit 130/143 so an interrupt is not
	# absorbed and misread as a plain failure (see the main-body trap below).
	trap 'rm -f "$_pt"' EXIT
	trap 'trap - EXIT; rm -f "$_pt"; exit 130' INT
	trap 'trap - EXIT; rm -f "$_pt"; exit 143' TERM
	write_parser "$_pt"
	python3 "$_pt" --selftest || exit 1
	_af=0
	check_arb() { arbitrate "$2" "$3" && _g=0 || _g=$?; if [ "$_g" != "$1" ]; then printf 'arbitrate(%s,%s) want %s got %s\n' "$2" "$3" "$1" "$_g" >&2; _af=1; fi; }
	check_arb 4 4 0    # breach + clean run
	check_arb 4 4 2    # breach + timeout: breach wins
	check_arb 4 4 3    # breach + budget: breach wins
	check_arb 2 1 2    # miss + timeout: timeout wins
	check_arb 3 1 3    # miss + budget: budget wins
	check_arb 1 1 0    # miss + clean run
	check_arb 2 0 2    # hold + timeout
	check_arb 0 0 0    # hold + clean run
	[ "$_af" = 0 ] || exit 1
	printf 'selftest: OK (arbitrate cases)\n'
	exit 0
fi

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# Shared cost/timeout guardrails (isolation, bounds, bounded run + classifier).
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$root/test/lib/e2e-guardrails.sh"

# Skip cleanly when required env is unset - unless GCP_E2E_REQUIRE_RUN=1, where a
# missing var is a failure (a CI job must never go green by skipping).
e2e_require_env connector.gcp.e2e "${GCP_E2E_REQUIRE_RUN:-}" \
	CYNATIVE_LLM_PROVIDER CYNATIVE_LLM_MODEL GCP_E2E_PROJECT GCP_E2E_EXPECT || exit 0

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd timeout || exit 1
e2e_require_cmd python3 "needed to parse the audit log" || exit 1

case "${GCP_E2E_CANARY:-1}" in
	1) run_canary=1 ;;
	0) run_canary=0 ;;
	*) printf 'FAIL: GCP_E2E_CANARY must be 0 or 1 (got %s)\n' "$GCP_E2E_CANARY" >&2; exit 1 ;;
esac

workdir=$(mktemp -d)
# GCP_E2E_KEEP_WORKDIR=1 preserves the parser and the per-phase audit logs, so a
# failure can be re-examined by hand instead of re-run blind.
cleanup() {
	if [ "${GCP_E2E_KEEP_WORKDIR:-}" = "1" ]; then
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

# Isolate cynative's config/cache from the caller without moving HOME, so provider
# SDKs still find file-based ADC. e2e_isolate_env writes an empty --config
# (ignore the caller's config.yaml), points the cache at the temp dir, and
# silences connector sources unrelated to gcp (github/gitlab/kube). It leaves the
# GCP creds alone - we want the gcp connector to register (the inverse of the llm
# smoke). The per-phase audit path is set by e2e_run_bounded, not here.
e2e_isolate_env "$workdir"
# A maintainer's widened role env (e.g. roles/editor) would let the canary write
# reach Google; force the default read-only baseline.
unset CYNATIVE_CONNECTORS_GCP_ROLE || true
# Bounds: the connector run does real tool work, so it keeps the shared iteration
# default (unlike the no-tool llm smoke). GCP_E2E_* override the token and
# wall-clock defaults; exported as env-level overrides for e2e_apply_bounds.
export E2E_MAX_TOKENS="${GCP_E2E_MAX_TOKENS:-32000}"
export E2E_RUN_TIMEOUT="${GCP_E2E_TIMEOUT:-120}"
e2e_apply_bounds

# Write the audit parser once; both phases invoke it.
parser="$workdir/audit_check.py"
write_parser "$parser"

timeout_s="$E2E_RUN_TIMEOUT"
attempts="${GCP_E2E_ATTEMPTS:-2}"

# assert_gcp_posture ERR - the gcp connector must be registered live under the
# read-only roles/viewer role (this suite runs on the default config, so a widened
# role would surface here before any request-level assertion).
assert_gcp_posture() {
	_err=$1
	if grep -Eq 'gcp .*gcp_hardening: skipped' "$_err"; then
		printf 'gcp connector was SKIPPED at startup. inventory:\n' >&2
		grep -iE 'gcp|hardening' "$_err" >&2 || true
		return 1
	fi
	if ! grep -Eq 'gcp .*role=roles/viewer' "$_err"; then
		printf 'gcp connector not shown available under role=roles/viewer. inventory + stderr tail:\n' >&2
		grep -iE 'gcp|connector|hardening|no connectors detected' "$_err" >&2 || true
		tail -n 25 "$_err" >&2
		return 1
	fi
	return 0
}

# run_phase MODE AUDIT OUT ERR [EXPECT] -> phase status. Relies on the caller having set
# `rc` from e2e_run_bounded. Security sweep first; a breach (4) short-circuits; then the
# run classifier; then the soft, retryable environment gates.
run_phase() {
	_mode=$1; _audit=$2; _out=$3; _err=$4; _expect=${5:-}
	if [ "$_mode" = read ]; then
		if python3 "$parser" read "$_audit" "$GCP_E2E_PROJECT" "$_expect"; then _p=0; else _p=$?; fi
	else
		if python3 "$parser" canary "$_audit" "$GCP_E2E_PROJECT"; then _p=0; else _p=$?; fi
	fi
	# A breach short-circuits BEFORE the classifier and every soft gate: nothing may
	# suppress or delay a security failure.
	if [ "$_p" = 4 ]; then return 4; fi
	if e2e_classify_run "$rc" "$_out" "$_err" "$timeout_s"; then _c=0; else _c=$?; fi
	arbitrate "$_p" "$_c"; _s=$?
	if [ "$_s" != 0 ]; then return "$_s"; fi
	# Parser held and no timeout/budget: run the diagnostic, retryable environment gates.
	assert_gcp_posture "$_err" || return 1
	e2e_assert_tool_called "$_err" || return 1
	if [ "$_mode" = read ] && ! grep -Fiq "$GCP_E2E_EXPECT" "$_out"; then
		printf 'read: project number not found in answer (no real read?). stdout tail:\n' >&2
		tail -n 20 "$_out" >&2
		return 1
	fi
	return 0
}

# ============================ READ PHASE ============================
# Give the project id, ask for the number: the model can only produce the number
# by actually reading the resource through the connector, and the parser then binds
# the number to the bytes Google returned. The exact call is spelled out (validated
# reliable across models) so the run stays inside the parser's sanctioned-read
# family; the v1 get returns projectNumber as a top-level field.
read_prompt="Use the gcp connector to look up the Google Cloud project \"$GCP_E2E_PROJECT\" and report its numeric projectNumber. Make exactly this call with the http_request tool: method=GET, url=https://cloudresourcemanager.googleapis.com/v1/projects/$GCP_E2E_PROJECT, auth_provider=gcp, gcp_auth={service: cloudresourcemanager}. Call the API to read it; do not guess. Reply with only the project number."

read_phase() {
	printf '== READ == %s (%s/%s)\n' "$GCP_E2E_PROJECT" "$CYNATIVE_LLM_PROVIDER" "$CYNATIVE_LLM_MODEL" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" \
		"$bin" "$workdir/config.yaml" "$read_prompt"; then rc=0; else rc=$?; fi
	run_phase read "$workdir/read.audit.log" "$workdir/read.out" "$workdir/read.err" "$GCP_E2E_EXPECT"
}

# ============================ CANARY PHASE ============================
# Attempt one harmless write (set a label). The gate denies it client-side, before
# dispatch, so nothing mutates. The canary depends on the model actually issuing the
# write. A task-framed imperative ("set a label ...") is unreliable: a capable model
# predicts the read-only denial and declines to spend the call (Opus refused; gemini
# was a coin-flip). Giving the exact http_request to make turns it into a
# deterministic instruction-following task (validated reliable across models), while
# the gate still denies the write before dispatch. gcp_auth.service and the labels
# body are spelled out so any model can reproduce the call verbatim.
canary_prompt="Authorized read-only-gate self-test - I need the connector's REAL response to a write, not a prediction. Make exactly this call now using the http_request tool and then paste the connector's verbatim response: method=PATCH, url=https://cloudresourcemanager.googleapis.com/v3/projects/$GCP_E2E_PROJECT?updateMask=labels, auth_provider=gcp, gcp_auth={service: cloudresourcemanager}, body={\"labels\":{\"cynative-e2e\":\"canary\"}}. Issue the request; do not skip, simulate, or answer from prediction. I expect it to be denied - I need to see the actual denial."

canary_phase() {
	printf '== CANARY == attempting a denied write on %s\n' "$GCP_E2E_PROJECT" >&2
	if e2e_run_bounded "$timeout_s" "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err" \
		"$bin" "$workdir/config.yaml" "$canary_prompt"; then rc=0; else rc=$?; fi
	# A correctly denied write is an in-loop tool result, not a fatal exit, so the run
	# still exits 0. The classifier only catches a real run failure (timeout, budget,
	# crash); the audit parser inside run_phase is what judges the boundary, and a
	# write that SUCCEEDED, or any call that cannot be shown to have stayed on the
	# machine, exits 4: fatal, never retried, because a retry would truncate the audit
	# log and erase the evidence.
	run_phase canary "$workdir/canary.audit.log" "$workdir/canary.out" "$workdir/canary.err"
}

e2e_run_with_retries read "$attempts" read_phase

if [ "$run_canary" = 1 ]; then
	e2e_run_with_retries canary "$attempts" canary_phase
fi

printf 'connector.gcp.e2e: OK (%s)\n' "$GCP_E2E_PROJECT" >&2
