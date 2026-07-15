#!/bin/sh
# connector.github.e2e.test.sh - live GitHub connector end-to-end test (cynative#53).
#
# Runs the real `cynative -p` against a real GitHub fixture repo through the github
# connector and asserts, from a black-box run: the connector registers under the
# configured read-only exposure ceiling, the model reads a private archived fixture
# repo and surfaces a marker it could only have obtained from GitHub, and a deliberate
# write plus a secret-scanning-alerts read are each denied client-side before the
# request reaches the network.
#
# NOT hermetic and NOT part of `make check`: it talks to a real provider and a real
# GitHub fixture repo and needs a real installation token. Skips (exit 0) when required
# env is unset, so `make connector-github-e2e` is a safe no-op.
#
# Usage: sh test/connector.github.e2e.test.sh [BINARY]
#        sh test/connector.github.e2e.test.sh --selftest   (offline parser check)
#
# Env:
#   CYNATIVE_LLM_PROVIDER, CYNATIVE_LLM_MODEL   required (drives the agent loop)
#   GITHUB_E2E_REPO           fixture repo "<owner>/<name>" (appears in the prompt)
#   GITHUB_E2E_EXPECT         fixture marker (NEVER in the prompt)
#   GITHUB_E2E_TOKEN          token for the read-only fixture App/PAT (re-exported as
#                             GH_TOKEN after env isolation, so it lights the github
#                             connector)
#   GITHUB_E2E_EXPECT_NO_AWS  =1 additionally assert the aws connector stayed dark
#                             (CI only; local ambient Bedrock creds legitimately
#                             register it)
#   GITHUB_E2E_TIMEOUT        wall-clock seconds per run (default 240; the first
#                             authorization cold-fetches the OpenAPI exposure table
#                             before any request is dispatched)
#   GITHUB_E2E_MAX_TOKENS     token backstop (default 32000)
#   GITHUB_E2E_CANARY         run the write and secret-scanning deny canaries (default
#                             1; 0 disables)
#   GITHUB_E2E_ATTEMPTS       per-phase attempts (default 2; model runs are
#                             non-deterministic, so one retry absorbs a rare miss)
#   GITHUB_E2E_KEEP_WORKDIR   =1 keep the temp workdir (parser, audit logs, output) for
#                             debugging instead of deleting it on exit
#   GITHUB_E2E_REQUIRE_RUN    =1 hard-fail instead of skipping when required env is unset
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
# `github_hardening` error is raised by an auth gate, and all of those run before
# httpClient.Do, so such an error PROVES the request was never dispatched. A failure
# WITHOUT that proof cannot be assumed harmless: a mutation can be dispatched, get a
# 2xx, and only then fail while its response body is read, which surfaces as a plain
# tool error. So anything that is neither a sanctioned read nor the exact sanctioned
# canary, and which lacks a github_hardening denial, is a security failure.
write_parser() {
	cat >"$1" <<'PY'
#!/usr/bin/env python3
"""Offline audit-log parser for the GitHub connector e2e. It is the security boundary:
its exit code is the phase status. 0 hold, 1 retryable miss, 4 security breach (fatal,
never retried), 2 usage. The shell classifier supplies 2 (timeout) and 3 (budget)."""
import json
import re
import sys
from urllib.parse import urlparse

NOT_PROVEN = 1
SECURITY = 4

GITHUB_HOST = "api.github.com"
BLOCKED = "github_hardening"
WRAP_DIRECT = "Error executing tool: auth: authorize action for provider github: "
WRAP_SANDBOX = "auth: authorize action for provider github: "


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
                if a.get(field) != r.get(field):
                    insecure("attempt/result disagree on %s for %r" % (field, k))
            if args_of(a) != args_of(r):
                insecure("attempt/result arguments disagree for %r" % (k,))
        out.append((k, slot))
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
    return a


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
        out.append(((h.get("key") or "").strip().lower(), (h.get("value") or "").strip()))
    return out


def header_of(rec, name):
    for k, v in headers_of(rec):
        if k == name:
            return v
    return None


def blocked_by_hardening(rec):
    """rec (a RESULT) was denied by some auth gate before dispatch: an exact wrapper
    prefix followed by github_hardening:, no recovered status, non-ok outcome. Proves
    nothing left the machine; does NOT prove WHICH gate fired."""
    if rec.get("outcome") == "ok" or status_of(rec) is not None:
        return False
    r = result_of(rec)
    for wrap in (WRAP_DIRECT, WRAP_SANDBOX):
        if r.startswith(wrap + BLOCKED + ":"):
            return True
    return False


def exact_ceiling_denial(rec, core):
    """rec (a RESULT) is EXACTLY the exposure-ceiling denial for core, inside one of the
    two permitted wrappers, outcome=error, no status. Exact equality: a denial substring
    inside a 200 body can never satisfy this."""
    if rec.get("outcome") != "error" or status_of(rec) is not None:
        return False
    r = result_of(rec)
    return r == WRAP_DIRECT + core or r == WRAP_SANDBOX + core


def parsed_url(args):
    return urlparse(_str(args.get("url")))


def sanctioned_read(rec, repo):
    """Exactly the sanctioned fixture read: GET the exact raw URL, github, no body, no
    query/fragment/userinfo/port, and NO request headers at all."""
    a = args_of(rec)
    u = parsed_url(a)
    return (
        a.get("auth_provider") == "github"
        and (a.get("method") or "") == "GET"
        and _str(a.get("url")) == "https://api.github.com/repos/" + repo
        and not u.query and not u.fragment and not u.username and not u.password and u.port is None
        and not _str(a.get("body"))
        and not headers_of(rec)
    )


def sweep_calls(calls, repo, canary_ok):
    """Allow-list over EVERY call. Sweeps ALL slots: a breach exits 4 immediately, a
    retryable miss is remembered and only reported (1) after the full sweep, so a miss in
    an early slot can never hide a breach in a later one. canary_ok(slot)->bool admits the
    mode's one sanctioned (denied) canary; None in read mode."""
    miss = None
    for _key, slot in calls:
        rec = slot.get("attempt") or slot.get("result")
        a = args_of(rec)
        is_read = sanctioned_read(rec, repo)
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
                 "machine (no github_hardening denial): %s outcome=%r" % (desc, result.get("outcome")))
    if miss:
        die(miss)


def mode_read(recs, repo, expect):
    calls = index_calls(recs)
    sweep_calls(calls, repo, canary_ok=None)
    # First pass: ANY sanctioned 200 read that is public fails hard, even if a valid
    # witness also exists (a public flip must never be hidden by a good record).
    witness = None
    for _key, slot in calls:
        r = slot.get("result")
        if r is None or not sanctioned_read(r, repo):
            continue
        if status_of(r) != 200:
            continue
        body, truncated = body_of(r)
        if truncated:
            continue
        try:
            doc = _loads(body)
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        if doc.get("full_name") == repo and doc.get("private") is False:
            insecure("read: the fixture repo is PUBLIC (private=false); a public 200 "
                     "cannot prove the connector injected the credential")
        desc = doc.get("description")
        if (doc.get("full_name") == repo and doc.get("private") is True
                and doc.get("archived") is True and doc.get("has_issues") is False
                and isinstance(desc, str) and expect in desc):
            witness = r
    if witness is None:
        die("read: no sanctioned github 200 response carried the private fixture marker "
            "(want GET https://api.github.com/repos/%s, HTTP 200, untruncated, "
            "private+archived body with the marker in description) - retry" % repo)
    print("read: OK (private+archived fixture body carried the marker at HTTP 200)")


def write_core(repo):
    return ('github_hardening: request exceeds configured exposure: '
            'PATCH /repos/%s needs write on "repos" (ceiling read)' % repo)


def secretscan_core(repo):
    return ('github_hardening: request exceeds configured exposure: '
            'GET /repos/%s/secret-scanning/alerts needs read on "secret-scanning" '
            '(ceiling none)' % repo)


def type_strict_eq(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(type_strict_eq(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(type_strict_eq(x, y) for x, y in zip(a, b))
    return a == b


def canary_defects(rec, core, method, url, body_obj):
    a = args_of(rec)
    bad = []
    if (a.get("method") or "") != method:
        bad.append("method=%r, want %s" % (a.get("method"), method))
    if _str(a.get("url")) != url:
        bad.append("url=%r, want %r" % (a.get("url"), url))
    if a.get("auth_provider") != "github":
        bad.append("auth_provider=%r" % a.get("auth_provider"))
    hs = headers_of(rec)
    if body_obj is not None:
        # Exactly one header, Content-Type: application/json. No Host, no Authorization,
        # no extras: an Authorization header would still get the exact ceiling denial
        # (AuthorizeAction precedes credential rejection), so the shape must be exact.
        if len(hs) != 1 or hs[0][0] != "content-type" or hs[0][1].split(";", 1)[0].strip().lower() != "application/json":
            bad.append("headers=%r, want exactly one Content-Type: application/json" % hs)
        try:
            got = _loads(_str(a.get("body")) or "null")
        except ValueError:
            got = None
        if not type_strict_eq(got, body_obj):
            bad.append("body=%r, want %r (type-strict)" % (a.get("body"), body_obj))
    else:
        if hs:
            bad.append("unexpected headers %r, want none" % hs)
        if _str(a.get("body")):
            bad.append("unexpected body %r" % a.get("body"))
    if not exact_ceiling_denial(rec, core):
        bad.append("not the exact exposure denial (want %r, outcome=error, no status)" % core)
    return bad


def _canary_mode(recs, repo, core, method, path, body_obj, label):
    url = "https://api.github.com/repos/%s%s" % (repo, path)

    def is_target(rec):
        a = args_of(rec)
        u = parsed_url(a)
        return ((a.get("method") or "") == method and u.hostname == GITHUB_HOST
                and u.path == "/repos/" + repo + path)

    def canary_ok(slot):
        r = slot.get("result")
        rec = slot.get("attempt") or r
        if r is None or not is_target(rec):
            return False
        return not canary_defects(r, core, method, url, body_obj)

    calls = index_calls(recs)
    sweep_calls(calls, repo, canary_ok)
    candidates = [slot for _k, slot in calls if is_target(slot.get("attempt") or slot.get("result"))]
    if not candidates:
        die("%s: no %s %s was attempted - the boundary was never exercised"
            % (label, method, path or "/repos/{repo}"))
    for slot in candidates:
        r = slot.get("result")
        if r is None:
            insecure("%s: the canary attempt has no result, cannot prove it was blocked" % label)
        bad = canary_defects(r, core, method, url, body_obj)
        if bad:
            die("%s: the %s call was not the sanctioned canary: %s" % (label, method, "; ".join(bad)))
    print("%s: OK (%d sanctioned canary denied by the exposure ceiling before dispatch)"
          % (label, len(candidates)))


def mode_canary(recs, repo):
    _canary_mode(recs, repo, write_core(repo), "PATCH", "", {"has_issues": False}, "canary")


def mode_secretscan(recs, repo):
    _canary_mode(recs, repo, secretscan_core(repo), "GET", "/secret-scanning/alerts", None, "secretscan")


def _selftest():
    import os
    import tempfile
    repo = "cynative/connector-e2e-fixture"
    mark = "driftwood-harbor-1731"
    url = "https://api.github.com/repos/" + repo
    ss_url = url + "/secret-scanning/alerts"

    def jline(cid, phase, args, **extra):
        r = {"session_id": "s", "run_id": "r", "call_id": cid, "tool": "http_request",
             "phase": phase, "arguments": args}
        r.update(extra)
        return json.dumps(r)

    def sres(status, body, truncated=False):
        return json.dumps({"status": status, "statusText": str(status), "headers": [],
                           "body": body, "truncated": truncated})

    read_args = {"method": "GET", "url": url, "auth_provider": "github"}
    ok_body = json.dumps({"full_name": repo, "private": True, "archived": True,
                          "has_issues": False, "description": "fixture - " + mark})
    write_args = {"method": "PATCH", "url": url, "auth_provider": "github",
                  "headers": [{"key": "Content-Type", "value": "application/json"}],
                  "body": '{"has_issues":false}'}
    wdenial = WRAP_DIRECT + write_core(repo)
    ss_args = {"method": "GET", "url": ss_url, "auth_provider": "github"}
    ssdenial = WRAP_DIRECT + secretscan_core(repo)

    def pair(cid, args, result, outcome="ok"):
        return [jline(cid, "attempt", args),
                jline(cid, "result", args, result=result, outcome=outcome, decision="approved")]

    cases = [
        ("read_ok", 0, "read", pair("c1", read_args, sres(200, ok_body)), mark),
        ("read_public", 4, "read", pair("c1", read_args, sres(200, json.dumps(
            {"full_name": repo, "private": False, "archived": True, "has_issues": False,
             "description": "x " + mark}))), mark),
        ("read_3xx", 1, "read", pair("c1", read_args, sres(302, "")), mark),
        ("read_trunc", 1, "read", pair("c1", read_args, sres(200, ok_body, truncated=True)), mark),
        ("read_foreign", 4, "read", pair("c1", {"method": "GET", "url": "https://gitlab.com/api/v4/x",
                                                 "auth_provider": "gitlab"}, sres(200, "{}")), mark),
        ("read_direct_ok", 0, "read", pair("c1", read_args,
            "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + ok_body), mark),
        ("read_malformed_mid", 4, "read", ["{bad json", jline("c1", "attempt", read_args)], mark),
        ("read_malformed_trailing", 0, "read", pair("c1", read_args, sres(200, ok_body)) + ["{partial"], mark),
        ("read_attemptonly", 1, "read", [jline("c1", "attempt", read_args)], mark),
        ("read_orphan", 4, "read", [jline("c1", "result", read_args, result=sres(200, ok_body), outcome="ok")], mark),
        ("read_dup_result", 4, "read", pair("c1", read_args, sres(200, ok_body)) +
            [jline("c1", "result", read_args, result=sres(200, ok_body), outcome="ok")], mark),
        ("read_no_truncated", 1, "read", pair("c1", read_args, json.dumps({"status": 200, "body": ok_body})), mark),
        ("read_nondict_args", 4, "read", ['{"session_id":"s","run_id":"r","call_id":"c1","tool":"http_request","phase":"attempt","arguments":"x"}'], mark),
        ("index_unknown_phase", 4, "read", [jline("c1", "attempt", read_args),
            jline("c1", "weird", read_args, result=sres(200, ok_body), outcome="ok")], mark),
        ("index_tuple_mismatch", 4, "read", [jline("c1", "attempt", read_args),
            jline("c1", "result", write_args, result=sres(200, "{}"), outcome="ok")], mark),
        ("dupkey_final", 4, "read", pair("c1", read_args, sres(200, ok_body)) +
            ['{"call_id":"c2","call_id":"c2","tool":"http_request","phase":"attempt","session_id":"s","run_id":"r","arguments":{}}'], mark),
        ("canary_ok", 0, "canary", pair("c1", write_args, wdenial, outcome="error")),
        ("canary_succeeded", 4, "canary", pair("c1", write_args, sres(200, "{}"))),
        ("canary_spoof", 4, "canary", pair("c1", write_args, sres(200, wdenial))),
        ("canary_wrongerr", 1, "canary", pair("c1", write_args,
            WRAP_DIRECT + "github_hardening: cannot classify request", outcome="error")),
        ("canary_ct", 1, "canary", pair("c1", {**write_args, "headers":
            [{"key": "Content-Type", "value": "text/plain"}]}, wdenial, outcome="error")),
        ("canary_mutated", 1, "canary", pair("c1", {**write_args, "body": '{"has_issues":true}'}, wdenial, outcome="error")),
        ("canary_intbody", 1, "canary", pair("c1", {**write_args, "body": '{"has_issues":0}'}, wdenial, outcome="error")),
        ("canary_authhdr", 1, "canary", pair("c1", {**write_args, "headers":
            [{"key": "Content-Type", "value": "application/json"}, {"key": "Authorization", "value": "Bearer x"}]},
            wdenial, outcome="error")),
        ("canary_attemptonly", 4, "canary", [jline("c1", "attempt", write_args)]),
        ("canary_dispatched", 4, "canary", pair("c1", write_args, "HTTP/2.0 403 Forbidden\r\n\r\n{}", outcome="error")),
        ("canary_sneak", 4, "canary", pair("c1", write_args, wdenial, outcome="error") +
            pair("c2", {"method": "PUT", "url": url + "/topics", "auth_provider": "github", "body": "{}"}, sres(200, "{}"))),
        ("miss_before_sneak", 4, "canary", pair("cA", write_args,
            WRAP_DIRECT + "github_hardening: cannot classify request", outcome="error") +
            pair("cB", {"method": "PUT", "url": url + "/topics", "auth_provider": "github", "body": "{}"}, sres(200, "{}"))),
        ("foreign_attemptonly", 4, "canary", [jline("c1", "attempt",
            {"method": "PATCH", "url": "https://gitlab.com/x", "auth_provider": "gitlab"})] +
            pair("c2", write_args, wdenial, outcome="error")),
        ("secretscan_ok", 0, "secretscan", pair("c1", ss_args, ssdenial, outcome="error")),
        ("secretscan_succeeded", 4, "secretscan", pair("c1", ss_args, sres(200, "[]"))),
        ("secretscan_attemptonly", 4, "secretscan", [jline("c1", "attempt", ss_args)]),
        ("secretscan_hdr", 1, "secretscan", pair("c1", {**ss_args, "headers":
            [{"key": "X-Foo", "value": "bar"}]}, ssdenial, outcome="error")),
        ("status_boundary", 4, "secretscan", pair("c1", ss_args, "HTTP/1.1 2000 Weird\r\n\r\n{}", outcome="error")),
    ]
    import io
    failures = 0
    for name, want, mode, lines, *rest in cases:
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        argv = ["x", mode, path, repo] + list(rest)
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
        print("usage: audit_check.py read AUDIT REPO EXPECT | canary AUDIT REPO | secretscan AUDIT REPO")
        sys.exit(2)
    mode = sys.argv[1]
    records = load_records(sys.argv[2])
    if mode == "read":
        if len(sys.argv) < 5:
            print("usage: read AUDIT REPO EXPECT")
            sys.exit(2)
        mode_read(records, sys.argv[3], sys.argv[4])
        return
    if mode == "canary":
        mode_canary(records, sys.argv[3])
        return
    if mode == "secretscan":
        mode_secretscan(records, sys.argv[3])
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

if [ "${1:-}" = "--selftest" ]; then
	command -v python3 >/dev/null 2>&1 || { printf 'FAIL: python3 not found\n' >&2; exit 1; }
	_pt=$(mktemp); trap 'rm -f "$_pt"' EXIT INT TERM
	write_parser "$_pt"
	python3 "$_pt" --selftest || exit 1
	# arbitrate cases are added in Task 3 (the arbitrate function is defined above this block).
	exit 0
fi
