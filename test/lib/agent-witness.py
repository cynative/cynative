#!/usr/bin/env python3
"""agent-witness.py - the read-phase witnesses of test/agent.e2e.test.sh.

    python3 -B test/lib/agent-witness.py PROJECT EXPECT AUDIT_LOG
    python3 -B test/lib/agent-witness.py --selftest

The agent suite hands its built-in a two-read task and proves, from the write-ahead
audit log, that both reads reached Google and came back:

  record witness  an http_request that GETs the fixture project's own record from
                  Cloud Resource Manager (path /v1/projects/{id} or /v3/projects/{id},
                  nothing appended) and returned an untruncated 200 whose BODY carries
                  EXPECT, the project number, fed out of band and never in the prompt.
  policy witness  an http_request that POSTs /v1/projects/{id}:getIamPolicy or
                  /v3/projects/{id}:getIamPolicy on the same host, with either the
                  project id or EXPECT in the path since the task has the agent note
                  the number first and the API accepts both, and returned an
                  untruncated 200 whose body is a JSON object. The path already names
                  what a 200 there returns, and a fields selector can omit any one
                  key (?fields=bindings drops etag), so no key is required.

The method and exact path matter. The policy response is on the same host with the
same id in its URL and carries the project number inside the Google-managed
service-agent principals, so a witness that only asked for "a Cloud Resource Manager
200 with the number in its body" would be minted by the policy read alone, and a
prose check on the report would be satisfied by the agent's own description.

Exit 0 when both witnesses exist, else 1, naming the missing one on stderr.

This is deliberately not a call into test/lib/connector_audit: that engine is a
sweep over sanctioned reads and fails closed on an unreadable, malformed,
duplicate-keyed, fold-colliding or unpaired record, which is right when every read
is judged. This suite runs no sweep, so the classifier is LENIENT where the engine
is not: a record it cannot use is skipped, never fatal, because these are
positive-evidence assertions and skipping a record can only make them HARDER to
pass. It is strict about the evidence itself: a status that merely looks like 200,
a truncated body, or the value appearing in a response HEADER rather than the body
must never mint a witness. The helpers mirror the engine's args_of, status_of and
body_of so the two stay readable side by side.
"""
import contextlib
import io
import json
import os
import re
import sys
import tempfile
from urllib.parse import urlparse

CRM = "cloudresourcemanager.googleapis.com"


def _no_dup(pairs):
    """Reject a duplicate JSON key: which value Go bound is decoder-internal, so the
    record is ambiguous and must not be read as evidence."""
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key %r" % k)
        out[k] = v
    return out


def loads(s):
    return json.loads(s, object_pairs_hook=_no_dup)


def text(v):
    return v if isinstance(v, str) else ""


def args_of(rec):
    """The record's arguments with keys case-folded the way Go's encoding/json binds
    them (a miscased "URL" is still the url on the wire), or None when unusable."""
    a = rec.get("arguments")
    if isinstance(a, str):
        try:
            a = loads(a)
        except ValueError:
            return None
    if not isinstance(a, dict):
        return None
    out = {}
    for k, v in a.items():
        f = k.casefold() if isinstance(k, str) else k
        if f in out:
            return None
        out[f] = v
    return out


def result_json(rec):
    """The sandbox path records StructuredRun's JSON as a STRING, so result needs a
    second decode. The direct path records the raw dump, which starts with the status
    line and so can never be mistaken for the structured wrapper."""
    try:
        obj = loads(text(rec.get("result")))
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def status_of(rec):
    obj = result_json(rec)
    # type(x) is int, not isinstance: isinstance(True, int) is True in Python, so an
    # isinstance check would let a JSON bool masquerade as a status.
    if obj is not None and type(obj.get("status")) is int:
        return obj["status"]
    # Anchor on the protocol version and require a boundary after the 3-digit status
    # so "HTTP/1.1 2000" cannot be read as 200.
    m = re.match(r"HTTP/[0-9.]+\s+([0-9]{3})(?![0-9])", text(rec.get("result")))
    return int(m.group(1)) if m else None


def dechunk(body):
    """Undo HTTP/1.1 chunked transfer framing. transport.FormatResponse hands
    httputil.DumpResponse a response whose TransferEncoding still says chunked when
    the provider answered that way, and the dump then re-frames the body in chunks;
    googleapis over HTTP/2 never does, so this is the HTTP/1.1 fallback. Chunk sizes
    count BYTES, so the framing is undone on the UTF-8 bytes of the dump (which
    FormatResponse made valid UTF-8) and decoded afterwards. A body that is not
    well-formed framing comes back unchanged, so the substring checks still see it
    and only the JSON parse of the policy witness can fail on it."""
    out = []
    rest = body.encode("utf-8", "replace")
    while True:
        line, sep, rest = rest.partition(b"\r\n")
        if not sep:
            return body
        try:
            size = int(line.split(b";", 1)[0].strip(), 16)
        except ValueError:
            return body
        if size == 0:
            return b"".join(out).decode("utf-8", "replace")
        if len(rest) < size or rest[size:size + 2] != b"\r\n":
            return body
        out.append(rest[:size])
        rest = rest[size + 2:]


def body_of(rec):
    """(body, truncated). Fail-closed on the structured path: a missing/non-false
    truncated flag, a non-string body or a non-int status counts as truncated. On the
    direct path the dump carries the status line and headers before the body, so cut
    them off - a marker appearing only in a response HEADER is not the provider's
    body and must not satisfy the assertion - and undo chunk framing the headers
    announce, which the shared engine's body_of does not need to (its witnesses are
    substring checks) but the policy witness's JSON parse does."""
    obj = result_json(rec)
    if obj is not None and ("status" in obj or "body" in obj or "truncated" in obj):
        body = obj.get("body")
        ok = (obj.get("truncated") is False and isinstance(body, str)
              and type(obj.get("status")) is int)
        return (body if isinstance(body, str) else ""), (not ok)
    dump = text(rec.get("result"))
    truncated = "[Response truncated at" in dump
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in dump:
            head, body = dump.split(sep, 1)
            if re.search(r"(?im)^transfer-encoding:.*\bchunked\b", head):
                body = dechunk(body)
            return body, truncated
    return "", truncated


def paired_results(raw):
    """(attempt, result) pairs of http_request records, in result order. The url
    comes from the ATTEMPT (write-ahead: it lands before the request runs) and the
    response from the matching RESULT; an unpaired result proves nothing about what
    was dispatched, so it is dropped, as is any line that is not a usable record."""
    attempts = {}
    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("tool") != "http_request":
            continue
        key = (rec.get("session_id"), rec.get("run_id"), rec.get("call_id"))
        if not all(isinstance(k, str) and k for k in key):
            continue
        if rec.get("phase") == "attempt":
            attempts[key] = rec
        elif rec.get("phase") == "result":
            results.append((key, rec))
    out = []
    for key, rec in results:
        attempt = attempts.get(key)
        if attempt is not None:
            out.append((attempt, rec))
    return out


def crm_path(args, methods):
    """The URL path of a Cloud Resource Manager call made with one of methods, or
    None. net/http sends an absent method as GET, so "" is GET. A URL urlparse rejects
    (a stray bracket reads as a bad IPv6 host) is a record that proves nothing,
    skipped like any other unusable one, not a crash that would discard a valid
    witness elsewhere in the log."""
    if text(args.get("method")).upper() not in methods:
        return None
    try:
        u = urlparse(text(args.get("url")))
    except ValueError:
        return None
    if u.hostname != CRM:
        return None
    return u.path


def is_record_witness(attempt, rec, project, expect):
    a = args_of(attempt)
    if a is None:
        return False
    if crm_path(a, ("", "GET")) not in ("/v1/projects/" + project, "/v3/projects/" + project):
        return False
    if status_of(rec) != 200:
        return False
    body, truncated = body_of(rec)
    return not truncated and expect in body


def is_policy_witness(attempt, rec, project, expect):
    """The task has the agent note the project number from the record before it reads
    the policy, and Cloud Resource Manager accepts either the id or the number in
    that path, so both name the fixture here. The record witness stays id-only: the
    id is the scoping key the prompt supplies and the number is what it must earn."""
    a = args_of(attempt)
    if a is None:
        return False
    if crm_path(a, ("POST",)) not in ("/v1/projects/%s:getIamPolicy" % project,
                                      "/v3/projects/%s:getIamPolicy" % project,
                                      "/v1/projects/%s:getIamPolicy" % expect,
                                      "/v3/projects/%s:getIamPolicy" % expect):
        return False
    if status_of(rec) != 200:
        return False
    body, truncated = body_of(rec)
    if truncated:
        return False
    try:
        policy = loads(body)
    except ValueError:
        return False
    return isinstance(policy, dict)


def classify(project, expect, path):
    """(record, policy): whether each witness exists in the audit log at path. An
    unreadable log has neither."""
    try:
        raw = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError):
        return False, False
    record = policy = False
    for attempt, rec in paired_results(raw):
        record = record or is_record_witness(attempt, rec, project, expect)
        policy = policy or is_policy_witness(attempt, rec, project, expect)
    return record, policy


def main(argv):
    if argv == ["--selftest"]:
        return selftest()
    if len(argv) != 3:
        print("usage: agent-witness.py PROJECT EXPECT AUDIT_LOG | --selftest", file=sys.stderr)
        return 2
    project, expect, path = argv
    record, policy = classify(project, expect, path)
    if record:
        print("read witness: OK (a Cloud Resource Manager 200 for the %s project record "
              "carried the expected value)" % project, file=sys.stderr)
    else:
        print("read witness: MISSING (no untruncated Cloud Resource Manager 200 for a GET of "
              "the %s project record carrying the expected value)" % project, file=sys.stderr)
    if policy:
        print("policy witness: OK (a Cloud Resource Manager 200 for the %s project IAM "
              "policy carried a policy object)" % project, file=sys.stderr)
    else:
        print("policy witness: MISSING (no untruncated Cloud Resource Manager 200 for a POST "
              "of the %s project getIamPolicy carrying a policy object)" % project, file=sys.stderr)
    return 0 if record and policy else 1


# --------------------------------------------------------------------------- selftest

P = "demo-proj"
N = "123456789012"
HOST = "https://" + CRM


def _rec(phase, call_id, **fields):
    rec = {"tool": "http_request", "phase": phase, "session_id": "s", "run_id": "r",
           "call_id": call_id}
    rec.update(fields)
    return rec


def _call(call_id, method, url, status=200, body="", truncated=False, headers=None,
          arguments=None, result=None):
    """A paired attempt + structured result, the sandbox shape (arguments and the
    StructuredRun JSON both recorded as strings)."""
    args = {"url": url, "auth_provider": "gcp"} if arguments is None else arguments
    if arguments is None and method is not None:
        args["method"] = method
    if result is None:
        res = {"status": status, "statusText": "%d x" % status,
               "headers": headers or {"Content-Type": ["application/json"]},
               "body": body, "truncated": truncated}
        result = json.dumps(res)
    return [_rec("attempt", call_id, arguments=json.dumps(args)),
            _rec("result", call_id, result=result)]


def _record(call_id="c1", version="v3", method="GET", url=None, **kw):
    url = url or "%s/%s/projects/%s" % (HOST, version, P)
    body = kw.pop("body", json.dumps({"name": "projects/" + N, "projectId": P}))
    return _call(call_id, method, url, body=body, **kw)


def _policy(call_id="c2", version="v1", method="POST", target=P, **kw):
    url = "%s/%s/projects/%s:getIamPolicy" % (HOST, version, target)
    body = kw.pop("body", json.dumps({"etag": "BwXyz", "bindings": [
        {"role": "roles/compute.serviceAgent",
         "members": ["serviceAccount:service-%s@compute-system.iam.gserviceaccount.com" % N]}]}))
    return _call(call_id, method, url, body=body, **kw)


def _lines(*groups):
    out = []
    for g in groups:
        for item in g:
            out.append(item if isinstance(item, str) else json.dumps(item))
    return "\n".join(out) + "\n"


def _dump(status_line, body, truncated=False, chunks=None):
    """A direct-path raw dump: status line, headers, blank line, body. With chunks,
    the body is written in HTTP/1.1 chunk framing of those sizes, as
    httputil.DumpResponse does for a response that arrived chunked."""
    headers = "Content-Type: application/json"
    if chunks:
        # Chunk sizes are byte counts, as Go writes them, so frame the UTF-8 bytes.
        headers += "\r\nTransfer-Encoding: chunked"
        framed = b""
        rest = body.encode("utf-8")
        for n in chunks:
            piece, rest = rest[:n], rest[n:]
            framed += b"%x\r\n%s\r\n" % (len(piece), piece)
        if rest:
            framed += b"%x\r\n%s\r\n" % (len(rest), rest)
        body = (framed + b"0\r\n\r\n").decode("utf-8", "replace")
    dump = "%s\r\n%s\r\n\r\n%s" % (status_line, headers, body)
    if truncated:
        dump += "\n\n... [Response truncated at 10 bytes]"
    return dump


def _cases():
    ok = _record() + _policy()
    yield "both witnesses (v3 record, v1 policy)", ok, (True, True)
    yield "both witnesses (v1 record, v3 policy)", _record(version="v1") + _policy(version="v3"), (True, True)
    yield "record only", _record(), (True, False)
    yield "policy only", _policy(), (False, True)
    yield "policy alone does not mint the record witness even with the number in its body", \
        _policy(), (False, True)
    yield "POST of the record is not the record witness", _record(method="POST") + _policy(), (False, True)
    yield "GET of getIamPolicy is not the policy witness", _record() + _policy(method="GET"), (True, False)
    yield "absent method on the record counts as GET", _record(method=None) + _policy(), (True, True)
    yield "absent method on the policy call is not POST", _record() + _policy(method=None), (True, False)
    yield "query string on the record path", _record(url="%s/v3/projects/%s?alt=json" % (HOST, P)) + _policy(), (True, True)
    yield "malformed bracketed host is skipped, later witnesses count", \
        _record(call_id="c0", url="https://[%s/v3/projects/%s" % (CRM, P)) + ok, (True, True)
    yield "other host is not a witness", _record(url="https://example.com/v3/projects/" + P) + _policy(), (False, True)
    yield "policy read addressed by the project number passes", _record() + _policy(target=N), (True, True)
    yield "policy read of another project does not pass", _record() + _policy(target="other-proj"), (True, False)
    yield "record fetched by number instead of id is not the witness (the id is the scoping key)", \
        _record(url="%s/v3/projects/%s" % (HOST, N)) + _policy(), (False, True)
    yield "record path with a trailing slash is not the record", \
        _record(url="%s/v3/projects/%s/" % (HOST, P)) + _policy(), (False, True)
    yield "record path with an extra segment is not the record", \
        _record(url="%s/v3/projects/%s/x" % (HOST, P)) + _policy(), (False, True)
    yield "structured truncated=true fails the record", _record(truncated=True) + _policy(), (False, True)
    yield "structured truncated=true fails the policy", _record() + _policy(truncated=True), (True, False)
    yield "record body without the number fails", _record(body=json.dumps({"projectId": P})) + _policy(), (False, True)
    yield "number only in a response header is not the body", \
        _record(body="{}", headers={"X-Num": [N]}) + _policy(), (False, True)
    yield "status 201 is not 200", _record(status=201) + _policy(status=201), (False, False)
    yield "policy 403 is not a witness", _record() + _policy(status=403), (True, False)
    yield "policy body with only bindings passes (a fields selector omits etag)", \
        _record() + _policy(body=json.dumps({"bindings": []})), (True, True)
    yield "policy read with ?fields=bindings passes", \
        _record() + _call("c2", "POST", "%s/v1/projects/%s:getIamPolicy?fields=bindings" % (HOST, P),
                          body=json.dumps({"bindings": []})), (True, True)
    yield "policy body that is not JSON fails", _record() + _policy(body="etag: BwXyz"), (True, False)
    yield "policy body that is a JSON list fails", _record() + _policy(body="[]"), (True, False)
    yield "policy body that is a bare JSON string fails", _record() + _policy(body='"etag"'), (True, False)
    yield "policy with no bindings but an etag passes", _record() + _policy(body=json.dumps({"etag": "BwXyz"})), (True, True)
    yield "empty policy object passes", _record() + _policy(body="{}"), (True, True)
    # Structured-result shapes that must not read as 200.
    yield "JSON bool status is not 200", \
        _record(result=json.dumps({"status": True, "body": N, "truncated": False})) + _policy(), (False, True)
    yield "structured result with a missing truncated flag fails closed", \
        _record(result=json.dumps({"status": 200, "body": N})) + _policy(), (False, True)
    # Direct-path raw dumps.
    yield "direct dump 200 with the number in the body passes", \
        _record(result=_dump("HTTP/1.1 200 OK", json.dumps({"name": "projects/" + N}))) + _policy(), (True, True)
    yield "direct dump 'HTTP/1.1 2000' is not 200", \
        _record(result=_dump("HTTP/1.1 2000 OK", N)) + _policy(), (False, True)
    yield "direct dump truncated marker fails", \
        _record(result=_dump("HTTP/1.1 200 OK", N, truncated=True)) + _policy(), (False, True)
    yield "direct dump with the number only in a header fails", \
        _record(result="HTTP/1.1 200 OK\r\nX-Num: %s\r\n\r\n{}" % N) + _policy(), (False, True)
    yield "direct dump with no header separator has no body", \
        _record(result="HTTP/1.1 200 OK\r\nX-Num: %s" % N) + _policy(), (False, True)
    yield "a result that is a JSON list is neither a structured result nor a dump", \
        _record(result=json.dumps([200, N])) + _policy(), (False, True)
    yield "direct dump policy 200 with etag passes", \
        _record() + _policy(result=_dump("HTTP/1.1 200 OK", json.dumps({"etag": "BwXyz"}))), (True, True)
    # Chunked HTTP/1.1 dumps: the framing is undone before the body is judged.
    yield "chunked direct dump policy 200 with etag passes", \
        _record() + _policy(result=_dump("HTTP/1.1 200 OK", json.dumps({"etag": "BwXyz", "bindings": []}), chunks=[5, 7])), (True, True)
    yield "chunked direct dump record with the number split across chunks passes", \
        _record(result=_dump("HTTP/1.1 200 OK", json.dumps({"name": "projects/" + N}), chunks=[20])) + _policy(), (True, True)
    yield "chunked direct dump with the truncated marker fails", \
        _record() + _policy(result=_dump("HTTP/1.1 200 OK", json.dumps({"etag": "BwXyz"}), chunks=[4], truncated=True)), (True, False)
    yield "chunk data not followed by CRLF is left as-is", \
        _record() + _policy(result="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}XX0\r\n\r\n"), (True, False)
    yield "chunk declaring more bytes than remain is left as-is", \
        _record() + _policy(result="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nff\r\n{}\r\n0\r\n\r\n"), (True, False)
    yield "malformed chunk framing is left as-is, so the policy JSON does not parse", \
        _record() + _policy(result="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n{\"etag\": \"BwXyz\"}\r\n0\r\n\r\n"), (True, False)
    yield "chunked policy with a non-ASCII condition title (byte-counted sizes) passes", \
        _record() + _policy(result=_dump("HTTP/1.1 200 OK", json.dumps(
            {"etag": "BwXyz", "bindings": [{"role": "roles/viewer", "members": ["user:a@example.com"],
                                            "condition": {"title": "Acc\u00e8s", "expression": "true"}}]},
            ensure_ascii=False), chunks=[64, 30])), (True, True)
    yield "chunked record whose number follows a multi-byte character passes", \
        _record(result=_dump("HTTP/1.1 200 OK", json.dumps({"displayName": "d\u00e9mo", "name": "projects/" + N},
                                                             ensure_ascii=False), chunks=[10])) + _policy(), (True, True)
    yield "chunked header without framing in the body is left as-is", \
        _record() + _policy(result="HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + json.dumps({"etag": "BwXyz"})), (True, True)
    # Pairing and record hygiene.
    yield "unpaired result proves nothing", [_record()[1]] + _policy(), (False, True)
    yield "arguments that are a JSON list are skipped", \
        [_rec("attempt", "c1", arguments=json.dumps(["GET"])), _record()[1]] + _policy(), (False, True)
    yield "an attempt without arguments is skipped", \
        [_rec("attempt", "c1"), _record()[1]] + _policy(), (False, True)
    yield "attempt without a result proves nothing", [_record()[0]] + _policy(), (False, True)
    yield "empty call id is skipped", \
        [dict(r, call_id="") for r in _record()] + _policy(), (False, True)
    yield "duplicate-key arguments are skipped", \
        [_rec("attempt", "c1", arguments='{"url": "%s/v3/projects/%s", "url": "https://example.com", "method": "GET"}' % (HOST, P)),
         _record()[1]] + _policy(), (False, True)
    yield "fold-colliding argument keys are skipped", \
        [_rec("attempt", "c1", arguments=json.dumps({"url": "https://example.com", "URL": "%s/v3/projects/%s" % (HOST, P), "method": "GET"})),
         _record()[1]] + _policy(), (False, True)
    yield "miscased URL and Method keys still match", \
        [_rec("attempt", "c1", arguments=json.dumps({"URL": "%s/v3/projects/%s" % (HOST, P), "Method": "get"})),
         _record()[1]] + _policy(), (True, True)
    yield "arguments recorded as an object rather than a string", \
        [_rec("attempt", "c1", arguments={"url": "%s/v3/projects/%s" % (HOST, P), "method": "GET"}),
         _record()[1]] + _policy(), (True, True)
    yield "non-JSON lines, blank lines and other tools are ignored", \
        ["not json", "", json.dumps({"tool": "code_execution", "phase": "result", "result": N}), json.dumps([1, 2])] + ok, (True, True)
    yield "a record from another tool with the same call id does not pair", \
        [dict(_record()[0], tool="code_execution"), _record()[1]] + _policy(), (False, True)
    yield "empty log has neither", [], (False, False)


def selftest():
    failures = []
    n = 0
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "audit.log")
        for name, lines, want in _cases():
            n += 1
            with open(path, "w", encoding="utf-8") as f:
                f.write(_lines(lines))
            got = classify(P, N, path)
            if got != want:
                failures.append("%s: want %r got %r" % (name, want, got))
        # An unreadable log has neither witness: missing, or not valid UTF-8.
        n += 1
        if classify(P, N, os.path.join(d, "missing.log")) != (False, False):
            failures.append("missing log: want (False, False)")
        n += 1
        with open(path, "wb") as f:
            f.write(b"\xff\xfe" + _lines(_record() + _policy()).encode("utf-8"))
        if classify(P, N, path) != (False, False):
            failures.append("non-UTF-8 log: want (False, False)")
        # The CLI contract: exit 0 only when both witnesses exist, naming the missing
        # one on stderr.
        n += 1
        with open(path, "w", encoding="utf-8") as f:
            f.write(_lines(_record()))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = main([P, N, path])
        if rc != 1 or "policy witness: MISSING" not in err.getvalue() \
                or "read witness: OK" not in err.getvalue():
            failures.append("cli: record-only log must exit 1 naming the policy witness")
        n += 1
        with open(path, "w", encoding="utf-8") as f:
            f.write(_lines(_record() + _policy()))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = main([P, N, path])
        if rc != 0 or "policy witness: OK" not in err.getvalue():
            failures.append("cli: both witnesses must exit 0")
    for f in failures:
        print("FAIL: " + f, file=sys.stderr)
    if failures:
        return 1
    print("selftest: OK (agent witness: %d cases)" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
