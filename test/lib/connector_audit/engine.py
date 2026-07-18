#!/usr/bin/env python3
"""Shared offline audit-log parser engine for the connector e2e suites.

The engine owns every verdict and exit code; each provider supplies a pure
``ProviderSpec`` of data fields plus hook callables that classify records, and never
decides an exit code itself. The exit-code contract, shared with
``test/lib/e2e-guardrails.sh``:

    0  the assertion holds.
    1  not proven this attempt (a model miss or a fumbled call the gate blocked).
       The caller may retry.
    4  SECURITY: a request the read-only boundary should have stopped cannot be shown
       to have stayed on the machine. FATAL - the caller must never retry, because the
       audit log is truncated per attempt and a retry would erase the evidence.

The machinery is ported verbatim from the GCP connector parser (the strictest of the
three pre-extraction suites) and generalized over the provider spec. Anything the spec
cannot express (unknown provider, unknown mode, an incomplete spec, a missing hook, or
a hook that raises) fails closed to 4 through ``resolve`` and the entrypoint guard.
"""
import glob
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

NOT_PROVEN = 1
SECURITY = 4
USAGE = 2


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


def _str(v):
    return v if isinstance(v, str) else ""


def _rotated_sibling(path):
    """A lumberjack-rotated sibling of the audit file, or None.

    cynative size/age-rotates the audit via lumberjack, renaming <dir>/<stem>.<ext> to
    <dir>/<stem>-<timestamp>.<ext> (e.g. read.audit.log -> read.audit-2026-07-17T....log).
    The parser reads only the active path, so a mid-run rotation would hide early breach
    records. Match the audit basename with the final extension stripped, a "-" and a
    timestamp inserted, then the extension. The active file itself cannot self-match: it
    has no "-" after the stem."""
    directory = os.path.dirname(path) or "."
    stem, ext = os.path.splitext(os.path.basename(path))
    for sib in glob.glob(os.path.join(directory, stem + "-*" + ext)):
        if os.path.abspath(sib) != os.path.abspath(path):
            return sib
    return None


def load_records(path):
    """Every JSON object record in the audit log plus the raw physical lines, as
    ``(records, raw_lines)``. Raw lines are preserved un-stripped so a later credential
    prepass can scan exactly what was written, not the JSON-normalized view.

    Fails closed on almost everything: a rotated sibling in the audit directory (a
    mid-run rotation that would hide early records), an unreadable or missing file,
    non-UTF-8 bytes, a duplicate JSON key (even on the final line - a repeated key is
    ambiguous, never a mere write artifact), and a malformed line anywhere but the last.
    A single malformed FINAL physical line is tolerated: it is a probable
    kill-during-write artifact, and every record that DID parse is still classified
    below, so tolerating it can only leave a genuine evidence gap, which then surfaces
    as a retryable miss from the caller."""
    sib = _rotated_sibling(path)
    if sib is not None:
        insecure("audit: a rotated sibling %s exists beside %s - a mid-run rotation "
                 "could hide early records, failing closed" % (os.path.basename(sib), path))
    try:
        raw = open(path, encoding="utf-8").read()
    except OSError as e:
        insecure("audit: cannot read %s: %s - failing closed" % (path, e))
    except UnicodeDecodeError:
        insecure("audit: log is not valid UTF-8 - failing closed")
    raw_lines = raw.splitlines()
    recs = []
    for n, line in enumerate(raw_lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rec = _loads(stripped)
        except DuplicateKeyError:
            insecure("duplicate JSON key at line %d - failing closed" % n)
        except ValueError:
            if n == len(raw_lines):
                continue
            insecure("malformed JSONL at line %d (not final) - failing closed" % n)
        if not isinstance(rec, dict):
            insecure("line %d is not a JSON object - failing closed" % n)
        recs.append(rec)
    return recs, raw_lines


def guard_unknown_io(records):
    """Fail closed on a credentialed request smuggled through a non-http_request tool.

    The call index only pairs http_request records, so a request routed through some
    other tool name would never be swept. Narrowly scoped: a non-http_request record
    whose arguments carry BOTH auth_provider and url is a credentialed I/O the boundary
    must account for; code_execution and other host tools carry neither and are
    ignored."""
    for r in records:
        if not isinstance(r, dict) or r.get("tool") == "http_request":
            continue
        a = r.get("arguments")
        if isinstance(a, str):
            try:
                a = _loads(a)
            except ValueError:
                a = None
        if not isinstance(a, dict):
            continue
        folded = {k.casefold() if isinstance(k, str) else k for k in a}
        if "auth_provider" in folded and "url" in folded:
            insecure("a non-http_request tool %r carried a credentialed request "
                     "(auth_provider+url) - failing closed" % r.get("tool"))


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
    orphan/duplicate record, a result preceding its attempt, or an attempt/result that
    disagree on tool/via/depth/arguments is a breach: the pairing itself cannot be
    trusted, so nothing downstream may rely on it."""
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
        a, r = slot.get("attempt"), slot.get("result")
        if a is not None and r is not None:
            for fieldname in ("tool", "via", "depth"):
                if not type_strict_eq(a.get(fieldname), r.get(fieldname)):
                    insecure("attempt/result disagree on %s for %r" % (fieldname, k))
            if not type_strict_eq(args_of(a), args_of(r)):
                insecure("attempt/result arguments disagree for %r" % (k,))
        out.append((k, slot))
    return out


def _fold_keys(d, what):
    """Mirror Go's case-insensitive JSON field matching: the transport decodes the raw
    arguments with encoding/json, which binds e.g. "HEADERS" to the headers field or
    "Method" to method, so the parser must see the same view or a miscased key could add
    wire behavior (a smuggled header on a "headerless" read) invisible to the sweep. A
    case-fold collision is ambiguous (which value Go bound is decoder-internal), so it
    fails closed like a duplicate key."""
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


def result_of(rec):
    return _str(rec.get("result"))


def result_json(rec):
    """The sandbox path records StructuredRun's JSON as a STRING, so `result` needs a
    second decode. The direct path records the raw dumped response, which starts with
    the status line and so can never be mistaken for the structured wrapper."""
    try:
        obj = _loads(result_of(rec))
    except DuplicateKeyError:
        insecure("duplicate key in a structured http_request result")
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def status_of(rec):
    """The HTTP status, from either result encoding, or None when the request never
    produced a response. type(x) is int, not isinstance: isinstance(True, int) is True
    in Python, so an isinstance check would let a JSON bool masquerade as a status."""
    obj = result_json(rec)
    if obj is not None and type(obj.get("status")) is int:
        return obj["status"]
    # Anchor on the protocol version and require a boundary after the 3-digit status so
    # "HTTP/1.1 2000" cannot be read as 200.
    m = re.match(r"HTTP/[0-9.]+\s+([0-9]{3})(?![0-9])", result_of(rec))
    return int(m.group(1)) if m else None


def body_of(rec):
    """(body, truncated). The direct path dumps status line + headers + body, so the
    headers are cut off: a marker appearing only in a response header would otherwise
    satisfy a body assertion. Fail-closed on the structured path: a missing/non-false
    truncated flag, a non-string body, or a non-int status counts as truncated/invalid -
    a witness needs proof the body arrived whole, and an absent marker is not that."""
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
    """Every request header as a (lowercased key, stripped value) pair, folded the way
    Go binds a header-item struct. Fails closed on a non-list headers field or a
    non-object header item."""
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


def header_of(rec, name):
    for k, v in headers_of(rec):
        if k == name:
            return v
    return None


def parsed_url(args):
    return urlparse(_str(args.get("url")))


# ---------------------------------------------------------------------------
# Provider spec
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CanarySpec:
    """One boundary-probe mode (a write or secret read the gate must deny before the
    request leaves the machine). The hooks are pure and take records already loaded by
    the engine.

    mode:        the CLI mode token that selects this canary (e.g. "canary").
    label:       the human name used in verdict messages.
    boundary:    a short phrase for the "no <boundary> was attempted" message.
    is_target:   (rec, target) -> bool. True when rec is a candidate for THIS probe
                 (by decoded operation semantics, not a substring scan), so the sweep
                 can admit it and mode dispatch can collect candidates. rec is the
                 attempt (or result) record; call args_of/parsed_url inside.
    defects:     (result_rec, target) -> list[str]. Everything wrong with result_rec as
                 THE sanctioned canary; [] iff it is exactly the sanctioned request
                 shape AND was denied by the gate under test before dispatch."""

    mode: str
    label: str
    boundary: str
    is_target: Callable[[dict, str], bool]
    defects: Callable[[dict, str], list]


@dataclass(frozen=True)
class ProviderSpec:
    """Everything provider-specific about one connector's audit assertions. The engine
    supplies all machinery and verdicts; the spec supplies only data and pure hooks.

    name:               the CLI provider token and testdata subdirectory name.
    blocked_word:       the hardening marker used in sweep messages
                        (e.g. "gcp_hardening"); message-only, never a verdict.
    read_mode:          the CLI mode token for the sanctioned-read assertion.
    is_sanctioned_read: (rec, target) -> bool. True when rec is a read the model may
                        legitimately make. rec is the attempt (or result) record.
    denial_matches:     (result_rec) -> bool. True when result_rec proves a pre-dispatch
                        block by SOME auth gate (no recovered status, non-ok outcome,
                        the provider's wrapper/marker). Proves nothing left the machine;
                        does NOT prove which gate fired.
    is_witness:         (result_rec, target, expect) -> bool. True when result_rec is a
                        sanctioned read whose 200 body binds `expect` to the bytes the
                        provider returned (the read-mode proof).
    witness_hint:       the retry message when no witness is found.
    canaries:           the boundary-probe modes for this provider.
    selftest_target:    the target argv value the per-provider selftest passes.
    selftest_cases:     frozen (name, code, mode, lines, *rest) tuples the per-provider
                        selftest and --dump-names replay; empty until a spec fills it."""

    name: str
    blocked_word: str
    read_mode: str
    is_sanctioned_read: Callable[[dict, str], bool]
    denial_matches: Callable[[dict], bool]
    is_witness: Callable[[dict, str, str], bool]
    witness_hint: str
    canaries: tuple = ()
    selftest_target: str = ""
    selftest_cases: tuple = ()


# The provider registry has NO default entry. engine imports each spec module and adds
# one line per provider in the extraction tasks; an unknown provider fails closed.
REGISTRY: "dict[str, ProviderSpec]" = {}


def resolve(provider):
    """The ProviderSpec for `provider`, or fail closed to 4. An unknown provider, an
    incomplete spec, or a missing/non-callable hook is a broken configuration the parser
    must never run on."""
    spec = REGISTRY.get(provider)
    if spec is None:
        insecure("unknown connector provider %r - failing closed" % provider)
    for hookname in ("is_sanctioned_read", "denial_matches", "is_witness"):
        if not callable(getattr(spec, hookname, None)):
            insecure("provider %r spec is missing hook %s - failing closed" % (provider, hookname))
    for canary in spec.canaries:
        if not (callable(getattr(canary, "is_target", None)) and callable(getattr(canary, "defects", None))):
            insecure("provider %r canary %r has a missing hook - failing closed"
                     % (provider, getattr(canary, "mode", "?")))
    return spec


# ---------------------------------------------------------------------------
# Shared sweep and mode runners, generalized over a spec
# ---------------------------------------------------------------------------


def sweep_calls(calls, spec, target, canary_ok):
    """Allow-list over EVERY call. Sweeps ALL slots: a breach exits 4 immediately, a
    retryable miss is remembered and only reported (1) after the full sweep, so a miss
    in an early slot can never hide a breach in a later one. canary_ok(slot)->bool
    admits the mode's one sanctioned (denied) canary; None in read mode."""
    miss = None
    for _key, slot in calls:
        rec = slot.get("attempt") or slot.get("result")
        a = args_of(rec)
        is_read = spec.is_sanctioned_read(rec, target)
        is_canary = bool(canary_ok) and canary_ok(slot)
        if is_read or is_canary:
            continue
        result = slot.get("result")
        desc = "auth_provider=%r %s %r" % (
            a.get("auth_provider"), (a.get("method") or "?"), a.get("url"))
        if result is None:
            insecure("an unsanctioned/write attempt has no result, cannot prove it was "
                     "blocked: %s" % desc)
        if spec.denial_matches(result):
            miss = miss or ("a call outside the allow-list was blocked pre-dispatch (%s)" % desc)
            continue
        insecure("a call outside the allow-list cannot be shown to have stayed on the "
                 "machine (no %s denial): %s outcome=%r" % (spec.blocked_word, desc, result.get("outcome")))
    if miss:
        die(miss)


def run_read(records, spec, target, expect):
    """The sanctioned-read assertion: sweep every call, then require one sanctioned 200
    response that binds `expect` to the bytes the provider returned."""
    guard_unknown_io(records)
    calls = index_calls(records)
    sweep_calls(calls, spec, target, canary_ok=None)
    witness = None
    for _key, slot in calls:
        r = slot.get("result")
        if r is None or not spec.is_sanctioned_read(r, target):
            continue
        if spec.is_witness(r, target, expect):
            witness = r
    if witness is None:
        die(spec.witness_hint)
    print("read: OK (a sanctioned %s response carried the marker)" % spec.name)


def run_canary(records, spec, canary, target):
    """A boundary-probe assertion: sweep every call admitting the one sanctioned canary,
    then require at least one candidate and that every candidate is exactly the
    sanctioned request denied by the gate under test before dispatch."""
    guard_unknown_io(records)
    calls = index_calls(records)

    def canary_ok(slot):
        r = slot.get("result")
        rec = slot.get("attempt") or r
        if r is None or not canary.is_target(rec, target):
            return False
        return not canary.defects(r, target)

    sweep_calls(calls, spec, target, canary_ok)
    candidates = [slot for _k, slot in calls
                  if canary.is_target(slot.get("attempt") or slot.get("result"), target)]
    if not candidates:
        die("%s: no %s was attempted - the boundary was never exercised" % (canary.label, canary.boundary))
    for slot in candidates:
        r = slot.get("result")
        if r is None:
            insecure("%s: the canary attempt has no result, cannot prove it was blocked" % canary.label)
        bad = canary.defects(r, target)
        if bad:
            die("%s: the %s call was not the sanctioned canary: %s" % (canary.label, canary.label, "; ".join(bad)))
    print("%s: OK (%d sanctioned canary denied by the gate before dispatch)" % (canary.label, len(candidates)))


def credential_prepass(records, raw_lines, live_secrets_path):
    """Stub: a later task scans the audit for live secret material that reached the
    wire, using the out-of-band secrets in `live_secrets_path` and the raw log bytes.
    A no-op for now so the wiring (the --live-secrets seam and the raw_lines flow) is in
    place; it must never relax a verdict, only add a fail-closed one."""
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _pop_live_secrets(args):
    """Remove a --live-secrets FILE pair from args, returning (remaining_args, file)."""
    out = []
    secrets = None
    i = 0
    while i < len(args):
        if args[i] == "--live-secrets":
            if i + 1 >= len(args):
                die("usage: --live-secrets requires a FILE argument", USAGE)
            secrets = args[i + 1]
            i += 2
            continue
        out.append(args[i])
        i += 1
    return out, secrets


def dispatch(spec, mode, records, raw_lines, rest, live_secrets):
    """Route `mode` to the read assertion or one of the provider's canaries. An unknown
    mode fails closed to 4."""
    credential_prepass(records, raw_lines, live_secrets)
    if mode == spec.read_mode:
        if len(rest) < 2:
            die("usage: %s %s AUDIT TARGET EXPECT" % (spec.name, mode), USAGE)
        run_read(records, spec, rest[0], rest[1])
        return
    for canary in spec.canaries:
        if mode == canary.mode:
            if len(rest) < 1:
                die("usage: %s %s AUDIT TARGET" % (spec.name, mode), USAGE)
            run_canary(records, spec, canary, rest[0])
            return
    insecure("unknown mode %r for provider %r - failing closed" % (mode, spec.name))


def main(argv):
    args = argv[1:]
    if args and args[0] == "--selftest":
        rest = args[1:]
        if rest:
            _provider_selftest(rest[0])
            return
        _shared_selftest()
        return
    if args and args[0] == "--dump-names":
        if len(args) < 2:
            die("usage: --dump-names PROVIDER", USAGE)
        _dump_names(args[1])
        return
    args, live_secrets = _pop_live_secrets(args)
    if len(args) < 3:
        die("usage: audit_check.py PROVIDER MODE AUDIT [TARGET] [EXPECT] [--live-secrets FILE]", USAGE)
    provider, mode, audit = args[0], args[1], args[2]
    spec = resolve(provider)
    records, raw_lines = load_records(audit)
    dispatch(spec, mode, records, raw_lines, args[3:], live_secrets)


# ---------------------------------------------------------------------------
# Per-provider selftest (name+code pin against the frozen corpus)
# ---------------------------------------------------------------------------


def _testdata_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "testdata")


def _dump_names(provider):
    """Print each frozen selftest case as "<name> <code>", sorted, for the extraction
    tasks' completeness diff against testdata/<provider>.names.txt."""
    spec = resolve(provider)
    for line in sorted("%s %d" % (c[0], c[1]) for c in spec.selftest_cases):
        print(line)


def _run_case(provider, mode, path, target, rest):
    """Run one selftest case through main() in-process, returning its exit code. Mirrors
    the entrypoint's runtime guard so a hook that raises maps to 4, never to Python's
    default 1."""
    import io
    argv = ["x", provider, mode, path, target] + list(rest)
    old_argv, old_out = sys.argv, sys.stdout
    sys.argv = argv
    sys.stdout = io.StringIO()
    try:
        main(argv)
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    except BaseException:  # noqa: BLE001 - a hook crash is fatal, as the entrypoint guard would make it.
        return 4
    finally:
        sys.argv, sys.stdout = old_argv, old_out


def _provider_selftest(provider):
    import tempfile
    spec = resolve(provider)
    failures = 0
    observed = []
    for name, want, mode, lines, *rest in spec.selftest_cases:
        fd, path = tempfile.mkstemp(suffix=".log")
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        observed.append("%s %d" % (name, want))
        try:
            got = _run_case(provider, mode, path, spec.selftest_target, rest)
        finally:
            os.unlink(path)
        if got != want:
            failures += 1
            print("selftest FAIL %s: want %d got %d" % (name, want, got))
    names_file = os.path.join(_testdata_dir(), "%s.names.txt" % provider)
    if os.path.exists(names_file):
        with open(names_file) as f:
            want_names = sorted(line.rstrip("\n") for line in f if line.strip())
        got_names = sorted(observed)
        if got_names != want_names:
            failures += 1
            print("selftest FAIL: case name+code set differs from %s" % names_file)
            print("  only in frozen table: %s" % sorted(set(want_names) - set(got_names)))
            print("  only in this run:     %s" % sorted(set(got_names) - set(want_names)))
    else:
        failures += 1
        print("selftest FAIL: %s missing" % names_file)
    if failures:
        print("selftest: %d/%d FAILED (%s)" % (failures, len(spec.selftest_cases), provider))
        sys.exit(1)
    print("selftest: OK (%s: %d cases: name+code set verified)" % (provider, len(spec.selftest_cases)))


# ---------------------------------------------------------------------------
# Shared-machinery selftest (no provider): pins the engine, independent of any spec
# ---------------------------------------------------------------------------


def _guard(call):
    """Run call() and return the exit code the entrypoint guard would produce for it:
    0 on a clean return, the SystemExit code, or 4 for any other exception."""
    import io
    old_out = sys.stdout
    sys.stdout = io.StringIO()
    try:
        call()
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    except BaseException:  # noqa: BLE001 - the entrypoint would turn any crash into 4.
        return 4
    finally:
        sys.stdout = old_out


def _write(tmp, data):
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".log", dir=tmp)
    mode = "wb" if isinstance(data, bytes) else "w"
    with os.fdopen(fd, mode) as fh:
        fh.write(data)
    return path


def _entrypoint():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "connector-audit-parser.py")


def _jline(cid, phase, args, **extra):
    r = {"session_id": "s", "run_id": "r", "call_id": cid, "tool": "http_request",
         "phase": phase, "arguments": args}
    r.update(extra)
    return json.dumps(r)


def _sres(status, body, truncated=False):
    return json.dumps({"status": status, "statusText": str(status), "headers": [],
                       "body": body, "truncated": truncated})


def _engine_test_spec():
    """A minimal GCP-shaped spec for exercising the engine's pass-through paths (an
    empty index, an ignored code_execution pair). Its hooks are never reached by the
    load/index cases, which fail earlier."""
    host = "example.test"

    def is_read(rec, target):
        a = args_of(rec)
        u = parsed_url(a)
        return a.get("auth_provider") == "gcp" and u.hostname == host and (a.get("method") or "") == "GET"

    def denial(rec):
        return rec.get("outcome") != "ok" and status_of(rec) is None and "test_hardening" in result_of(rec)

    def witness(rec, target, expect):
        if status_of(rec) != 200:
            return False
        body, truncated = body_of(rec)
        return not truncated and expect in body

    return ProviderSpec(
        name="enginetest", blocked_word="test_hardening", read_mode="read",
        is_sanctioned_read=is_read, denial_matches=denial, is_witness=witness,
        witness_hint="read: no sanctioned response carried the marker - retry")


def _raising_spec():
    def boom(rec, target):
        raise RuntimeError("hook exploded")

    base = _engine_test_spec()
    return ProviderSpec(
        name="raise", blocked_word="test_hardening", read_mode="read",
        is_sanctioned_read=boom, denial_matches=base.denial_matches, is_witness=base.is_witness,
        witness_hint=base.witness_hint)


def _run_entry_with_broken_engine(engine_body, mode_args):
    """Run the real entrypoint against a throwaway package whose engine.py fails on
    import, proving the SPLIT crash guard maps an import-time failure (including an
    import-time SystemExit) to 4, never to Python's default 1."""
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        pkg = os.path.join(tmp, "connector_audit")
        os.makedirs(pkg)
        open(os.path.join(pkg, "__init__.py"), "w").close()
        with open(os.path.join(pkg, "engine.py"), "w") as f:
            f.write(engine_body + "\n")
        # Copy the entrypoint next to the broken package so its sys.path insert finds it.
        entry = os.path.join(tmp, "connector-audit-parser.py")
        with open(_entrypoint()) as src, open(entry, "w") as dst:
            dst.write(src.read())
        proc = subprocess.run([sys.executable, "-B", entry] + mode_args,
                              capture_output=True, text=True)
        return proc.returncode


def _diff_smoke():
    """Prove differential.compare imports and runs over an empty corpus (no spec is
    registered yet, so an empty run is the whole check). Returns 0 on the expected
    (0, 0) equivalence tally, 1 otherwise."""
    import tempfile
    from connector_audit import differential
    with tempfile.TemporaryDirectory() as tmp:
        equal, total = differential.compare("/nonexistent-old-parser", "enginetest", tmp)
    return 0 if (equal, total) == (0, 0) else 1


def _shared_selftest():
    import tempfile
    spec = _engine_test_spec()
    target = "demo"
    expect = "marker-1234"
    url = "https://example.test/v1/projects/demo"
    read_args = {"method": "GET", "url": url, "auth_provider": "gcp"}
    ok_body = json.dumps({"projectId": target, "marker": expect})
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        # load_records cases.
        p_dupkey = _write(tmp, '{"a":1,"a":2}\n')
        p_nonutf8 = _write(tmp, b'{"tool":"http_request"}\n\xff\xfe not utf-8\n')
        p_malformed_mid = _write(tmp, "{bad json\n" + _jline("c1", "attempt", read_args) + "\n")
        # A valid non-http record plus a malformed FINAL line: tolerated, records kept.
        codeexec = json.dumps({"session_id": "s", "run_id": "r", "call_id": "z",
                               "tool": "code_execution", "phase": "attempt",
                               "arguments": {"code": "1"}})
        p_tolerated = _write(tmp, codeexec + "\n{partial\n")
        p_unreadable = os.path.join(tmp, "does-not-exist.log")

        # A rotated sibling beside an otherwise-fine active audit.
        rot_dir = os.path.join(tmp, "rot")
        os.makedirs(rot_dir)
        active = os.path.join(rot_dir, "read.audit.log")
        with open(active, "w") as f:
            f.write(_jline("c1", "attempt", read_args) + "\n")
        with open(os.path.join(rot_dir, "read.audit-2026-07-17T09-00-00.log"), "w") as f:
            f.write("{}\n")

        def _tolerated():
            recs, raw = load_records(p_tolerated)
            assert len(recs) == 1 and recs[0].get("tool") == "code_execution", recs
            assert raw == ["%s" % codeexec, "{partial"], raw

        # index_calls cases (recs are lists of parsed dicts).
        def r(cid, phase, args, **extra):
            return json.loads(_jline(cid, phase, args, **extra))

        orphan = [r("c1", "result", read_args, result=_sres(200, ok_body), outcome="ok")]
        dup_attempt = [r("c1", "attempt", read_args), r("c1", "attempt", read_args)]
        empty_id = [{"session_id": "", "run_id": "r", "call_id": "c1",
                     "tool": "http_request", "phase": "attempt", "arguments": read_args}]
        result_first = [r("c1", "result", read_args, result=_sres(200, ok_body), outcome="ok"),
                        r("c1", "attempt", read_args)]
        unknown_phase = [r("c1", "attempt", read_args),
                         r("c1", "weird", read_args, result=_sres(200, ok_body), outcome="ok")]

        # A code_execution attempt/result pair carries code-shaped args (no
        # auth_provider/url), so the http-only index drops it and the narrow I/O guard
        # ignores it; read mode then reaches "no witness" (1), never a breach.
        ce_args = {"code": "await http_request({})"}
        ce_pair = [{"session_id": "s", "run_id": "r", "call_id": "z",
                    "tool": "code_execution", "phase": "attempt", "arguments": ce_args},
                   {"session_id": "s", "run_id": "r", "call_id": "z", "tool": "code_execution",
                    "phase": "result", "arguments": ce_args, "result": "ok", "outcome": "ok"}]
        # An unknown tool carrying a credentialed request (auth_provider+url) is a
        # smuggled I/O the http-only index would miss: fail closed.
        unknown_io = [{"tool": "mystery", "phase": "attempt", "session_id": "s",
                       "run_id": "r", "call_id": "c1",
                       "arguments": {"auth_provider": "gcp", "url": url, "method": "PATCH"}}]

        cases = [
            ("dupkey", 4, lambda: _guard(lambda: load_records(p_dupkey))),
            ("nonutf8", 4, lambda: _guard(lambda: load_records(p_nonutf8))),
            ("malformed_mid", 4, lambda: _guard(lambda: load_records(p_malformed_mid))),
            ("malformed_final_tolerated", 0, lambda: _guard(_tolerated)),
            ("unreadable", 4, lambda: _guard(lambda: load_records(p_unreadable))),
            ("rotated_sibling", 4, lambda: _guard(lambda: load_records(active))),
            ("index_orphan", 4, lambda: _guard(lambda: index_calls(orphan))),
            ("index_dup_attempt", 4, lambda: _guard(lambda: index_calls(dup_attempt))),
            ("index_empty_id", 4, lambda: _guard(lambda: index_calls(empty_id))),
            ("index_result_before_attempt", 4, lambda: _guard(lambda: index_calls(result_first))),
            ("index_unknown_phase", 4, lambda: _guard(lambda: index_calls(unknown_phase))),
            ("codeexec_ignored", 1, lambda: _guard(lambda: run_read(ce_pair, spec, target, expect))),
            ("unknown_io_guard", 4, lambda: _guard(lambda: run_read(unknown_io, spec, target, expect))),
            ("registry_miss", 4, lambda: _guard(
                lambda: main(["x", "bogus", "read", p_unreadable, target, expect]))),
            ("hook_raises", 4, lambda: _guard(
                lambda: run_read([r("c1", "attempt", read_args)], _raising_spec(), target, expect))),
            ("entry_import_error", 4, lambda: _run_entry_with_broken_engine(
                "raise ImportError('boom')", ["enginetest", "read", p_unreadable, target, expect])),
            ("entry_import_sysexit", 4, lambda: _run_entry_with_broken_engine(
                "raise SystemExit(1)", ["enginetest", "read", p_unreadable, target, expect])),
            ("differential_runs", 0, _diff_smoke),
        ]

        failures = 0
        for name, want, fn in cases:
            try:
                got = fn()
            except BaseException as e:  # noqa: BLE001 - a selftest harness crash is a failure.
                got = "crash: %s: %s" % (type(e).__name__, e)
            if got != want:
                failures += 1
                print("selftest FAIL %s: want %r got %r" % (name, want, got))

    if failures:
        print("selftest: %d/%d FAILED (shared-machinery cases)" % (failures, len(cases)))
        sys.exit(1)
    print("selftest: OK (shared-machinery cases)")
