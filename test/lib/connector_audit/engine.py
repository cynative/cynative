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
import base64
import glob
import json
import os
import re
import sys
from dataclasses import dataclass, replace
from typing import Callable
from urllib.parse import quote_plus, unquote_plus, urlparse

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
    ignored.

    A lookup_read record whose via is api_reference is skipped here because
    sweep_lookup_reads judges it, in every mode. One with any other via, including a
    model's call to an invented tool of that name, which the loop records with no via, is
    still a smuggled request."""
    for r in records:
        if not isinstance(r, dict) or r.get("tool") == "http_request":
            continue
        if r.get("tool") == LOOKUP_READ and r.get("via") == VIA_API_REFERENCE:
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
    """Ordered list of (key, {attempt, result, attempt_pos, result_pos}) for every
    http_request call, keyed by (session_id, run_id, call_id). A missing id component, an
    unknown phase, an orphan/duplicate record, a result preceding its attempt, or an
    attempt/result that disagree on tool/via/depth/arguments is a breach: the pairing
    itself cannot be trusted, so nothing downstream may rely on it.

    `attempt_pos`/`result_pos` are the record's index within the http_request record
    SEQUENCE, so a spec that must prove one call was adjudicated before another was even
    attempted (a two-hop read whose second hop may only target an endpoint an earlier hop
    established) has a real ordering to check. It is the physical write order of the audit,
    not a timestamp: concurrent sandbox calls interleave, and a clock is not evidence.

    `attempt_at`/`result_at` are the same records' indices in the FULL record list, so an
    http_request can be ordered against the api_reference and lookup_read records rule (a)
    judges, which the http-only positions cannot do."""
    calls = {}
    order = []
    pos = -1
    for at, r in enumerate(recs):
        if r.get("tool") != "http_request":
            continue
        pos += 1
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
            slot["attempt_pos"] = pos
            slot["attempt_at"] = at
        elif phase == "result":
            if "attempt" not in slot:
                insecure("result without a preceding attempt for %r" % (key,))
            if "result" in slot:
                insecure("duplicate result for %r" % (key,))
            slot["result"] = r
            slot["result_pos"] = pos
            slot["result_at"] = at
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
class LookupTarget:
    """One target the audit log already binds, for rule (a): a lookup_read is admitted only
    when some LookupTarget names its auth_provider and URL authority, accepts its arguments,
    and was established at a full-record position before the read's attempt.

    auth_provider: the connector the read must name, e.g. "gke".
    authority:     the bare authority the read's URL must carry, compared as a string.
    auth_matches:  (folded child arguments) -> bool. True when the read's auth block names
                   exactly the bound target.
    position:      the index, in the full record list, of the record that established the
                   target (GKE: the hop-1 result)."""

    auth_provider: str
    authority: str
    auth_matches: Callable[[dict], bool]
    position: int


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
                        Per-record and context-free; a connector whose sanctioning depends
                        on OTHER calls supplies plan_reads instead (see below). It MUST be
                        a pure function of the record's ARGUMENTS - never its outcome,
                        status or body - because default_read_plan evaluates it once per
                        call (on the attempt) and reuses that one verdict for both the
                        sweep exemption and witness candidacy, where the pre-plan engine
                        evaluated it twice, on the attempt and then on the result.
                        index_calls already fails closed when a paired attempt and result
                        disagree on arguments, so for an argument-only predicate the two
                        are identical; a predicate that read the result would silently
                        change meaning.
    plan_reads:         optional (calls, target) -> set of sanctioned call keys, replacing
                        the per-record default. It exists because sanctioning is a SECURITY
                        decision, not a convenience: sweep_calls exempts a sanctioned call
                        from the fatal unsanctioned sweep WITHOUT looking at its result, so
                        anything the read family admits can no longer be caught having
                        succeeded. A connector whose read is only legitimate relative to an
                        earlier call (a two-hop read whose second hop must target an
                        endpoint an earlier hop established) therefore has to decide that
                        BEFORE the sweep, never afterwards: checking it after would
                        downgrade a successful unbound request to a retryable miss, and the
                        per-attempt audit truncation would erase it on retry.
                        None means default_read_plan, i.e. exactly the per-record
                        is_sanctioned_read behavior.
    denial_matches:     (result_rec) -> bool. True when result_rec proves a pre-dispatch
                        block by SOME auth gate (no recovered status, non-ok outcome,
                        the provider's wrapper/marker). Proves nothing left the machine;
                        does NOT prove which gate fired.
    is_witness:         (result_rec, target, expect) -> bool. True when result_rec is a
                        sanctioned read whose 200 body binds `expect` to the bytes the
                        provider returned (the read-mode proof).
    witness_hint:       the retry message when no witness is found.
    canaries:           the boundary-probe modes for this provider.
    selftest_target:    the default target argv value the per-provider selftest passes.
    selftest_targets:   optional ((case_name, target), ...) overrides of selftest_target,
                        for a provider whose modes do not share one target. GKE's read
                        target deliberately omits the control-plane endpoint (only hop-1
                        bytes may bind it) while its canary targets carry it, so one
                        target cannot drive both; and the cases that pin a WRONG target
                        arity need their own value per case, not per mode. Empty for a
                        provider whose modes share one target.
    lookup_targets:     optional (calls, target) -> list of LookupTarget, the targets a
                        lookup_read may be bound to (rule (a), condition 6). None binds
                        nothing, so a successful lookup read exits 4 and a denied one is a
                        retryable miss.
    selftest_cases:     frozen (name, code, mode, lines, *rest) tuples the per-provider
                        selftest and --dump-names replay; empty until a spec fills it.
                        lines is normally a list of JSONL strings (joined with a
                        newline and written as text); it may also be `bytes` (written
                        verbatim, for a case that needs invalid UTF-8) or `None` (the
                        case's audit path must not exist, e.g. AWS's frozen
                        read_unreadable)."""

    name: str
    blocked_word: str
    read_mode: str
    is_sanctioned_read: Callable[[dict, str], bool]
    denial_matches: Callable[[dict], bool]
    is_witness: Callable[[dict, str, str], bool]
    witness_hint: str
    canaries: tuple = ()
    plan_reads: "Callable[[list, str], set] | None" = None
    lookup_targets: "Callable[[list, str], list] | None" = None
    selftest_target: str = ""
    selftest_targets: tuple = ()
    selftest_cases: tuple = ()


# The provider registry has NO default entry. engine imports each spec module and adds
# one line per provider in the extraction tasks; an unknown provider fails closed.
REGISTRY: "dict[str, ProviderSpec]" = {}

from .specs import aws, gcp, github, gke  # noqa: E402 - registered after ProviderSpec is defined.

REGISTRY["aws"] = aws.SPEC
REGISTRY["gcp"] = gcp.SPEC
REGISTRY["github"] = github.SPEC
REGISTRY["gke"] = gke.SPEC


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
    # plan_reads is optional, but a spec that SET it to a non-callable would silently fall
    # back to the per-record default and lose exactly the contextual sanctioning it was
    # added for, so a present-but-unusable value fails closed like a missing hook.
    if getattr(spec, "plan_reads", None) is not None and not callable(spec.plan_reads):
        insecure("provider %r spec has a non-callable plan_reads - failing closed" % provider)
    if getattr(spec, "lookup_targets", None) is not None and not callable(spec.lookup_targets):
        insecure("provider %r spec has a non-callable lookup_targets - failing closed" % provider)
    for canary in spec.canaries:
        if not (callable(getattr(canary, "is_target", None)) and callable(getattr(canary, "defects", None))):
            insecure("provider %r canary %r has a missing hook - failing closed"
                     % (provider, getattr(canary, "mode", "?")))
    return spec


# ---------------------------------------------------------------------------
# Shared sweep and mode runners, generalized over a spec
# ---------------------------------------------------------------------------


def default_read_plan(calls, spec, target):
    """The sanctioned-read key set for a spec with no plan_reads: exactly the per-record
    is_sanctioned_read verdict, evaluated on the attempt (or, for an unadjudicated call,
    the result). One decision per call, reused by the sweep and by witness candidacy, so
    the two can never disagree about what was sanctioned - index_calls already fails closed
    when an attempt and its result disagree on arguments, and every per-record predicate
    reads only arguments, so the single evaluation is equivalent to the two it replaces."""
    planned = set()
    for key, slot in calls:
        rec = slot.get("attempt") or slot.get("result")
        if spec.is_sanctioned_read(rec, target):
            planned.add(key)
    return planned


def read_plan(calls, spec, target):
    """The sanctioned-read key set for this spec: its own contextual plan_reads when it has
    one, else the per-record default. Fails closed on a plan that is not a set of keys the
    index actually holds, since a plan that invented a key would exempt a call nobody can
    point at, and one that returned a non-collection would make `key in planned` silently
    false-y or raise."""
    if spec.plan_reads is None:
        return default_read_plan(calls, spec, target)
    planned = spec.plan_reads(calls, target)
    if not isinstance(planned, (set, frozenset)):
        insecure("provider %r plan_reads returned %r, want a set of call keys - failing "
                 "closed" % (spec.name, type(planned).__name__))
    known = {key for key, _slot in calls}
    unknown = planned - known
    if unknown:
        insecure("provider %r plan_reads sanctioned %d call key(s) the audit does not hold "
                 "- failing closed" % (spec.name, len(unknown)))
    return planned


def redacted_url(raw):
    """scheme://authority/path for a request URL: userinfo, query and fragment removed,
    everything else preserved byte for byte, and the result escaped to pure ASCII.

    Cut out of the RAW string rather than reassembled from urlparse's pieces. Reassembly
    loses what a maintainer reading this line is usually chasing: an IPv6 literal's
    brackets, an explicit :0, the host's exact spelling (#308, #334 turn on exactly that),
    and a trailing bare ";" that distinguishes two S3 object keys.

    Userinfo is a credential the prepass deliberately does not detect (it is excluded from
    the positional rules), and a query can carry a signing or session param, so neither may
    reach a CI log: redacting the defect suffix alone would leave the secret earlier on the
    same line. The path stays, because it is what identifies the call; an opaque token
    embedded in a path is therefore still printed, and the audit log holds it either way.

    The ASCII escape is load-bearing, not cosmetic. A verdict is printed, and under an
    ASCII stdout a non-ASCII URL would raise UnicodeEncodeError, which the phase runner
    turns into exit 4: a retryable miss would become a fatal, never-retried breach."""
    s = _str(raw).split("#", 1)[0].split("?", 1)[0]
    scheme, sep, rest = s.partition("://")
    if not sep or not scheme:
        return "<unparseable url>"
    authority, slash, path = rest.partition("/")
    authority = authority.rsplit("@", 1)[-1]
    if not authority:
        return "<unparseable url>"
    out = "%s://%s%s%s" % (scheme, authority, slash, path)
    return out.encode("ascii", "backslashreplace").decode("ascii")


def sweep_calls(calls, spec, planned, canary_ok, explain=None):
    """Allow-list over EVERY call. Sweeps ALL slots: a breach exits 4 immediately, a
    retryable miss is remembered and only reported (1) after the full sweep, so a miss
    in an early slot can never hide a breach in a later one. `planned` is the sanctioned
    read key set from read_plan; canary_ok(slot)->bool admits the mode's one sanctioned
    (denied) canary; None in read mode.

    explain(slot)->str|None returns a suffix saying why a denied call was not the
    sanctioned canary. A miss carrying one is preferred over a bare miss, because this
    single line is the whole diagnosis in a CI log: the run dies here and never reaches
    run_canary's own defect message. It only ever ADDS text to a verdict the sweep had
    already reached, so it cannot change an exit code."""
    miss = None
    explained = None
    for key, slot in calls:
        rec = slot.get("attempt") or slot.get("result")
        a = args_of(rec)
        is_read = key in planned
        is_canary = bool(canary_ok) and canary_ok(slot)
        if is_read or is_canary:
            continue
        result = slot.get("result")
        desc = "auth_provider=%r %s %r" % (
            a.get("auth_provider"), (a.get("method") or "?"), redacted_url(a.get("url")))
        if result is None:
            insecure("an unsanctioned/write attempt has no result, cannot prove it was "
                     "blocked: %s" % desc)
        if spec.denial_matches(result):
            text = "a call outside the allow-list was blocked pre-dispatch (%s)" % desc
            if explain and not explained:
                why = explain(slot)
                if why:
                    explained = text + why
            miss = miss or text
            continue
        insecure("a call outside the allow-list cannot be shown to have stayed on the "
                 "machine (no %s denial): %s outcome=%r" % (spec.blocked_word, desc, result.get("outcome")))
    if explained or miss:
        die(explained or miss)


# ---------------------------------------------------------------------------
# Rule (a): the credentialed reads a targeted api_reference lookup makes
# ---------------------------------------------------------------------------

LOOKUP_READ = "lookup_read"
VIA_API_REFERENCE = "api_reference"
API_REFERENCE = "api_reference"
DECISION_UNPROMPTED = "unprompted"
# The connectors whose lookups read a cluster. azure is admitted only once its own rule
# lands, because its reads carry blocks that differ per read.
LOOKUP_PROVIDERS = frozenset(("eks", "gke", "aks", "kubernetes"))
# The http_request argument keys a lookup read may carry besides its <auth_provider>_auth
# block. There is no body key, so nothing but a GET with one header reaches the cluster.
_LOOKUP_ARG_KEYS = frozenset(("method", "url", "headers", "timeout_seconds",
                              "max_response_body_size", "auth_provider"))
_LOOKUP_HEADERS = [{"key": "Accept", "value": "application/json"}]
# The most reads of each kind one lookup makes: the root twice (the stale-hash re-read), the
# document three times (hashed, re-hashed, unhashed) and /version once. They sum to the
# reader's whole budget of 6, so a seventh read always exceeds one of them.
LOOKUP_BUDGET = {"root": 2, "document": 3, "version": 1}

# One lookup read URL, matched against the WHOLE raw string, as hop2_url is compared: https,
# an authority from a conservative alphabet with no userinfo, then exactly /version,
# /openapi/v3, or one group-version document with an optional upper-case 128-character hash.
# The group and version pieces are then held to the Go grammars below.
_LOOKUP_URL_RE = re.compile(
    r"https://(?P<authority>[A-Za-z0-9.:\[\]-]+)"
    r"(?:(?P<version_path>/version)|(?P<root>/openapi/v3)"
    r"|/openapi/v3/(?:api/(?P<core>[^/?#]+)|apis/(?P<group>[^/?#]+)/(?P<version>[^/?#]+))"
    r"(?:\?hash=[0-9A-F]{128})?)")
# internal/auth/k8s/openapi_root.go: a version is a DNS-1035 label, a group a DNS-1123
# subdomain, with the same byte limits.
_K8S_VERSION_RE = re.compile(r"[a-z]([-a-z0-9]{0,61}[a-z0-9])?")
_K8S_GROUP_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?(\.[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?)*")
_K8S_MAX_VERSION = 63
_K8S_MAX_GROUP = 253


def _valid_version(s):
    return len(s) <= _K8S_MAX_VERSION and _K8S_VERSION_RE.fullmatch(s) is not None


def _valid_group(s):
    return len(s) <= _K8S_MAX_GROUP and _K8S_GROUP_RE.fullmatch(s) is not None


def lookup_doc_key(model):
    """The document key Go's k8s.ParseAPIVersion builds from model, or None where it refuses
    the model. It mirrors that function exactly: a model with no "/" is a core version
    (api/<v>); otherwise the text before the first "/" is the group, so "core/v1" is a group
    named core (apis/core/v1), as the Go side reads it."""
    if not isinstance(model, str):
        return None
    group, sep, version = model.partition("/")
    if not sep:
        return "api/" + model if _valid_version(model) else None
    if not (_valid_group(group) and _valid_version(version)):
        return None
    return "apis/%s/%s" % (group, version)


def lookup_url(url):
    """(authority, kind, document key) for a lookup read URL, kind one of root, document and
    version, the key None except for a document. None when the URL is not one of those
    shapes exactly."""
    m = _LOOKUP_URL_RE.fullmatch(_str(url))
    if m is None:
        return None
    authority = m.group("authority")
    if m.group("version_path"):
        return authority, "version", None
    if m.group("root"):
        return authority, "root", None
    core, group, version = m.group("core"), m.group("group"), m.group("version")
    if core is not None:
        key = lookup_doc_key(core)
    else:
        key = lookup_doc_key(group + "/" + version)
    if key is None:
        return None
    return authority, "document", key


def _object_args(rec, what):
    """A record's arguments as a case-folded object, failing closed on anything else."""
    a = rec.get("arguments")
    if isinstance(a, str):
        try:
            a = _loads(a)
        except ValueError:
            insecure("unparseable %s arguments" % what)
    if not isinstance(a, dict):
        insecure("%s arguments are not an object" % what)
    return _fold_keys(a, what + " arguments")


def index_lookup_reads(records):
    """Ordered (key, slot) pairs for every lookup_read record whose via is api_reference,
    keyed by (session_id, run_id, call_id), with `attempt_at`/`result_at` the records'
    full-record positions. As strict as index_calls: an empty id, an unknown phase, a
    duplicate, an orphan result, or an attempt and result that disagree on depth,
    parent_call_id or arguments exits 4. cynative, not the model, writes these records, so
    a malformed one means the code under test changed."""
    slots = {}
    order = []
    for at, r in enumerate(records):
        if r.get("tool") != LOOKUP_READ or r.get("via") != VIA_API_REFERENCE:
            continue
        key = (r.get("session_id"), r.get("run_id"), r.get("call_id"))
        if not all(isinstance(k, str) and k for k in key):
            insecure("lookup_read record with an empty id tuple: %r" % (key,))
        slot = slots.get(key)
        if slot is None:
            slot = {}
            slots[key] = slot
            order.append(key)
        phase = r.get("phase")
        if phase == "attempt":
            if "attempt" in slot:
                insecure("duplicate lookup_read attempt for %r" % (key,))
            slot["attempt"], slot["attempt_at"] = r, at
        elif phase == "result":
            if "attempt" not in slot:
                insecure("lookup_read result without a preceding attempt for %r" % (key,))
            if "result" in slot:
                insecure("duplicate lookup_read result for %r" % (key,))
            slot["result"], slot["result_at"] = r, at
        else:
            insecure("lookup_read record with unknown phase %r" % (phase,))
    out = []
    for key in order:
        slot = slots[key]
        a, r = slot.get("attempt"), slot.get("result")
        if r is not None:
            # tool and via need no comparison: only records carrying both values are indexed.
            for fieldname in ("depth", "parent_call_id"):
                if not type_strict_eq(a.get(fieldname), r.get(fieldname)):
                    insecure("lookup_read attempt/result disagree on %s for %r" % (fieldname, key))
            if not type_strict_eq(_object_args(a, "lookup_read"), _object_args(r, "lookup_read")):
                insecure("lookup_read attempt/result arguments disagree for %r" % (key,))
        out.append((key, slot))
    return out


def _index_parents(records):
    """Every api_reference record by (session_id, run_id, call_id), with its full-record
    position. Kept as lists and judged only when a lookup_read names the key, so a run whose
    lookups made no reads is judged exactly as before."""
    parents = {}
    for at, r in enumerate(records):
        if r.get("tool") == API_REFERENCE:
            key = (r.get("session_id"), r.get("run_id"), r.get("call_id"))
            parents.setdefault(key, []).append((at, r))
    return parents


def _lookup_parent(parents, key, slot):
    """Condition 2: the parent api_reference call that encloses this read, as (parent key,
    the parent's folded arguments), or exit 4."""
    a, r = slot["attempt"], slot["result"]
    pid = a.get("parent_call_id")
    if not (isinstance(pid, str) and pid):
        insecure("lookup_read %r names no parent call" % (key,))
    pkey = (key[0], key[1], pid)
    recs = parents.get(pkey, [])
    if [rec.get("phase") for _at, rec in recs] != ["attempt", "result"]:
        insecure("lookup_read %r: its parent %r is not exactly one api_reference attempt then one "
                 "result in the same session and run" % (key, pid))
    (attempt_at, pa), (result_at, pr) = recs
    pargs = _object_args(pa, "api_reference")
    if not (type_strict_eq(pa.get("depth"), pr.get("depth"))
            and type_strict_eq(pargs, _object_args(pr, "api_reference"))):
        insecure("api_reference attempt/result disagree for %r" % (pkey,))
    if not (attempt_at < slot["attempt_at"] and slot["result_at"] < result_at):
        insecure("lookup_read %r does not lie between its parent's attempt and result" % (key,))
    if pr.get("decision") != DECISION_UNPROMPTED or pr.get("outcome") == "denied":
        insecure("lookup_read %r: its parent's result is not an unprompted, undenied lookup "
                 "(decision=%r outcome=%r)" % (key, pr.get("decision"), pr.get("outcome")))
    if not type_strict_eq(r.get("decision"), pr.get("decision")):
        insecure("lookup_read %r: decision %r differs from its parent's" % (key, r.get("decision")))
    if not type_strict_eq(a.get("depth"), pa.get("depth")):
        insecure("lookup_read %r: depth %r differs from its parent's" % (key, a.get("depth")))
    return pkey, pargs


def _lookup_recipe(key, args, pargs):
    """Conditions 3 and 4, but for the document key, which needs the URL: the read names its
    parent's connector, carries a case-folded subset of the parent's block with equal values,
    and has a lookup read's fixed shape. Returns the read's auth_provider."""
    ap = args.get("auth_provider")
    if not isinstance(ap, str) or ap not in LOOKUP_PROVIDERS:
        insecure("lookup_read %r: auth_provider %r is not a targeted-lookup connector" % (key, ap))
    connector = pargs.get("connector")
    if not isinstance(connector, str) or connector.casefold() != ap:
        insecure("lookup_read %r: auth_provider %r is not its parent's connector" % (key, ap))
    block_key = ap + "_auth"
    extra = set(args) - _LOOKUP_ARG_KEYS - {block_key}
    if extra:
        insecure("lookup_read %r carries %s, outside a lookup read's shape" % (key, sorted(extra)))
    if args.get("method") != "GET":
        insecure("lookup_read %r: method %r is not GET" % (key, args.get("method")))
    if not type_strict_eq(args.get("headers"), _LOOKUP_HEADERS):
        insecure("lookup_read %r: headers are not exactly one Accept: application/json" % (key,))
    child, parent = args.get(block_key), pargs.get(block_key)
    if not (isinstance(child, dict) and isinstance(parent, dict)):
        insecure("lookup_read %r: it or its parent carries no %s object" % (key, block_key))
    child = _fold_keys(child, "lookup_read " + block_key)
    parent = _fold_keys(parent, "api_reference " + block_key)
    for k, v in child.items():
        if k not in parent or not type_strict_eq(v, parent[k]):
            insecure("lookup_read %r: %s.%s is not its parent's value" % (key, block_key, k))
    return ap


def _lookup_bindings(spec, calls, target):
    """The spec's lookup targets (condition 6), or none for a spec without the hook. Fails
    closed on a hook that returns anything but a list of LookupTarget."""
    if spec.lookup_targets is None:
        return []
    bindings = spec.lookup_targets(calls, target)
    if not isinstance(bindings, (list, tuple)) or not all(isinstance(b, LookupTarget) for b in bindings):
        insecure("provider %r lookup_targets did not return a list of LookupTarget - failing closed"
                 % spec.name)
    return bindings


def sweep_lookup_reads(records, calls, spec, target):
    """Rule (a): judge every lookup_read an api_reference lookup wrote. A read is admitted
    only when all of these hold: (1) it is strictly paired; (2) an unprompted, undenied
    parent in the same session, run and depth encloses it, with the same decision; (3) it
    names the parent's connector, a subset of the parent's block, and a document key the
    parent's model builds; (4) it has a lookup read's shape; (5) its URL is exactly one of
    the lookup's paths at an authority with no userinfo; (6) a spec binding names its
    auth_provider and authority, accepts its arguments and precedes its attempt; (7) its
    parent's reads that passed 1 to 5 fit the budget, counted whether or not 6 binds them,
    so a looping recipe cannot hide extra reads behind retryable misses.

    Failing 1 to 5 or 7 exits 4 whatever the result. Failing only 6 is a retryable miss when
    the spec's denial_matches accepts the result and 4 otherwise, since a credential may have
    reached an unbound host. The miss is RETURNED, so the caller reports it only after
    sweep_calls also ran without a breach. An admitted read is never a witness or a canary:
    neither is drawn from these records."""
    reads = index_lookup_reads(records)
    if not reads:
        return None
    parents = _index_parents(records)
    judged = []
    counts = {}
    for key, slot in reads:
        if "result" not in slot:
            insecure("lookup_read %r has no result, cannot prove what it did" % (key,))
        pkey, pargs = _lookup_parent(parents, key, slot)
        args = _object_args(slot["attempt"], "lookup_read")
        ap = _lookup_recipe(key, args, pargs)
        parts = lookup_url(args.get("url"))
        if parts is None:
            insecure("lookup_read %r: %s is not a lookup read URL" % (key, redacted_url(args.get("url"))))
        authority, kind, doc_key = parts
        if kind == "document" and doc_key != lookup_doc_key(pargs.get("model")):
            insecure("lookup_read %r: document %r is not the one its parent's model names" % (key, doc_key))
        tally = counts.setdefault(pkey, dict.fromkeys(LOOKUP_BUDGET, 0))
        tally[kind] += 1
        if tally[kind] > LOOKUP_BUDGET[kind]:
            insecure("lookup %r made more than %d %s read(s)" % (pkey, LOOKUP_BUDGET[kind], kind))
        judged.append((key, slot, ap, authority, args))
    bindings = _lookup_bindings(spec, calls, target)
    miss = None
    for key, slot, ap, authority, args in judged:
        if any(b.auth_provider == ap and b.authority == authority and b.position < slot["attempt_at"]
               and b.auth_matches(args) for b in bindings):
            continue
        result = slot["result"]
        desc = "auth_provider=%r GET %r" % (ap, redacted_url(args.get("url")))
        if spec.denial_matches(result):
            miss = miss or "a targeted lookup read of an unbound target was blocked pre-dispatch (%s)" % desc
            continue
        insecure("a targeted lookup read of a target the audit does not bind cannot be shown to "
                 "have stayed on the machine (no %s denial): %s outcome=%r"
                 % (spec.blocked_word, desc, result.get("outcome")))
    return miss


def run_read(records, spec, target, expect):
    """The sanctioned-read assertion: sweep every call, then require one sanctioned 200
    response that binds `expect` to the bytes the provider returned. Witness candidacy is
    drawn from the SAME planned key set the sweep exempted, so a record can never be
    waved past the sweep as a read and then judged by different rules as a witness."""
    guard_unknown_io(records)
    calls = index_calls(records)
    planned = read_plan(calls, spec, target)
    lookup_miss = sweep_lookup_reads(records, calls, spec, target)
    sweep_calls(calls, spec, planned, canary_ok=None)
    if lookup_miss:
        die(lookup_miss)
    witness = None
    for key, slot in calls:
        r = slot.get("result")
        if key not in planned or r is None:
            continue
        if spec.is_witness(r, target, expect):
            witness = r
    if witness is None:
        die(spec.witness_hint)
    print("read: OK (a sanctioned %s response carried the marker)" % spec.name)


# A defect string embeds the offending value right after one of these: "headers=[...]",
# "body='...'", "url='...'", "not the exact ... denial (want ...)". Cutting at the first of
# them leaves the field name and drops every byte the provider interpolated.
_DEFECT_VALUE_START = re.compile(r"""[=('"\[]""")


def defect_labels(bad):
    """Field-name-only labels for a canary defect list.

    Diagnostics name the family, never the bytes - the rule credential_prepass already
    states for its own messages. A provider's defect text interpolates the offending
    header list, body and URL verbatim, and the prepass deliberately admits an
    Authorization value that matches no known live secret and no recognized secret shape,
    so printing that text could copy an opaque credential into a CI log. The field name is
    the whole diagnosis anyway: it says WHICH check rejected the candidate, and the audit
    log holds the bytes for anyone who needs them. Length-capped so a provider that ever
    leads a defect with raw data still cannot spill much."""
    out = []
    for b in bad:
        m = _DEFECT_VALUE_START.search(b)
        label = (b[:m.start()] if m else b).strip().rstrip(",").strip()
        out.append(label[:60] or "unspecified")
    return out


def run_canary(records, spec, canary, target):
    """A boundary-probe assertion: sweep every call admitting the one sanctioned canary,
    then require at least one candidate and that every candidate is exactly the
    sanctioned request denied by the gate under test before dispatch. The sweep still
    admits the provider's read family, so a legitimate read the model makes on its way to
    the probe (a two-hop connector must rediscover its endpoint here too) is not a breach."""
    guard_unknown_io(records)
    calls = index_calls(records)
    planned = read_plan(calls, spec, target)

    def canary_defects(slot):
        """slot's defect list as THE sanctioned canary, or None when it is not even a
        candidate for this probe."""
        r = slot.get("result")
        rec = slot.get("attempt") or r
        if r is None or not canary.is_target(rec, target):
            return None
        return canary.defects(r, target)

    def canary_ok(slot):
        bad = canary_defects(slot)
        return bad is not None and not bad

    def explain(slot):
        bad = canary_defects(slot)
        if not bad:
            return None
        return ": it targeted the %s boundary but was not the sanctioned canary: %s" % (
            canary.label, "; ".join(defect_labels(bad)))

    lookup_miss = sweep_lookup_reads(records, calls, spec, target)
    sweep_calls(calls, spec, planned, canary_ok, explain)
    if lookup_miss:
        die(lookup_miss)
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
            die("%s: the %s call was not the sanctioned canary: %s"
                % (canary.label, canary.label, "; ".join(defect_labels(bad))))
    print("%s: OK (%d sanctioned canary denied by the gate before dispatch)" % (canary.label, len(candidates)))


# credName mirrors internal/redact credentialRules' key vocabulary exactly (the
# underscore-optional, multi-component *_token family included), so the parser
# recognizes the same credential-named fields the production redactor targets.
_CRED_NAME = (r"access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|passwd|passphrase|"
              r"secret[_-]?access[_-]?key|session[_-]?token|api[_-]?key|apikey|private[_-]?key|"
              r"(?:[a-z0-9]+_)+token|token")
# _CRED_SUFFIX is the same vocabulary after an arbitrary [\w.-]* prefix, where the
# multi-component "*_token" alternative is redundant (the prefix and bare "token"
# already match it) and makes Python's backtracking quadratic on "a_a_a_...".
_CRED_SUFFIX = _CRED_NAME.replace(r"(?:[a-z0-9]+_)+token|", "")
assert _CRED_SUFFIX != _CRED_NAME

# _KEY_END mirrors rules.go keyEnd: a key or variable name that ENDS in a credential
# word (DB_PASSWORD, webhookSecret), except bare "token", which takes no prefix so
# pagination cursors (nextPageToken, NextToken) are not read as credentials.
_KEY_END = (r"[\w.-]*(?:access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|secret|password|"
            r"passwd|passphrase|secret[_-]?access[_-]?key|session[_-]?token|api[_-]?key|apikey|private[_-]?key)|"
            r"(?:[a-z0-9]+_)+token|token")
# _FLAG_ARG mirrors rules.go flagArg: a command-line flag ending in a credential word.
_FLAG_ARG = (r"--[\w-]*(?:token|password|passwd|passphrase|secret|api[-_]?key|"
             r"secret[-_]?access[-_]?key|private[-_]?key|bearer)")
# A JSON string body (any escape, a backslash before a newline included), its end (a
# closing quote, or end of content for a value truncated at the cap), and a lazy run
# of scalar members between a name and its value, as rules.go jsonValue/jsonEnd/jsonFields.
_JSON_VALUE = r'(?:\\[\s\S]|[^"\\])*'
_JSON_END = r'(?:"|\\?\Z)'
_JSON_FIELDS = r'(?:\s*,\s*"' + _JSON_VALUE + r'"\s*:\s*(?:"' + _JSON_VALUE + r'"|[\w.+-]+))*?'

# The structural passes in internal/redact (structure.go, structure_json.go),
# mirrored: a YAML value whose extent depends on indentation, a name/value pair
# split across a mapping, a credential flag among command-line array elements or in
# the command string of ["sh","-c",...], and a JSON object member whose name is
# spelled with escapes or repeated. Go's \w and \s are ASCII, so these patterns
# spell both out and use re.A; Go's (?i) also folds the long s and the Kelvin sign
# to s and k, which _fold does by hand. Each detector exposes finditer() and sub()
# the way a compiled regex does, with the value as group(1) and its exact span in
# the scanned text, so the prepass and the e2e scrub use it like the regex rules.
# Known differences: in a JSON body cut short or broken, Go still pairs the members
# it read before the break, while json reads no object it cannot finish (a direct
# key there is still found). Go also redacts the decoded content of JSON strings
# (internal/redact/encoded.go) as the prepass expands them, with these differences:
# Go reads only a string that holds an escape, keys included, four levels deep at
# most, and reads a surrogate pair as two U+FFFD; and past an error it reads only a
# string that is never closed, while the prepass expands only a string json.loads
# parses whole.
_WS = r"[\t\n\f\r ]"
_PLACEHOLDER = re.compile(r"\[REDACTED:[a-z0-9-]+\]\Z")
_KEY_END_FULL = re.compile(r"(?:" + _KEY_END + r")\Z", re.I | re.A)
_DIRECT_KEY = re.compile(r"[\w.-]*(?:" + _CRED_SUFFIX + r")\Z", re.I | re.A)
_FLAG_FULL = re.compile(r"(?:" + _FLAG_ARG + r")\Z", re.I | re.A)
_FLAG_JOINED = re.compile(r"(?:" + _FLAG_ARG + r")=", re.I | re.A)
_YAML_KEY = re.compile(r"([ \t]*(?:-[ \t]+)*)([A-Za-z0-9_.-]+|\"(?:[^\"\\]|\\[\s\S])*\"|'(?:[^']|'')*')"
                       r"[ \t]*:(?:[ \t]+|\Z)")
_YAML_MAPPING_LINE = re.compile(r":(?:[ \t]|[ \t]*\Z)")
_YAML_QUOTED_KEY = re.compile(r"(?:\"(?:[^\"\\]|\\[\s\S])*\"|'(?:[^']|'')*')[ \t]*:(?:[ \t]|\Z)")
_YAML_PROPS = re.compile(r"(?:[&!][^ \t]*(?:[ \t]+|\Z))*")
_HEX4 = re.compile(r"[0-9a-fA-F]{4}")
_YAML_BLOCK = re.compile(r"[|>][0-9+-]*\Z")
_SHELL = re.compile(r"(?:[A-Za-z0-9_./-]*/)?(?:sh|bash|dash|ash|ksh|zsh)\Z")
_SHELL_FLAG = re.compile(r"-[A-Za-z]*c[A-Za-z]*\Z")
_SHELL_ARG_OPTION = re.compile(r"(?:[-+][oO]|--rcfile|--init-file)\Z")
_RUN_START = re.compile(r'[\[,]' + _WS + r'*"')
_ELEMENT = re.compile(r'"((?:\\[\s\S]|[^"\\])*)(")?')
_SEPARATOR = re.compile(_WS + r'*,' + _WS + r'*"')
_KEY_COLON = re.compile(_WS + r"*:")
_MEMBER_COLON = re.compile(_WS + r"*:" + _WS + r"*")
_JSON_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _redacted(val, rx=None):
    """True when val is the redactor's placeholder. A structural detector reports a
    whole value, so it must be exactly one placeholder: one followed by more text
    (a continued YAML value after a token label) is a leak. A regex rule's capture
    can run past the placeholder into the serialization around it (the escaped
    newline after sig=[REDACTED:...] in a raw audit line), so a prefix is enough. A
    capture of backslashes alone is that serialization around an empty value (the
    escaped quote of "sig=\\\"" in a raw line), which the redactor leaves as it is."""
    if isinstance(rx, _Detector):
        return bool(_PLACEHOLDER.match(val))
    return val.startswith("[REDACTED") or not val.strip("\\")


def _fold(t):
    """t with the two non-ASCII letters Go's (?i) folds to ASCII ones replaced."""
    return t.replace(chr(0x17F), "s").replace(chr(0x212A), "k")


class _Found:
    """A match-like hit from a structural detector: group(0) and group(1) are both
    the value (decoded and unquoted for a JSON or shell value, the source text for a
    YAML one), and start()/end() are the exact span of its source in the scanned
    string."""

    def __init__(self, value, start, end):
        self._value, self._start, self._end = value, start, end

    def group(self, _i=0):
        return self._value

    def start(self, _i=0):
        return self._start

    def end(self, _i=0):
        return self._end


class _Detector:
    """Wraps a function text -> [_Found] in the slice of the re.Pattern interface the
    prepass and the e2e scrub use."""

    def __init__(self, find):
        self._find = find

    def finditer(self, text):
        return self._find(text)

    def sub(self, repl, text):
        out, last = [], 0
        for m in sorted(self._find(text), key=lambda f: f.start()):
            if m.start() < last:
                continue
            out.append(text[last:m.start()])
            out.append(repl(m))
            last = m.end()
        out.append(text[last:])
        return "".join(out)


def _indent(t):
    return len(t) - len(t.lstrip(" \t"))


def _blank(t):
    return t.lstrip(" \t") == ""


def _blank_or_comment(t):
    t = t.lstrip(" \t")
    return t == "" or t[0] == "#"


def _yaml_lines(s):
    """(start, end) of each line, without its line break or one trailing '\\r'."""
    out, start = [], 0
    while True:
        nl = s.find("\n", start)
        end = len(s) if nl < 0 else nl
        out.append((start, end - 1 if s[start:end].endswith("\r") else end))
        if nl < 0:
            return out
        start = nl + 1


def _continuation(s, lines, i, col, block):
    last = i
    for j in range(i + 1, len(lines)):
        text = s[lines[j][0]:lines[j][1]]
        if _blank(text) or (not block and _blank_or_comment(text)):
            continue
        if _indent(text) <= col:
            break
        last = j
    return last


def _scalar_below(s, lines, i, col):
    for j in range(i + 1, len(lines)):
        text = s[lines[j][0]:lines[j][1]]
        if _blank_or_comment(text):
            continue
        t = text.lstrip(" \t")
        k = t[len(_YAML_PROPS.match(t).group(0)):]
        key = k and (_YAML_QUOTED_KEY.match(k) if k[0] in "\"'" else _YAML_MAPPING_LINE.search(_strip_comment(k)))
        if _indent(text) <= col or t == "-" or t.startswith("- ") or t[0] in "[{" or key:
            return -1
        return j
    return -1


def _close_quote(s, start):
    q, i = s[start], start + 1
    while i < len(s):
        if q == '"' and s[i] == "\\":
            i += 1
        elif s[i] == q and q == "'" and i + 1 < len(s) and s[i + 1] == "'":
            i += 1
        elif s[i] == q:
            return i
        i += 1
    return -1


def _line_of(lines, i, off):
    while i + 1 < len(lines) and lines[i + 1][0] <= off:
        i += 1
    return i


def _strip_comment(v):
    for i in range(1, len(v)):
        if v[i] == "#" and v[i - 1] in " \t":
            return v[:i]
    return v


def _unquote(v):
    if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
        return v[1:-1]
    return v


def _yaml_extent(s, lines, i, e):
    """Set e's value end (and first/below/multi) and return its last line, as extent."""
    e["first"] = e["start"] + len(_YAML_PROPS.match(s, e["start"], lines[i][1]).group(0))
    line = i
    v = s[e["first"]:lines[i][1]]
    if v == "" or v[0] == "#":
        line = _scalar_below(s, lines, i, e["col"])
        if line < 0:
            return i
        e["below"] = True
        e["first"] = lines[line][0] + _indent(s[lines[line][0]:lines[line][1]])
        p = len(_YAML_PROPS.match(s, e["first"], lines[line][1]).group(0))
        if e["first"] + p < lines[line][1]:
            e["first"] += p
    elif v[0] in "[{" and not v.startswith("[REDACTED:"):
        return i
    v = s[e["first"]:lines[line][1]]
    last = _continuation(s, lines, line, e["col"], bool(_YAML_BLOCK.match(_strip_comment(v).strip())))
    e["multi"] = last > i
    e["end"] = lines[last][1]
    if v[0] in "\"'":
        q = _close_quote(s, e["first"])
        if q >= 0:
            closing = _line_of(lines, line, q)
            last = _continuation(s, lines, closing, e["col"], False)
            e["end"] = q + 1
            if last > closing:
                e["end"] = lines[last][1]
            e["multi"] = last > i
        else:
            last = len(lines) - 1
            e["end"], e["multi"] = lines[last][1], last > i
    elif not e["multi"]:
        e["end"] = e["first"] + len(_strip_comment(v).rstrip(" \t"))
    return last


def _name_value(s, e):
    """The scalar of a "name" entry when it is one line, unquoted and without a
    comment, or "", as nameValue."""
    if e["end"] <= e.get("first", e["start"]) or "\n" in s[e["first"]:e["end"]]:
        return ""
    return _unquote(_strip_comment(s[e["first"]:e["end"]]).rstrip(" \t\r"))


def _yaml_entries(s, lines):
    out, i = [], 0
    while i < len(lines):
        text = s[lines[i][0]:lines[i][1]]
        if _blank_or_comment(text):
            i += 1
            continue
        g = _YAML_KEY.match(text)
        if g is None:
            out.append({"key": "", "col": _indent(text), "item": False, "multi": False})
            i += 1
            continue
        e = {"key": _unquote(g.group(2)), "json": g.group(2)[0] == '"', "col": g.end(1), "item": "-" in g.group(1),
             "colon": lines[i][0] + g.end(2) + text[g.end(2):].index(":") + 1,
             "start": lines[i][0] + g.end(0), "below": False, "multi": False}
        e["end"] = e["first"] = e["start"]
        if _DIRECT_KEY.match(e["key"]) or e["key"].lower() in ("name", "value"):
            i = _yaml_extent(s, lines, i, e)
        i += 1
        out.append(e)
    return out


def _yaml_mappings(es):
    ids, stack = [], []
    for i, e in enumerate(es):
        while stack:
            top = es[stack[-1]]
            if top["col"] < e["col"] or (top["col"] == e["col"] and e["key"] and not e["item"]):
                break
            stack.pop()
        if not e["key"]:
            ids.append(-1)
            continue
        if not stack or es[stack[-1]]["col"] != e["col"]:
            stack.append(i)
        ids.append(stack[-1])
    return ids


def _json_scalar(v):
    """True when v, without a trailing comma, parses as a JSON scalar, as the
    json.Valid check in yamlValue."""
    if v.endswith(","):
        v = v[:-1]
    try:
        json.loads(v)
    except ValueError:
        return False
    return True


def _quote_end(d, j):
    """The offset of the quote closing the one at d[j], or len(d), as quoteEnd."""
    k = j + 1
    while k < len(d):
        if d[j] == '"' and d[k] == "\\":
            k += 1
        elif d[k] == d[j]:
            return k
        k += 1
    return len(d)


def _expansion_end(d, i):
    """The offset after the command substitution starting at d[i], as expansionEnd."""
    if d[i] == "`":
        j = i + 1
        while j < len(d):
            if d[j] == "\\":
                j += 1
            elif d[j] == "`":
                return j + 1
            j += 1
        return len(d)
    if d.startswith("$(", i):
        depth, j = 0, i + 1
        while j < len(d):
            if d[j] == "\\":
                j += 1
            elif d[j] in "\"'":
                j = _quote_end(d, j)
            elif d[j] == "(":
                depth += 1
            elif d[j] == ")":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return len(d)
    return i


def _find_yaml(s):
    if ":" not in s:
        return []
    entries = _yaml_entries(s, _yaml_lines(s))
    ids = _yaml_mappings(entries)
    named = {ids[i] for i, e in enumerate(entries)
             if e["key"].lower() == "name" and _KEY_END_FULL.match(_fold(_name_value(s, e)))}
    out = []
    for i, e in enumerate(entries):
        if not ((ids[i] in named and e["key"].lower() == "value")
                or (e["multi"] and _DIRECT_KEY.match(e["key"]))):
            continue
        if e["end"] == e["start"] or (e["json"] and _json_scalar(s[e["first"]:e["end"]])):
            continue
        start = e["colon"] if e["below"] else e["start"]
        out.append(_Found(s[start:e["end"]], start, e["end"]))
    return out


def _flag_values(words):
    """(index, offset) of each credential value in a command line, as flagValues."""
    out = []
    for i, w in enumerate(_fold(w) for w in words):
        m = _FLAG_JOINED.match(w)
        if m:
            out.append((i, m.end()))
            continue
        if _FLAG_FULL.match(w) and i + 1 < len(words) and not w.startswith("--no-"):
            out.append((i + 1, 0))
    return out


def _shell_command(words, i):
    """The index of the command a shell named at words[i] runs, or -1, as shellCommand."""
    j = i + 1
    while j < len(words) and words[j][:1] in ("-", "+") and words[j]:
        if _SHELL_FLAG.match(words[j]):
            return j + 1
        if _SHELL_ARG_OPTION.match(words[j]):
            j += 1
        j += 1
    return -1


def _decode_json_string(body):
    """The body of a JSON string decoded up to its first invalid or incomplete escape,
    with the offset in body each decoded character starts at, plus the end."""
    out, raw, i = [], [], 0
    while i < len(body):
        if body[i] != "\\":
            out.append(body[i])
            raw.append(i)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt == "u":
            hexa = body[i + 2:i + 6]
            ch = chr(int(hexa, 16)) if _HEX4.fullmatch(hexa) else None
            n = 6
        else:
            ch, n = _JSON_ESCAPES.get(nxt), 2
        if ch is None:
            break
        out.append(ch)
        raw.append(i)
        i += n
    raw.append(i)
    return "".join(out), raw


def _shell_words(d):
    """(start, end, text, at) per word, as shellWords: quotes, backslashes and line
    joins removed, at giving each character's offset in d."""
    out, i = [], 0
    while True:
        while i < len(d) and d[i] in " \t\n":
            i += 1
        if i >= len(d):
            return out
        if d[i] == "#":
            nl = d.find("\n", i)
            i = len(d) if nl < 0 else nl + 1
            continue
        if d[i] in ";&|<>()":
            i += 1
            continue
        start, text, at, quoted = i, [], [], False

        def add(j):
            text.append(d[j])
            at.append(j)

        while i < len(d) and d[i] not in " \t\n;&|<>()":
            c = d[i]
            if c == "'":
                quoted, i = True, i + 1
                while i < len(d) and d[i] != "'":
                    add(i)
                    i += 1
                i += 1
            elif c == '"':
                quoted, i = True, i + 1
                while i < len(d) and d[i] != '"':
                    if d[i] == "\\" and i + 1 < len(d) and d[i + 1] == "\n":
                        i += 2
                        continue
                    if d[i] == "\\" and i + 1 < len(d) and d[i + 1] in "$`\"\\":
                        i += 1
                    add(i)
                    i += 1
                i += 1
            elif c == "\\":
                if i + 1 < len(d) and d[i + 1] != "\n":
                    add(i + 1)
                i += 2
            else:
                end = max(_expansion_end(d, i), i + 1)
                while i < end:
                    add(i)
                    i += 1
        i = min(i, len(d))
        if text or quoted:
            out.append((start, i, "".join(text), at))


def _array_run(s, q):
    """The string elements (start, end, stop, closed) from the quote at q on, and the
    offset where reading stopped, as run() in structure_json.go."""
    out = []
    while True:
        g = _ELEMENT.match(s, q)
        if g.group(2) is None:
            out.append((q + 1, g.end(1), len(s), False))
            return out, len(s)
        stop = g.end()
        if _KEY_COLON.match(s, stop):
            return out, stop
        out.append((q + 1, g.end(1), stop, True))
        sep = _SEPARATOR.match(s, stop)
        if sep is None:
            return out, stop
        q = sep.end() - 1


def _shell_found(s, e):
    start, end, stop, closed = e
    cmd, raw = _decode_json_string(s[start:end])
    partial = raw[-1] < end - start
    words = _shell_words(cmd)
    out = []
    for i, off in _flag_values([w[2] for w in words]):
        w_start, w_end, text, at = words[i]
        dec_start = at[off - 1] + 1 if off > 0 else w_start
        if partial and w_end == len(cmd):
            # A word that runs into a bad escape takes the bytes after it, so its
            # value is the raw text, which no placeholder check can mistake.
            out.append(_Found(s[start + raw[dec_start]:stop - closed], start + raw[dec_start], stop - closed))
        else:
            out.append(_Found(text[off:], start + raw[dec_start], start + raw[w_end]))
    return out


def _find_commands(s):
    if "--" not in s and "\\u002d" not in s.lower():
        return []
    out, pos = [], 0
    while True:
        m = _RUN_START.search(s, pos)
        if m is None:
            return out
        elems, end = _array_run(s, m.end() - 1)
        words, raws = [], []
        for a, b, _stop, _closed in elems:
            raw = s[a:b]
            word, offsets = _decode_json_string(raw) if "\\" in raw else (raw, None)
            words.append(word)
            raws.append(offsets)
        values = _flag_values(words)
        taken = {i for i, off in values if off == 0}
        shell = set()
        for i in range(len(elems)):
            if not _SHELL.match(words[i]):
                continue
            c = _shell_command(words, i)
            if i < c < len(elems):
                if not any(k in taken for k in range(i, c)):
                    shell.add(c)
                out.extend(_shell_found(s, elems[c]))
        for i, off in values:
            if i not in shell:
                start, end_, stop, closed = elems[i]
                raw_off = raws[i][off] if raws[i] is not None else off
                # A value decoded only up to a bad escape is reported raw, so a
                # placeholder prefix does not pass for the whole value.
                cut = raws[i] is not None and raws[i][-1] < end_ - start
                value = s[start + raw_off:stop - closed] if cut else words[i][off:]
                out.append(_Found(value, start + raw_off, stop - closed))
        pos = max(end, m.end())


def _json_text(raw):
    """A JSON string body decoded, or as far as it decodes when it is cut short."""
    return _decode_json_string(raw)[0]


def _find_objects(s):
    """String values of credential-named members, and the "value" members of an object
    whose "name" member is a credential name, with names decoded, as objects()."""
    t = s.lstrip(" \t\r\n")
    if not t or t[0] not in "{[":
        return []
    paired = set()

    def hook(pairs):
        if any(k.lower() == "name" and isinstance(v, str) and _KEY_END_FULL.match(_fold(v)) for k, v in pairs):
            paired.update(v for k, v in pairs if k.lower() == "value" and isinstance(v, str))
        return dict(pairs)

    # Read value after value (NDJSON too) up to the first syntax error, as Go's
    # decoder does; members past it are not read.
    dec, idx, stop = json.JSONDecoder(object_pairs_hook=hook), 0, len(s)
    while True:
        while idx < len(s) and s[idx] in " \t\r\n":
            idx += 1
        if idx >= len(s):
            break
        try:
            _, idx = dec.raw_decode(s, idx)
        except (ValueError, RecursionError) as e:
            stop = getattr(e, "pos", idx)
            break
    # Every string, read once from left to right, so a member's span is exact.
    out, strings = [], list(_ELEMENT.finditer(s))
    for k, v in zip(strings, strings[1:]):
        colon = _MEMBER_COLON.match(s, k.end())
        if k.group(2) is None or k.start() > stop or colon is None or colon.end() != v.start():
            continue
        key, val = _json_text(k.group(1)), _json_text(v.group(1))
        if _KEY_END_FULL.match(_fold(key)) or (key.lower() == "value" and val in paired):
            out.append(_Found(val, v.start(1), v.end(1) if v.group(2) else len(s)))
    return out


# class-2: whole-content secret families (internal/redact contentRules), scanned
# anywhere. Each is keyword-pre-gated - run the regex only when a cheap distinctive
# substring is present, no entropy heuristics - mirroring the production redactor. A
# raw (unredacted) match is a breach; a "[REDACTED:<label>]" placeholder carries none
# of these shapes, so an already-redacted value is accepted for free.
_CONTENT_RULES = (
    (("PRIVATE KEY",),
     re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S),
     "pem-private-key"),
    (("LS0tLS1CRUdJTi",),
     re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]+(?:[ \t]*\r?\n[ \t]*[A-Za-z0-9+/=]{32,})*"),
     "base64-pem"),
    (("eyJ",), re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?"), "jwt"),
    (("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"),
     re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{82,})"), "github-token"),
    (("glpat-",), re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "gitlab-token"),
    (("xox", "xapp-"), re.compile(r"(?:xox[baprse]-|xapp-)[A-Za-z0-9-]{10,}"), "slack-token"),
    (("AIza",), re.compile(r"AIza[A-Za-z0-9_-]{35}"), "google-api-key"),
    (("ya29.",), re.compile(r"ya29\.[A-Za-z0-9_-]{20,}"), "google-oauth-token"),
    (("AKIA", "ASIA", "AROA", "AIDA"), re.compile(r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}"),
     "aws-access-key-id"),
    (("sk-",),
     re.compile(r"\bsk-(?:ant-[A-Za-z0-9_-]{20,}|proj-[A-Za-z0-9_-]{20,}|"
                r"svcacct-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{20,})"), "llm-api-key"),
)

# class-3: positional credential families (internal/redact credentialRules). A
# credential-named JSON/XML/YAML/env field or a signing/session query param leaks by
# position: the captured value is a breach unless it is already the redactor's
# placeholder (which begins "[REDACTED"). URL userinfo and denylisted credential-header
# values are deliberately absent here: they are VALUE-gated, and the class-1/class-2
# anywhere-scan already flags them exactly when the value is a real secret, so the AWS
# canary_url "u:p" and GitHub canary "Authorization: Bearer x" stay canary defects (1),
# not leaks.
_POSITIONAL_RULES = (
    (re.compile(r'"(?:' + _KEY_END + r')"\s*:\s*"(' + _JSON_VALUE + r')' + _JSON_END, re.I), "credential-field"),
    # Name/value pairs in either order (ECS, Batch, CodeBuild and Kubernetes env),
    # mirroring rules.go's pair rules.
    (re.compile(r'"name"\s*:\s*"(?:' + _KEY_END + r')"' + _JSON_FIELDS + r'\s*,\s*"value"\s*:\s*"('
                + _JSON_VALUE + r')' + _JSON_END, re.I), "credential-field"),
    (re.compile(r'"value"\s*:\s*"(' + _JSON_VALUE + r')"' + _JSON_FIELDS + r'\s*,\s*"name"\s*:\s*"(?:'
                + _KEY_END + r')"', re.I), "credential-field"),
    # The structural passes: YAML pairs and multi-line values, command-line flags
    # (array elements and shell command strings), and decoded JSON object members.
    (_Detector(_find_yaml), "credential-field"),
    (_Detector(_find_commands), "credential-field"),
    (_Detector(_find_objects), "credential-field"),
    (re.compile(r"<(?:" + _CRED_NAME + r")>([^<]*)</[A-Za-z0-9_:.-]+>", re.I), "credential-field"),
    # YAML "key: value" line: the key ENDS in a credential name, so DB_/AWS_/client-
    # prefixes are allowed, plus an optional "- " sequence-item marker. Line-anchored
    # (re.M) so a prose "token:" mid-line is not matched; the value's first char excludes
    # '[' so an already-redacted "[REDACTED:...]" placeholder keeps its label and inline
    # lists are skipped. Mirrors internal/redact rules.go's YAML credential-field rule,
    # same credName vocabulary. Covers kubeconfig / k8s-manifest piped input.
    (re.compile(r"^[ \t]*(?:-[ \t]+)?[\w.-]*(?:" + _CRED_SUFFIX + r")[ \t]*:[ \t]*([^\s\[][^\r\n]*)",
                re.I | re.M), "credential-field"),
    # env "KEY=value" line: same key vocabulary (AWS_SECRET_ACCESS_KEY, DB_PASSWORD,
    # API_TOKEN, ...), an optional shell "export " prefix, and the same '[' exclusion.
    # Mirrors internal/redact rules.go's env credential-field rule. Covers .env / shell
    # piped input.
    (re.compile(r"^[ \t]*(?:export[ \t]+)?[\w.-]*(?:" + _CRED_SUFFIX + r")[ \t]*=[ \t]*([^\s\[][^\r\n]*)",
                re.I | re.M), "credential-field"),
    (re.compile(r"(?:X-Amz-Signature|X-Goog-Signature|Signature|sig)=([^&\"'\s]+)", re.I),
     "signed-url-signature"),
    (re.compile(r"(?:X-Amz-Security-Token)=([^&\"'\s]+)", re.I), "aws-session-token"),
)


def _read_live_secrets(secrets_path):
    """The out-of-band live secret values, one BASE64-encoded value per line, blanks
    dropped. Encoding keeps a multi-line credential (a JSON key blob) as a single exact
    needle rather than per-line needles that false-positive against an audit. The suites
    always pass the flag, so a MISSING/UNREADABLE file, or a non-base64 line, is a wiring
    bug and fails closed (4). An EMPTY file is legitimate: ambient-credential runs (AWS
    profiles/instance roles, GCP ADC, Bedrock/Vertex chains) enumerate no env secret and
    rely on the class-2/class-3 SHAPE families, so an empty file must not fail.
    secrets_path is None only on the offline replay that passes no flag; class-1 is then
    skipped, never fatal, so the frozen corpus stays inert. Only the PATH is ever named in
    a diagnostic; the decoded values are returned and never printed."""
    if secrets_path is None:
        return []
    text = None
    try:
        text = open(secrets_path, encoding="utf-8").read()
    except OSError as e:
        insecure("credential prepass: cannot read live-secrets file %s: %s - failing closed"
                 % (secrets_path, e))
    except UnicodeDecodeError:
        insecure("credential prepass: live-secrets file is not valid UTF-8 - failing closed")
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(base64.b64decode(line, validate=True).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            insecure("credential prepass: live-secrets file has a non-base64 line - failing closed")
    return out


def _cred_expand(value, blobs):
    """Append every text view of `value` that a secret could hide in: the string
    itself, and - since arguments can be a JSON string and a result wraps a JSON body -
    a further decode of any JSON-string leaf. dict/list values are dumped so a positional
    "key":"value" rule can see them, then walked so nested strings are decoded too."""
    if isinstance(value, str):
        blobs.append(value)
        try:
            inner = json.loads(value)
        except ValueError:
            return
        if isinstance(inner, (dict, list, str)):
            _cred_expand(inner, blobs)
    elif isinstance(value, dict):
        blobs.append(json.dumps(value))
        for v in value.values():
            _cred_expand(v, blobs)
    elif isinstance(value, list):
        blobs.append(json.dumps(value))
        for v in value:
            _cred_expand(v, blobs)


def _cred_blobs(records, raw_lines):
    """Every text unit to scan: the raw physical lines (including a tolerated trailing
    partial that never parsed into a record, so it cannot evade the scan) plus each
    record's arguments and result, recursively expanded and JSON-double-decoded."""
    blobs = [ln for ln in raw_lines if isinstance(ln, str)]
    for rec in records:
        if isinstance(rec, dict):
            _cred_expand(rec.get("arguments"), blobs)
            _cred_expand(rec.get("result"), blobs)
    return blobs


def credential_prepass(records, raw_lines, live_secrets_path):
    """Fail closed (4) when known live credential bytes or production-recognized
    credential material appear in the recorded audit. Runs before every mode assertion,
    over both `arguments` (written verbatim for approval-gated I/O) and `result`
    (redacted at source) of every record, plus the raw physical bytes. Three value-based
    classes: class-1 exact live-secret values (literal AND percent-encoded); class-2
    whole-content secret shapes; class-3 positional credential fields and signing/session
    params. Every string is scanned in both its literal and its percent-decoded form, so
    a secret url-encoded on the wire cannot slip through. It only ever ADDS a fail-closed
    verdict; it never relaxes one. Diagnostics name the family only, never the bytes."""
    secrets = _read_live_secrets(live_secrets_path)
    for blob in _cred_blobs(records, raw_lines):
        if not blob:
            continue
        decoded = unquote_plus(blob)
        texts = (blob, decoded) if decoded != blob else (blob,)
        for text in texts:
            # class-1: exact live-secret bytes, matched literally or percent-encoded.
            for secret in secrets:
                if secret in text or quote_plus(secret) in text:
                    insecure("credential prepass: a live secret value appears in the audit - failing closed")
            # class-2: whole-content production secret shapes (keyword-pre-gated).
            for keywords, rx, label in _CONTENT_RULES:
                if any(k in text for k in keywords) and rx.search(text):
                    insecure("credential prepass: a %s shape appears in the audit - failing closed" % label)
            # class-3: positional credential fields and signing/session params; a value
            # that is exactly a placeholder is the redactor having fired, so it is accepted.
            for rx, label in _POSITIONAL_RULES:
                for m in rx.finditer(text):
                    val = m.group(1)
                    if val and not _redacted(val, rx):
                        insecure("credential prepass: a %s value appears in the audit - failing closed" % label)
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _pop_live_secrets_path(args):
    """Remove a --live-secrets FILE pair from args, returning (remaining_args, secrets_path).

    Every name on this seam is `*_path`: what is threaded from argv down to
    `_read_live_secrets` is the FILE PATH, never the secret values it holds. The decoded
    values exist only inside `credential_prepass`, which never prints one (a diagnostic
    names the credential family, never the bytes)."""
    out = []
    secrets_path = None
    i = 0
    while i < len(args):
        if args[i] == "--live-secrets":
            if i + 1 >= len(args):
                die("usage: --live-secrets requires a FILE argument", USAGE)
            secrets_path = args[i + 1]
            i += 2
            continue
        out.append(args[i])
        i += 1
    return out, secrets_path


def dispatch(spec, mode, records, raw_lines, rest, live_secrets_path):
    """Route `mode` to the read assertion or one of the provider's canaries. An unknown
    mode fails closed to 4."""
    credential_prepass(records, raw_lines, live_secrets_path)
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
    args, live_secrets_path = _pop_live_secrets_path(args)
    if len(args) < 3:
        die("usage: audit_check.py PROVIDER MODE AUDIT [TARGET] [EXPECT] [--live-secrets FILE]", USAGE)
    provider, mode, audit = args[0], args[1], args[2]
    spec = resolve(provider)
    records, raw_lines = load_records(audit)
    dispatch(spec, mode, records, raw_lines, args[3:], live_secrets_path)


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
    import shutil
    import tempfile
    spec = resolve(provider)
    failures = 0
    observed = []
    targets = dict(spec.selftest_targets)
    for name, want, mode, lines, *rest in spec.selftest_cases:
        tmpdir = None
        if lines is None:
            # A case whose audit path must not exist (e.g. AWS's frozen
            # read_unreadable): allocate a path inside a fresh, otherwise-empty temp
            # dir, but never create the file there.
            tmpdir = tempfile.mkdtemp()
            path = os.path.join(tmpdir, "missing.audit.log")
        elif isinstance(lines, bytes):
            # Raw file content, verbatim (e.g. a case needing invalid UTF-8 that no
            # Python str can carry through a plain text write).
            fd, path = tempfile.mkstemp(suffix=".log")
            with os.fdopen(fd, "wb") as fh:
                fh.write(lines)
        else:
            fd, path = tempfile.mkstemp(suffix=".log")
            with os.fdopen(fd, "w") as fh:
                fh.write("\n".join(lines) + "\n")
        observed.append("%s %d" % (name, want))
        try:
            got = _run_case(provider, mode, path, targets.get(name, spec.selftest_target), rest)
        finally:
            if tmpdir is not None:
                shutil.rmtree(tmpdir, ignore_errors=True)
            else:
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


def _planning_spec(plan):
    """A spec whose per-record is_sanctioned_read sanctions NOTHING, so any read that
    survives the sweep did so because `plan` sanctioned it. That inversion is what makes the
    contextual-plan cases real: with the default plan every call would be unsanctioned."""
    base = _engine_test_spec()
    return ProviderSpec(
        name="planner", blocked_word="test_hardening", read_mode="read",
        is_sanctioned_read=lambda rec, target: False, denial_matches=base.denial_matches,
        is_witness=base.is_witness, witness_hint=base.witness_hint, plan_reads=plan)


def _resolve_with(spec):
    """Run resolve() against `spec`, registered under its own name for the duration. The
    registry is module state, so the entry is always removed again - a selftest that leaked
    a fake provider into REGISTRY would change what a later real run resolves."""
    previous = REGISTRY.get(spec.name)
    REGISTRY[spec.name] = spec
    try:
        return resolve(spec.name)
    finally:
        if previous is None:
            REGISTRY.pop(spec.name, None)
        else:
            REGISTRY[spec.name] = previous


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


def _verdict(call):
    """Run call() and return (printed verdict, exit code). Selftest helpers assert BOTH:
    a helper that only swallowed SystemExit would pass a `die` mutated to exit 0."""
    import contextlib
    import io
    buf = io.StringIO()
    code = 0
    with contextlib.redirect_stdout(buf):
        try:
            call()
        except SystemExit as e:
            # sys.exit() is SystemExit(None), which is process exit 0; only a non-int,
            # non-None argument is the conventional 1.
            if e.code is None:
                code = 0
            elif isinstance(e.code, int):
                code = e.code
            else:
                code = 1
    return buf.getvalue(), code


def _sweep_redacts_url_credentials(spec, target):
    """The verdict prefix names the call, and it must not carry the URL's userinfo.

    The credential prepass excludes userinfo from its positional rules, so an opaque
    `user:secret@host` passes the prepass unrewritten. Printing the raw URL would put it in
    a CI log, which redacting only the defect suffix does not prevent: it sits earlier on
    the same line."""
    secret = "opaque-userinfo-value"
    bad_url = "https://u:%s@example.test/v1/projects/demo?sig=abc#frag" % secret
    args = {"method": "DELETE", "url": bad_url, "auth_provider": "gcp"}
    records = [
        json.loads(_jline("c8", "attempt", args)),
        json.loads(_jline("c8", "result", args, result="test_hardening: denied", outcome="error"))]
    msg, code = _verdict(lambda: run_read(records, spec, target, "unused"))
    assert code == NOT_PROVEN, "want a retryable miss, got exit %r: %r" % (code, msg)
    assert secret not in msg, "URL userinfo leaked into the verdict: %r" % msg
    assert "sig=abc" not in msg and "frag" not in msg, "URL query/fragment survived: %r" % msg
    assert "example.test/v1/projects/demo" in msg, "the call is no longer identifiable: %r" % msg


def _structural_spans():
    """Each structural detector reports the value and the exact span of its source,
    in the raw text the e2e scrub rewrites (the prepass also scans expanded JSON, which
    would hide a detector that only works on decoded text)."""
    cases = [
        (_find_commands, '["--passw\\u006frd","x"]', [("x", 20, 21)]),
        (_find_commands, '["--passw\\u006frd=b\\u0020c"]', [("b c", 18, 26)]),
        (_find_commands, '["\\u0073h","-c","app --token y"]', [("y", 29, 30)]),
        (_find_commands, '["--password","sh","-c","app --token y"]', [("y", 37, 38), ("sh", 15, 17)]),
        (_find_yaml, "password:\n  &pw \"a\nb\"\nn: p\n", [("\n  &pw \"a\nb\"", 9, 21)]),
        (_find_commands, '["\\u002d\\u002dpassword","y"]', [("y", 25, 26)]),
        (_find_yaml, "x: y\npassword: \"first\nTAIL\nnext: k\n", [("\"first\nTAIL\nnext: k\n", 15, 35)]),
        (_find_commands, '["sh","-c","app --password=$(printf a b) c"]', [("$(printf a b)", 27, 40)]),
        (_find_yaml, "password: &pw |\n  # x\nnext: p\n", [("&pw |\n  # x", 10, 21)]),
        (_find_objects, '{"DB_PASSW\\u004fRD":"\\u0068i"}', [("hi", 21, 28)]),
    ]
    for find, text, want in cases:
        got = [(f.group(1), f.start(), f.end()) for f in find(text)]
        assert got == want, "%s(%r) = %r, want %r" % (find.__name__, text, got, want)


def _redacted_url_shapes():
    """redacted_url keeps the authority exactly as submitted, minus userinfo.

    Rebuilding it from urlparse's parsed pieces loses information a maintainer needs: an
    IPv6 literal loses its brackets and reads as an ambiguous host:port, an explicit :0 is
    dropped, and a non-ASCII host is silently case-folded to a spelling the caller never
    sent, which is the exact class of bug #334 and #308 were about. Path params belong to
    the path and distinguish two different requests."""
    cases = [
        ("https://u:pw@[2001:db8::1]:6443/api/v1/pods", "https://[2001:db8::1]:6443/api/v1/pods"),
        ("https://[2001:db8::1]/api", "https://[2001:db8::1]/api"),
        ("https://host:0/api", "https://host:0/api"),
        ("https://host/a/b;v=1", "https://host/a/b;v=1"),
        ("https://HOST.Example.TEST/a", "https://HOST.Example.TEST/a"),
        ("https://u%40x:pw@host/a", "https://host/a"),
        ("not a url", "<unparseable url>"),
        # A trailing bare ";" is part of the object key; two S3 requests differ by it.
        ("https://b.s3.us-east-1.amazonaws.com/report;", "https://b.s3.us-east-1.amazonaws.com/report;"),
        # Non-ASCII is escaped, never dropped and never passed through: a verdict printed
        # under an ASCII stdout would otherwise raise UnicodeEncodeError, and the engine
        # turns any crash into exit 4 - a retryable miss would become a fatal breach. The
        # escaped form also shows the exact spelling, which is what a host-divergence bug
        # (#308, #334) turns on.
        ("https://iam.amazonaws.com/caf\u00e9", "https://iam.amazonaws.com/caf\\xe9"),
        ("https://\u00e9xample.test/a", "https://\\xe9xample.test/a"),
    ]
    for raw, want in cases:
        got = redacted_url(raw)
        assert got == want, "redacted_url(%r) = %r, want %r" % (raw, got, want)
        got.encode("ascii")
    for raw in (None, 12345, b"https://host/a"):
        redacted_url(raw).encode("ascii")


def _verdict_reports_clean_exit():
    """_verdict must not report a bare sys.exit() as a miss: SystemExit(None) is process
    exit 0, and mapping it to 1 would let a `die` that merely stopped printing pass a case
    that asserts NOT_PROVEN."""
    assert _verdict(lambda: None) == ("", 0), _verdict(lambda: None)
    assert _verdict(lambda: sys.exit()) == ("", 0), _verdict(lambda: sys.exit())
    assert _verdict(lambda: sys.exit(4))[1] == SECURITY


def _candidate_loop_labels_defects(spec, target, url):
    """run_canary's own candidate verdict redacts too.

    It is reached only when the defective candidate is ALSO a sanctioned read, so the sweep
    skips it and the candidate loop is what rejects it. Without this the sweep case covers
    one of the two verdicts and a regression in the other ships silently."""
    secret = "sk-live-CANDIDATE9999"
    args = {"method": "GET", "url": url, "auth_provider": "gcp"}
    records = [
        json.loads(_jline("c7", "attempt", args)),
        json.loads(_jline("c7", "result", args, result=_sres(200, "{}"), outcome="ok"))]
    probe = CanarySpec(
        mode="canary", label="canary", boundary="GET probe",
        is_target=lambda rec, t: (args_of(rec).get("method") or "") == "GET",
        defects=lambda rec, t: ["body='%s', want the sanctioned body" % secret])
    msg, code = _verdict(lambda: run_canary(records, spec, probe, target))
    assert code == NOT_PROVEN, "want a retryable miss, got exit %r: %r" % (code, msg)
    assert "was not the sanctioned canary" in msg, "not the candidate-loop verdict: %r" % msg
    assert "body" in msg, "defect field not named by the candidate loop: %r" % msg
    assert secret not in msg, "defect VALUE leaked from the candidate loop: %r" % msg


def _sweep_explains_defects(spec, target, url):
    """The sweep's miss message must name the defective FIELDS of a denied canary
    candidate and none of their values.

    A provider's defect text embeds the offending header list, body and URL verbatim, and
    the credential prepass deliberately admits an Authorization value that matches no known
    live secret and no recognized secret shape. Printing that text would copy an opaque
    credential into a CI log, so this asserts the field name survives and the value does
    not - the same rule the prepass states for its own diagnostics."""
    secret = "sk-live-DEADBEEF0123"
    canary_args = {"method": "POST", "url": url, "auth_provider": "gcp"}
    # An unrelated denied call FIRST, so the explanation cannot come from "the first miss".
    other = {"method": "DELETE", "url": url, "auth_provider": "gcp"}
    records = [
        json.loads(_jline("c1", "attempt", other)),
        json.loads(_jline("c1", "result", other, result="test_hardening: denied", outcome="error")),
        json.loads(_jline("c9", "attempt", canary_args)),
        json.loads(_jline("c9", "result", canary_args,
                          result="test_hardening: denied", outcome="error"))]
    probe = CanarySpec(
        mode="canary", label="canary", boundary="POST probe",
        is_target=lambda rec, t: (args_of(rec).get("method") or "") == "POST",
        defects=lambda rec, t: ["headers=[('authorization', '%s')], want none" % secret])
    msg, code = _verdict(lambda: run_canary(records, spec, probe, target))
    assert code == NOT_PROVEN, "want a retryable miss, got exit %r: %r" % (code, msg)
    assert "headers" in msg, "defect field not named: %r" % msg
    assert secret not in msg, "defect VALUE leaked into the verdict: %r" % msg


# ---------------------------------------------------------------------------
# Rule (a) selftest: targeted lookup reads (lookup_read children of api_reference)
# ---------------------------------------------------------------------------

_LK_EP = "34.120.0.10"
_LK_BLOCK = {"cluster_name": "demo-cluster", "location": "us-central1-f", "project": "demo-proj"}
_LK_PARENT = {"connector": "gke", "model": "apps/v1", "operation": "listAppsV1NamespacedDeployment",
              "gke_auth": _LK_BLOCK}
_LK_HASH = "AB" * 64
_LK_ROOT = "/openapi/v3"
_LK_DOC = "/openapi/v3/apis/apps/v1"
_LK_VERSION = "/version"
_LK_OK = json.dumps({"status": 200, "bytes": 10, "sha256": "00" * 32, "truncated": False})
_LK_DENIED = "test_hardening: denied"
# The timeout and size cap each read kind carries, as the Go recipe sets them.
_LK_BOUNDS = {_LK_ROOT: (20, 2 << 20), _LK_VERSION: (10, 64 << 10)}


def _lk_args(path, ap="gke", block=None, endpoint=_LK_EP, **over):
    """A lookup_read's arguments exactly as the Go reader writes them."""
    timeout, cap = _LK_BOUNDS.get(path, (60, 10 << 20))
    a = {"method": "GET", "url": "https://" + endpoint + path,
         "headers": [{"key": "Accept", "value": "application/json"}],
         "timeout_seconds": timeout, "max_response_body_size": cap, "auth_provider": ap,
         ap + "_auth": _LK_BLOCK if block is None else block}
    a.update(over)
    return a


def _lk_rec(cid, phase, tool, args, **extra):
    r = {"session_id": "s", "run_id": "r", "call_id": cid, "depth": 0, "phase": phase,
         "tool": tool, "arguments": args}
    r.update(extra)
    return r


def _lk_child(cid, path="/openapi/v3", args=None, result=_LK_OK, outcome="ok", parent="P1",
              attempt_extra=None, result_extra=None):
    """One lookup_read attempt and result pair."""
    a = _lk_args(path) if args is None else args
    att = _lk_rec(cid, "attempt", "lookup_read", a, via="api_reference", parent_call_id=parent)
    res = _lk_rec(cid, "result", "lookup_read", a, via="api_reference", parent_call_id=parent,
                  decision="unprompted", outcome=outcome, result=result)
    att.update(attempt_extra or {})
    res.update(result_extra or {})
    return [att, res]


def _lk_parent(phase, cid="P1", args=None, **extra):
    a = _LK_PARENT if args is None else args
    if phase == "attempt":
        return _lk_rec(cid, "attempt", "api_reference", a, **extra)
    r = _lk_rec(cid, "result", "api_reference", a, decision="unprompted", outcome="ok",
                result='{"outcome":"found"}')
    r.update(extra)
    return r


def _lk_lookup(children, cid="P1", args=None, attempt_extra=None, result_extra=None):
    """A parent api_reference call enclosing the given child records."""
    return ([_lk_parent("attempt", cid, args, **(attempt_extra or {}))] + children
            + [_lk_parent("result", cid, args, **(result_extra or {}))])


def _lk_bootstrap(cid, call="clusters.get", target="gke/demo-proj/us-central1-f/demo-cluster"):
    a = {"connector": "gke", "call": call, "target": target}
    return [_lk_rec(cid, "attempt", "lookup_bootstrap", a, via="api_reference", parent_call_id="P1"),
            _lk_rec(cid, "result", "lookup_bootstrap", a, via="api_reference", parent_call_id="P1",
                    decision="unprompted", outcome="ok", result="ok")]


def _lk_witness():
    """An http_request pair the engine test spec sanctions, whose 200 carries the marker, so a
    lookup case's verdict turns on the lookup sweep alone."""
    args = {"method": "GET", "url": "https://example.test/v1/projects/demo", "auth_provider": "gcp"}
    body = json.dumps({"projectId": "demo", "marker": "marker-1234"})
    return [json.loads(_jline("w1", "attempt", args)),
            json.loads(_jline("w1", "result", args, result=_sres(200, body), outcome="ok"))]


def _lk_binding(position=-1, ap="gke", authority=_LK_EP, matches=None):
    return LookupTarget(auth_provider=ap, authority=authority,
                        auth_matches=matches or (lambda a: True), position=position)


def _lk_spec(bind=None, name="lookups"):
    """The engine test spec plus a lookup_targets hook. bind(calls, target) defaults to one
    binding for _LK_EP that precedes every record."""
    base = _engine_test_spec()
    return ProviderSpec(
        name=name, blocked_word="test_hardening", read_mode="read",
        is_sanctioned_read=base.is_sanctioned_read, denial_matches=base.denial_matches,
        is_witness=base.is_witness, witness_hint=base.witness_hint,
        lookup_targets=bind or (lambda calls, t: [_lk_binding()]))


def _lk_strict(call):
    """_guard, but a crash is reported as such instead of as 4. A rule (a) breach must be a
    deliberate verdict: a guard that is removed and leaves a KeyError behind would otherwise
    still read as exit 4 and survive its mutation check."""
    import io
    old_out = sys.stdout
    sys.stdout = io.StringIO()
    try:
        call()
        return 0
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 1
    except Exception as e:  # noqa: BLE001 - the case table compares this string to an exit code.
        return "crash: %s" % type(e).__name__
    finally:
        sys.stdout = old_out


def _lk_read(records, spec=None):
    return _lk_strict(lambda: run_read(records, spec or _lk_spec(), "demo", "marker-1234"))


def _lk_base(children=None, **kw):
    """The witness plus one lookup whose children default to one bound root read."""
    return _lk_witness() + _lk_lookup(_lk_child("c1") if children is None else children, **kw)


def _lk_drop(recs, key):
    out = []
    for rec in recs:
        rec = dict(rec)
        rec.pop(key, None)
        out.append(rec)
    return out


def _lk_with(recs, **fields):
    return [dict(rec, **fields) for rec in recs]


def _lk_canary(records, spec=None):
    probe = CanarySpec(
        mode="canary", label="canary", boundary="POST probe",
        is_target=lambda rec, t: (args_of(rec).get("method") or "") == "POST",
        defects=lambda rec, t: [])
    return _lk_strict(lambda: run_canary(records, spec or _lk_spec(), probe, "demo"))


def _lk_canary_records():
    args = {"method": "POST", "url": "https://example.test/v1/projects/demo", "auth_provider": "gcp"}
    return [json.loads(_jline("k1", "attempt", args)),
            json.loads(_jline("k1", "result", args, result=_LK_DENIED, outcome="error"))]


def _lk_unsanctioned_success():
    args = {"method": "DELETE", "url": "https://example.test/v1/projects/demo", "auth_provider": "gcp"}
    return [json.loads(_jline("x1", "attempt", args)),
            json.loads(_jline("x1", "result", args, result=_sres(200, "{}"), outcome="ok"))]


def _lk_unsanctioned_denied():
    args = {"method": "DELETE", "url": "https://example.test/v1/projects/demo", "auth_provider": "gcp"}
    return [json.loads(_jline("x1", "attempt", args)),
            json.loads(_jline("x1", "result", args, result=_LK_DENIED, outcome="error"))]


def _lk_url(url):
    return _lk_args(_LK_ROOT, url=url)


def _lookup_cases():  # noqa: PLR0915 - one flat case table; splitting it hides the table.
    """The rule (a) cases: every condition of sweep_lookup_reads, its verdict split, the sweep
    ordering, the hook validation and the P3 key-folding seeds. Each case builds its records
    and its spec inside the lambda, so a missing engine name fails that case alone."""
    hashed = _LK_DOC + "?hash=" + _LK_HASH
    # Indices in _lk_base(): w1 attempt 0, w1 result 1, parent attempt 2, child attempt 3.
    child_at = 3
    other_block = dict(_LK_BLOCK, cluster_name="other-cluster")
    return [
        # The baseline: one bound root read inside an unprompted parent. Admitted, never a
        # witness, so the witness pair decides and the verdict is 0.
        ("lookup_admitted", 0, lambda: _lk_read(_lk_base())),
        ("lookup_full_recipe", 0, lambda: _lk_read(_lk_base(
            _lk_child("c1") + _lk_child("c2", hashed) + _lk_child("c3", _LK_VERSION)))),
        # guard_unknown_io skips a lookup_read only when its via is api_reference: one with no
        # via is a credentialed request smuggled through an unknown tool name.
        ("lookup_guard_requires_via", 4, lambda: _lk_read(
            _lk_witness() + _lk_lookup(_lk_drop(_lk_child("c1"), "via")))),
        # lookup_bootstrap records carry neither url nor auth_provider and are not judged.
        ("lookup_bootstrap_inert", 0, lambda: _lk_read(_lk_base(_lk_bootstrap("b1") + _lk_child("c1")))),
        ("lookup_bootstrap_alone", 0, lambda: _lk_read(_lk_witness() + _lk_bootstrap("b1"))),
        # A spec with no lookup_targets binds nothing: a successful read is unbound (4), a denied
        # one a retryable miss (1).
        ("lookup_no_hook_success", 4, lambda: _lk_read(_lk_base(), _engine_test_spec())),
        ("lookup_no_hook_denied", 1, lambda: _lk_read(
            _lk_base(_lk_child("c1", result=_LK_DENIED, outcome="error")), _engine_test_spec())),
        # An admitted lookup read is never a witness.
        ("lookup_never_witness", 1, lambda: _lk_read(_lk_lookup(_lk_child("c1")))),

        # ---- condition 1: strict pairing ----
        ("lookup_child_no_result", 4, lambda: _lk_read(_lk_base(_lk_child("c1")[:1]))),
        ("lookup_child_orphan_result", 4, lambda: _lk_read(_lk_base(_lk_child("c1")[1:]))),
        ("lookup_child_dup_attempt", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1")[:1] + _lk_child("c1")))),
        ("lookup_child_result_first", 4, lambda: _lk_read(_lk_base(_lk_child("c1")[::-1]))),
        # A third record with an unknown phase beside a well-formed pair, so the verdict
        # turns on the phase check alone.
        ("lookup_child_unknown_phase", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1") + _lk_child("c1", result_extra={"phase": "weird"})[1:]))),
        ("lookup_child_dup_result", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1") + _lk_child("c1")[1:]))),
        ("lookup_child_empty_id", 4, lambda: _lk_read(_lk_base(_lk_with(_lk_child("c1"), call_id="")))),
        ("lookup_child_parent_disagrees", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", result_extra={"parent_call_id": "P2"})))),
        ("lookup_child_args_disagree", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", result_extra={"arguments": _lk_args(_LK_VERSION)})))),
        ("lookup_child_depth_disagrees", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", result_extra={"depth": 1})))),

        # ---- condition 2: the parent ----
        ("lookup_no_parent", 4, lambda: _lk_read(_lk_witness() + _lk_child("c1"))),
        # An empty parent id names no parent, even when a parent record has an empty call_id.
        ("lookup_child_empty_parent_id", 4, lambda: _lk_read(_lk_base(_lk_child("c1", parent=""), cid=""))),
        ("lookup_parent_other_run", 4, lambda: _lk_read(_lk_base(
            attempt_extra={"run_id": "r2"}, result_extra={"run_id": "r2"}))),
        ("lookup_parent_no_result", 4, lambda: _lk_read(_lk_base()[:-1])),
        ("lookup_parent_dup_attempt", 4, lambda: _lk_read(
            _lk_witness() + [_lk_parent("attempt")] + _lk_lookup(_lk_child("c1")))),
        # Two results and no attempt: the right count of records, in the wrong phases.
        ("lookup_parent_two_results", 4, lambda: _lk_read(
            _lk_witness() + [_lk_parent("result")] + _lk_child("c1") + [_lk_parent("result")])),
        ("lookup_parent_result_first", 4, lambda: _lk_read(
            _lk_witness() + [_lk_parent("result")] + _lk_child("c1") + [_lk_parent("attempt")])),
        ("lookup_parent_args_disagree", 4, lambda: _lk_read(_lk_base(
            result_extra={"arguments": dict(_LK_PARENT, model="batch/v1")}))),
        ("lookup_parent_depth_disagrees", 4, lambda: _lk_read(_lk_base(result_extra={"depth": 1}))),
        ("lookup_parent_args_unparseable", 4, lambda: _lk_read(_lk_base(
            attempt_extra={"arguments": "not json"}, result_extra={"arguments": "not json"}))),
        ("lookup_parent_denied", 4, lambda: _lk_read(_lk_base(result_extra={"outcome": "denied"}))),
        # The child carries the parent's decision too, so only the parent's own label decides.
        ("lookup_parent_ungated", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", result_extra={"decision": "ungated"}), result_extra={"decision": "ungated"}))),
        # An unavailable lookup still made its reads: an error outcome is not a denial.
        ("lookup_parent_error_ok", 0, lambda: _lk_read(_lk_base(result_extra={"outcome": "error"}))),
        ("lookup_child_after_parent", 4, lambda: _lk_read(_lk_witness() + _lk_lookup([]) + _lk_child("c1"))),
        ("lookup_child_before_parent", 4, lambda: _lk_read(_lk_witness() + _lk_child("c1") + _lk_lookup([]))),
        ("lookup_child_straddles_parent", 4, lambda: _lk_read(
            _lk_witness() + [_lk_parent("attempt")] + _lk_child("c1")[:1] + [_lk_parent("result")]
            + _lk_child("c1")[1:])),
        ("lookup_child_depth_differs", 4, lambda: _lk_read(_lk_base(_lk_with(_lk_child("c1"), depth=1)))),
        ("lookup_child_decision_differs", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", result_extra={"decision": "approved"})))),

        # ---- condition 3: the recipe ----
        ("lookup_provider_differs", 4, lambda: _lk_read(_lk_base(
            args=dict(_LK_PARENT, connector="aks")))),
        ("lookup_connector_case_variant", 0, lambda: _lk_read(_lk_base(
            args=dict(_LK_PARENT, connector="GKE")))),
        ("lookup_block_value_differs", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", args=_lk_args(_LK_ROOT, block=other_block))))),
        ("lookup_block_extra_key", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", args=_lk_args(_LK_ROOT, block=dict(_LK_BLOCK, zone="x")))))),
        ("lookup_parent_no_block", 4, lambda: _lk_read(_lk_base(
            args={k: v for k, v in _LK_PARENT.items() if k != "gke_auth"}))),
        ("lookup_parent_extra_block_key", 0, lambda: _lk_read(_lk_base(
            args=dict(_LK_PARENT, gke_auth=dict(_LK_BLOCK, zone="x"))))),
        ("lookup_doc_key_mismatch", 4, lambda: _lk_read(_lk_base(_lk_child("c1", "/openapi/v3/apis/batch/v1")))),
        ("lookup_doc_hashed", 0, lambda: _lk_read(_lk_base(_lk_child("c1", hashed)))),
        ("lookup_doc_core_group", 0, lambda: _lk_read(_lk_base(
            _lk_child("c1", "/openapi/v3/api/v1"), args=dict(_LK_PARENT, model="v1")))),
        # ParseAPIVersion takes "core/v1" as a group named core, so the document key is
        # apis/core/v1. The parser mirrors that exactly.
        ("lookup_doc_named_core_group", 0, lambda: _lk_read(_lk_base(
            _lk_child("c1", "/openapi/v3/apis/core/v1"), args=dict(_LK_PARENT, model="core/v1")))),
        ("lookup_doc_model_invalid", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", _LK_DOC), args=dict(_LK_PARENT, model="apps/v1/x")))),
        ("lookup_doc_model_missing", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", _LK_DOC), args={k: v for k, v in _LK_PARENT.items() if k != "model"}))),

        # ---- condition 4: the shape ----
        ("lookup_extra_arg_body", 4, lambda: _lk_read(_lk_base(_lk_child("c1", args=dict(
            _lk_args(_LK_ROOT), body="x"))))),
        ("lookup_method_post", 4, lambda: _lk_read(_lk_base(_lk_child("c1", args=dict(
            _lk_args(_LK_ROOT), method="POST"))))),
        ("lookup_no_headers", 4, lambda: _lk_read(_lk_base(_lk_child("c1", args=dict(
            _lk_args(_LK_ROOT), headers=[]))))),
        ("lookup_two_headers", 4, lambda: _lk_read(_lk_base(_lk_child("c1", args=dict(
            _lk_args(_LK_ROOT), headers=[{"key": "Accept", "value": "application/json"},
                                         {"key": "X-Extra", "value": "1"}]))))),
        ("lookup_header_other_value", 4, lambda: _lk_read(_lk_base(_lk_child("c1", args=dict(
            _lk_args(_LK_ROOT), headers=[{"key": "Accept", "value": "application/yaml"}]))))),
        # azure is outside the rule until its own lands, even with a binding that names it.
        ("lookup_azure_provider", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", args=_lk_args(_LK_ROOT, ap="azure")),
            args=dict(_LK_PARENT, connector="azure", azure_auth=_LK_BLOCK)),
            _lk_spec(lambda c, t: [_lk_binding(ap="azure")]))),

        # ---- condition 5: the URL ----
        ("lookup_path_secrets", 4, lambda: _lk_read(_lk_base(_lk_child("c1", "/api/v1/namespaces/default/secrets")))),
        ("lookup_query_watch", 4, lambda: _lk_read(_lk_base(_lk_child("c1", _LK_DOC + "?watch=1")))),
        ("lookup_hash_lowercase", 4, lambda: _lk_read(_lk_base(_lk_child("c1", _LK_DOC + "?hash=" + "ab" * 64)))),
        ("lookup_hash_short", 4, lambda: _lk_read(_lk_base(_lk_child("c1", _LK_DOC + "?hash=" + _LK_HASH[:127])))),
        ("lookup_hash_on_root", 4, lambda: _lk_read(_lk_base(_lk_child("c1", _LK_ROOT + "?hash=" + _LK_HASH)))),
        ("lookup_trailing_slash", 4, lambda: _lk_read(_lk_base(_lk_child("c1", _LK_ROOT + "/")))),
        ("lookup_userinfo", 4, lambda: _lk_read(_lk_base(_lk_child("c1", args=_lk_url(
            "https://u:p@" + _LK_EP + _LK_ROOT))))),
        ("lookup_http_scheme", 4, lambda: _lk_read(_lk_base(_lk_child("c1", args=_lk_url(
            "http://" + _LK_EP + _LK_ROOT))))),
        ("lookup_bad_group", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", "/openapi/v3/apis/APPS/v1"), args=dict(_LK_PARENT, model="APPS/v1")))),

        # ---- condition 6: the target binding ----
        ("lookup_unbound_denied", 1, lambda: _lk_read(_lk_base(
            _lk_child("c1", result=_LK_DENIED, outcome="error")), _lk_spec(lambda c, t: []))),
        ("lookup_unbound_success", 4, lambda: _lk_read(_lk_base(), _lk_spec(lambda c, t: []))),
        # The binding must PRECEDE the child's attempt: equal is not before.
        ("lookup_bind_at_attempt", 4, lambda: _lk_read(_lk_base(), _lk_spec(
            lambda c, t: [_lk_binding(position=child_at)]))),
        ("lookup_bind_before_attempt", 0, lambda: _lk_read(_lk_base(), _lk_spec(
            lambda c, t: [_lk_binding(position=child_at - 1)]))),
        ("lookup_bind_other_provider", 4, lambda: _lk_read(_lk_base(), _lk_spec(
            lambda c, t: [_lk_binding(ap="eks")]))),
        ("lookup_bind_other_authority", 4, lambda: _lk_read(_lk_base(), _lk_spec(
            lambda c, t: [_lk_binding(authority="35.190.0.20")]))),
        ("lookup_bind_predicate_rejects", 4, lambda: _lk_read(_lk_base(), _lk_spec(
            lambda c, t: [_lk_binding(matches=lambda a: False)]))),
        # An explicit port is a different authority from the bare one the binding names.
        ("lookup_port_unbound", 4, lambda: _lk_read(_lk_base(_lk_child("c1", args=_lk_url(
            "https://" + _LK_EP + ":443" + _LK_ROOT))))),
        ("lookup_port_unbound_denied", 1, lambda: _lk_read(_lk_base(_lk_child(
            "c1", args=_lk_url("https://" + _LK_EP + ":443" + _LK_ROOT), result=_LK_DENIED,
            outcome="error")))),

        # ---- condition 7: the budget, counted over every child that passed 1 to 5 ----
        ("lookup_three_roots", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1") + _lk_child("c2") + _lk_child("c3")))),
        ("lookup_four_documents", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", hashed) + _lk_child("c2", hashed) + _lk_child("c3", _LK_DOC)
            + _lk_child("c4", _LK_DOC)))),
        ("lookup_two_versions", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1", _LK_VERSION) + _lk_child("c2", _LK_VERSION)))),
        ("lookup_full_budget", 0, lambda: _lk_read(_lk_base(
            _lk_child("c1") + _lk_child("c2") + _lk_child("c3", hashed) + _lk_child("c4", hashed)
            + _lk_child("c5", _LK_DOC) + _lk_child("c6", _LK_VERSION)))),
        # Two bound roots plus a denied root on another authority: the unbound one counts too,
        # so a looping recipe cannot hide extra reads behind retryable misses.
        ("lookup_unbound_denied_counts", 4, lambda: _lk_read(_lk_base(
            _lk_child("c1") + _lk_child("c2") + _lk_child(
                "c3", args=_lk_args(_LK_ROOT, endpoint="35.190.0.20"), result=_LK_DENIED,
                outcome="error")))),
        ("lookup_budget_is_per_parent", 0, lambda: _lk_read(
            _lk_base(_lk_child("c1") + _lk_child("c2"))
            + _lk_lookup(_lk_child("c3", parent="P2") + _lk_child("c4", parent="P2"), cid="P2"))),

        # ---- sweep ordering: a miss is reported only after both sweeps ran clean ----
        ("lookup_miss_then_http_breach", 4, lambda: _lk_read(
            _lk_base(_lk_child("c1", result=_LK_DENIED, outcome="error")) + _lk_unsanctioned_success(),
            _lk_spec(lambda c, t: []))),
        ("lookup_breach_after_http_miss", 4, lambda: _lk_read(
            _lk_unsanctioned_denied() + _lk_base(), _lk_spec(lambda c, t: []))),

        # ---- the parent's key folding (P3) ----
        ("lookup_parent_two_spellings", 4, lambda: _lk_read(_lk_base(
            args=dict(_LK_PARENT, GKE_AUTH=_LK_BLOCK)))),
        ("lookup_parent_block_collision", 4, lambda: _lk_read(_lk_base(
            args=dict(_LK_PARENT, gke_auth=dict(_LK_BLOCK, Project="demo-proj"))))),
        # encoding/json binds Cluster_Name to cluster_name, and so does the fold.
        ("lookup_fold_case_variant", 0, lambda: _lk_read(_lk_base(args=dict(_LK_PARENT, gke_auth={
            "Cluster_Name": "demo-cluster", "location": "us-central1-f", "project": "demo-proj"})))),
        # U+017F (long s) folds to s in both Go's EqualFold and casefold: the same binding.
        ("lookup_fold_017f", 0, lambda: _lk_read(_lk_base(args=dict(_LK_PARENT, gke_auth={
            "cluſter_name": "demo-cluster", "location": "us-central1-f", "project": "demo-proj"})))),
        # U+212A (Kelvin sign) folds to k in both: gKe_auth binds as gke_auth.
        ("lookup_fold_212a", 0, lambda: _lk_read(_lk_base(args={
            "connector": "gke", "model": "apps/v1", "operation": "listAppsV1NamespacedDeployment",
            "gKe_auth": _LK_BLOCK}))),
        # U+FB06 (the st ligature) casefolds to "st", which Go's simple folding does not do, so
        # the parser sees two spellings of cluster_name where Go bound one: it errs closed.
        ("lookup_fold_fb06", 4, lambda: _lk_read(_lk_base(args=dict(_LK_PARENT, gke_auth=dict(
            _LK_BLOCK, **{"cluﬆer_name": "demo-cluster"}))))),

        # ---- the hook itself ----
        ("lookup_targets_noncallable", 4, lambda: _guard(lambda: _resolve_with(replace(
            _lk_spec(name="lookups-noncallable"), lookup_targets="not a callable")))),
        ("lookup_targets_not_a_list", 4, lambda: _lk_read(_lk_base(), _lk_spec(lambda c, t: None))),
        ("lookup_targets_bad_item", 4, lambda: _lk_read(_lk_base(), _lk_spec(
            lambda c, t: [("gke", _LK_EP, None, -1)]))),
        # A hook that raises is a crash, which the entrypoint guard turns into 4.
        ("lookup_targets_raises", 4, lambda: _guard(lambda: run_read(
            _lk_base(), _lk_spec(lambda c, t: 1 / 0), "demo", "marker-1234"))),

        # ---- canary mode runs the same sweep ----
        ("lookup_canary_admitted", 0, lambda: _lk_canary(_lk_canary_records() + _lk_lookup(_lk_child("c1")))),
        ("lookup_canary_unbound", 4, lambda: _lk_canary(
            _lk_canary_records() + _lk_lookup(_lk_child("c1")), _lk_spec(lambda c, t: []))),
    ]


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

        # A well-formed sanctioned-shape pair whose 200 carries the marker: the baseline the
        # contextual-plan cases vary, so their verdicts turn on the plan and nothing else.
        ok_pair = [r("c1", "attempt", read_args),
                   r("c1", "result", read_args, result=_sres(200, ok_body), outcome="ok")]
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

        # credential_prepass fixtures (#56). Each drives the prepass directly through
        # _guard: a clean scan returns None (0), a hit calls insecure (4). The live
        # secrets are neutral-shaped values (no production shape of their own), so only
        # the class-1 exact-value scan can catch them; enc_secret carries the url-unsafe
        # bytes that pin the percent-encoding path.
        live_secret = "s3cr3t-ambient-value-xyz0"
        enc_secret = "aa/bb+cc=dd-EE"

        def _b64line(s):
            return base64.b64encode(s.encode("utf-8")).decode("ascii") + "\n"

        # The live-secrets file is base64-encoded, one value per line (see
        # _read_live_secrets), so a multi-line credential stays a single exact needle.
        p_secrets = _write(tmp, _b64line(live_secret) + _b64line(enc_secret))
        # A multi-line credential blob whose non-secret lines ("{", a project id) must
        # NOT false-positive on their own, while a verbatim leak of the whole blob does.
        multi_secret = '{\n  "project_id": "cynative-cli-ci",\n  "token_url": "x"\n}'
        p_secrets_multi = _write(tmp, _b64line(multi_secret))

        def cp(lines, secrets_path=None):
            recs = []
            for ln in lines:
                try:
                    recs.append(json.loads(ln))
                except ValueError:
                    pass
            credential_prepass(recs, lines, secrets_path)

        # class-2: an AKIA-shaped access key sitting in verbatim (unredacted) arguments.
        akia_line = _jline("c1", "attempt", {
            "method": "GET", "url": "https://iam.amazonaws.com/", "auth_provider": "aws",
            "body": "x=AKIAIOSFODNN7EXAMPLE"})
        # class-2: an unredacted PEM private key in a direct-path result dump.
        pem_result = ("HTTP/1.1 200 OK\r\n\r\n-----BEGIN PRIVATE KEY-----"
                      "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7-----END PRIVATE KEY-----")
        pem_line = _jline("c1", "result",
                          {"method": "GET", "url": "https://iam.amazonaws.com/", "auth_provider": "aws"},
                          result=pem_result, outcome="ok")
        # raw_lines scan: a credential in a tolerated malformed FINAL line that never
        # parses into a record, so only the physical-byte scan can see it.
        clean_line = _jline("c1", "attempt", read_args)
        partial_secret_line = '{"result":"leak AKIAIOSFODNN7EXAMPLE'
        # class-1: a header value equal to a live secret (needs the fixture file).
        hdr_secret_line = _jline("c1", "attempt", {
            "method": "GET", "url": "https://api.github.com/", "auth_provider": "github",
            "headers": [{"key": "X-Custom", "value": live_secret}]})
        # class-2 via userinfo: a real github-token-shaped secret as the URL password.
        ui_secret_line = _jline("c1", "attempt", {
            "method": "GET", "url": "https://x:ghp_" + ("0" * 40) + "@api.github.com/",
            "auth_provider": "github"})
        # value-gated userinfo: u:p is no secret, so it stays a canary defect, not a leak.
        ui_plain_line = _jline("c1", "attempt", {
            "method": "POST", "url": "https://u:p@iam.amazonaws.com:444/", "auth_provider": "aws"})
        # value-gated header: Authorization: Bearer x carries no secret value.
        authhdr_line = _jline("c1", "attempt", {
            "method": "PATCH", "url": "https://api.github.com/repos/x/y", "auth_provider": "github",
            "headers": [{"key": "Authorization", "value": "Bearer x"}]})
        # an exact placeholder is the redactor having done its job: accepted.
        redacted_line = _jline("c1", "result",
                               {"method": "GET", "url": "https://api.github.com/", "auth_provider": "github"},
                               result="response body: [REDACTED:jwt] ok", outcome="ok")
        # an empty signing param value before a JSON escaped quote, which the redactor
        # leaves as it is (#410), and one whose value follows a backslash.
        sig_empty_line = _jline("c1", "result",
                                {"method": "GET", "url": "https://api.github.com/", "auth_provider": "github"},
                                result='["u?sig=\\"a","u?X-Amz-Security-Token=\\"b"]', outcome="ok")
        sig_backslash_line = _jline("c1", "result",
                                    {"method": "GET", "url": "https://api.github.com/", "auth_provider": "github"},
                                    result="sig=\\" + live_secret, outcome="ok")
        # the non-secret witness fact (a project number) must not be mistaken for a leak.
        witness_line = _jline("c1", "result", {
            "method": "GET",
            "url": "https://cloudresourcemanager.googleapis.com/v1/projects/demo",
            "auth_provider": "gcp"}, result=_sres(
                200, json.dumps({"projectId": "demo", "projectNumber": "123456789012"})), outcome="ok")
        # class-1 under percent-encoding: the live secret url-encoded in a query.
        enc_line = _jline("c1", "attempt", {
            "method": "GET", "url": "https://iam.amazonaws.com/?token=aa%2Fbb%2Bcc%3Ddd-EE",
            "auth_provider": "aws"})
        # class-3 (new YAML/env line rules): a neutral-shaped value under a credential-
        # named key, carried as a request body. The value is the neutral live-secret
        # string (no production shape of its own) but NO --live-secrets file is passed,
        # so class-1 stays off and only the new YAML/env class-3 rule can flag it - a
        # true RED-before/GREEN-after pin of that rule (a passed live-secrets file would
        # let class-1 short-circuit before the class-3 rule ever ran).
        yaml_cred_line = _jline("c1", "attempt", {
            "method": "GET", "url": "https://iam.amazonaws.com/", "auth_provider": "aws",
            "body": "password: " + live_secret})
        env_cred_line = _jline("c1", "attempt", {
            "method": "GET", "url": "https://iam.amazonaws.com/", "auth_provider": "aws",
            "body": "AWS_SECRET_ACCESS_KEY=" + live_secret})
        # class-3 (#307 shapes): a neutral value under a prefixed JSON key, in a
        # name/value pair (both orders, JSON and YAML) or after a credential flag. As
        # above, no --live-secrets file, so only the class-3 rule can flag each one.
        def _body_line(body):
            return _jline("c1", "attempt", {
                "method": "GET", "url": "https://iam.amazonaws.com/", "auth_provider": "aws", "body": body})
        shape307_leaks = [
            ("prefixed_key", '{"DB_PASSWD":"%s"}' % live_secret),
            ("name_value", '[{"name":"DB_PASSWORD","type":"PLAINTEXT","value":"%s"}]' % live_secret),
            ("value_name", '[{"value":"%s","name":"API_KEY"}]' % live_secret),
            ("yaml_pair", "- Name: DB_PASSWORD\n  Value: %s\n" % live_secret),
            # Truncated, so the body does not parse into elements: a parsed element
            # "--db-password=v" on its own also reads as an env line.
            ("flag_joined", '["--db-password=%s' % live_secret),
            ("flag_separate", '["--generate-secret","--token","%s"]' % live_secret),
            ("kebab_key", '{"service-api-key":"%s"}' % live_secret),
            ("yaml_pair_reversed", "- value: %s\n  name: DB_PASSWORD\n" % live_secret),
        ]
        # The same shapes with nothing to flag: a pagination cursor, a non-credential
        # pair, a flag-shaped member value, values the redactor already replaced, a
        # boolean flag whose next element is another flag, and a flag-shaped object key.
        shape307_clean = _body_line(
            '{"nextPageToken":"%s","items":[{"name":"DB_HOST","value":"%s"}],"t":"--token","public":"%s",'
            '"env":[{"name":"DB_PASSWORD","value":"[REDACTED:credential-field]"}],'
            '"args":["--token","[REDACTED:credential-field]"],'
            '"cmd":["--no-generate-secret","--client-name","%s"],"--token=%s":1}'
            % (live_secret, live_secret, live_secret, live_secret, live_secret))
        # class-3 (#401 shapes, the structural detectors): a YAML pair with a comment on
        # the name line, a multi-line value after a token label, a JSON key spelled with
        # an escape in a body cut short (json.loads cannot read it), a repeated "value"
        # member, a flag inside a shell command, a flag value starting "--", and a
        # placeholder followed by more text, which is not a whole redacted value.
        shape401_leaks = [
            ("yaml_pair_comment", "- name: DB_PASSWORD # db\n  value: %s\n" % live_secret),
            ("yaml_multiline_after_label", "password: [REDACTED:github-token]\n  %s\n" % live_secret),
            ("json_escaped_key_truncated", '{"DB_PASSW\\u004fRD":"%s' % live_secret),
            ("json_duplicate_value",
             '{"name":"DB_PASSWORD","value":"[REDACTED:credential-field]","value":"%s"}' % live_secret),
            ("shell_command_flag", '["sh","-c","app --token %s --port 80"]' % live_secret),
            ("flag_value_dashes", '["--password","--%s"]' % live_secret),
            ("placeholder_with_tail", '{"password":"[REDACTED:jwt]%s"}' % live_secret),
            ("yaml_pair_in_block_scalar",
             "data:\n  config.yaml: |\n    - name: DB_PASSWORD\n      value: %s\n" % live_secret),
            ("shell_flag_spelled_with_quotes", '["sh","-c","app \\"--pass\\"word %s"]' % live_secret),
            ("yaml_block_after_anchor", "password: &pw |\n  # %s\nnext: public\n" % live_secret),
            ("yaml_name_on_next_line", "- name:\n    DB_PASSWORD\n  value: %s\n" % live_secret),
            ("yaml_quoted_value_holding_colon", "password:\n  \"a: %s\"\n" % live_secret),
            ("flag_value_cut_after_placeholder",
             '["--password","[REDACTED:credential-field]\\q%s"]' % live_secret),
            ("shell_value_cut_after_placeholder", '["sh","-c","app --token [REDACTED:jwt]\\q%s"]' % live_secret),
            ("yaml_quoted_value_after_props_below", "password:\n  &pw \"a: %s\"\n" % live_secret),
            ("flag_value_dashes_before_positional", '["app","--password","--%s","input.txt"]' % live_secret),
            ("shell_after_options", '["bash","--noprofile","-o","pipefail","-ec","app --token %s"]' % live_secret),
            ("flag_hyphens_escaped", '["\\u002d\\u002dpassword","%s"]' % live_secret),
            ("shell_value_substitution", '["sh","-c","app --password=$(printf %s)"]' % live_secret),
            ("yaml_quoted_key_block", '"password": |\n  %s\n' % live_secret),
            ("flag_spelled_with_escapes", '["--passw\\u006frd","%s"]' % live_secret),
            ("shell_flag_line_join", '["sh","-c","app --pass\\\\\\nword %s"]' % live_secret),
        ]
        # The redactor's output for those shapes, and shapes it leaves alone: a nested
        # mapping under a credential-named key, a pair split across two mappings, an
        # escaped pagination cursor, and a command no shell runs.
        shape401_clean = _body_line(
            "- name: DB_PASSWORD # db\n  value: [REDACTED:credential-field]\n"
            "password: [REDACTED:credential-field]\n"
            "volumes:\n- name: db\n  secret:\n    secretName: %s\n"
            "items:\n  - name: DB_PASSWORD\nvalue: %s\n"
            '{"n\\u0065xtPageToken":"%s","args":["echo","app --token %s"],'
            '"cmd":["sh","-c","app --token [REDACTED:credential-field] --port 80"],'
            '"DB_PASSW\\u004fRD":"\\u005bREDACTED:credential-field]"}'
            % (live_secret, live_secret, live_secret, live_secret))
        # --live-secrets edge paths (class-1 file mechanism): an empty file is valid
        # (ambient-credential runs enumerate no env secret) and a missing/unreadable path
        # is a wiring bug that fails closed.
        p_empty_secrets = _write(tmp, "")
        p_missing_secrets = os.path.join(tmp, "no-such-secrets.txt")
        # class-1 multi-line: a verbatim leak of the WHOLE credential blob is caught, but a
        # benign audit carrying only its non-secret fragments ("{", the project id) must
        # NOT false-positive - the regression the base64 exact-value encoding closes.
        multi_leak_line = _jline("c1", "result", read_args,
                                 result="HTTP/1.1 200 OK\r\n\r\n" + multi_secret, outcome="ok")
        multi_benign_line = _jline("c1", "result", read_args,
                                   result='HTTP/1.1 200 OK\r\n\r\n{"projectId":"cynative-cli-ci"}',
                                   outcome="ok")

        cases = [
            ("sweep_names_the_canary_defect", 0, lambda: _guard(
                lambda: _sweep_explains_defects(spec, target, url))),
            ("sweep_redacts_url_credentials", 0, lambda: _guard(
                lambda: _sweep_redacts_url_credentials(spec, target))),
            ("candidate_loop_labels_defects", 0, lambda: _guard(
                lambda: _candidate_loop_labels_defects(spec, target, url))),
            ("redacted_url_shapes", 0, lambda: _guard(_redacted_url_shapes)),
            ("structural_spans", 0, lambda: _guard(_structural_spans)),
            ("verdict_reports_clean_exit", 0, lambda: _guard(_verdict_reports_clean_exit)),
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
            # A contextual plan is genuinely consulted: the per-record predicate sanctions
            # nothing, so this pair reaches the witness check only via plan_reads. Without
            # the plan it would be an unsanctioned 200 and a breach, which is exactly what
            # the next case pins.
            ("plan_sanctions", 0, lambda: _guard(lambda: run_read(
                ok_pair, _planning_spec(lambda calls, t: {k for k, _s in calls}), target, expect))),
            ("plan_sanctions_nothing", 4, lambda: _guard(lambda: run_read(
                ok_pair, _planning_spec(lambda calls, t: set()), target, expect))),
            # A plan that is not a set would make `key in planned` silently false-y (a list
            # of keys happens to work, a string or None does not) - fail closed instead.
            ("plan_not_a_set", 4, lambda: _guard(lambda: run_read(
                ok_pair, _planning_spec(lambda calls, t: [k for k, _s in calls]), target, expect))),
            # A plan naming a key the index does not hold would exempt a call nobody can
            # point at; a typo'd key set is a broken spec, not a pass.
            ("plan_unknown_key", 4, lambda: _guard(lambda: run_read(
                ok_pair, _planning_spec(lambda calls, t: {("s", "r", "ghost")}), target, expect))),
            ("plan_raises", 4, lambda: _guard(lambda: run_read(
                ok_pair, _planning_spec(lambda calls, t: 1 / 0), target, expect))),
            ("plan_noncallable", 4, lambda: _guard(
                lambda: _resolve_with(_planning_spec("not a callable")))),
            ("entry_import_error", 4, lambda: _run_entry_with_broken_engine(
                "raise ImportError('boom')", ["enginetest", "read", p_unreadable, target, expect])),
            ("entry_import_sysexit", 4, lambda: _run_entry_with_broken_engine(
                "raise SystemExit(1)", ["enginetest", "read", p_unreadable, target, expect])),
            ("cred_akia_in_args", 4, lambda: _guard(lambda: cp([akia_line]))),
            ("cred_pem_in_result", 4, lambda: _guard(lambda: cp([pem_line]))),
            ("cred_trailing_partial", 4, lambda: _guard(lambda: cp([clean_line, partial_secret_line]))),
            ("cred_header_eq_live_secret", 4, lambda: _guard(lambda: cp([hdr_secret_line], p_secrets))),
            ("cred_userinfo_real_secret", 4, lambda: _guard(lambda: cp([ui_secret_line]))),
            ("cred_userinfo_nonsecret_ok", 0, lambda: _guard(lambda: cp([ui_plain_line]))),
            ("cred_authhdr_bearer_ok", 0, lambda: _guard(lambda: cp([authhdr_line]))),
            ("cred_redacted_placeholder_ok", 0, lambda: _guard(lambda: cp([redacted_line]))),
            ("cred_signing_empty_value_ok", 0, lambda: _guard(lambda: cp([sig_empty_line]))),
            ("cred_signing_value_after_backslash", 4, lambda: _guard(lambda: cp([sig_backslash_line]))),
            ("cred_witness_fact_ok", 0, lambda: _guard(lambda: cp([witness_line]))),
            ("cred_percent_encoded_secret", 4, lambda: _guard(lambda: cp([enc_line], p_secrets))),
            ("cred_multiline_blob_leaked", 4, lambda: _guard(lambda: cp([multi_leak_line], p_secrets_multi))),
            ("cred_multiline_no_false_positive", 0, lambda: _guard(lambda: cp([multi_benign_line], p_secrets_multi))),
            # class-3 new rules: a credential-named YAML/env line leaks its value.
            ("cred_yaml_credential_field", 4, lambda: _guard(lambda: cp([yaml_cred_line]))),
            ("cred_env_credential_field", 4, lambda: _guard(lambda: cp([env_cred_line]))),
        ] + [
            ("cred_307_" + name, 4, (lambda line: lambda: _guard(lambda: cp([line])))(_body_line(body)))
            for name, body in shape307_leaks
        ] + [
            ("cred_307_clean", 0, lambda: _guard(lambda: cp([shape307_clean]))),
        ] + [
            ("cred_401_" + name, 4, (lambda line: lambda: _guard(lambda: cp([line])))(_body_line(body)))
            for name, body in shape401_leaks
        ] + [
            ("cred_401_clean", 0, lambda: _guard(lambda: cp([shape401_clean]))),
            ("cred_401_pretty_json_clean", 0, lambda: _guard(lambda: cp([_body_line(
                '{\n  "name": "DB_PASSWORD",\n  "value": "[REDACTED:credential-field]",\n  "n": 1\n}\n'
                '{\n  "name": "DB_PASSWORD",\n  "value": 123\n}')]))),
            # --live-secrets edge paths: a missing/unreadable file fails closed, an empty
            # file is valid (class-1 skipped) and leaves an otherwise-clean scan clean.
            ("cred_missing_secrets_file", 4, lambda: _guard(lambda: cp([clean_line], p_missing_secrets))),
            ("cred_empty_secrets_file", 0, lambda: _guard(lambda: cp([clean_line], p_empty_secrets))),
        ]
        cases.extend(_lookup_cases())

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
