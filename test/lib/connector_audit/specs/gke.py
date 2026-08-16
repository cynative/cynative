#!/usr/bin/env python3
"""GKE connector e2e provider spec: the TWO-HOP read family, the ClusterRole-policy
denial, and the two boundary canaries (a ConfigMap create, and a Secrets list the `view`
ClusterRole denies outright).

GKE is the first connector whose legitimate read is not a single self-contained request.
The connector has no default cluster and its own documented workflow is two hops: resolve
the control-plane endpoint through the GCP Container API (`auth_provider=gcp`), then talk
to the Kubernetes API at that endpoint (`auth_provider=gke`). The suite deliberately does
not hand the endpoint to the model, so the read phase exercises that discovery for real.

WHY THIS SPEC HAS plan_reads AND AN is_sanctioned_read THAT DENIES EVERYTHING
----------------------------------------------------------------------------
engine.sweep_calls exempts a sanctioned read from the fatal unsanctioned-call sweep
WITHOUT looking at its result, so whatever the read family admits can no longer be caught
having SUCCEEDED. A per-record predicate cannot express hop 2's actual precondition: the
endpoint is not a constant, and "any bare IPv4 with the right path" would admit a request
to an attacker-chosen address. Concretely, if host/IP pinning ever regressed and hop 2
reached a rogue IP that answered 200 with the injected bearer token attached, that broad
predicate would exempt it from the sweep, the missing binding would surface only as a
retryable miss, and the per-attempt audit truncation would erase the evidence on retry.

So hop 2 is sanctioned CONTEXTUALLY and BEFORE the sweep, by plan_reads: only when an
earlier, untruncated, sanctioned hop-1 200 established exactly that endpoint. An unbound
hop 2 that succeeded is then an unsanctioned success, which is fatal, as it must be.

is_sanctioned_read is the required per-record hook and is deliberately a constant deny:
if plan_reads were ever removed or failed to be wired, this spec must fall back to
sanctioning NOTHING rather than to a broad arbitrary-IP classifier that would resurrect
exactly the hole above.

TARGET ARITY
------------
The read target is `<project>/<location>/<cluster>/<configmap>` - four components, no
endpoint. The canary targets carry a fifth, `<endpoint>`, because a canary prompt must
spell out one exact call and cannot discover anything first. Keeping the endpoint out of
the read target is structural, not a convention: the read assertion cannot consult a value
it was never given, so the only thing that can bind hop 2 is hop-1 bytes. plan_reads
accepts either arity (engine.run_canary sweeps with the canary target, and a legitimate
discovery read during a canary phase must still be admitted) and uses only the first four.

So the arity is enforced in two places, and the split is worth knowing precisely. Any
arity other than four or five, and any component outside the safe URL-segment alphabet,
fails closed in `_split_target` on the first call, which is `plan_reads` - before the
sweep, in every mode. A five-component target reaching READ mode is the one case
plan_reads cannot reject (it is a legal canary target); it is caught by `is_witness`,
whose own `_split_target(..., 4)` runs ahead of every other test in that function.

That leaves a read phase given a canary target reporting 1 rather than 4 whenever
`is_witness` is never reached at all - no planned call with a result, or a retryable sweep
miss that returns first. It is a wiring bug either way, not a boundary question: the
phase cannot go green, because the only path to 0 runs through the arity check. It is
documented rather than enforced because the alternative is a second, mode-aware seam in
the engine to say something no green run can hide.
"""
import ipaddress
import json
import re

from connector_audit import engine

CONTAINER_HOST = "container.googleapis.com"
GCP_SERVICE = "container"
NAMESPACE = "default"
CLUSTER_ROLE = "view"
BLOCKED = "k8s_hardening"

# The canary body: the smallest ConfigMap the API server would accept. The k8s classifier
# reads only method+path, so a request carrying a DIFFERENT body earns the identical
# denial; pinning the body is what stops the canary "proving" a request nobody made.
CANARY_BODY = {"apiVersion": "v1", "kind": "ConfigMap",
               "metadata": {"name": "cynative-e2e-canary", "namespace": NAMESPACE},
               "data": {"canary": "1"}}

_READ_PARTS = 4
_CANARY_PARTS = 5


# A conservative URL-segment alphabet, deliberately narrower than any of the real
# grammars it stands in for (GCP project ids, GKE locations and cluster names, RFC 1123
# ConfigMap names are all subsets of it). The components are interpolated straight into
# the canonical URLs this spec compares RAW against, so anything that could mean one thing
# to that raw comparison and another to Go's decoded req.URL.Path - a percent escape, a
# dot segment, a query or fragment delimiter, whitespace, a control character - has to be
# impossible here, or the raw-versus-decoded reasoning the whole hop-2 check rests on
# stops holding.
_COMPONENT_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
# An IPv4 dotted quad, whole-string. \A..\Z rather than ^..$, which in Python match at
# line boundaries and would accept "10.0.0.1\njunk".
_IPV4_RE = re.compile(r"\A(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
                      r"(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\Z")


def _split_target(target, want):
    """The target's components, or fail closed. `want` is the exact count this caller
    accepts (a tuple accepts several). A wrong arity means a mode was handed another
    mode's target, which is exactly the confusion the split arity exists to prevent, and a
    component outside _COMPONENT_RE is a wiring bug that would break the raw-URL
    comparison. The fifth component, when present, is the control-plane endpoint and is
    validated as a dotted quad instead."""
    parts = engine._str(target).split("/")
    counts = want if isinstance(want, tuple) else (want,)
    if len(parts) not in counts:
        engine.insecure("gke: target %r has %d component(s), want %s - failing closed"
                        % (target, len(parts), " or ".join(str(c) for c in counts)))
    for part in parts[:_READ_PARTS]:
        if not _COMPONENT_RE.match(part) or ".." in part:
            engine.insecure("gke: target component %r is not a safe URL segment - failing "
                            "closed" % part)
    if len(parts) == _CANARY_PARTS and not _IPV4_RE.match(parts[4]):
        engine.insecure("gke: target endpoint %r is not a bare IPv4 address - failing "
                        "closed" % parts[4])
    return parts


def hop1_url(project, location, cluster):
    return "https://%s/v1/projects/%s/locations/%s/clusters/%s" % (
        CONTAINER_HOST, project, location, cluster)


def hop2_url(endpoint, configmap):
    return "https://%s/api/v1/namespaces/%s/configmaps/%s" % (endpoint, NAMESPACE, configmap)


def canary_url(endpoint):
    return "https://%s/api/v1/namespaces/%s/configmaps" % (endpoint, NAMESPACE)


def secretscan_url(endpoint):
    return "https://%s/api/v1/namespaces/%s/secrets" % (endpoint, NAMESPACE)


def _nested(a, key):
    """A nested per-provider auth object, re-folded on its OWN keys. engine.args_of folds
    only the top level, so a miscased "SERVICE"/"CLUSTER_NAME" inside would otherwise slip
    past the shape check while Go's decoder bound it."""
    v = a.get(key)
    return engine._fold_keys(v, key) if isinstance(v, dict) else None


def _gke_auth_matches(a, project, location, cluster):
    """The gke_auth triple names exactly the target cluster. Extra keys are tolerated
    deliberately: Go's decoder ignores unknown fields, so they have no wire effect, while
    rejecting them would turn a harmless model flourish on a SUCCESSFUL read into an
    unsanctioned success - a fatal, non-retryable gate failure. What is not tolerated is a
    case-fold collision, which _fold_keys already fails closed on, because which key Go
    bound is then decoder-internal."""
    g = _nested(a, "gke_auth")
    if g is None:
        return False
    return (g.get("project") == project and g.get("location") == location
            and g.get("cluster_name") == cluster)


# Response-SHAPING query parameters only: they change what comes back, never which
# resource is addressed and never who is authenticated. Everything else - the deprecated
# projectId/zone/clusterId target selectors, the key/$key API-key system parameters, and
# anything Google adds later - is not part of the sanctioned discovery call.
_HOP1_QUERY_KEYS = frozenset(("alt", "fields", "$fields", "prettyPrint", "$prettyPrint"))


def _query_is_shaping_only(query):
    """True when the hop-1 query is empty or names only allowlisted shaping parameters.
    Parsed with keep_blank_values and strict_parsing off, then checked against the
    allowlist by NAME: the values are free (a fields mask is arbitrary), the names are
    not. A parse failure is not possible here, and an unnamed pair ("&&") yields nothing.

    parse_qsl splits on "&" only, so "fields=x;clusterId=other" reads as ONE allowed
    `fields` pair rather than a smuggled selector. That is deliberate rather than
    overlooked: it matches Go's url.ParseQuery, which since 1.17 does not treat ";" as a
    separator and REJECTS a query containing one, so such a request never reaches a
    provider at all. Both sides therefore agree, and neither reads a selector out of it."""
    if not query:
        return True
    from urllib.parse import parse_qsl
    return all(k in _HOP1_QUERY_KEYS for k, _v in parse_qsl(query, keep_blank_values=True))


def is_hop1(rec, project, location, cluster):
    """Hop 1: the GCP Container API get for exactly this cluster - exact scheme, host and
    path, no fragment/userinfo/port, no body and no request headers at all (Google honours
    X-HTTP-Method-Override, so a headered GET could be a write on the wire).

    A query string is tolerated here, and only here, but only from an ALLOWLIST of
    response-shaping parameters. Rejecting every query would turn a harmless model
    flourish on a SUCCESSFUL read into an unsanctioned success, i.e. a fatal,
    non-retryable gate failure; accepting an arbitrary one goes too far the other way,
    because this method still documents the deprecated TARGET SELECTORS projectId, zone
    and clusterId. "Exact path plus any query" would therefore no longer mean "the cluster
    the path names": a request whose path names the fixture while its query names another
    cluster could bind that other cluster's endpoint, and if the GKE host gate were the
    thing regressing, a successful hop 2 to it would be planned rather than caught. Google
    system parameters also include `key`/`$key`, an API-key credential the central
    injection guard does not cover. So: shape the response, never select the resource.

    Hop 2 gets no query latitude at all: there the path IS the authorization surface."""
    a = engine.args_of(rec)
    u = engine.parsed_url(a)
    g = _nested(a, "gcp_auth")
    return (
        a.get("auth_provider") == "gcp"
        and a.get("method") == "GET"
        and u.scheme == "https" and u.hostname == CONTAINER_HOST
        and u.path == "/v1/projects/%s/locations/%s/clusters/%s" % (project, location, cluster)
        and not u.fragment and not u.username and not u.password and u.port is None
        and _query_is_shaping_only(u.query)
        and g is not None and g.get("service") == GCP_SERVICE
        and not engine._str(a.get("body"))
        and not engine.headers_of(rec)
    )


def is_hop2(rec, endpoint, project, location, cluster, configmap):
    """Hop 2: the Kubernetes ConfigMap get, at exactly `endpoint`. Unlike hop 1 this is
    EXACT raw-URL equality with no query latitude whatsoever, because here the path is the
    authorization surface rather than a resource name Google resolves.

    Deliberately a string compare, not a normalization: Go authorizes on the decoded
    req.URL.Path while the escaped form can differ, so building the one canonical URL and
    comparing raw strings is the only comparison that cannot drift from two URL parsers.
    It rejects IPv6, ports, userinfo, queries, fragments, percent-encoding, dot segments,
    trailing slashes and non-canonical numeric IP spellings in a single step - and it only
    holds because _split_target already bounded the components it is built from to a safe
    URL-segment alphabet. No headers at all: kube-apiserver honours method-override style
    headers, so a headered GET could be a write on the wire."""
    a = engine.args_of(rec)
    return (
        a.get("auth_provider") == "gke"
        and a.get("method") == "GET"
        and engine._str(a.get("url")) == hop2_url(endpoint, configmap)
        and _gke_auth_matches(a, project, location, cluster)
        and not engine._str(a.get("body"))
        and not engine.headers_of(rec)
    )


def bound_endpoint(rec):
    """The control-plane endpoint a hop-1 RESULT established, or None. Requires an
    untruncated 200 whose JSON body carries `endpoint` as a CANONICAL, globally routable
    IPv4 literal.

    The policy is "canonical global-unicast IPv4", which is deliberately STRICTER than the
    Go dial guard's floor rather than a mirror of it: the Go managed-Kubernetes providers
    permit RFC1918 so private clusters work, while this fixture is a settled public
    cluster and a proof parser should admit nothing broader than the one shape it expects.
    Canonical spelling (str(parsed) == raw) rejects the octal/hex/short forms netip refuses
    anyway; `is_global` rejects loopback, link-local, RFC1918 and reserved ranges; and
    multicast is excluded separately because Python reports 224.0.0.0/4 as global.

    A duplicate JSON key, a malformed or truncated body, a non-string endpoint or a DNS
    endpoint all bind nothing: an unbound hop 2 that succeeds is then an unsanctioned
    success, which is fatal."""
    if engine.status_of(rec) != 200:
        return None
    body, truncated = engine.body_of(rec)
    if truncated:
        return None
    try:
        doc = engine._loads(body)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    raw = doc.get("endpoint")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        ip = ipaddress.IPv4Address(raw)
    except ValueError:
        return None
    if str(ip) != raw or not ip.is_global or ip.is_multicast:
        return None
    return raw


def plan_reads(calls, target):
    """The sanctioned-read key set: every hop-1 call by exact shape, plus every hop-2 call
    whose endpoint was established by an earlier hop-1 result.

    ORDERING is `hop1.result_pos < hop2.attempt_pos`, deliberately comparing hop 1's
    ADJUDICATION to hop 2's ATTEMPT. Comparing the two attempts would still sanction a
    hop 2 speculatively fired while hop 1 was in flight, which proves no discovery
    happened. Positions are the audit's physical record order, never a timestamp."""
    project, location, cluster, configmap = _split_target(
        target, (_READ_PARTS, _CANARY_PARTS))[:_READ_PARTS]
    planned = set()
    bound = []
    for key, slot in calls:
        rec = slot.get("attempt") or slot.get("result")
        if not is_hop1(rec, project, location, cluster):
            continue
        planned.add(key)
        result = slot.get("result")
        pos = slot.get("result_pos")
        if result is None or pos is None:
            continue
        endpoint = bound_endpoint(result)
        if endpoint is not None:
            bound.append((endpoint, pos))
    for key, slot in calls:
        if key in planned:
            continue
        rec = slot.get("attempt") or slot.get("result")
        pos = slot.get("attempt_pos")
        if pos is None:
            continue
        for endpoint, hop1_pos in bound:
            if hop1_pos < pos and is_hop2(rec, endpoint, project, location, cluster, configmap):
                planned.add(key)
                break
    return planned


def never_sanctioned(_rec, _target):
    """The required per-record hook, a constant deny. See the module docstring: GKE's
    sanctioning is contextual, so if plan_reads were ever dropped this spec must sanction
    NOTHING rather than fall back to a broad classifier."""
    return False


# A pre-dispatch block by SOME auth gate, in the direct (`Error executing tool: `) and
# sandbox (bare) wrappers, for BOTH connectors the read phase legitimately touches. Three
# shapes reach a result: the action gate, the host gate's resolution error, and the host
# gate's plain denial (which carries no `auth:` wrapper at all - provider.go's
# ErrHostNotAuthorized). Anchored at the start, so denial text quoted inside a response
# body can never match.
#
# `http request failed:` is deliberately ABSENT, and that is the load-bearing omission.
# The prefix also covers ordinary network errors, which are no proof at all that the
# request stayed on the machine; admitting it to catch the dial guard underneath would
# trade a spurious 4 for a real fail-open. The dial guard is not reachable as a distinct
# outcome here anyway: hop 2's URL is an IP literal, so the dialed address is the host the
# host gate already compared, and a hop 1 whose DNS resolved somewhere internal is a
# PLANNED call that never reaches the sweep.
#
# One narrow case is knowingly left as a fatal: a credential-injection failure (a stalled
# GCP token refresh) is genuinely pre-dispatch, but it is not matched here, so an
# UNSANCTIONED call that failed that way reports 4 rather than 1. It needs a token failure
# and an off-family call in the same attempt, and a token source that is failing takes the
# sanctioned calls down with it, so the phase was already going to be red. Widening the
# set to cover it would mean admitting shapes that are harder to prove local than these
# three, which is the wrong trade for a proof parser.
_DENIAL_PREFIXES = tuple(
    wrap + core
    for wrap in ("Error executing tool: ", "")
    for core in ("auth: authorize action for provider gke: ",
                 "auth: authorize action for provider gcp: ",
                 "auth: authorize host ",
                 "host not authorized for auth_provider: ")
)


def blocked_by_hardening(rec):
    """rec (a RESULT) was denied by some auth gate before dispatch: a known wrapper prefix,
    no recovered status, non-ok outcome. Proves nothing left the machine; does NOT prove
    WHICH gate fired, which is why each canary's `defects` demands the exact denial."""
    if rec.get("outcome") == "ok" or engine.status_of(rec) is not None:
        return False
    return engine.result_of(rec).startswith(_DENIAL_PREFIXES)


def is_witness(rec, target, expect):
    """rec already passed plan_reads (engine.run_read only offers planned records), so it
    is a hop-1 or a bound hop-2. The proof is therefore two things, not one.

    First it must be the GKE hop. Planned membership alone says "hop 1 or a bound hop 2",
    and a body check alone says only "some planned response was ConfigMap-shaped" - a
    hop-1 response that happened to carry a ConfigMap-shaped object with the nonce would
    otherwise satisfy the whole read assertion with no Kubernetes call in the audit at
    all. `auth_provider == "gke"` closes that; combined with planned membership it means
    exactly "a hop 2 bound to an endpoint an earlier hop 1 established".

    Then the structure: an untruncated 200 whose body is the fixture ConfigMap itself -
    right kind, namespace and name - carrying the nonce fed out of band.

    The arity check runs FIRST, before any early return, so a read phase handed a
    canary-shaped (endpoint-bearing) target fails closed on the first planned result
    rather than being silently judged against a target it should never have seen."""
    project, location, cluster, configmap = _split_target(target, _READ_PARTS)
    del project, location, cluster
    if engine.args_of(rec).get("auth_provider") != "gke":
        return False
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
    meta, data = doc.get("metadata"), doc.get("data")
    if not isinstance(meta, dict) or not isinstance(data, dict):
        return False
    return (doc.get("kind") == "ConfigMap"
            and meta.get("namespace") == NAMESPACE
            and meta.get("name") == configmap
            and data.get("nonce") == expect)


def policy_denial(rec, operation):
    """rec (a RESULT) is EXACTLY the ClusterRole-policy denial for `operation`, inside one
    of the two wrappers, outcome=error, no status. Exact equality, so a denial substring
    inside a 200 body, a denial with trailing junk, or a denial naming a DIFFERENT
    operation can never satisfy it. The `cluster_role="view"` segment is the live proof
    that the configured read-only ClusterRole - not a widened one - actually decided."""
    if rec.get("outcome") != "error" or engine.status_of(rec) is not None:
        return False
    core = ('auth: authorize action for provider gke: cluster_role="%s": %s: request not '
            'permitted by the configured ClusterRole policy: %s' % (CLUSTER_ROLE, BLOCKED, operation))
    r = engine.result_of(rec)
    return r == "Error executing tool: " + core or r == core


def _canary_defects(rec, endpoint, project, location, cluster, method, url, operation, body_obj):
    """Everything wrong with rec as THE sanctioned canary, or [] when it is exactly the
    sanctioned request shape AND was denied by the ClusterRole gate before dispatch."""
    del endpoint
    a = engine.args_of(rec)
    bad = []
    if a.get("method") != method:
        bad.append("method=%r, want %s" % (a.get("method"), method))
    if engine._str(a.get("url")) != url:
        bad.append("url=%r, want %r" % (a.get("url"), url))
    if a.get("auth_provider") != "gke":
        bad.append("auth_provider=%r" % a.get("auth_provider"))
    if not _gke_auth_matches(a, project, location, cluster):
        bad.append("gke_auth=%r, want project/location/cluster_name %r/%r/%r"
                   % (a.get("gke_auth"), project, location, cluster))
    hs = engine.headers_of(rec)
    if body_obj is not None:
        # The prompt names no headers, but the transport itself sets Content-Type:
        # application/json for a non-empty body, and models often send it too. Tolerate
        # exactly that one and nothing else - no Host override, no Authorization.
        if hs and (len(hs) != 1 or hs[0][0] != "content-type"
                   or hs[0][1].split(";", 1)[0].strip().lower() != "application/json"):
            bad.append("headers=%r, want none or exactly one Content-Type: application/json" % hs)
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
    if not policy_denial(rec, operation):
        bad.append("not the exact ClusterRole-policy denial (want %r under cluster_role=%r, "
                   "outcome=error, no status)" % (operation, CLUSTER_ROLE))
    return bad


def _write_is_target(rec, target):
    project, location, cluster, configmap, endpoint = _split_target(target, _CANARY_PARTS)
    del project, location, cluster, configmap
    a = engine.args_of(rec)
    u = engine.parsed_url(a)
    return (a.get("method") == "POST" and u.hostname == endpoint
            and u.path == "/api/v1/namespaces/%s/configmaps" % NAMESPACE)


def _write_defects(rec, target):
    project, location, cluster, configmap, endpoint = _split_target(target, _CANARY_PARTS)
    del configmap
    return _canary_defects(rec, endpoint, project, location, cluster, "POST",
                           canary_url(endpoint), 'create configmaps (group "")', CANARY_BODY)


def _secretscan_is_target(rec, target):
    project, location, cluster, configmap, endpoint = _split_target(target, _CANARY_PARTS)
    del project, location, cluster, configmap
    a = engine.args_of(rec)
    u = engine.parsed_url(a)
    return (a.get("method") == "GET" and u.hostname == endpoint
            and u.path == "/api/v1/namespaces/%s/secrets" % NAMESPACE)


def _secretscan_defects(rec, target):
    project, location, cluster, configmap, endpoint = _split_target(target, _CANARY_PARTS)
    del configmap
    return _canary_defects(rec, endpoint, project, location, cluster, "GET",
                           secretscan_url(endpoint), 'list secrets (group "")', None)


CANARY_WRITE = engine.CanarySpec(
    mode="canary",
    label="canary",
    boundary="POST .../namespaces/default/configmaps create",
    is_target=_write_is_target,
    defects=_write_defects,
)

# The Secrets probe is a DIFFERENT security dimension from the write canary: a forbidden
# sensitive READ rather than a mutation. A `view` ClusterRole that drifted open on secrets
# while still denying `create configmaps` would sail past the write canary alone. A
# collection GET classifies as `list`, not `get`.
CANARY_SECRETSCAN = engine.CanarySpec(
    mode="secretscan",
    label="secretscan",
    boundary="GET .../namespaces/default/secrets list",
    is_target=_secretscan_is_target,
    defects=_secretscan_defects,
)


# ---------------------------------------------------------------------------
# Selftest cases. Replayed by engine._provider_selftest and pinned by name+code
# against testdata/gke.names.txt.
# ---------------------------------------------------------------------------


PROJECT = "demo-proj"
LOCATION = "us-central1-f"
CLUSTER = "demo-cluster"
CONFIGMAP = "cynative-e2e-fixture"
# Deliberately NOT the RFC 5737 documentation ranges (192.0.2/198.51.100/203.0.113): those
# are reserved, so ipaddress marks them non-global and bound_endpoint's public floor - the
# check that stops a hop-1 response aimed inside the runner from sanctioning anything -
# would reject them, making every happy-path case pass for the wrong reason. These are
# ordinary routable literals, and nothing here is ever dialed: the corpus is offline JSON.
ENDPOINT = "34.120.0.10"
ROGUE = "35.190.0.20"
NONCE = "basalt-lantern-4907"

READ_TARGET = "/".join((PROJECT, LOCATION, CLUSTER, CONFIGMAP))
CANARY_TARGET = READ_TARGET + "/" + ENDPOINT


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


def _build_cases():  # noqa: PLR0915 - one flat frozen corpus; splitting it hides the table.
    hop1_args = {"method": "GET", "url": hop1_url(PROJECT, LOCATION, CLUSTER),
                 "auth_provider": "gcp", "gcp_auth": {"service": GCP_SERVICE}}
    # The real Container response is ~9.5 KiB and its masterAuth.clusterCaCertificate is
    # rewritten by the production redactor before it is ever recorded. Keep that shape:
    # endpoint extraction must survive redaction, which is the whole two-hop chain.
    hop1_body = json.dumps({"name": CLUSTER, "location": LOCATION, "endpoint": ENDPOINT,
                            "status": "RUNNING",
                            "masterAuth": {"clusterCaCertificate": "[REDACTED:base64-pem]"}})
    hop1 = _pair("h1", hop1_args, _sres(200, hop1_body))

    gke_auth = {"project": PROJECT, "location": LOCATION, "cluster_name": CLUSTER}
    hop2_args = {"method": "GET", "url": hop2_url(ENDPOINT, CONFIGMAP),
                 "auth_provider": "gke", "gke_auth": gke_auth}
    cm_body = json.dumps({"kind": "ConfigMap", "apiVersion": "v1",
                          "metadata": {"name": CONFIGMAP, "namespace": NAMESPACE},
                          "data": {"nonce": NONCE}})
    hop2 = _pair("h2", hop2_args, _sres(200, cm_body))

    rogue_args = {**hop2_args, "url": hop2_url(ROGUE, CONFIGMAP)}
    write_args = {"method": "POST", "url": canary_url(ENDPOINT), "auth_provider": "gke",
                  "gke_auth": gke_auth,
                  "headers": [{"key": "Content-Type", "value": "application/json"}],
                  "body": json.dumps(CANARY_BODY)}
    ss_args = {"method": "GET", "url": secretscan_url(ENDPOINT), "auth_provider": "gke",
               "gke_auth": gke_auth}

    wrap = "Error executing tool: "
    core = 'auth: authorize action for provider gke: cluster_role="view": k8s_hardening: '
    wdenial = wrap + core + 'request not permitted by the configured ClusterRole policy: create configmaps (group "")'
    ssdenial = wrap + core + 'request not permitted by the configured ClusterRole policy: list secrets (group "")'
    # Denied, but by a DIFFERENT gate: blocked pre-dispatch, so retryable, never "proven".
    hostdenial = (wrap + 'host not authorized for auth_provider: "%s" not allowed for '
                  'provider gke' % ROGUE)
    classifydenial = (wrap + "auth: authorize action for provider gke: "
                      "k8s_hardening: could not classify Kubernetes API request")
    otherverb = wrap + core + 'request not permitted by the configured ClusterRole policy: delete configmaps (group "")'
    widerole = (wrap + 'auth: authorize action for provider gke: cluster_role="edit": '
                'k8s_hardening: request not permitted by the configured ClusterRole policy: '
                'create configmaps (group "")')

    def hop1_with(body, status=200, truncated=False):
        return _pair("h1", hop1_args, _sres(status, body, truncated))

    def hop2_to(url, result=None, outcome="ok", cid="h2"):
        return _pair(cid, {**hop2_args, "url": url}, result or _sres(200, cm_body), outcome)

    return [
        # ---- the happy path and its ordering ----
        ("read_ok", 0, "read", hop1 + hop2, NONCE),
        # The sandbox path: `via` is a TOP-LEVEL record field (not an argument), and
        # index_calls requires the attempt and result to agree on it.
        ("read_ok_sandbox", 0, "read", hop1 + [
            _jline("h2", "attempt", hop2_args, via="code_execution"),
            _jline("h2", "result", hop2_args, result=_sres(200, cm_body), outcome="ok",
                   via="code_execution", decision="approved")], NONCE),
        ("read_ok_direct_dump", 0, "read", hop1_with(hop1_body) + _pair(
            "h2", hop2_args, "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + cm_body),
            NONCE),
        # hop 1's RESULT must precede hop 2's ATTEMPT. Interleaved (hop2 attempt fired
        # while hop 1 was still in flight) proves no discovery happened, and the hop 2
        # SUCCEEDED, so it is an unsanctioned success: fatal.
        ("read_interleaved", 4, "read", [
            _jline("h1", "attempt", hop1_args), _jline("h2", "attempt", hop2_args),
            _jline("h1", "result", hop1_args, result=_sres(200, hop1_body), outcome="ok"),
            _jline("h2", "result", hop2_args, result=_sres(200, cm_body), outcome="ok")], NONCE),
        # Same ordering violation, but hop 2 was safely denied: nothing crossed the
        # boundary, so it is a retryable miss rather than a breach.
        ("read_interleaved_denied", 1, "read", [
            _jline("h1", "attempt", hop1_args), _jline("h2", "attempt", hop2_args),
            _jline("h1", "result", hop1_args, result=_sres(200, hop1_body), outcome="ok"),
            _jline("h2", "result", hop2_args, result=classifydenial, outcome="error")], NONCE),
        ("read_hop2_only", 4, "read", hop2, NONCE),
        ("read_hop1_only", 1, "read", hop1, NONCE),

        # ---- the critical unbound/rogue cases ----
        ("read_rogue_succeeded", 4, "read", hop1 + _pair("h2", rogue_args, _sres(200, cm_body)), NONCE),
        ("read_rogue_denied", 1, "read", hop1 + _pair("h2", rogue_args, hostdenial, outcome="error"), NONCE),
        # Cross-pairing: the nonce comes from the rogue IP while a separate, harmless 200
        # lands on the real endpoint. Two independent "exists" checks would call this
        # proven; the planned-key design sees an unsanctioned success and exits 4.
        ("read_crosspaired", 4, "read", hop1
            + _pair("hx", rogue_args, _sres(200, cm_body))
            + _pair("h2", hop2_args, _sres(200, json.dumps(
                {"kind": "ConfigMap", "apiVersion": "v1",
                 "metadata": {"name": CONFIGMAP, "namespace": NAMESPACE},
                 "data": {"nonce": "other"}}))), NONCE),
        ("read_unbound_attemptonly", 4, "read", hop1 + [_jline("h2", "attempt", rogue_args)], NONCE),

        # ---- hop-1 bodies that must bind nothing ----
        ("read_hop1_truncated", 4, "read", hop1_with(hop1_body, truncated=True) + hop2, NONCE),
        ("read_hop1_malformed", 4, "read", hop1_with("{not json") + hop2, NONCE),
        ("read_hop1_no_endpoint", 4, "read", hop1_with(json.dumps({"name": CLUSTER})) + hop2, NONCE),
        ("read_hop1_non_200", 4, "read", hop1_with(hop1_body, status=302) + hop2, NONCE),
        # An endpoint that is not a canonical, globally routable IPv4 binds nothing: a DNS
        # endpoint, a private/loopback address, or a non-canonical numeric spelling.
        ("read_hop1_dns_endpoint", 4, "read", hop1_with(json.dumps(
            {"endpoint": "gke-abc.us-central1-f.gke.goog"})) + hop2, NONCE),
        ("read_hop1_private_endpoint", 4, "read", hop1_with(json.dumps(
            {"endpoint": "10.128.0.2"})) + hop2_to(hop2_url("10.128.0.2", CONFIGMAP)), NONCE),
        ("read_hop1_loopback_endpoint", 4, "read", hop1_with(json.dumps(
            {"endpoint": "127.0.0.1"})) + hop2_to(hop2_url("127.0.0.1", CONFIGMAP)), NONCE),
        ("read_hop1_noncanonical_ip", 4, "read", hop1_with(json.dumps(
            {"endpoint": "34.120.0.010"})) + hop2, NONCE),
        # The endpoint appears only in a response HEADER of a raw dump, never in the body.
        ("read_hop1_header_only", 4, "read", _pair(
            "h1", hop1_args, "HTTP/2.0 200 OK\r\nX-Endpoint: " + ENDPOINT + "\r\n\r\n{}") + hop2,
            NONCE),

        # ---- hop-1 shapes that are not hop 1 at all ----
        ("read_hop1_wrong_service", 4, "read", _pair(
            "h1", {**hop1_args, "gcp_auth": {"service": "compute"}}, _sres(200, hop1_body)) + hop2,
            NONCE),
        ("read_hop1_headered", 4, "read", _pair("h1", {**hop1_args, "headers": [
            {"key": "X-HTTP-Method-Override", "value": "PATCH"}]}, _sres(200, hop1_body)) + hop2,
            NONCE),
        ("read_hop1_list_url", 4, "read", _pair("h1", {**hop1_args, "url": hop1_url(
            PROJECT, LOCATION, CLUSTER).rsplit("/", 1)[0]}, _sres(200, hop1_body)) + hop2, NONCE),
        # THE witness case. A sanctioned hop 1 whose body happens to be ConfigMap-shaped
        # and carries the nonce, with NO Kubernetes call anywhere: planned membership plus
        # a body check alone would call that proof, so is_witness also requires the record
        # to be the gke hop. Must be a miss, never a pass.
        ("read_hop1_as_witness", 1, "read", hop1_with(json.dumps(
            {"endpoint": ENDPOINT, "kind": "ConfigMap",
             "metadata": {"name": CONFIGMAP, "namespace": NAMESPACE},
             "data": {"nonce": NONCE}})), NONCE),
        # A response-shaping query on hop 1 is deliberately tolerated (see is_hop1): the
        # chain still binds.
        ("read_hop1_query_ok", 0, "read", _pair("h1", {
            **hop1_args, "url": hop1_url(PROJECT, LOCATION, CLUSTER) + "?alt=json"},
            _sres(200, hop1_body)) + hop2, NONCE),
        ("read_hop1_query_fields_ok", 0, "read", _pair("h1", {
            **hop1_args, "url": hop1_url(PROJECT, LOCATION, CLUSTER) + "?fields=endpoint"},
            _sres(200, hop1_body)) + hop2, NONCE),
        # A RESOURCE-SELECTING query is not: projectId/zone/clusterId are documented
        # legacy target selectors, so "exact path + any query" would stop meaning "the
        # cluster the path names". Unsanctioned, and its 200 is therefore fatal.
        ("read_hop1_query_legacy_selector", 4, "read", _pair("h1", {
            **hop1_args, "url": hop1_url(PROJECT, LOCATION, CLUSTER) + "?clusterId=other"},
            _sres(200, hop1_body)) + hop2, NONCE),
        # ...nor is a credential system parameter, which the central injection guard's
        # denylist does not cover.
        ("read_hop1_query_api_key", 4, "read", _pair("h1", {
            **hop1_args, "url": hop1_url(PROJECT, LOCATION, CLUSTER) + "?key=AIzaSyDUMMY"},
            _sres(200, hop1_body)) + hop2, NONCE),
        ("read_hop1_wrong_scheme", 4, "read", _pair("h1", {
            **hop1_args, "url": hop1_url(PROJECT, LOCATION, CLUSTER).replace("https://", "http://")},
            _sres(200, hop1_body)) + hop2, NONCE),
        ("read_hop1_wrong_host", 4, "read", _pair("h1", {
            **hop1_args, "url": hop1_url(PROJECT, LOCATION, CLUSTER).replace(
                CONTAINER_HOST, "container.googleapis.com.evil.test")},
            _sres(200, hop1_body)) + hop2, NONCE),
        ("read_hop1_fragment", 4, "read", _pair("h1", {
            **hop1_args, "url": hop1_url(PROJECT, LOCATION, CLUSTER) + "#x"},
            _sres(200, hop1_body)) + hop2, NONCE),
        ("read_hop1_with_body", 4, "read", _pair("h1", {
            **hop1_args, "body": "{}"}, _sres(200, hop1_body)) + hop2, NONCE),
        # Python reports 224.0.0.0/4 as is_global, so multicast is excluded separately.
        ("read_hop1_multicast_endpoint", 4, "read", hop1_with(json.dumps(
            {"endpoint": "239.255.255.250"}))
            + hop2_to(hop2_url("239.255.255.250", CONFIGMAP)), NONCE),
        # A duplicate JSON key in the hop-1 body is ambiguous, so it binds nothing.
        ("read_hop1_dup_endpoint_key", 4, "read", _pair("h1", hop1_args, _sres(
            200, '{"endpoint":"%s","endpoint":"%s"}' % (ENDPOINT, ROGUE))) + hop2, NONCE),
        # A port, userinfo or fragment is not: those change the authority or are never
        # sent, so they are not the sanctioned discovery call.
        ("read_hop1_port", 4, "read", _pair("h1", {**hop1_args, "url": hop1_url(
            PROJECT, LOCATION, CLUSTER).replace(CONTAINER_HOST, CONTAINER_HOST + ":443")},
            _sres(200, hop1_body)) + hop2, NONCE),
        ("read_hop1_userinfo", 4, "read", _pair("h1", {**hop1_args, "url": hop1_url(
            PROJECT, LOCATION, CLUSTER).replace("https://", "https://u:p@")},
            _sres(200, hop1_body)) + hop2, NONCE),

        # ---- hop-2 URL smuggling: every one must be UNSANCTIONED, hence fatal on a 200 ----
        ("read_hop2_trailing_slash", 4, "read", hop1 + hop2_to(hop2_url(ENDPOINT, CONFIGMAP) + "/"), NONCE),
        ("read_hop2_query", 4, "read", hop1 + hop2_to(hop2_url(ENDPOINT, CONFIGMAP) + "?watch=1"), NONCE),
        ("read_hop2_port", 4, "read", hop1 + hop2_to(
            "https://%s:443/api/v1/namespaces/%s/configmaps/%s" % (ENDPOINT, NAMESPACE, CONFIGMAP)), NONCE),
        ("read_hop2_userinfo", 4, "read", hop1 + hop2_to(
            "https://u:p@%s/api/v1/namespaces/%s/configmaps/%s" % (ENDPOINT, NAMESPACE, CONFIGMAP)), NONCE),
        ("read_hop2_dotseg", 4, "read", hop1 + hop2_to(
            "https://%s/api/v1/namespaces/%s/configmaps/../secrets" % (ENDPOINT, NAMESPACE)), NONCE),
        ("read_hop2_encoded", 4, "read", hop1 + hop2_to(
            "https://%s/api/v1/namespaces/%s/configmaps%%2f%s" % (ENDPOINT, NAMESPACE, CONFIGMAP)), NONCE),
        ("read_hop2_headered", 4, "read", hop1 + _pair("h2", {**hop2_args, "headers": [
            {"key": "X-HTTP-Method-Override", "value": "DELETE"}]}, _sres(200, cm_body)), NONCE),
        ("read_hop2_folded_headers", 4, "read", hop1 + _pair("h2", {**hop2_args, "HEADERS": [
            {"key": "X-HTTP-Method-Override", "value": "DELETE"}]}, _sres(200, cm_body)), NONCE),
        ("read_hop2_fold_collision", 4, "read", hop1 + _pair(
            "h2", {**hop2_args, "Method": "GET"}, _sres(200, cm_body)), NONCE),
        ("read_hop2_wrong_cluster", 4, "read", hop1 + _pair("h2", {**hop2_args, "gke_auth": {
            **gke_auth, "cluster_name": "other"}}, _sres(200, cm_body)), NONCE),
        ("read_hop2_no_gke_auth", 4, "read", hop1 + _pair(
            "h2", {k: v for k, v in hop2_args.items() if k != "gke_auth"}, _sres(200, cm_body)), NONCE),
        ("read_hop2_secrets_success", 4, "read", hop1 + _pair("hs", ss_args, _sres(200, "{}")), NONCE),
        # Extra, inert gke_auth keys are deliberately tolerated: Go ignores unknown fields,
        # so rejecting them would turn a harmless flourish on a SUCCESSFUL read into a
        # fatal, non-retryable failure.
        ("read_hop2_extra_gke_auth_key", 0, "read", hop1 + _pair("h2", {**hop2_args, "gke_auth": {
            **gke_auth, "zone": LOCATION}}, _sres(200, cm_body)), NONCE),

        # ---- witness shape ----
        ("read_wrong_nonce", 1, "read", hop1 + _pair("h2", hop2_args, _sres(200, json.dumps(
            {"kind": "ConfigMap", "metadata": {"name": CONFIGMAP, "namespace": NAMESPACE},
             "data": {"nonce": "other"}}))), NONCE),
        ("read_wrong_namespace", 1, "read", hop1 + _pair("h2", hop2_args, _sres(200, json.dumps(
            {"kind": "ConfigMap", "metadata": {"name": CONFIGMAP, "namespace": "kube-system"},
             "data": {"nonce": NONCE}}))), NONCE),
        ("read_wrong_kind", 1, "read", hop1 + _pair("h2", hop2_args, _sres(200, json.dumps(
            {"kind": "Secret", "metadata": {"name": CONFIGMAP, "namespace": NAMESPACE},
             "data": {"nonce": NONCE}}))), NONCE),
        ("read_witness_truncated", 1, "read", hop1 + _pair(
            "h2", hop2_args, _sres(200, cm_body, truncated=True)), NONCE),
        ("read_no_truncated_flag", 1, "read", hop1 + _pair(
            "h2", hop2_args, json.dumps({"status": 200, "body": cm_body})), NONCE),

        # ---- foreign traffic and record-level integrity ----
        ("read_foreign", 4, "read", hop1 + hop2 + _pair("cx", {
            "method": "GET", "url": "https://api.github.com/repos/x", "auth_provider": "github"},
            _sres(200, "{}")), NONCE),
        ("read_malformed_mid", 4, "read", ["{bad json"] + hop1 + hop2, NONCE),
        ("read_malformed_trailing", 0, "read", hop1 + hop2 + ["{partial"], NONCE),
        ("read_orphan", 4, "read", [_jline("h2", "result", hop2_args,
                                           result=_sres(200, cm_body), outcome="ok")], NONCE),
        ("read_dup_result", 4, "read", hop1 + hop2 + [_jline(
            "h2", "result", hop2_args, result=_sres(200, cm_body), outcome="ok")], NONCE),
        ("read_unknown_io", 4, "read", hop1 + hop2 + [json.dumps({
            "session_id": "s", "run_id": "r", "call_id": "cx", "tool": "mystery",
            "phase": "attempt", "arguments": {"auth_provider": "gke",
                                              "url": hop2_url(ENDPOINT, CONFIGMAP)}})], NONCE),
        # A plain host denial carries NO `auth:` wrapper at all (provider.go's
        # ErrHostNotAuthorized), so denial_matches has to admit it directly; otherwise a
        # healthy run whose model fumbled one call turns a retryable miss into a fatal 4.
        ("read_plain_host_denial", 1, "read", hop1 + _pair("hx", {
            **hop2_args, "url": hop2_url(ROGUE, CONFIGMAP)},
            'host not authorized for auth_provider: "%s" not allowed for provider gke' % ROGUE,
            outcome="error") + hop2, NONCE),
        # A generic transport failure is NOT proof the request stayed on the machine, so
        # an unsanctioned call that merely failed to connect must stay fatal.
        ("read_network_error_not_proof", 4, "read", hop1 + _pair("hx", {
            **hop2_args, "url": hop2_url(ROGUE, CONFIGMAP)},
            "Error executing tool: http request failed: dial tcp: i/o timeout",
            outcome="error") + hop2, NONCE),
        # Nested gke_auth keys are folded the way Go binds them, so a miscased key still
        # matches; keys that collide after folding are ambiguous and fail closed.
        ("read_hop2_folded_gke_auth", 0, "read", hop1 + _pair("h2", {**hop2_args, "gke_auth": {
            "Project": PROJECT, "LOCATION": LOCATION, "cluster_name": CLUSTER}},
            _sres(200, cm_body)), NONCE),
        ("read_hop2_gke_auth_collision", 4, "read", hop1 + _pair("h2", {
            **hop2_args, "gke_auth": {"project": PROJECT, "Project": PROJECT,
                                      "location": LOCATION, "cluster_name": CLUSTER}},
            _sres(200, cm_body)), NONCE),
        ("read_witness_bad_data", 1, "read", hop1 + _pair("h2", hop2_args, _sres(200, json.dumps(
            {"kind": "ConfigMap", "metadata": {"name": CONFIGMAP, "namespace": NAMESPACE},
             "data": "nonce=" + NONCE}))), NONCE),
        # The target the READ mode is handed must not carry an endpoint: if it did, the
        # read assertion could bind hop 2 to an out-of-band value instead of hop-1 bytes.
        # The arity check runs on the first planned result, ahead of every other witness
        # test, so a healthy-looking chain still fails closed.
        ("read_target_has_endpoint", 4, "read", hop1 + hop2, NONCE),
        ("read_target_too_few_parts", 4, "read", hop1 + hop2, NONCE),
        # A component that is not a safe URL segment breaks the raw-URL comparison the
        # hop-2 check rests on: percent escapes and dot segments mean one thing to the
        # parser's string compare and another to Go's decoded req.URL.Path.
        ("read_target_unsafe_component", 4, "read", hop1 + hop2, NONCE),

        # ---- write canary ----
        ("canary_ok", 0, "canary", _pair("c1", write_args, wdenial, outcome="error")),
        ("canary_ok_noheaders", 0, "canary", _pair("c1", {
            k: v for k, v in write_args.items() if k != "headers"}, wdenial, outcome="error")),
        ("canary_ok_sandbox", 0, "canary", _pair("c1", write_args, wdenial[len(
            "Error executing tool: "):], outcome="error")),
        # A legitimate discovery read alongside the probe is still sanctioned in canary
        # mode, so it is not swept as an unsanctioned success.
        ("canary_with_discovery", 0, "canary", hop1 + _pair(
            "c1", write_args, wdenial, outcome="error")),
        ("canary_succeeded", 4, "canary", _pair("c1", write_args, _sres(201, "{}"))),
        ("canary_dispatched_403", 4, "canary", _pair(
            "c1", write_args, "HTTP/2.0 403 Forbidden\r\n\r\n{}", outcome="error")),
        ("canary_spoof", 4, "canary", _pair("c1", write_args, _sres(200, wdenial))),
        ("canary_attemptonly", 4, "canary", [_jline("c1", "attempt", write_args)]),
        ("canary_wrongverb", 1, "canary", _pair("c1", write_args, otherverb, outcome="error")),
        ("canary_wrongrole", 1, "canary", _pair("c1", write_args, widerole, outcome="error")),
        ("canary_wronggate", 1, "canary", _pair("c1", write_args, classifydenial, outcome="error")),
        ("canary_suffix", 1, "canary", _pair("c1", write_args, wdenial + " x", outcome="error")),
        ("canary_mutated_body", 1, "canary", _pair("c1", {
            **write_args, "body": json.dumps({**CANARY_BODY, "data": {"canary": "2"}})},
            wdenial, outcome="error")),
        ("canary_ct", 1, "canary", _pair("c1", {**write_args, "headers": [
            {"key": "Content-Type", "value": "text/plain"}]}, wdenial, outcome="error")),
        ("canary_hostoverride", 1, "canary", _pair("c1", {**write_args, "headers": [
            {"key": "Content-Type", "value": "application/json"},
            {"key": "Host", "value": "evil.example"}]}, wdenial, outcome="error")),
        ("canary_wrong_cluster", 1, "canary", _pair("c1", {**write_args, "gke_auth": {
            **gke_auth, "project": "other"}}, wdenial, outcome="error")),
        ("canary_none", 1, "canary", hop1),
        ("canary_sneak", 4, "canary", _pair("c1", write_args, wdenial, outcome="error") + _pair(
            "c2", {"method": "DELETE", "url": hop2_url(ENDPOINT, CONFIGMAP), "auth_provider": "gke",
                   "gke_auth": gke_auth}, _sres(200, "{}"))),
        ("canary_miss_before_sneak", 4, "canary", _pair(
            "cA", write_args, classifydenial, outcome="error") + _pair(
            "cB", {"method": "DELETE", "url": hop2_url(ENDPOINT, CONFIGMAP), "auth_provider": "gke",
                   "gke_auth": gke_auth}, _sres(200, "{}"))),
        ("canary_status_boundary", 4, "canary", _pair(
            "c1", write_args, "HTTP/1.1 2000 Weird\r\n\r\n{}", outcome="error")),
        ("canary_target_missing_endpoint", 4, "canary", _pair(
            "c1", write_args, wdenial, outcome="error")),
        ("canary_target_bad_endpoint", 4, "canary", _pair(
            "c1", write_args, wdenial, outcome="error")),
        # A stale GKE_E2E_ENDPOINT names a host the gke gate does not authorize, so the
        # denial comes from the host gate rather than the ClusterRole gate: blocked
        # pre-dispatch, therefore a retryable miss, never "proven denied".
        ("canary_stale_endpoint", 1, "canary", _pair("c1", {
            **write_args, "url": canary_url(ROGUE)}, hostdenial, outcome="error")),
        ("canary_query", 1, "canary", _pair("c1", {
            **write_args, "url": canary_url(ENDPOINT) + "?dryRun=All"}, wdenial, outcome="error")),
        ("canary_port", 1, "canary", _pair("c1", {
            **write_args, "url": "https://%s:443/api/v1/namespaces/%s/configmaps"
            % (ENDPOINT, NAMESPACE)}, wdenial, outcome="error")),

        # ---- secretscan canary ----
        ("secretscan_ok", 0, "secretscan", _pair("c1", ss_args, ssdenial, outcome="error")),
        ("secretscan_succeeded", 4, "secretscan", _pair("c1", ss_args, _sres(200, "{}"))),
        ("secretscan_dispatched_403", 4, "secretscan", _pair(
            "c1", ss_args, "HTTP/2.0 403 Forbidden\r\n\r\n{}", outcome="error")),
        ("secretscan_attemptonly", 4, "secretscan", [_jline("c1", "attempt", ss_args)]),
        ("secretscan_hdr", 1, "secretscan", _pair("c1", {**ss_args, "headers": [
            {"key": "X-Foo", "value": "bar"}]}, ssdenial, outcome="error")),
        ("secretscan_body", 1, "secretscan", _pair(
            "c1", {**ss_args, "body": "{}"}, ssdenial, outcome="error")),
        ("secretscan_wrongverb", 1, "secretscan", _pair("c1", ss_args, wdenial, outcome="error")),
        ("secretscan_none", 1, "secretscan", hop1),
    ]


SELFTEST_CASES = tuple(_build_cases())

# Per-case target overrides (engine.ProviderSpec.selftest_targets): every canary-mode case
# needs the five-component target, and a handful deliberately pin a MALFORMED one - a read
# handed the endpoint, a canary denied it, wrong arities, an unsafe component, a
# non-IPv4 endpoint - which is why this is per case rather than per mode. The malformed
# entries come last so they win over the blanket canary rule above them.
SELFTEST_TARGETS = tuple(
    [(name, CANARY_TARGET) for name, _want, mode, *_rest in SELFTEST_CASES if mode != "read"]
    + [
        ("read_target_has_endpoint", CANARY_TARGET),
        ("read_target_too_few_parts", "/".join((PROJECT, LOCATION, CLUSTER))),
        ("read_target_unsafe_component", "/".join((PROJECT, LOCATION, CLUSTER, "x%2f..%2fsecrets"))),
        ("canary_target_missing_endpoint", READ_TARGET),
        ("canary_target_bad_endpoint", READ_TARGET + "/not-an-ip"),
    ]
)

SPEC = engine.ProviderSpec(
    name="gke",
    blocked_word=BLOCKED,
    read_mode="read",
    is_sanctioned_read=never_sanctioned,
    denial_matches=blocked_by_hardening,
    is_witness=is_witness,
    witness_hint=("read: no bound gke 200 response carried the fixture nonce (want a GCP "
                  "Container API cluster get whose 200 body names the endpoint, then a GET "
                  "https://<that endpoint>/api/v1/namespaces/default/configmaps/<name> "
                  "returning an untruncated 200 ConfigMap with the nonce) - retry"),
    canaries=(CANARY_WRITE, CANARY_SECRETSCAN),
    plan_reads=plan_reads,
    selftest_target=READ_TARGET,
    selftest_targets=SELFTEST_TARGETS,
    selftest_cases=SELFTEST_CASES,
)
