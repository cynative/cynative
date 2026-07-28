#!/usr/bin/env python3
"""check-llm-smoke-secrets.py - pin the llm-smoke / release secret boundary.

The api-key legs read exactly two secrets across the workflow_call boundary, and
release.yaml forwards ONLY those two names, never `secrets: inherit`. Pin the
boundary from both sides:

  llm-smoke.yaml - the sorted-unique set of `secrets.<NAME>` references must be
    exactly the two api keys;
  release.yaml   - the job that calls llm-smoke.yaml must forward exactly those
    two names, and each one as an identity forward (`NAME: ${{ secrets.NAME }}`),
    so a real secret cannot cross the boundary wearing an allow-listed name;
  both files     - bracket-form `secrets[...]` and whole-object uses of the
    secrets context (`toJSON(secrets)`, a bare `${{ secrets }}`) are rejected,
    since either hands over more than a named key;
  both files     - a `secrets:` key whose value is the scalar `inherit` is
    rejected, or a future edit could hand every release secret (App key,
    signing, PAT) to the gate.

The forwarding check is the one that matters most and the one no earlier version
had: the exact-set assertion counts REFERENCES inside llm-smoke.yaml, so on its
own it is satisfied by a caller that forwards `OPENAI_API_KEY: ${{ secrets.APP_
PRIVATE_KEY }}`. The name the gate sees is unchanged; the value is the App key.

This parses the workflows with a real YAML parser rather than grepping the raw
text, which is what makes the tripwire hold on the spellings a line-based scan
misses. Three of those bit the previous grep implementation (cynative#216):

  * `secrets:` with the scalar `inherit` on the FOLLOWING line, and the folded
    (`>-`) and tagged (`!!str`) spellings, all of which parse to the identical
    node as the one-line form;
  * a `#` inside a `run: |` block scalar (a shell comment, or a parameter
    expansion like ${MODEL#us.}), which is not a YAML comment at all but which
    a comment-stripping scan drops along with any `${{ secrets.* }}` after it;
  * an apostrophe in a plain scalar earlier on a line, which desynchronizes a
    quote-tracking comment stripper and makes the trailing comment count as
    live YAML. This repo writes comments containing the literal phrase
    `secrets: inherit`, so that misfire was a live false positive.

Comments carry no meaning here: the parser drops them, so prose can neither hide
a reference nor invent one. Expression scanning is likewise confined to `${{ }}`
spans inside string scalars, so the word "secrets" in a step name or a shell
line is not a match.

It remains a tripwire rather than a full Actions expression evaluator: it reads
the workflow as written, so it cannot follow a secret name assembled at runtime.
Everything unresolved fails closed - a missing, unreadable, non-UTF-8 or
unparseable file, an unterminated `${{` span, or a release workflow with no
recognizable call to the gate.

Usage: python3 scripts/ci/check-llm-smoke-secrets.py [llm-smoke.yaml] [release.yaml]
"""

from __future__ import annotations

import os
import re
import sys

DEFAULT_SMOKE = ".github/workflows/llm-smoke.yaml"
DEFAULT_RELEASE = ".github/workflows/release.yaml"

# The exact set llm-smoke.yaml may name, and the exact set release.yaml may
# forward. Anything else widens the gate's secret access across workflow_call.
ALLOWED_SMOKE_SECRETS = frozenset({"ANTHROPIC_API_KEY", "OPENAI_API_KEY"})

# How the gate may be called: the local form, or this repo by full path. A `uses:`
# whose basename matches but whose owner does not is a retarget, not the gate.
TRUSTED_GATE_PREFIXES = ("./", "cynative/cynative/")

# A `secrets` context root: the identifier, not part of a longer name. A leading
# dot is rejected separately (see secrets_uses) so that whitespace around the dot
# in `inputs . secrets` is handled too. Actions resolves context ids
# case-insensitively.
_SECRETS_ROOT = re.compile(r"(?<![A-Za-z0-9_])secrets(?![A-Za-z0-9_])", re.IGNORECASE)
_NAME = re.compile(r"[A-Za-z0-9_]+")


def fail(message: str) -> None:
    """Print a FAIL line and exit non-zero. Every check fails closed.

    Code scanning flags this sink because some messages name keys read from a
    mapping called `secrets`. Those are secret NAMES read from a workflow file in
    version control, never a secret VALUE: this script takes two file paths, reads
    nothing else, and no credential is in scope at any point. Naming which key is
    at fault is the whole diagnostic, so it stays; the values never are printed.
    """
    # codeql[py/clear-text-logging-sensitive-data]
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def load_workflow(path: str):
    """Parse a workflow, failing closed on anything that is not readable YAML."""
    try:
        import yaml
    except ImportError:
        fail(
            "PyYAML not found - needed to parse the workflows for the llm-smoke "
            "secret-boundary pin. Install it (apt: python3-yaml, pip: PyYAML)."
        )
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except OSError as err:
        fail(f"workflow not readable: {path}: {err}")
    except UnicodeDecodeError as err:
        fail(f"workflow is not valid UTF-8, so it cannot be parsed: {path}: {err}")
    try:
        return yaml.safe_load(text)
    except Exception as err:  # noqa: BLE001 - any parse failure must fail closed
        fail(f"{path} is not parseable YAML, so the secret boundary cannot be pinned: {err}")
    return None


def _step(trail: str, key) -> str:
    return f"{trail}.{key}" if trail else str(key)


def walk_strings(node, trail: str = "", seen: set[int] | None = None):
    """Yield ``(path, text)`` for every string scalar in the tree, keys included.

    ``seen`` guards against YAML's shared nodes: an alias-heavy document would
    otherwise be traversed once per reference (exponential on nested aliases,
    which is a CI hang), and a self-referencing anchor would recurse forever.
    """
    if seen is None:
        seen = set()
    if isinstance(node, str):
        yield (trail, node)
        return
    if isinstance(node, (dict, list, tuple)):
        if id(node) in seen:
            return
        seen.add(id(node))
    if isinstance(node, dict):
        for key, value in node.items():
            where = _step(trail, key)
            if isinstance(key, str):
                yield (where, key)
            yield from walk_strings(value, where, seen)
    elif isinstance(node, (list, tuple)):
        for position, item in enumerate(node):
            yield from walk_strings(item, f"{trail}[{position}]", seen)


def expressions(text: str):
    """Yield ``(body, closed)`` for each ``${{ ... }}`` span, literals blanked.

    Actions string literals are single-quoted with `''` as the escape. Blanking
    them keeps a `}` inside a literal (the idiomatic `format('{0}', ...)`) from
    ending the span early, and keeps the word "secrets" inside a literal from
    counting as a context access.

    ``closed`` is False for a span with no terminating `}}`. Actions interpolates
    `${{ }}` everywhere including `run:` bodies, so an unterminated span is a
    workflow GitHub would reject; the caller fails closed on it rather than
    guessing at where the expression was meant to end.
    """
    index = 0
    length = len(text)
    while True:
        start = text.find("${{", index)
        if start < 0:
            return
        pos = start + 3
        body: list[str] = []
        closed = False
        while pos < length:
            char = text[pos]
            if char == "'":
                body.append(" ")
                pos += 1
                while pos < length:
                    if text[pos] == "'":
                        if text.startswith("''", pos):
                            body.append("  ")
                            pos += 2
                            continue
                        body.append(" ")
                        pos += 1
                        break
                    body.append(" ")
                    pos += 1
                continue
            if text.startswith("}}", pos):
                pos += 2
                closed = True
                break
            body.append(char)
            pos += 1
        yield ("".join(body), closed)
        index = pos


def secrets_uses(body: str):
    """Yield ``(kind, name)`` for each secrets-context access in an expression.

    kind is "named" (with the key name), "bracket", or "whole".
    """
    for match in _SECRETS_ROOT.finditer(body):
        before = body[: match.start()].rstrip()
        if before.endswith("."):
            # `inputs.secrets`, `needs.x.outputs.secrets`: a different context.
            continue
        rest = body[match.end():].lstrip()
        if rest.startswith("["):
            yield ("bracket", "")
            continue
        if rest.startswith("."):
            name = _NAME.match(rest[1:].lstrip())
            if name is None:
                # `secrets .` with nothing resolvable: treat as whole-object.
                yield ("whole", "")
                continue
            yield ("named", name.group(0))
            continue
        yield ("whole", "")


def scan_expressions(path: str, tree) -> set[str]:
    """Reject bracket-form and whole-object uses; return the named-key set."""
    named: set[str] = set()
    for where, text in walk_strings(tree):
        if "${{" not in text:
            continue
        for body, closed in expressions(text):
            if not closed:
                fail(
                    f"{path} has an unterminated '${{{{' expression at {where}; Actions would "
                    "reject the workflow, and this pin will not guess where it ends."
                )
            for kind, name in secrets_uses(body):
                if kind == "bracket":
                    fail(
                        f"{path} uses bracket-form secrets[...] at {where}; only dot-form "
                        "secrets.NAME is allowed so this pin can enforce the exact set."
                    )
                if kind == "whole":
                    fail(
                        f"{path} references the secrets context as a whole object at {where}; "
                        "only named secrets.NAME keys are allowed."
                    )
                named.add(name)
    return named


def reject_inherit(path: str, node, trail: str = "", seen: set[int] | None = None) -> None:
    """Reject any `secrets:` key whose value is the scalar `inherit`.

    Structural, so every spelling that parses to the same node is caught: the
    one-line form, the value on the next line, folded/literal block scalars,
    quoted values, `!!str inherit`, and anchor/alias indirection.
    """
    if seen is None:
        seen = set()
    if isinstance(node, (dict, list, tuple)):
        if id(node) in seen:
            return
        seen.add(id(node))
    if isinstance(node, dict):
        for key, value in node.items():
            where = _step(trail, key)
            if (
                isinstance(key, str)
                and key.strip().lower() == "secrets"
                and isinstance(value, str)
                and value.strip().lower() == "inherit"
            ):
                fail(
                    f"{path} uses 'secrets: inherit' (at {where}) - reusable gates must be "
                    "granted only the exact named secrets they need, never the full set."
                )
            reject_inherit(path, value, where, seen)
    elif isinstance(node, (list, tuple)):
        for position, item in enumerate(node):
            reject_inherit(path, item, f"{trail}[{position}]", seen)


def _identity_forward(name: str) -> re.Pattern[str]:
    """`${{ secrets.NAME }}` and nothing else: same name in, same name out."""
    return re.compile(
        r"^\$\{\{\s*secrets\s*\.\s*" + re.escape(name) + r"\s*\}\}$",
        re.IGNORECASE,
    )


def check_forwarding(release_path: str, release, smoke_path: str) -> None:
    """Pin what release.yaml hands the gate: exactly the two names, each itself.

    Without this the exact-set arm is satisfied by a caller that forwards a real
    secret under an allow-listed name, since llm-smoke.yaml's own text does not
    change. Scoped to the job that calls the gate, so the other reusable calls in
    release.yaml (connector-e2e, scoop-publish) keep their own grants.
    """
    smoke_name = os.path.basename(smoke_path)
    jobs = release.get("jobs") if isinstance(release, dict) else None
    if not isinstance(jobs, dict):
        fail(f"{release_path} has no jobs: mapping, so the secret-forwarding boundary cannot be pinned.")

    want = sorted(ALLOWED_SMOKE_SECRETS)
    matched = 0
    for job_id, job in jobs.items():
        if not isinstance(job, dict) or not isinstance(job.get("uses"), str):
            continue
        target = job["uses"].split("@", 1)[0].strip()
        if os.path.basename(target) != smoke_name:
            continue
        matched += 1
        # The basename alone does not say whose workflow it is. Without this, a call
        # retargeted at attacker/collector/.github/workflows/llm-smoke.yaml@main still
        # looks like the gate, and forwarding the two identity-mapped keys to it
        # satisfies every other arm.
        if not target.startswith(TRUSTED_GATE_PREFIXES):
            fail(
                f"{release_path} job '{job_id}' calls {smoke_name} as {target!r}, which is not "
                "this repository's own workflow; the gate must be called as "
                f"{' or '.join(repr(p) for p in TRUSTED_GATE_PREFIXES)}, or the two api keys "
                "would be forwarded outside the repo."
            )
        granted = job.get("secrets")
        if not isinstance(granted, dict):
            fail(
                f"{release_path} job '{job_id}' calls {smoke_name} without an explicit "
                "secrets: mapping; the gate must be granted exactly "
                f"[{' '.join(want)}], named one by one."
            )
        got = sorted(str(key) for key in granted)
        if got != want:
            fail(
                f"{release_path} job '{job_id}' forwards [{' '.join(got)}] to {smoke_name}, "
                f"expected exactly [{' '.join(want)}] - any other name crosses the "
                "workflow_call boundary into the gate."
            )
        for key, value in granted.items():
            if not isinstance(value, str) or not _identity_forward(str(key)).match(value.strip()):
                # The offending value is deliberately not echoed. It is workflow source,
                # not a secret value, but a check about secret handling has no business
                # reprinting file content when naming the job and key locates it anyway.
                fail(
                    f"{release_path} job '{job_id}' does not forward {key} as "
                    f"'${{{{ secrets.{key} }}}}'; a secret must not cross the boundary "
                    "under a different name."
                )
    if matched == 0:
        fail(
            f"{release_path} has no job calling {smoke_name}, so the secret-forwarding "
            "boundary cannot be pinned. Update this check if the gate was renamed."
        )


def main(argv: list[str]) -> int:
    smoke_path = argv[1] if len(argv) > 1 else DEFAULT_SMOKE
    release_path = argv[2] if len(argv) > 2 else DEFAULT_RELEASE

    smoke = load_workflow(smoke_path)
    release = load_workflow(release_path)

    # Both sides: no bracket form, no whole-object access, no inherit. release.yaml
    # is the side that forwards secrets, so it needs the expression checks just as
    # much - a forwarded `NAME: ${{ toJSON(secrets) }}` would hand the whole bundle
    # across under an allow-listed name.
    smoke_named = scan_expressions(smoke_path, smoke)
    scan_expressions(release_path, release)
    reject_inherit(smoke_path, smoke)
    reject_inherit(release_path, release)
    check_forwarding(release_path, release, smoke_path)

    # Only llm-smoke.yaml gets the exact-set assertion on references: release.yaml
    # legitimately names many secrets, and what it may hand the gate is pinned by
    # check_forwarding instead.
    if smoke_named != set(ALLOWED_SMOKE_SECRETS):
        got = " ".join(sorted(smoke_named))
        want = " ".join(sorted(ALLOWED_SMOKE_SECRETS))
        fail(
            f"{smoke_path} secrets.* references are [{got}], expected exactly [{want}] - "
            "a new reference would widen the gate's secret access across workflow_call."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
