#!/usr/bin/env python3
"""Old-vs-new differential comparator for the shared connector audit parser.

The extraction moves each suite's embedded parser into this shared engine plus a
per-provider spec. `compare` proves the move is behavior-preserving by replaying the
FROZEN pre-port corpus (test/lib/connector_audit/testdata/<provider>/) against BOTH the
old embedded parser and the new standalone entrypoint, and asserting the two exit codes
agree with each other AND with the case's frozen code. Replaying the original bytes (not
the newly ported selftest cases) is what makes a byte or argv altered during the port
fail rather than fake-pass; the names.txt name+code pin is the completeness half.

`compare` is a one-time extraction-equivalence proof: run by hand against a provider's
frozen corpus during that provider's migration onto this shared engine, comparing it
against the old, since-deleted embedded parser. It is not re-run by make sh-test.
Ongoing protection is each provider's --selftest, which replays the ported cases, plus
the names.txt name+code pin.
"""
import os
import subprocess
import sys
import tempfile


def _entrypoint():
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "connector-audit-parser.py")


def _read_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def _read_lines(path):
    with open(path, encoding="utf-8") as f:
        return [line.rstrip("\n") for line in f]


def _setup_audit(tmp, raw):
    """Materialize a case's audit condition inside tmp, returning the audit path.

    Most cases carry raw audit bytes. A case whose input is a single ``STATE=<name>``
    line instead encodes a filesystem condition the bytes cannot express:
      missing          - the audit path does not exist.
      unreadable       - the file exists but cannot be read.
      rotated-sibling  - a valid active file plus a lumberjack-rotated sibling beside it.
    """
    text = raw.decode("utf-8", "replace").strip()
    if text.startswith("STATE="):
        state = text[len("STATE="):].strip()
        if state == "missing":
            return os.path.join(tmp, "missing.audit.log")
        if state == "unreadable":
            path = os.path.join(tmp, "unreadable.audit.log")
            with open(path, "wb") as f:
                f.write(b"{}\n")
            os.chmod(path, 0)
            return path
        if state == "rotated-sibling":
            path = os.path.join(tmp, "read.audit.log")
            with open(path, "wb") as f:
                f.write(b"{}\n")
            with open(os.path.join(tmp, "read.audit-2026-07-17T09-00-00.log"), "wb") as f:
                f.write(b"{}\n")
            return path
        raise ValueError("unknown STATE %r" % state)
    fd, path = tempfile.mkstemp(suffix=".log", dir=tmp)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return path


def _run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode


def compare(old_parser_path, provider, corpus_dir):
    """Replay every case dir under corpus_dir against the old parser and the new
    entrypoint. Returns (equivalent, total). A run over a missing or empty corpus is a
    clean (0, 0), which is the whole check until a provider spec is registered."""
    if not os.path.isdir(corpus_dir):
        print("equivalent: 0/0")
        return 0, 0
    cases = sorted(d for d in os.listdir(corpus_dir)
                   if os.path.isdir(os.path.join(corpus_dir, d)))
    entry = _entrypoint()
    equivalent = 0
    total = 0
    for name in cases:
        case = os.path.join(corpus_dir, name)
        code_path = os.path.join(case, "code")
        argv_path = os.path.join(case, "argv")
        input_path = os.path.join(case, "input")
        if not (os.path.exists(code_path) and os.path.exists(argv_path) and os.path.exists(input_path)):
            continue
        total += 1
        want = int(_read_lines(code_path)[0])
        argv_tail = [a for a in _read_lines(argv_path) if a != ""]
        with tempfile.TemporaryDirectory() as tmp:
            audit = _setup_audit(tmp, _read_bytes(input_path))
            argv = [audit if a == "@AUDIT@" else a for a in argv_tail]
            old_rc = _run([sys.executable, "-B", old_parser_path] + argv)
            new_rc = _run([sys.executable, "-B", entry, provider] + argv)
        if old_rc == new_rc == want:
            equivalent += 1
        else:
            print("differential MISMATCH %s: old=%d new=%d want=%d" % (name, old_rc, new_rc, want))
    print("equivalent: %d/%d" % (equivalent, total))
    return equivalent, total


if __name__ == "__main__":
    import argparse

    _parser = argparse.ArgumentParser(
        description="Replay a provider's frozen differential corpus against the pre-extraction "
                    "embedded parser and the shared entrypoint, and assert the two agree.")
    _parser.add_argument("--old", required=True, metavar="PATH",
                         help="path to the extracted pre-extraction embedded parser")
    _parser.add_argument("provider", help="provider token (e.g. aws, gcp, github)")
    _parser.add_argument("corpus_dir", help="frozen corpus directory, e.g. testdata/<provider>")
    _args = _parser.parse_args()
    _equivalent, _total = compare(_args.old, _args.provider, _args.corpus_dir)
    sys.exit(0 if _equivalent == _total else 1)
