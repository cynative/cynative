# shellcheck shell=sh
# connector-e2e.sh - shared shell orchestration for the live connector e2e suites
# (cynative#152), extracted from the three suites' near-identical `arbitrate` +
# `run_phase` (added in cynative#39/#52/#53). Sourced, never executed: it defines
# helpers and has no side effects at source time beyond pulling in the shared cost/
# timeout guardrails (test/lib/e2e-guardrails.sh), which every caller here needs
# anyway.
#
# Every caller of this file lives directly in test/ (the three connector suites plus
# this library's own unit test), so `dirname "$0"` at source time always resolves to
# test/ - the same $0-relative trick the suites already use to find `root`/`here`.
#
# Phase-status contract, shared with test/lib/e2e-guardrails.sh and
# test/lib/connector_audit/engine.py:
#   0  the phase's assertions hold.
#   1  not proven this attempt (a model miss or a fumbled call the gate blocked).
#      Retryable.
#   2  the run timed out.
#   3  the token budget was hit. FATAL, never retried.
#   4  a SECURITY assertion failed: a request the read-only boundary should have
#      stopped was dispatched, or a write succeeded, or the audit parser itself
#      exited abnormally. FATAL, and never retried.
_connector_e2e_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$_connector_e2e_dir/lib/e2e-guardrails.sh"

# arbitrate PARSER_RC CLASSIFY_RC -> final phase status. Pure (no guardrail library
# calls), so an offline caller can exercise it directly. A security breach (4)
# dominates even a timeout or budget hit; otherwise a nonzero classifier (2 timeout /
# 3 budget / 1 error) wins; else the parser's own 0 (hold) or 1 (miss).
arbitrate() {
	if [ "$1" = 4 ]; then return 4; fi
	if [ "$2" != 0 ]; then return "$2"; fi
	return "$1"
}

# connector_run_phase PROVIDER MODE PARSER AUDIT OUT ERR RC TIMEOUT POSTURE_FN TARGET
# EXPECT_VALUE LIVE_SECRET_FILE -> phase status. Every argument is explicit (no
# caller-global `rc`, no eval, no callback command-strings): POSTURE_FN and, at
# invocation time, EXPECT_VALUE are plain values the shell resolves as an ordinary
# command/argument, never interpreted as source text.
#
# Runs the shared audit parser (PARSER) as the security boundary: its exit code is
# normalized to the 0/1/4 contract (any abnormal exit, e.g. a usage error or a missing
# parser path, becomes 4) BEFORE anything else runs, and a 4 short-circuits before the
# run classifier and every soft gate below - nothing may suppress or delay a security
# failure. Only once the parser holds (0/1) does the run classifier (RC/OUT/ERR/
# TIMEOUT) get consulted and the two arbitrated. A clean arbitration (0) then runs the
# connector-specific posture check (POSTURE_FN), the generic tool-called assertion, and
# (read mode only) checks EXPECT_VALUE landed in OUT.
connector_run_phase() {
	_provider=$1
	_mode=$2
	_parser=$3
	_audit=$4
	_out=$5
	_err=$6
	_rc=$7
	_timeout=$8
	_posture_fn=$9
	shift 9
	_target=$1
	_expect=$2
	_secret_file=$3

	if [ -n "$_secret_file" ]; then
		if python3 -B "$_parser" "$_provider" "$_mode" "$_audit" "$_target" "$_expect" \
			--live-secrets "$_secret_file"; then
			_p=0
		else
			_p=$?
		fi
	else
		if python3 -B "$_parser" "$_provider" "$_mode" "$_audit" "$_target" "$_expect"; then
			_p=0
		else
			_p=$?
		fi
	fi
	# The parser can abnormally exit in ways its own 0/1/4 contract never would (a
	# usage error exits 2, a missing/unreadable parser exits 2, a signal or crash
	# exits something else): normalize any code outside 0/1/4 to 4 so an abnormal
	# exit is never mistaken for a retryable miss.
	case "$_p" in 0 | 1 | 4) ;; *) _p=4 ;; esac
	# A breach short-circuits BEFORE the classifier and every soft gate: nothing may
	# suppress or delay a security failure.
	if [ "$_p" = 4 ]; then return 4; fi
	if e2e_classify_run "$_rc" "$_out" "$_err" "$_timeout"; then _c=0; else _c=$?; fi
	arbitrate "$_p" "$_c"
	_s=$?
	if [ "$_s" != 0 ]; then return "$_s"; fi
	# Parser held and no timeout/budget: run the connector-specific posture check,
	# then the generic diagnostic, retryable environment gates.
	"$_posture_fn" "$_err" || return 1
	e2e_assert_tool_called "$_err" || return 1
	if [ "$_mode" = read ] && ! grep -Fq "$_expect" "$_out"; then
		printf 'read: expected value not found in the answer (no real read?). stdout tail:\n' >&2
		tail -n 20 "$_out" >&2
		return 1
	fi
	return 0
}

# e2e_pin_audit_size - export a rotation-free audit configuration so no lumberjack
# rotation fires during a bounded run. A mid-run rotation would rename the active audit
# file the running suite is about to read, and the parser's own rotated-sibling sweep
# (test/lib/connector_audit/engine.py load_records) is the fail-closed backstop for the
# case where one slips through anyway. Idempotent; runs in the current shell (it
# exports), so do NOT call it via command substitution.
e2e_pin_audit_size() {
	export CYNATIVE_AUDIT_MAX_SIZE_MB=4096
	export CYNATIVE_AUDIT_RETENTION_DAYS=3650
	export CYNATIVE_AUDIT_COMPRESS=false
}

# _e2e_scrub_file SRC DEST SECRET_FILE - write a scrubbed copy of SRC to DEST.
# SECRET_FILE may be empty (no exact class-1 live-secret values to scrub; the
# class-2/class-3 shape families still run). Reuses the shared audit parser's regex
# families (test/lib/connector_audit/engine.py _CONTENT_RULES/_POSITIONAL_RULES/
# _read_live_secrets) so the scrub can never drift from the credential prepass that
# gates the run. Matches class-1 in both literal and percent-encoded form and
# class-2/class-3 in both literal and percent-decoded form (cynative#59 review-4):
# a shape or a live secret hiding behind percent-encoding must not survive into the
# published summary. Those passes only know a secret's literal and quote_plus()
# canonical form, so a NON-canonical reversible encoding (lowercase %2f, an over-
# encoded %61%62, %20 for a space) would still slip through; a final line backstop
# mirrors the prepass's decoded-view detection and drops any whole line whose
# percent-decoded form still reveals a secret the passes could not scrub, the only
# safe move when the encoding cannot be enumerated (cynative#152). Never fails the
# caller (a scrub problem must not mask the real failure being reported): on any error
# it falls back to writing an empty DEST.
_e2e_scrub_file() {
	_src=$1
	_dst=$2
	_secrets=$3
	python3 -B - "$_src" "$_dst" "$_secrets" "$_connector_e2e_dir/lib" <<'PYEOF' || : > "$_dst"
import sys
from urllib.parse import quote_plus, unquote_plus

sys.path.insert(0, sys.argv[4])
from connector_audit.engine import _CONTENT_RULES, _POSITIONAL_RULES, _read_live_secrets

src, dst, secrets_path = sys.argv[1], sys.argv[2], (sys.argv[3] or None)
secrets = [s for s in _read_live_secrets(secrets_path) if s] if secrets_path else []


def redact_decoded_matches(t, decoded):
    """Pass 1: find every class-1/2/3 match in the CLEAN decoded view and redact its
    full span - both literal and percent-encoded form - directly in `t` (still
    untouched by any other pass). This must run BEFORE any literal-regex pass touches
    `t`: a shape whose characters straddle a percent-encoded byte (e.g. a base64 blob
    containing "+") would otherwise regex-match only its unencoded prefix in `t`,
    leaving a half-redacted shape with a leftover encoded tail - a real leak. Finding
    the full match in `decoded` first and mopping up both encodings in one shot avoids
    that entirely."""
    for secret in secrets:
        if secret and secret in decoded:
            t = t.replace(secret, "[REDACTED:live-secret]")
            enc = quote_plus(secret)
            if enc != secret:
                t = t.replace(enc, "[REDACTED:live-secret]")
    for keywords, rx, label in _CONTENT_RULES:
        if any(k in decoded for k in keywords):
            for m in rx.finditer(decoded):
                val = m.group(0)
                t = t.replace(val, "[REDACTED:%s]" % label)
                enc = quote_plus(val)
                if enc != val:
                    t = t.replace(enc, "[REDACTED:%s]" % label)
    for rx, label in _POSITIONAL_RULES:
        for m in rx.finditer(decoded):
            val = m.group(1)
            if not val or val.startswith("[REDACTED"):
                continue
            t = t.replace(val, "[REDACTED:%s]" % label)
            enc = quote_plus(val)
            if enc != val:
                t = t.replace(enc, "[REDACTED:%s]" % label)
    return t


def has_secret(t):
    """True when a class-1 live secret, a class-2 shape, or a class-3 positional
    credential value appears in `t` - the same detection the credential prepass runs,
    over the same imported rules. A "[REDACTED..." value carries none of these shapes
    and the class-3 loop skips it, so an already-redacted line reads clean."""
    for secret in secrets:
        if secret and secret in t:
            return True
    for keywords, rx, _label in _CONTENT_RULES:
        if any(k in t for k in keywords) and rx.search(t):
            return True
    for rx, _label in _POSITIONAL_RULES:
        for m in rx.finditer(t):
            val = m.group(1)
            if val and not val.startswith("[REDACTED"):
                return True
    return False


def redact_literal(t):
    """Pass 2: the ordinary literal-matching redaction, over whatever pass 1 left
    (secrets/shapes never behind encoding, the common case)."""
    for secret in secrets:
        t = t.replace(secret, "[REDACTED:live-secret]")
        enc = quote_plus(secret)
        if enc != secret:
            t = t.replace(enc, "[REDACTED:live-secret]")
    for keywords, rx, label in _CONTENT_RULES:
        if any(k in t for k in keywords):
            t = rx.sub("[REDACTED:%s]" % label, t)
    for rx, label in _POSITIONAL_RULES:
        def repl(m, _label=label):
            val = m.group(1)
            if not val or val.startswith("[REDACTED"):
                return m.group(0)
            whole = m.group(0)
            s, e = m.start(1) - m.start(0), m.end(1) - m.start(0)
            return whole[:s] + ("[REDACTED:%s]" % _label) + whole[e:]
        t = rx.sub(repl, t)
    return t


try:
    with open(src, encoding="utf-8", errors="replace") as f:
        text = f.read()
except OSError:
    text = ""

decoded = unquote_plus(text)
if decoded != text:
    text = redact_decoded_matches(text, decoded)
text = redact_literal(text)

# Pass 3: non-canonical-encoding backstop (cynative#152). Passes 1-2 know only a
# secret's literal and quote_plus() canonical form, so a secret in a NON-canonical
# reversible encoding (lowercase %2f, an over-encoded %61%62, %20 for a space) survives
# them. Mirror the credential prepass line by line, over whatever passes 1-2 left: if a
# line's percent-decoded view still reveals a secret/shape the redaction could not
# scrub from the line itself, drop the whole line - the only safe move when the
# encoding cannot be enumerated. A line already clean after passes 1-2 decodes to no
# secret, so this never over-redacts a benign percent-encoded line (a path, a query).
lines = text.split("\n")
for i, line in enumerate(lines):
    dec = unquote_plus(line)
    if dec != line and has_secret(dec):
        lines[i] = "[REDACTED-LINE]"
text = "\n".join(lines)

with open(dst, "w", encoding="utf-8") as f:
    f.write(text)
PYEOF
}

# e2e_collect_artifacts SUITE WORKDIR ARTIFACTS_DIR SECRET_FILE - on a fatal failure,
# publish a SANITIZED artifact summary for CI upload (cynative#59). A no-op when
# ARTIFACTS_DIR is empty (the local default; CI sets CONNECTOR_E2E_ARTIFACTS_DIR,
# cynative#153). Writes <ARTIFACTS_DIR>/<SUITE>/<phase>.{out,err} for every *.out/
# *.err file WORKDIR holds (read/canary/secretscan, whichever phases ran before the
# failure), each scrubbed by _e2e_scrub_file over the class-1 exact live-secret
# values from SECRET_FILE and the class-2/class-3 secret-shape families, plus
# meta.txt naming only the suite and the collected filenames - never secret bytes.
#
# Deliberately does NOT copy *.audit.log. http_request ARGUMENTS are written
# verbatim for approval-gated I/O (RedactArgs is false for them), so on a
# credential-prepass 4 the audit is known to contain a credential in `arguments`;
# publishing it would leak exactly what cynative#56 detects. The raw evidence stays
# only in the private WORKDIR (preserved today by each suite's *_KEEP_WORKDIR knob).
#
# ARTIFACTS_DIR must be a path OUTSIDE WORKDIR so the suite's own cleanup() does not
# delete what was just collected; callers must invoke this BEFORE a fatal exit; a
# `cleanup()` running first would remove the evidence before this ever runs.
#
# Never fails the caller (mkdir -p returning nonzero, e.g. an unwritable
# ARTIFACTS_DIR, is swallowed): a collection problem must not mask or replace the
# real failure being reported.
e2e_collect_artifacts() {
	_suite=$1
	_workdir=$2
	_artifacts_dir=$3
	_secret_file=$4
	[ -n "$_artifacts_dir" ] || return 0
	_dest="$_artifacts_dir/$_suite"
	mkdir -p "$_dest" 2>/dev/null || return 0
	{
		printf 'suite: %s\n' "$_suite"
		printf 'collected_utc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
	} > "$_dest/meta.txt"
	for _f in "$_workdir"/*.out "$_workdir"/*.err; do
		[ -e "$_f" ] || continue
		_name=$(basename "$_f")
		_e2e_scrub_file "$_f" "$_dest/$_name" "$_secret_file"
		printf 'file: %s\n' "$_name" >> "$_dest/meta.txt"
	done
	return 0
}

# e2e_write_live_secrets DEST VAR... - build the out-of-band class-1 live-secret file
# the credential prepass reads via --live-secrets. Writes each SET and NON-EMPTY named
# env var's value, one per line, to DEST at mode 0600; the values never touch argv or a
# diagnostic. DEST must be its OWN mktemp path OUTSIDE the retained workdir, and its
# removal must be composed into the suite's existing cleanup() (rm -f "$secret_file"),
# never a competing `trap ... EXIT INT TERM` - which in POSIX sh would REPLACE the
# suite's signal handlers and break the EXIT-cleanup + INT/TERM-exit-130/143 discipline.
# The file MAY be empty: ambient-credential runs (AWS profiles/instance roles, GCP ADC,
# Bedrock/Vertex chains) enumerate no env secret and are covered by the class-2/class-3
# SHAPE families, so an empty file is valid and must not fail. The var value is read
# through eval on the caller-supplied name (POSIX sh has no other portable indirection),
# the same seam e2e_require_env uses; the names are compile-time literals in the suites.
e2e_write_live_secrets() {
	_dest=$1
	shift
	: > "$_dest"
	chmod 600 "$_dest"
	for _var in "$@"; do
		eval "_val=\${$_var:-}"
		if [ -n "$_val" ]; then
			printf '%s\n' "$_val" >> "$_dest"
		fi
	done
}
