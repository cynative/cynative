#!/usr/bin/env bash
# scripts/demo/capture.sh — regenerate the README demo screenshot assets.
# Real identifiers are NEVER stored here. Exact real->placeholder pairs live in
# scripts/demo/sanitize.map.local (gitignored; see sanitize.map.example). This committed
# file carries only placeholders + generic structural patterns, so it is public-safe.
set -euo pipefail

FREEZE_VERSION="v0.2.2"
WIDTH=100
COLS="${DEMO_COLS:-3}"   # fallback even-split count when DEMO_RANGES is empty (RANGES_DEFAULT is the curated path)
RANGES_DEFAULT="1,68 69,135 136,203"  # curated 3-col split of the committed capture (LINE_BASE=1, 1-based incl.):
                                  # col1 = banner→connectors→LLM welcome→typed query→code_execution that lists the
                                  #        workflows + mapConcurrent fan-out over them (GitHub source);
                                  # col2 = mapConcurrent fan-out over the assumed AWS roles (iam() helper + xml.parse)
                                  #        + the "critical issue spotted" aha;
                                  # col3 = 🔬 verification panel→VERIFIED CRITICAL finding→3-role contrast table→bottom line→footer.
                                  # The 3 ranges cover the whole 202-line capture (no dropped middle) and are ~equal line
                                  # counts (68/67/68); cmd_render then pads every column to one shared box (identical W x H).
                                  # Re-pick on a fresh capture.
LINE_BASE=1                       # 0 or 1; confirmed in Task 1 Step 2 (freeze --lines base)
BG="#1e1e2e"
ASSET_DIR="docs/assets"
CAPTURE="${ASSET_DIR}/demo.capture.ansi"
COL_PREFIX="${ASSET_DIR}/demo-col"
LOCAL_MAP="scripts/demo/sanitize.map.local"
PLACEHOLDER_ACCOUNT="123456789012"
PLACEHOLDER_UUID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"   # the only UUID generic validate exempts
FREEZE_BIN=""
ELIDE_COLS="${DEMO_ELIDE_COLS:-100}"   # render-time: truncate lines longer than this many VISIBLE cols (caps the one long
                                       # code line so the auto-computed uniform column width stays tight)
FREEZE_WIDTH="${DEMO_FREEZE_WIDTH:-}"    # optional freeze pixel-width override; empty => cmd_render auto-computes the shared box
FREEZE_HEIGHT="${DEMO_FREEZE_HEIGHT:-}"  # optional freeze pixel-height override; empty => cmd_render auto-computes the shared box
RENDER_SRC=""                           # set by cmd_render to the elided render input
AUTODIR=""                              # set by cmd_render to the pass-1 temp dir (global so the EXIT trap can clean it)
SANITIZE_TMP=""                         # set by cmd_sanitize to the out-of-repo intermediate (global so the EXIT trap can clean it on failure)

die() { echo "capture.sh: $*" >&2; exit 1; }
require_map() { [[ -f "$LOCAL_MAP" ]] || die "missing $LOCAL_MAP (copy scripts/demo/sanitize.map.example and fill real values)"; }

# ensure_freeze installs the pinned freeze ONCE to a version-keyed temp dir and reuses the
# binary, instead of `go run`-recompiling it per column/format (4x recompile is slow/flaky).
ensure_freeze() {
  [[ -n "$FREEZE_BIN" ]] && return
  # Install into a USER-PRIVATE cache dir (mode 0700), never a world-writable /tmp path, so a local
  # attacker can't pre-plant a malicious `freeze` at a predictable path that we'd then execute.
  local dir="${XDG_CACHE_HOME:-$HOME/.cache}/cynative-freeze-${FREEZE_VERSION}"
  [[ -x "$dir/freeze" ]] || { mkdir -p -m 700 "$dir"; GOBIN="$dir" go install "github.com/charmbracelet/freeze@${FREEZE_VERSION}" || die "go install freeze failed"; }
  FREEZE_BIN="$dir/freeze"
}
list_artifacts() { ls "$CAPTURE" "${COL_PREFIX}"*.svg 2>/dev/null || true; }

# elide_file truncates each line to ELIDE_COLS *visible* columns (ANSI-aware), appending a
# reset + ellipsis, so a few pathologically long code lines don't blow up the image width.
elide_file() { # $1=in $2=out
  python3 - "$1" "$2" "$ELIDE_COLS" <<'PY'
import re, sys
inf, outf, w = sys.argv[1], sys.argv[2], int(sys.argv[3])
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\a\x1b]*(?:\a|\x1b\\)')
def elide(line):
    out = []; col = 0; i = 0; cut = False
    while i < len(line):
        m = ANSI.match(line, i)
        if m: out.append(m.group(0)); i = m.end(); continue
        if col >= w: cut = True; break
        out.append(line[i]); col += 1; i += 1
    return "".join(out) + ("\x1b[0m…" if cut else "")
data = open(inf, encoding="utf-8", errors="replace").read().split("\n")
open(outf, "w", encoding="utf-8").write("\n".join(elide(l) for l in data))
PY
}

freeze_col() { # $1=start $2=end $3=out-basename(no ext) -> SVG
  # --width/--height are freeze's OUTPUT PIXEL dimensions; pass them only when both are set (forces a fixed-size,
  # padded canvas). Empty => auto-size to content. The ${arr[@]+...} guard keeps an empty array safe under set -u.
  local dims=()
  [[ -n "$FREEZE_WIDTH" && -n "$FREEZE_HEIGHT" ]] && dims=(--width "$FREEZE_WIDTH" --height "$FREEZE_HEIGHT")
  "$FREEZE_BIN" \
    --language ansi "$RENDER_SRC" --lines "$1,$2" \
    --window ${dims[@]+"${dims[@]}"} --padding 20 --background "$BG" \
    --font.size 10 --line-height 1.2 \
    --border.radius 8 --shadow.blur 18 --shadow.y 10 \
    --output "${3}.svg"
}

max_svg_dims() { # $@=svg files -> "MAXW MAXH" (ceil int) across their root <svg width/height>
  python3 - "$@" <<'PY'
import math, re, sys
mw = mh = 0.0
for f in sys.argv[1:]:
    m = re.search(r'width="([0-9.]+)" height="([0-9.]+)"', open(f, encoding="utf-8", errors="replace").read())
    if not m: sys.exit(f"max_svg_dims: no <svg> dimensions in {f}")
    mw = max(mw, float(m.group(1))); mh = max(mh, float(m.group(2)))
print(math.ceil(mw), math.ceil(mh))
PY
}

cmd_live() {
  [[ $# -eq 2 ]] || die "usage: capture.sh live <query> <raw-out>"
  # Raw-out holds UNSANITIZED PTY bytes, so it MUST be a path git actually ignores — not merely a
  # *.raw.ansi name (.gitignore only ignores docs/assets/*.raw.ansi). check-ignore covers any
  # committable in-repo path (incl. the sanitized $CAPTURE) regardless of suffix or location.
  git check-ignore -q -- "$2" 2>/dev/null || die "raw-out must be a git-ignored path (e.g. docs/assets/<name>.raw.ansi) — refusing to write an unsanitized capture to a committable path"
  [[ -L "$2" ]] && die "raw-out is a symlink — refusing (it could redirect the unsanitized capture into a tracked target)"
  # Restrict the raw-out to the intended capture shape: the next step unlinks this path, so without
  # this a maintainer could point it at another git-ignored file (e.g. .env, coverage.out) and clobber it.
  [[ "$2" == docs/assets/*.raw.ansi && "$2" != *..* ]] || die "raw-out must match docs/assets/*.raw.ansi (no '..') — refusing to risk clobbering an unrelated ignored file"
  COLUMNS="$WIDTH" python3 - "$1" "$2" <<'PY'
import fcntl, os, pty, re, select, signal, struct, sys, termios, time
query, out = sys.argv[1], sys.argv[2]
cols = int(os.environ.get("COLUMNS", "100"))
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\a\x1b]*(?:\a|\x1b\\)')
strip = lambda b: ANSI.sub('', b.decode('utf-8', 'replace'))
APPROVAL = re.compile(r'Execute\?.*\[N\]o')
OSC11 = b"\x1b]11;?"; OSC11_REPLY = b"\x1b]11;rgb:1e1e/1e1e/2e2e\x07"  # answer bg-color probe
buf = bytearray()
pid, fd = pty.fork()
if pid == 0:
    # Set the tty window size so cynative/glamour wrap at `cols` (the COLUMNS env alone
    # is ignored — glamour reads the winsize ioctl). Tall rows so height isn't constrained.
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 200, cols, 0, 0))
    # Launch INTERACTIVE (no positional task) so the welcome + '>' prompt appear and the operator's
    # query is TYPED at the prompt — making the question visible in the captured screenshot.
    os.execvpe("cynative", ["cynative"],
               dict(os.environ, COLUMNS=str(cols), LINES="200", TERM="xterm-256color"))
keys_sent = 0; query_sent = False; sent_exit = False; start = time.time(); rc = 0; osc_replied = 0
MAX_WAIT = int(os.environ.get("DEMO_MAX_WAIT", "600"))   # hard cap; raise via DEMO_MAX_WAIT for slow high-reasoning models
while True:
    if not sent_exit and time.time() - start > MAX_WAIT:   # hard cap, enforced even under continuous output
        rc = 2; break
    r, _, _ = select.select([fd], [], [], 1.0)
    if r:
        try: d = os.read(fd, 65536)
        except OSError: break
        if not d: break
        if sent_exit:
            continue                              # drain post-exit echo without capturing it into buf
        buf.extend(d)
        # Count OSC-11 probes in the ACCUMULATED stream (not just this chunk) and answer any new
        # ones, so a probe split across two os.read() boundaries is still replied to (no stall).
        total_osc = bytes(buf).count(OSC11)
        while osc_replied < total_osc:
            os.write(fd, OSC11_REPLY); osc_replied += 1
        full = strip(bytes(buf)); tail = full[-4000:]
        # Type the QUERY at the first interactive prompt (after the welcome), so the question is
        # visible in the capture; then drive the turn.
        if not query_sent and tail.rstrip().endswith(">"):
            time.sleep(0.5); os.write(fd, query.encode("utf-8") + b"\r"); query_sent = True
        # Answer EVERY distinct approval prompt with 'a' (approve this tool for the session),
        # so a multi-tool run never blocks. Count prompts seen vs keys sent to avoid double-answers.
        elif len(APPROVAL.findall(full)) > keys_sent and APPROVAL.search(tail):
            time.sleep(0.4); os.write(fd, b"a"); keys_sent += 1
        # Exit once the turn finished: footer printed AND back at the interactive prompt.
        # "model call" is a substring of both "1 model call" and "N model calls".
        elif query_sent and "model call" in full and tail.rstrip().endswith(">"):
            time.sleep(0.5); os.write(fd, b"exit\r"); sent_exit = True
    elif sent_exit:
        break
# Unlink any pre-existing entry first (removes only THIS name, never a tracked inode's content),
# then create FRESH + exclusive: O_NOFOLLOW blocks a symlink, and unlink + O_EXCL blocks writing
# through a hard link into a tracked file (and fails closed if anything races to recreate the path).
try: os.unlink(out)
except FileNotFoundError: pass
fd_out = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
os.write(fd_out, bytes(buf)); os.close(fd_out)
status = 0
try: os.kill(pid, signal.SIGTERM); _, status = os.waitpid(pid, 0)
except (ProcessLookupError, ChildProcessError): pass
# Fail loudly if we never reached the footer/prompt (cynative missing, startup/config failure, or an
# early crash): a partial/failed transcript must not silently flow into committed README assets.
if rc == 0 and not sent_exit: rc = 3
if rc == 2:
    sys.stderr.write("capture.sh live: TIMED OUT before completion; capture may be partial\n")
elif rc:
    sys.stderr.write(f"capture.sh live: did not reach completion (child status={status}); transcript is partial/failed\n")
if rc: sys.exit(rc)
PY
  echo "capture.sh: wrote raw capture to $2 ($(wc -l < "$2") lines)" >&2
}

cmd_scan() {
  [[ $# -eq 1 ]] || die "usage: capture.sh scan <raw-in>"
  [[ -r "$1" ]] || die "cannot read $1"
  python3 - "$1" <<'PY'
import re, sys
data = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
data = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', data)        # de-ANSI for readability
pats = {
    "account-12digit": r'\b\d{12}\b',
    "arn":             r'arn:aws[^\s"<]*',
    "ipv4":            r'\b\d{1,3}(?:\.\d{1,3}){3}\b',
    "url":             r'https?://[^\s"<)]+',
    "email":           r'[\w.+-]+@[\w-]+\.[\w.-]+',
    "slug":            r'\b[\w.-]+/[\w.-]+\b',
}
for name, p in pats.items():
    found = sorted(set(re.findall(p, data)))
    if found:
        print(f"== {name} =="); [print("  " + x) for x in found]
PY
}

cmd_sanitize() {
  [[ $# -eq 1 ]] || die "usage: capture.sh sanitize <raw-in>"
  require_map; mkdir -p "$ASSET_DIR"
  # Unsanitized intermediate lives OUTSIDE the repo (still holds real ids after the control-strip
  # pass but before substitution) and is removed on any exit, so it can't be accidentally committed.
  SANITIZE_TMP="$(mktemp "${TMPDIR:-/tmp}/cynative-sanitize.XXXXXX")"
  trap 'rm -f "${SANITIZE_TMP:-}"' EXIT
  # Strip OSC (7/8-bit) + non-SGR CSI (7/8-bit, full grammar) + bare CR; keep only bare SGR (final 'm', no intermediates).
  perl -0777 -pe '
    s/\e\][^\a\e\x9c]*(?:\a|\e\\|\x9c)//g;
    s/\x9d[^\a\e\x9c]*(?:\a|\e\\|\x9c)//g;
    s/\e\[([0-?]*)([ -\/]*)([@-~])/ ($3 eq "m" && $2 eq "") ? "\e[${1}m" : "" /ge;
    s/\x9b([0-?]*)([ -\/]*)([@-~])/ ($3 eq "m" && $2 eq "") ? "\e[${1}m" : "" /ge;
    s/\r(?!\n)//g;
  ' "$1" > "$SANITIZE_TMP"
  python3 - "$SANITIZE_TMP" "$LOCAL_MAP" <<'PY'
import re, sys
p, mapf = sys.argv[1], sys.argv[2]
pairs = []
for line in open(mapf, encoding="utf-8"):
    line = line.rstrip("\n")
    if not line or line.startswith("#"): continue
    # Fail CLOSED on a malformed (e.g. space- instead of tab-separated) entry — silently skipping
    # it would leave the real identifier neither substituted nor in the denylist.
    if "\t" not in line: sys.exit(f"capture.sh sanitize: malformed map line (need REAL<TAB>PLACEHOLDER): {line!r}")
    real, ph = line.split("\t", 1)
    if not real: sys.exit(f"capture.sh sanitize: malformed map line (empty real value): {line!r}")
    pairs.append((real, ph))
# Fail CLOSED on an all-comment / empty map: publishing the merely control-stripped raw with NO
# substitutions would ship real identifiers (the generic gate misses slugs/hostnames/cluster names).
if not pairs: sys.exit("capture.sh sanitize: sanitize.map.local has no active REAL<TAB>PLACEHOLDER entries — refusing to publish an unsanitized capture")
# Longest real first: a shorter value can't pre-mutate a longer overlapping id (e.g. an org id
# that is a substring of a full repo slug / ARN) before the longer entry's substitution runs.
pairs.sort(key=lambda kv: len(kv[0]), reverse=True)
s = open(p, encoding="utf-8", errors="replace").read()
# Match each identifier even when split by a retained SGR sequence or a soft line-wrap, so a
# wrapped/colorized real id can't survive. Only ANSI or a real newline-wrap may sit between
# chars (NOT bare spaces), so short tokens like "audit" can't spuriously match "a u d i t".
INTER = r'(?:\x1b\[[0-?]*[ -/]*[@-~]|[ \t]*\n[ \t]*)*'
for real, ph in pairs:
    s = re.sub(INTER.join(re.escape(c) for c in real), ph, s)
open(p, "w", encoding="utf-8").write(s)
PY
  mv "$SANITIZE_TMP" "$CAPTURE"
  trap - EXIT
  echo "capture.sh: wrote sanitized capture to $CAPTURE ($(wc -l < "$CAPTURE") lines)" >&2
}

cmd_render() {
  [[ -r "$CAPTURE" ]] || die "missing/unreadable $CAPTURE (run sanitize first)"
  ensure_freeze
  RENDER_SRC="$(mktemp "${TMPDIR:-/tmp}/cynative-demo-render-XXXXXX")"   # private path, not predictable
  AUTODIR="$(mktemp -d "${TMPDIR:-/tmp}/cynative-demo-auto-XXXXXX")"
  trap 'rm -f "${RENDER_SRC:-}"; rm -rf "${AUTODIR:-}"' EXIT
  elide_file "$CAPTURE" "$RENDER_SRC"
  local total per i start end ranges range
  total="$(awk 'END{print NR}' "$RENDER_SRC")"   # logical line count: awk counts an unterminated final line; wc -l (newlines) would undercount it
  ranges="${DEMO_RANGES:-$RANGES_DEFAULT}"
  # Build the list of start,end column ranges: explicit ranges if given, else an even COLS split.
  local -a cols=()
  if [[ -n "$ranges" ]]; then
    for range in $ranges; do cols+=("$range"); done
  else
    per=$(( (total + COLS - 1) / COLS ))
    for (( i=0; i<COLS; i++ )); do
      start=$(( i*per + LINE_BASE )); end=$(( (i+1)*per + LINE_BASE - 1 ))
      (( end > total + LINE_BASE - 1 )) && end=$(( total + LINE_BASE - 1 ))
      cols+=("${start},${end}")
    done
  fi
  # Fail closed if the (curated) ranges no longer reach the end of the capture — otherwise a longer
  # fresh capture would silently drop its tail from the rendered columns while validate (which scans
  # the whole .ansi) still passes, publishing a truncated screenshot.
  local maxend=0 e
  for range in ${cols[@]+"${cols[@]}"}; do e="${range#*,}"; (( e > maxend )) && maxend="$e"; done
  (( maxend >= total )) || die "render: ranges reach line $maxend but the capture has $total lines — update RANGES_DEFAULT to cover the tail"
  # PASS 1 (unless both dims are forced): auto-size each column, then take the largest W/H so every
  # column can be padded to one shared box -> all final SVGs are identical width x height.
  if [[ -z "$FREEZE_WIDTH" || -z "$FREEZE_HEIGHT" ]]; then
    FREEZE_WIDTH=""; FREEZE_HEIGHT=""
    i=1; for range in ${cols[@]+"${cols[@]}"}; do freeze_col "${range%,*}" "${range#*,}" "${AUTODIR}/c${i}"; i=$((i+1)); done
    read -r FREEZE_WIDTH FREEZE_HEIGHT < <(max_svg_dims "${AUTODIR}"/c*.svg) || die "render: could not size columns"
  fi
  # PASS 2: re-render every column at the shared box. Clear stale columns only now — once we are
  # committed to re-rendering — so an earlier die (coverage check / pass-1 failure) can't delete the
  # already-published SVGs.
  rm -f "${COL_PREFIX}"*.svg
  i=1; for range in ${cols[@]+"${cols[@]}"}; do freeze_col "${range%,*}" "${range#*,}" "${COL_PREFIX}${i}"; i=$((i+1)); done
  echo "capture.sh: rendered ${#cols[@]} columns at ${FREEZE_WIDTH}x${FREEZE_HEIGHT}px -> ${COL_PREFIX}*.svg" >&2
}

cmd_validate() {  # generic structural scan; no local map needed (fresh-checkout safe)
  [[ -r "$CAPTURE" ]] || die "missing/unreadable $CAPTURE"
  local artifacts; mapfile -t artifacts < <(list_artifacts)
  [[ ${#artifacts[@]} -gt 0 ]] || die "no artifacts to validate (run render/sanitize first)"
  python3 - "$PLACEHOLDER_ACCOUNT" "$PLACEHOLDER_UUID" "${artifacts[@]}" <<'PY'
import ipaddress, re, sys, urllib.parse
placeholder_account = sys.argv[1]; placeholder_uuid = sys.argv[2].lower(); files = sys.argv[3:]
testnet = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
def safe_ip(s):
    try: a = ipaddress.ip_address(s)
    except ValueError: return True   # not an IP literal (e.g. a version string) — ignore
    # Strict: ONLY documented TEST-NET placeholder ranges are exempt. Every other literal IP —
    # public OR private/loopback/internal — is flagged, so no real network topology survives.
    return any(a in n for n in testnet)
leaks = set()
def scan(f, data):
    for m in set(re.findall(r'\b\d{12}\b', data)):
        if m != placeholder_account: leaks.add((f, "account?", m))
    for m in set(re.findall(r'arn:aws[^\s"<]*', data)):
        acct = m.split(":")[4] if m.count(":") >= 4 else ""
        # Exempt placeholder-account ARNs, AWS-managed/service ARNs (account segment == 'aws'), and
        # example-[-.] placeholder resources; flag everything else — INCLUDING account-less ARNs (e.g.
        # arn:aws:s3:::real-bucket). The example exemption requires example-/example. so a real name
        # like examplecorp-prod-bucket is NOT treated as a placeholder.
        if m.endswith("…"): continue   # render-elided ARN (ends in …): identifier is cut off; visible prefix is still scanned by the account/IP/email checks
        if acct in (placeholder_account, "aws"): continue
        if re.search(r'(^|[:/])example[-.]', m): continue
        leaks.add((f, "arn?", m))
    for m in set(re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', data)):
        if not safe_ip(m): leaks.add((f, "public-ip?", m))
    for m in set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', data)):
        dom = m.split("@")[-1].lower(); label = dom.split(".")[0]
        # Exempt ONLY RFC reserved example.{com,org,net} (incl. subdomains) or an explicit example
        # placeholder label (example / example-*), not any domain merely CONTAINING "example".
        if not (re.search(r'(^|\.)example\.(com|org|net)$', dom) or label == "example" or label.startswith("example-")):
            leaks.add((f, "email?", m))
    # IPv6 literals: candidates validated by ipaddress (non-IPs ignored); only the RFC3849
    # 2001:db8::/32 doc range is exempt. The lookbehind keeps ARN '::' from matching.
    for m in set(re.findall(r'(?<![\w:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])', data)):
        if m.count(":") >= 2 and not safe_ip(m): leaks.add((f, "ipv6?", m))
    # UUIDs (subscription/tenant/cluster ids): only the documented placeholder UUID is exempt.
    for m in set(re.findall(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', data)):
        if m.lower() != placeholder_uuid: leaks.add((f, "uuid?", m))
for f in files:
    try: data = open(f, "rb").read().decode("utf-8", "replace")
    except OSError as e: print(f"validate: cannot read {f}: {e}", file=sys.stderr); sys.exit(2)
    # Strip ANSI (and SVG markup for .svg files ONLY). Then scan THREE views: a wrap-collapsed one
    # (catches an id SPLIT across a soft wrap, e.g. 123456\n789012), a newline-preserved one (so a
    # blanket collapse can't MERGE an id with the next line's token, e.g. an account beside other
    # digits in a table), and a URL-decoded one (catches percent-encoded ARNs/accounts in IAM
    # policy docs / URLs).
    base = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\a\x1b]*(?:\a|\x1b\\)', '', data)
    # Drop freeze's embedded <style> @font-face base64 blob FIRST — otherwise the unbounded email
    # regex backtracks over hundreds of KB of base64 (validate stalls), and a chance digit run could
    # false-match the account/UUID checks.
    if f.endswith(".svg"): base = re.sub(r'<style[^>]*>.*?</style>', '', base, flags=re.S); base = re.sub(r'<[^>]*>', '', base)
    collapsed = re.sub(r'[ \t]*\n[ \t]*', '', base)
    scan(f, collapsed)                              # wrap-collapsed view
    scan(f, base)                                   # boundary-preserving view
    scan(f, urllib.parse.unquote(collapsed))        # URL-decoded + wrap-collapsed (catches a wrapped %XX triplet)
    scan(f, urllib.parse.unquote(base))             # URL-decoded + boundary-preserving (so two encoded ARNs on separate lines can't merge into one match)
if leaks:
    for f, k, v in sorted(leaks): print(f"LEAK[{k}]: {v} in {f}", file=sys.stderr)
    sys.exit(1)
PY
  echo "capture.sh: generic validation passed" >&2
}

cmd_validate_local() {  # exact denylist from the gitignored local map
  require_map
  local artifacts
  [[ -r "$CAPTURE" ]] || die "missing/unreadable $CAPTURE (run sanitize first)"
  mapfile -t artifacts < <(list_artifacts)
  [[ ${#artifacts[@]} -gt 0 ]] || die "no artifacts to validate (run render first)"
  # Match each real id against BOTH the raw bytes AND a normalized view (ANSI + XML tags + ALL
  # whitespace stripped), so a leak split by SGR or a line-wrap is still caught (fail-closed).
  python3 - "$LOCAL_MAP" "${artifacts[@]}" <<'PY' || die "local validation FAILED — real identifiers present"
import re, sys, urllib.parse
mapf, files = sys.argv[1], sys.argv[2:]
reals = []
for line in open(mapf, encoding="utf-8"):
    line = line.rstrip("\n")
    if not line or line.startswith("#"): continue
    # Fail CLOSED on a malformed entry — a silently-skipped real id is in neither the substitution
    # nor this denylist, so a single bad line could let a real identifier survive.
    if "\t" not in line: print(f"validate-local: malformed map line (need REAL<TAB>PLACEHOLDER): {line!r}", file=sys.stderr); sys.exit(2)
    real = line.split("\t", 1)[0]
    if not real: print(f"validate-local: malformed map line (empty real value): {line!r}", file=sys.stderr); sys.exit(2)
    reals.append(real)
if not reals: print("validate-local: sanitize.map.local has no active entries — cannot verify (fill REAL<TAB>PLACEHOLDER rows)", file=sys.stderr); sys.exit(2)
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\a\x1b]*(?:\a|\x1b\\)')
def norm(s, is_svg):
    s = ANSI.sub('', s)
    if is_svg:
        s = re.sub(r'<style[^>]*>.*?</style>', '', s, flags=re.S)   # drop freeze's base64 @font-face blob first
        s = re.sub(r'<[^>]*>', '', s)                               # then SVG markup; never strip <...> from the raw capture
    return re.sub(r'\s+', '', s)
fail = False
for f in files:
    try: raw = open(f, "rb").read().decode("utf-8", "replace")
    except OSError as e: print(f"validate-local: cannot read {f}: {e}", file=sys.stderr); sys.exit(2)
    n = norm(raw, f.endswith(".svg"))
    nd = urllib.parse.unquote(n)   # URL-decode AFTER normalizing, so a soft-wrapped %XX triplet (e.g. %2\nF) is rejoined to %2F first, then decoded
    for r in reals:
        rn = re.sub(r'\s+', '', r)
        if rn and (r in raw or rn in n or rn in nd):
            print(f"LEAK: real identifier '{r}' in {f}", file=sys.stderr); fail = True
sys.exit(1 if fail else 0)
PY
  echo "capture.sh: local denylist validation passed" >&2
}

main() {
  local sub="${1:-}"; shift || true
  case "$sub" in
    live)           cmd_live "$@";;
    scan)           cmd_scan "$@";;
    sanitize)       cmd_sanitize "$@";;
    render)         [[ $# -eq 0 ]] || die "render takes no args"; cmd_render;;
    validate)       [[ $# -eq 0 ]] || die "validate takes no args"; cmd_validate;;
    validate-local) [[ $# -eq 0 ]] || die "validate-local takes no args"; cmd_validate_local;;
    all)
      [[ $# -eq 0 ]] || die "all takes no args"
      cmd_render; cmd_validate
      # When the local map is present (regen on a maintainer box), also run the exact denylist —
      # the generic patterns don't cover slugs/hostnames/UUIDs, so `all` alone could miss them.
      if [[ -f "$LOCAL_MAP" ]]; then cmd_validate_local; fi
      ;;
    *) die "usage: capture.sh {live <q> <out>|scan <raw>|sanitize <raw>|render|validate|validate-local|all}";;
  esac
}
main "$@"
