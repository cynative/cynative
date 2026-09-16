#!/bin/sh
# proxy.smoke.test.sh - hermetic proxy routing test (cynative#332).
#
# Drives the real binary through a loopback intercepting CONNECT proxy with the
# kubernetes connector, a static bearer token, a CA minted here, and a scripted
# OpenAI-compatible model, so registration, the ClusterRole fetch and a model
# request all cross the proxy without touching a real backend. Five phases:
#   1  doctor: the connector registers through the proxy (ClusterRole fetch).
#   2  read: the model's namespaces request crosses the proxy; the audit record
#      carries route=proxy and the answer carries the fixture marker.
#   3  delete: the gate denies the write before it reaches the proxy; the audit
#      record has outcome=error and no route.
#   4  proxy down: registration fails on the proxy hop instead of dialing the
#      cluster direct.
#   5  https:// proxy: the run stops at startup, before any connector line and
#      before the live fixture proxy is asked for anything.
# Part of `make sh-test`. Needs go (builds this checkout once), python3 and
# openssl. Each cynative run is bounded by a portable watchdog (no GNU timeout).
# Every run gets an explicit environment (env -i) so nothing ambient leaks in.
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091  # sourced at runtime via a $0-relative path.
. "$root/test/lib/e2e-guardrails.sh"

case "$(uname -s)" in
	Linux|Darwin) ;;
	*) printf 'skip: unsupported OS %s\n' "$(uname -s)" >&2; exit 0 ;;
esac

e2e_require_cmd go "needed to build cynative" || exit 1
e2e_require_cmd python3 "needed for the proxy and model fixtures" || exit 1
e2e_require_cmd openssl "needed to mint the test CA" || exit 1

proxy_pid=''
llm_pid=''
cyn_pid=''
workdir=''
cleanup() {
	[ -z "$cyn_pid" ] || kill "$cyn_pid" 2>/dev/null || true
	[ -z "$proxy_pid" ] || kill "$proxy_pid" 2>/dev/null || true
	[ -z "$llm_pid" ] || kill "$llm_pid" 2>/dev/null || true
	[ -z "$workdir" ] || rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

workdir=$(mktemp -d)
home="$workdir/home"
emptybin="$workdir/bin"
mkdir -p "$home/gh" "$home/glab" "$emptybin" "$workdir/cache"
audit="$workdir/audit.log"
proxylog="$workdir/proxy.log"
run_timeout=${PROXY_SMOKE_TIMEOUT:-60}
marker="ns-proxy-smoke-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
token="fake-token-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
authority="kube.example.test:6443"

bin=$(e2e_build_binary "$root" "$workdir") || exit 1

# --- test CA and leaf (SAN kube.example.test); config files, not -addext, so
# LibreSSL on macOS accepts them ---
cat > "$workdir/ca.cnf" <<'CNF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = cynative proxy smoke CA
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign
CNF
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -config "$workdir/ca.cnf" \
	-keyout "$workdir/ca.key" -out "$workdir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=kube.example.test" \
	-keyout "$workdir/leaf.key" -out "$workdir/leaf.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:kube.example.test\nextendedKeyUsage=serverAuth\n' > "$workdir/leaf.ext"
openssl x509 -req -in "$workdir/leaf.csr" -CA "$workdir/ca.pem" -CAkey "$workdir/ca.key" -CAcreateserial \
	-days 2 -extfile "$workdir/leaf.ext" -out "$workdir/leaf.pem" >/dev/null 2>&1
ca_b64=$(base64 < "$workdir/ca.pem" | tr -d '\n')

kubeconfig="$workdir/kubeconfig"
cat > "$kubeconfig" <<KUBE
apiVersion: v1
kind: Config
current-context: proxy-smoke
clusters:
- name: c
  cluster:
    server: https://$authority
    certificate-authority-data: $ca_b64
contexts:
- name: proxy-smoke
  context:
    cluster: c
    user: u
users:
- name: u
  user:
    token: $token
KUBE

# --- fixtures ---
# fake-llm.py reads its script name from the command line, so it is restarted per phase.
start_llm() { # script
	[ -z "$llm_pid" ] || { kill "$llm_pid" 2>/dev/null || true; wait "$llm_pid" 2>/dev/null || true; }
	rm -f "$workdir/llm.port"
	python3 "$root/test/lib/fake-llm.py" "$workdir/llm.port" "$1" &
	llm_pid=$!
	_i=0
	while [ ! -s "$workdir/llm.port" ]; do
		_i=$((_i + 1))
		[ "$_i" -lt 100 ] || { printf 'FAIL: fake model did not start\n' >&2; exit 1; }
		sleep 0.1
	done
	llm_port=$(cat "$workdir/llm.port")
}

python3 "$root/test/lib/intercept-proxy.py" "$workdir/proxy.port" "$proxylog" \
	"$workdir/leaf.pem" "$workdir/leaf.key" "$authority" "$marker" "$token" &
proxy_pid=$!
_i=0
while [ ! -s "$workdir/proxy.port" ]; do
	_i=$((_i + 1))
	[ "$_i" -lt 100 ] || { printf 'FAIL: proxy fixture did not start\n' >&2; exit 1; }
	sleep 0.1
done
proxy_port=$(cat "$workdir/proxy.port")
proxy_url="http://127.0.0.1:$proxy_port"

start_llm read

cfg="$workdir/config.yaml"
write_config() { # llm_port
	cat > "$cfg" <<CFG
llm:
  provider: openai
  model: fake-model
  network_config:
    base_url: http://127.0.0.1:$1
    max_retries: 0
    default_request_timeout_in_seconds: 20
cache:
  dir: $workdir/cache
audit:
  path: $audit
connectors:
  kubernetes:
    cluster_role: view
CFG
}
write_config "$llm_port"

# run_cyn PROXY OUT ERR ARGS... - one bounded cynative run under an explicit
# environment. Returns the exit code (143 when the watchdog killed it).
run_cyn() {
	_proxy=$1
	_out=$2
	_err=$3
	shift 3
	: > "$audit"
	: > "$proxylog"
	env -i HOME="$home" PATH="$emptybin" KUBECONFIG="$kubeconfig" \
		GH_CONFIG_DIR="$home/gh" GLAB_CONFIG_DIR="$home/glab" \
		OPENAI_API_KEY=fake CYNATIVE_CACHE_DIR="$workdir/cache" CYNATIVE_AUDIT_PATH="$audit" \
		HTTPS_PROXY="$_proxy" AWS_EC2_METADATA_DISABLED=true \
		GCE_METADATA_HOST="127.0.0.1:$llm_port" MSI_ENDPOINT="http://127.0.0.1:$llm_port/dead-end" \
		"$bin" --config "$cfg" "$@" >"$_out" 2>"$_err" </dev/null &
	cyn_pid=$!
	( sleep "$run_timeout"; kill "$cyn_pid" 2>/dev/null ) &
	_wd=$!
	if wait "$cyn_pid"; then _rc=0; else _rc=$?; fi
	cyn_pid=''
	kill "$_wd" 2>/dev/null || true
	wait "$_wd" 2>/dev/null || true
	return "$_rc"
}

# expect_rc WANT GOT PHASE ERRFILE - exact exit status; 143 is the watchdog.
expect_rc() {
	[ "$2" -ne 143 ] || { printf 'FAIL: %s timed out after %ss\n' "$3" "$run_timeout" >&2; exit 1; }
	[ "$2" -eq "$1" ] || { printf 'FAIL: %s exited %s, want %s. stderr tail:\n' "$3" "$2" "$1" >&2; tail -n 20 "$4" >&2; exit 1; }
}

# check_audit ROUTE OUTCOME RESULT_SUBSTRING - exactly one http_request result
# record with the expected route ("none" for absent), outcome and result text.
check_audit() {
	python3 - "$audit" "$1" "$2" "$3" <<'PY'
import json, sys
path, want_route, want_outcome, want_result = sys.argv[1:5]
recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
results = [r for r in recs if r.get("tool") == "http_request" and r.get("phase") == "result"]
if len(results) != 1:
    sys.exit("FAIL: want exactly one http_request result record, got %d" % len(results))
r = results[0]
if r.get("route", "none") != want_route:
    sys.exit("FAIL: route=%s want %s" % (r.get("route", "none"), want_route))
if r.get("outcome") != want_outcome:
    sys.exit("FAIL: outcome=%s want %s" % (r.get("outcome"), want_outcome))
if want_result not in str(r.get("result", "")):
    sys.exit("FAIL: result lacks %r: %r" % (want_result, str(r.get("result", ""))[:300]))
PY
}

# check_proxy MODE - the proxy log holds exactly the expected traffic:
#   doctor: one CONNECT to the fixture authority and exactly one request, the
#           ClusterRole GET with the expected bearer;
#   read:   two CONNECTs and exactly the ClusterRole GET then the namespaces
#           GET, both with the expected bearer;
#   delete: one CONNECT and exactly the ClusterRole GET (the write never left);
#   empty:  no events at all.
check_proxy() {
	python3 - "$proxylog" "$authority" "$1" <<'PY'
import json, sys
path, authority, mode = sys.argv[1:4]
events = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
connects = [e for e in events if e["event"] == "connect"]
requests = [(r["method"], r["path"], r["auth"]) for r in events if r["event"] == "request"]
ROLE = ("GET", "/apis/rbac.authorization.k8s.io/v1/clusterroles/view", "expected")
NS = ("GET", "/api/v1/namespaces", "expected")
want = {"doctor": (1, [ROLE]), "read": (2, [ROLE, NS]), "delete": (1, [ROLE]), "empty": (0, [])}[mode]
bad = [c for c in connects if c["authority"] != authority or not c["allowed"]]
if bad:
    sys.exit("FAIL: unexpected CONNECT authorities: %r" % bad)
if len(connects) != want[0]:
    sys.exit("FAIL: %d CONNECTs, want %d" % (len(connects), want[0]))
if requests != want[1]:
    sys.exit("FAIL: requests %r, want %r" % (requests, want[1]))
PY
}

out="$workdir/out"
err="$workdir/err"

printf '== phase 1: doctor through the proxy ==\n' >&2
run_cyn "$proxy_url" "$out" "$err" doctor && rc=0 || rc=$?
expect_rc 0 "$rc" "doctor through the proxy" "$err"
grep -q '✓ kubernetes' "$err" || { printf 'FAIL: kubernetes did not register through the proxy. stderr:\n' >&2; cat "$err" >&2; exit 1; }
grep -q '~ egress' "$err" || { printf 'FAIL: egress notice missing. stderr:\n' >&2; cat "$err" >&2; exit 1; }
check_proxy doctor

printf '== phase 2: model read through the proxy ==\n' >&2
run_cyn "$proxy_url" "$out" "$err" -p 'List the namespaces of the cluster.' --auto-approve && rc=0 || rc=$?
expect_rc 0 "$rc" "model read" "$err"
grep -q "$marker" "$out" || { printf 'FAIL: answer lacks the fixture marker. stdout:\n' >&2; cat "$out" >&2; exit 1; }
check_audit proxy ok "$marker"
check_proxy read

printf '== phase 3: denied write never reaches the proxy ==\n' >&2
start_llm delete
write_config "$llm_port"
run_cyn "$proxy_url" "$out" "$err" -p 'Delete the doomed namespace.' --auto-approve && rc=0 || rc=$?
expect_rc 0 "$rc" "denied write" "$err"
check_audit none error 'cluster_role='
check_proxy delete

# The configured proxy here is a dead port, not the fixture, so the fixture log
# says nothing about this run either way. What rules out a direct dial is that
# the failure names the proxy hop: a connector that ignored the policy would
# fail on the unresolvable fixture hostname instead.
printf '== phase 4: proxy down, no direct fallback ==\n' >&2
run_cyn "http://127.0.0.1:1" "$out" "$err" doctor && rc=0 || rc=$?
expect_rc 1 "$rc" "doctor with the proxy down" "$err"
grep -q '✗ kubernetes' "$err" || { printf 'FAIL: kubernetes should be unavailable. stderr:\n' >&2; cat "$err" >&2; exit 1; }
grep -q 'proxyconnect' "$err" || { printf 'FAIL: failure should name the proxy hop. stderr:\n' >&2; cat "$err" >&2; exit 1; }

# The rejected scheme names the live fixture, which the scheme check refuses
# before it looks at the host, so the empty log is real evidence: the same
# authority spelled http:// is phase 1, which logs two events.
printf '== phase 5: https:// proxy rejected at startup ==\n' >&2
run_cyn "https://127.0.0.1:$proxy_port" "$out" "$err" doctor && rc=0 || rc=$?
expect_rc 1 "$rc" "https proxy" "$err"
grep -q 'egress' "$err" || { printf 'FAIL: startup error missing. stderr:\n' >&2; cat "$err" >&2; exit 1; }
grep -q 'unsupported scheme' "$err" || { printf 'FAIL: startup error should name the scheme. stderr:\n' >&2; cat "$err" >&2; exit 1; }
grep -q 'kubernetes' "$err" && { printf 'FAIL: connectors must not register after the startup error\n' >&2; exit 1; }
check_proxy empty

printf 'OK: proxy smoke (doctor + read + denied write + proxy down + https rejected)\n'
