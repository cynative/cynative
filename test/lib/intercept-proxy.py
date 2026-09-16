#!/usr/bin/env python3
"""Loopback intercepting CONNECT proxy for test/proxy.smoke.test.sh.

Usage: intercept-proxy.py <portfile> <logfile> <cert.pem> <key.pem> <authority> <marker> <token>

Binds 127.0.0.1 on an ephemeral port and writes the port to <portfile>. Accepts
CONNECT for exactly <authority> (host:port), answers 200, terminates TLS with
<cert.pem>/<key.pem> and serves a fixed Kubernetes fixture inside the tunnel: the
"view" ClusterRole and a namespace list whose only namespace is named <marker>.
Every other CONNECT authority is refused with 403 and every other inner request
gets a 403 Status. Appends one JSON line per event to <logfile>:
  {"event": "connect", "authority": ..., "allowed": bool}
  {"event": "request", "method": ..., "path": ..., "auth": "expected"|"other"|"none"}
  {"event": "plain", "method": ..., "target": ...}
where "expected" means the Authorization header carried exactly "Bearer <token>";
the token itself is never written. A plain (non-CONNECT) request of any method
is answered 405 and logged, so no traffic reaches this proxy without leaving a
line. Hermetic: loopback-only; no upstream connection is ever made. Stdlib only.
"""
import http.server
import json
import socketserver
import ssl
import sys
import threading

portfile, logfile, certfile, keyfile, allowed, marker, token = sys.argv[1:8]
log_lock = threading.Lock()


def log(event):
    with log_lock, open(logfile, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


CLUSTER_ROLE = {
    "kind": "ClusterRole",
    "apiVersion": "rbac.authorization.k8s.io/v1",
    "metadata": {"name": "view"},
    "rules": [
        {
            "apiGroups": [""],
            "resources": ["namespaces", "pods", "services", "configmaps"],
            "verbs": ["get", "list", "watch"],
        }
    ],
}
NAMESPACES = {
    "kind": "NamespaceList",
    "apiVersion": "v1",
    "items": [{"metadata": {"name": marker}}],
}
FORBIDDEN = {"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 403}


class Inner(http.server.BaseHTTPRequestHandler):
    """Serves the cluster fixture inside an established tunnel."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _record(self):
        header = self.headers.get("Authorization")
        if header is None:
            auth = "none"
        elif header == "Bearer " + token:
            auth = "expected"
        else:
            auth = "other"
        log({"event": "request", "method": self.command, "path": self.path, "auth": auth})

    def do_GET(self):
        self._record()
        if self.path == "/apis/rbac.authorization.k8s.io/v1/clusterroles/view":
            self._reply(200, CLUSTER_ROLE)
        elif self.path == "/api/v1/namespaces":
            self._reply(200, NAMESPACES)
        else:
            self._reply(403, FORBIDDEN)

    def _refuse(self):
        self._record()
        self._reply(403, FORBIDDEN)

    do_POST = _refuse
    do_PUT = _refuse
    do_PATCH = _refuse
    do_DELETE = _refuse


class Proxy(http.server.BaseHTTPRequestHandler):
    """Answers CONNECT, then hands the TLS-wrapped socket to Inner."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_CONNECT(self):
        ok = self.path == allowed
        log({"event": "connect", "authority": self.path, "allowed": ok})
        self.close_connection = True
        if not ok:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self.wfile.flush()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, keyfile)
        try:
            tls = ctx.wrap_socket(self.connection, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            Inner(tls, self.client_address, self.server)
        except (ssl.SSLError, OSError, ConnectionError):
            pass
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def _not_connect(self):
        log({"event": "plain", "method": self.command, "target": self.path})
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def __getattr__(self, name):
        # The base handler dispatches on "do_" + method and answers an unlogged
        # 501 when the attribute is missing; every verb but CONNECT logs instead.
        if name.startswith("do_"):
            return self._not_connect
        raise AttributeError(name)


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


srv = Server(("127.0.0.1", 0), Proxy)
with open(portfile, "w", encoding="utf-8") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
