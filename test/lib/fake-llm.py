#!/usr/bin/env python3
"""OpenAI-compatible scripted model for test/proxy.smoke.test.sh.

Usage: fake-llm.py <portfile> <script>     script: read | delete

Serves POST /v1/chat/completions, non-streaming. The first call of a run (no
tool message in the conversation yet) answers with one http_request tool call
chosen by <script>; the next call answers with a final message that copies the
tool result the model received, prefixed "RESULT: ". GET /v1/models lists the
fake model. Every other path answers 400 at once, so the same listener doubles
as a dead end for the SDK metadata probes the suite points here through
GCE_METADATA_HOST and MSI_ENDPOINT (a 400 is outside both SDKs' retry sets).
Hermetic: loopback-only. Stdlib only.
"""
import http.server
import json
import socketserver
import sys

portfile, script = sys.argv[1], sys.argv[2]
KUBE = "https://kube.example.test:6443"
CALLS = {
    "read": {"method": "GET", "url": KUBE + "/api/v1/namespaces", "auth_provider": "kubernetes"},
    "delete": {"method": "DELETE", "url": KUBE + "/api/v1/namespaces/doomed", "auth_provider": "kubernetes"},
}
MAX_RESULT = 4000


def completion(message, finish_reason):
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 0,
        "model": "fake-model",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def text_of(content):
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return str(content)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _dead_end(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            self.rfile.read(length)
        self._send(400, {"error": "dead end"})

    def do_GET(self):
        if self.path == "/v1/models":
            self._send(200, {"object": "list", "data": [{"id": "fake-model", "object": "model"}]})
        else:
            self._dead_end()

    def do_POST(self):
        if self.path != "/v1/chat/completions":
            self._dead_end()
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        req = json.loads(self.rfile.read(length) or b"{}")
        tool_msgs = [m for m in req.get("messages", []) if m.get("role") == "tool"]
        if not tool_msgs:
            call = {
                "id": "call_1",
                "type": "function",
                "function": {"name": "http_request", "arguments": json.dumps(CALLS[script])},
            }
            self._send(200, completion({"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls"))
            return
        result = text_of(tool_msgs[-1].get("content"))[:MAX_RESULT]
        self._send(200, completion({"role": "assistant", "content": "RESULT: " + result}, "stop"))

    do_PUT = _dead_end
    do_PATCH = _dead_end
    do_DELETE = _dead_end


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


srv = Server(("127.0.0.1", 0), Handler)
with open(portfile, "w", encoding="utf-8") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
