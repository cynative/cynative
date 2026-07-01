"""Loopback HTTP fixture server for the install.sh test scripts.

Usage: serve-fixture.py <serve_dir> <portfile>
Binds 127.0.0.1 on an ephemeral port, writes the chosen port to <portfile>, then
serves <serve_dir> forever with logging silenced. Loopback-only and hermetic.
"""
import sys, functools, http.server
srv_dir, portfile = sys.argv[1], sys.argv[2]


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


handler = functools.partial(Quiet, directory=srv_dir)
httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
with open(portfile, "w") as f:
    f.write(str(httpd.server_address[1]))
httpd.serve_forever()
