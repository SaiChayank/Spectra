"""Lab-only HTTPS echo-ish server: POST /?n=<bytes> -> n filler bytes. Stdlib only.

One self-signed certificate (made at image build) serves whatever SNI the client sends.
Never logs or stores request bodies. Exits 0 after DURATION_S + 300 s.
"""
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        left = int(self.headers.get("Content-Length", 0))
        while left > 0:  # read and discard
            left -= len(self.rfile.read(min(left, 65536)))
        n = min(int(parse_qs(urlparse(self.path).query).get("n", ["200"])[0]), 1_000_000)
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"x" * n)
        self.close_connection = True

    def log_message(self, *a):
        pass


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain("/app/cert.pem", "/app/key.pem")
httpd = ThreadingHTTPServer(("0.0.0.0", 443), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
threading.Timer(int(os.environ["DURATION_S"]) + 300, httpd.shutdown).start()
print("serving", os.environ.get("SNI"), flush=True)
httpd.serve_forever()
