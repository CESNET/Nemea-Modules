#!/usr/bin/env python3

import time
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

hostName = ""
hostPort = 8080


class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write("GET OK\n".encode("utf-8"))

    def do_POST(self):
        self._set_headers()
        print(self.rfile.read(int(self.headers['Content-Length'])))
        self.wfile.write("POST OK\n".encode("utf-8"))

    def do_HEAD(self):
        self._set_headers()

test_server = HTTPServer((hostName, hostPort), S)
print(time.asctime(), "Server Starts - %s:%s" % (hostName, hostPort))

try:
    test_server.serve_forever()
except KeyboardInterrupt:
    pass

test_server.server_close()
print(time.asctime(), "Server Stops - %s:%s" % (hostName, hostPort))
