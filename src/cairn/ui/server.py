"""The UI's HTTP server: localhost-only, stdlib-only.

The server binds the loopback interface exclusively — the workbench is a local
single-user tool, not a network service — and refuses request bodies above
1 MiB. It serves the embedded dashboard and the JSON API; there is no auth
because there is no network exposure, and every endpoint is read-only or
simulator-gated by construction (ADR-031).
"""

from __future__ import annotations

import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cairn.ui.app import MAX_BODY_BYTES, dispatch

_STATIC_DIR = Path(__file__).parent / "static"


class _Handler(BaseHTTPRequestHandler):
    server_version = "cairn-ui"

    def log_message(self, format: str, *args: object) -> None:
        # Quiet by default; a flashing workbench should not splatter request
        # lines (which can carry paths) into arbitrary terminals.
        pass

    def _send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path not in ("/", "/index.html"):
            self._send_json(404, {"error": "not found"})
            return
        try:
            body = (_STATIC_DIR / "index.html").read_bytes()
        except OSError:
            self._send_json(500, {"error": "the dashboard asset is missing"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self.path.startswith("/api/"):
            self._send_json(404, {"error": "not found"})
            return
        name = self.path.removeprefix("/api/").strip("/")
        length_header = self.headers.get("Content-Length")
        try:
            length = int(length_header) if length_header is not None else 0
        except ValueError:
            self._send_json(400, {"error": "invalid Content-Length"})
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "request body is too large"})
            return
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "request body is not valid JSON"})
            return
        if not isinstance(body, dict):
            self._send_json(400, {"error": "request body must be a JSON object"})
            return
        status, payload = dispatch("POST", name, body)
        self._send_json(status, payload)


def serve(port: int = 8722, *, open_browser: bool = True) -> None:
    """Serve the dashboard on the loopback interface and open a browser."""
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    print(f"cairn ui: serving the local workbench at {url} (loopback only)")
    print("read-only checks and simulator-gated writes; close with Ctrl+C")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Serve the Cairn local workbench")
    parser.add_argument("--port", type=int, default=8722)
    parser.add_argument("--no-browser", action="store_true")
    arguments = parser.parse_args()
    serve(arguments.port, open_browser=not arguments.no_browser)
