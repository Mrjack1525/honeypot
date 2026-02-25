from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from honeypot.plix_pob import PLIXPOBEngine


LOG_PATH = os.getenv("HONEYPOT_LOG_FILE", "logs/honeypot_events.jsonl")
engine = PLIXPOBEngine(log_file=LOG_PATH)


class HoneypotHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.57"

    def _send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send_json(200, {"status": "healthy"})
            return

        result = engine.process(
            source_ip=self.client_address[0],
            method=self.command,
            path=parsed.path,
            user_agent=self.headers.get("User-Agent", "unknown"),
            query=parsed.query,
        )

        self._send_json(
            503,
            {
                "status": "ok",
                "message": "resource temporarily unavailable",
                "tracking_id": result["plix_pob"]["probe"]["timestamp"],
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def run() -> None:
    host = os.getenv("HONEYPOT_HOST", "0.0.0.0")
    port = int(os.getenv("HONEYPOT_PORT", "8080"))

    server = ThreadingHTTPServer((host, port), HoneypotHandler)
    print(f"[honeypot] listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
