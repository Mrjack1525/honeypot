from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from honeypot.plix_pob import PLIXPOBEngine


engine = PLIXPOBEngine()


class HoneypotHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.57"

    def _handle(self) -> None:
        parsed = urlparse(self.path)
        result = engine.process(
            source_ip=self.client_address[0],
            method=self.command,
            path=parsed.path,
            user_agent=self.headers.get("User-Agent", "unknown"),
            query=parsed.query,
        )

        body = json.dumps(
            {
                "status": "ok",
                "message": "resource temporarily unavailable",
                "tracking_id": result["plix_pob"]["probe"]["timestamp"],
            }
        ).encode("utf-8")

        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    def do_POST(self) -> None:  # noqa: N802
        self._handle()

    def do_PUT(self) -> None:  # noqa: N802
        self._handle()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        # Silence default console logs; events are recorded through PLIX-POB.
        return


def run(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), HoneypotHandler)
    print(f"[honeypot] listening on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
