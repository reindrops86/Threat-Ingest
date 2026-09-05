from __future__ import annotations

import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
CREWAI_SRC = PROJECT_ROOT / "crewai_project" / "src"
if str(CREWAI_SRC) not in sys.path:
    sys.path.insert(0, str(CREWAI_SRC))

from gtm_project.evidence import load_evidence_catalog
from gtm_project.pipeline import DeterministicGTMFlow


class GTMBridgeHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            self._reply(HTTPStatus.OK, {"status": "healthy", "service": "gtm-n8n-bridge"})
            return
        self._reply(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        if self.path not in {"/tools/research", "/tools/run"}:
            self._reply(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(size) or b"{}")
            evidence = load_evidence_catalog(PROJECT_ROOT / "crewai_project" / "data" / "evidence_catalog.json")
            result = DeterministicGTMFlow(evidence, implementation="n8n_simulation").run(str(payload.get("brief") or f"Build a GTM plan for {payload.get('domain', 'fintech')}"))
            response = result["research"] if self.path == "/tools/research" else result
            self._reply(HTTPStatus.OK, response)
        except (ValueError, json.JSONDecodeError) as error:
            self._reply(HTTPStatus.BAD_REQUEST, {"error": str(error)})

    def _reply(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    print("GTM n8n bridge listening on http://127.0.0.1:8000")
    ThreadingHTTPServer(("127.0.0.1", 8000), GTMBridgeHandler).serve_forever()