from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any, Tuple


SUSPICIOUS_PATHS = {
    "/wp-login.php",
    "/admin",
    "/.env",
    "/phpmyadmin",
    "/cgi-bin/luci",
}


@dataclass
class HoneypotEvent:
    timestamp: str
    source_ip: str
    method: str
    path: str
    user_agent: str
    query: str


class LlamaAnalyzer:
    def __init__(self, api_url: str, model: str, timeout: float = 5.0) -> None:
        self.api_url = api_url
        self.model = model
        self.timeout = timeout

    def classify(self, event: HoneypotEvent) -> Tuple[str, str]:
        payload = {
            "model": self.model,
            "stream": False,
            "prompt": (
                "You are a SOC analyst. Classify the event as low, medium, or high threat and "
                "give a short reason in one sentence. Event JSON: "
                f"{json.dumps(asdict(event), separators=(',', ':'))}"
            ),
        }

        try:
            from urllib.request import Request, urlopen

            req = Request(
                self.api_url,
                method="POST",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req, timeout=self.timeout) as response:  # nosec B310
                parsed = json.loads(response.read().decode("utf-8"))
                message = parsed.get("response", "").strip()
                severity = _extract_severity(message)
                if not message:
                    message = "AI returned empty response; fallback used."
                return severity, message
        except Exception:
            return heuristic_classification(event)


def _extract_severity(message: str) -> str:
    lowered = message.lower()
    for label in ("high", "medium", "low"):
        if label in lowered:
            return label
    return "medium"


def heuristic_classification(event: HoneypotEvent) -> Tuple[str, str]:
    score = 0

    if event.path in SUSPICIOUS_PATHS:
        score += 2
    if "sqlmap" in event.user_agent.lower() or "nmap" in event.user_agent.lower():
        score += 2
    if event.method not in {"GET", "HEAD"}:
        score += 1
    if ".." in event.path or "%2e%2e" in event.path.lower():
        score += 2

    if score >= 4:
        return "high", "Heuristic match: likely automated exploitation attempt."
    if score >= 2:
        return "medium", "Heuristic match: suspicious reconnaissance traffic."
    return "low", "Heuristic match: low-confidence anomaly."


class PLIXPOBEngine:
    """Implements Probe, Log, Inspect, eXplain, Prioritize, Orchestrate Block."""

    def __init__(self, log_file: str = "honeypot_events.jsonl") -> None:
        api_url = os.getenv("LLAMA_API_URL", "http://localhost:11434/api/generate")
        model = os.getenv("LLAMA_MODEL", "llama3.1")
        timeout = float(os.getenv("LLAMA_TIMEOUT", "5"))

        self.log_file = log_file
        self.ai = LlamaAnalyzer(api_url=api_url, model=model, timeout=timeout)

    def process(self, source_ip: str, method: str, path: str, user_agent: str, query: str = "") -> Dict[str, Any]:
        event = HoneypotEvent(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            source_ip=source_ip,
            method=method,
            path=path,
            user_agent=user_agent,
            query=query,
        )

        severity, reason = self.ai.classify(event)
        block_recommended = severity in {"high", "medium"}

        result = {
            "plix_pob": {
                "probe": asdict(event),
                "log": "written",
                "inspect": {
                    "path_flagged": event.path in SUSPICIOUS_PATHS,
                    "ua_flagged": any(k in user_agent.lower() for k in ("sqlmap", "nmap", "nikto")),
                },
                "explain": {"severity": severity, "reason": reason},
                "prioritize": {"score": _severity_score(severity), "severity": severity},
                "orchestrate_block": {
                    "recommended": block_recommended,
                    "ttl_seconds": 3600 if block_recommended else 0,
                },
            }
        }

        self._write_event(result)
        return result

    def _write_event(self, payload: Dict[str, Any]) -> None:
        with open(self.log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, separators=(",", ":")) + "\n")


def _severity_score(severity: str) -> int:
    return {"low": 25, "medium": 65, "high": 90}.get(severity, 50)
