from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ServerGuard:
    """Evidence-first moderation workflow for managed servers.

    A first detection can only create a warning. A separate verification with
    new evidence is required before a case can become ban-eligible.
    """

    def __init__(self, storage_path: str) -> None:
        self.storage_path = Path(storage_path)
        self._lock = threading.RLock()
        self._ensure_storage()

    def _ensure_storage(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.storage_path.exists():
            self._save({"cases": {}, "events": []})

    def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.storage_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"cases": {}, "events": []}

    def _save(self, data: Dict[str, Any]) -> None:
        temp_path = self.storage_path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp_path.replace(self.storage_path)

    @staticmethod
    def _score(category: str, evidence: Dict[str, Any]) -> tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []
        text = str(evidence.get("text") or "").lower()

        if category == "cheat":
            indicators = ("aimbot", "wallhack", "speed hack", "injected", "modified client")
            for indicator in indicators:
                if indicator in text:
                    score += 35
                    reasons.append(f"text_indicator:{indicator}")
            if evidence.get("server_log_match"):
                score += 35
                reasons.append("server_log_match")
            if evidence.get("behavioral_anomaly"):
                score += 25
                reasons.append("behavioral_anomaly")
        elif category == "scam":
            indicators = ("send crypto", "free nitro", "verify wallet", "gift card", "login here")
            for indicator in indicators:
                if indicator in text:
                    score += 30
                    reasons.append(f"text_indicator:{indicator}")
            if evidence.get("malicious_url"):
                score += 45
                reasons.append("malicious_url")
            if evidence.get("repeat_offender_pattern"):
                score += 30
                reasons.append("repeat_offender_pattern")
        elif category == "screen":
            if evidence.get("screen_consent") is True:
                score += 10
                reasons.append("screen_consent")
            if evidence.get("suspicious_overlay"):
                score += 40
                reasons.append("suspicious_overlay")
            if evidence.get("known_cheat_ui"):
                score += 45
                reasons.append("known_cheat_ui")
        return min(score, 100), reasons

    def inspect_server(self, server_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        required = {
            "server_id": bool(server_id),
            "owner_id": bool(config.get("owner_id")),
            "logging_enabled": config.get("logging_enabled") is True,
            "moderation_webhook": bool(config.get("moderation_webhook")),
            "backup_enabled": config.get("backup_enabled") is True,
            "restricted_permissions": config.get("restricted_permissions") is True,
        }
        missing = [name for name, valid in required.items() if not valid]
        return {
            "server_id": server_id,
            "properly_configured": not missing,
            "missing_or_invalid": missing,
            "checked_at": _now(),
        }

    def detect(self, server_id: str, subject_id: str, category: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            data = self._load()
            score, reasons = self._score(category, evidence)
            case_id = str(uuid.uuid4())
            case = {
                "case_id": case_id,
                "server_id": server_id,
                "subject_id": subject_id,
                "category": category,
                "state": "warning",
                "warning_count": 1,
                "verification_count": 0,
                "score": score,
                "reasons": reasons,
                "evidence": [evidence],
                "created_at": _now(),
                "updated_at": _now(),
            }
            data.setdefault("cases", {})[case_id] = case
            data.setdefault("events", []).append({"type": "warning_issued", "case_id": case_id, "at": _now()})
            self._save(data)
            return case

    def verify(self, case_id: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            data = self._load()
            case = data.setdefault("cases", {}).get(case_id)
            if not case:
                raise KeyError(case_id)
            if case["state"] == "banned":
                return case

            score, reasons = self._score(case["category"], evidence)
            case["verification_count"] += 1
            case["evidence"].append(evidence)
            case["score"] = max(case["score"], score)
            case["reasons"] = sorted(set(case["reasons"] + reasons))
            case["updated_at"] = _now()

            corroborated = len(case["evidence"]) >= 2 and len(case["reasons"]) >= 2
            if case["score"] >= 75 and corroborated:
                case["state"] = "ban_eligible"
                event_type = "verified_for_ban"
            else:
                case["state"] = "monitoring"
                event_type = "verification_inconclusive"
            data["events"].append({"type": event_type, "case_id": case_id, "at": _now()})
            self._save(data)
            return case

    def get_case(self, case_id: str) -> Dict[str, Any] | None:
        with self._lock:
            return self._load().get("cases", {}).get(case_id)

    def ban(self, case_id: str, moderator_id: str) -> Dict[str, Any]:
        with self._lock:
            data = self._load()
            case = data.setdefault("cases", {}).get(case_id)
            if not case:
                raise KeyError(case_id)
            if case["state"] != "ban_eligible":
                raise ValueError("case must be verified before it can be banned")
            case["state"] = "banned"
            case["banned_by"] = moderator_id
            case["banned_at"] = _now()
            case["updated_at"] = _now()
            data["events"].append({"type": "ban_applied", "case_id": case_id, "moderator_id": moderator_id, "at": _now()})
            self._save(data)
            return case


def build_guard(data_dir: str) -> ServerGuard:
    return ServerGuard(os.path.join(data_dir, "server_guard.json"))