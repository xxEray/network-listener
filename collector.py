#!/usr/bin/env python3
"""collector.py v1.5 — venue collector: UDP ingest + HMAC verify + incident
aggregation + password-protected web dashboard (§8, §9, §10).

Standard library only, Python 3.8+ (Win7 compatible).

- UDP :48123 receives HMAC-SHA256-signed JSON packets from listener.exe
  (canonical sorted-keys JSON over the body without the "hmac" field —
  byte-compatible with listener.make_signed).
- Every valid event except heartbeats is appended to logs\\YYYY-MM-DD.jsonl.
- Non-whitelisted DNS and unmapped public TCP events are aggregated into
  incidents.jsonl keyed by account+target+process (one tier, D38), with
  collector-side grading from policy.json and high-risk flags.
- state.json snapshots machine state for restart recovery; sessions.json
  tracks per-account session windows; retention sweeps old logs/incidents.
- Web dashboard: HTTPS 8443 with self-signed cert (falls back to HTTP 8080),
  PBKDF2-SHA256 password in dashboard.json, HttpOnly session cookie,
  5 failed logins per IP -> 60s lock, single-file vanilla-JS UI polling /api/*.
- policy.json can be imported from the dashboard and takes effect without
  restarting the collector.

v1 scope: no CA cert install, no TCP fallback channel, no scheduled task,
no service mode.
"""
import argparse
import csv
import hashlib
import hmac
import http.server
import io
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.5"
DEFAULT_UDP_PORT = 48123
DEFAULT_WEB_PORT = 8443
DEFAULT_HTTP_PORT = 8080
ONLINE_SECONDS = 45      # §10.2 status thresholds
LATE_SECONDS = 90
CONFLICT_WINDOW = 90     # same machine_id from 2 IPs within 90s -> key_conflict
KEY_ERROR_WINDOW = 90
MAX_EVENTS_PER_INCIDENT = 50
SESSION_TTL = 12 * 3600
LOGIN_MAX_FAILS = 5
LOGIN_LOCK_SECONDS = 60
DEFAULT_SUSPICIOUS_TLDS = ["top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "work"]
DEFAULT_INTERACTIVE_PROCS = [
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
    "brave.exe", "vivaldi.exe", "360se.exe", "360chrome.exe", "qqbrowser.exe",
    "sogouexplorer.exe", "maxthon.exe", "browser.exe", "duckduckgo.exe",
]
DEFAULT_SYSTEM_PROCS = [
    "svchost.exe", "lsass.exe", "services.exe", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "spoolsv.exe", "taskhostw.exe", "conhost.exe",
    "sihost.exe", "dwm.exe", "fontdrvhost.exe", "wudfhost.exe", "searchindexer.exe",
    "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe", "wmiapsrv.exe",
]

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(message: str) -> None:
    print(f"[{utc_now()}] collector: {message}", flush=True)


def read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            return json.load(f)
    except (IOError, ValueError):
        return default


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(str(path) + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(temp, path)


def canonical_json(obj: Any) -> str:
    """Must match listener.make_signed exactly."""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def parse_iso_time(value: Any, fallback: float) -> float:
    try:
        text = str(value).strip().rstrip("Zz")
        if "." in text:
            dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
        # listener/agent always sends UTC (SystemTime from wevtutil carries Z)
        return dt.replace(tzinfo=timezone.utc).timestamp()
    except (ValueError, TypeError):
        return fallback


def is_ip_address(text: str) -> bool:
    return bool(IP_RE.match(text.strip()))


def tld_of_domain(domain: str) -> str:
    host = domain.strip().rstrip(".").lower()
    if not host or is_ip_address(host):
        return ""
    return host.rsplit(".", 1)[-1]


def verify_packet(data: bytes, secrets_map: Dict[str, str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Verify an HMAC-signed packet. Returns (payload, None) or (None, reason)."""
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, "bad_json"
    if not isinstance(payload, dict):
        return None, "bad_json"
    machine = str(payload.get("machine", ""))
    sig = str(payload.get("hmac", ""))
    if not machine or not sig:
        return None, "missing_fields"
    secret = secrets_map.get(machine)
    if secret is None:
        return None, "unknown_machine"
    body = {k: v for k, v in payload.items() if k != "hmac"}
    expected = hmac.new(secret.encode("utf-8"), canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None, "hmac_fail"
    return payload, None


def make_signed(payload: Dict[str, Any], secret: str) -> bytes:
    """Test helper, byte-compatible with listener.make_signed."""
    body = dict(payload)
    body.pop("hmac", None)
    body["hmac"] = hmac.new(secret.encode("utf-8"), canonical_json(body).encode("utf-8"), hashlib.sha256).hexdigest()
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class Store:
    """In-memory state + JSONL/JSON persistence for one collector process."""

    def __init__(self, base: Path, retain_days: int = 7, venue: str = ""):
        self.base = base
        self.logs_dir = base / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.incidents_file = base / "incidents.jsonl"
        self.sessions_file = base / "sessions.json"
        self.state_file = base / "state.json"
        self.policy_file = base / "policy.json"
        self.retain_days = max(1, int(retain_days))
        self.venue = venue
        self.lock = threading.RLock()
        self.machines: Dict[str, Dict[str, Any]] = {}
        self.last_seq: Dict[str, int] = {}
        self.key_errors: Dict[str, Dict[str, Any]] = {}
        self.ip_history: Dict[str, List[Dict[str, Any]]] = {}
        self.unknown: Dict[str, Dict[str, Any]] = {}
        self.incidents: Dict[str, Dict[str, Any]] = {}
        self.roster: Dict[str, Dict[str, Any]] = {}      # machine_id -> roster row
        self.accounts: Dict[str, Dict[str, Any]] = {}    # account -> {name, venue, machine_ids}
        self.sessions: Dict[str, Dict[str, Any]] = {}    # account -> session info
        self.policy: Dict[str, Any] = {}
        self.counters: Dict[str, int] = {}
        self.dirty = False
        self.last_sweep = time.time()
        self.load_roster()
        self.load_policy()
        self.load_state()
        self.load_incidents()

    # ---------- loading ----------

    def load_roster(self) -> None:
        rows = read_json(self.base / "roster.json", [])
        if not isinstance(rows, list):
            rows = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            mid = str(row.get("machine_id", "")).strip()
            account = str(row.get("account", "")).strip()
            if not mid or not account:
                continue
            self.roster[mid] = {
                "account": account,
                "name": str(row.get("name", "")),
                "venue": str(row.get("venue", "")),
            }
            info = self.accounts.setdefault(account, {"name": row.get("name", ""), "venue": row.get("venue", ""), "machine_ids": []})
            if mid not in info["machine_ids"]:
                info["machine_ids"].append(mid)
        if self.roster:
            log(f"名册载入：{len(self.roster)} 台机器 / {len(self.accounts)} 个账号")

    def load_policy(self) -> None:
        raw_policy = read_json(self.policy_file, {})
        if not isinstance(raw_policy, dict):
            raw_policy = {}
            log("policy.json 不是对象，已改用默认分级策略")
        self.policy = self.normalize_policy(raw_policy, self.venue)

    @staticmethod
    def normalize_policy(policy: Any, venue: str = "") -> Dict[str, Any]:
        """Validate a policy object and fill only the fields collector consumes."""
        if not isinstance(policy, dict):
            raise ValueError("policy 必须是 JSON 对象")
        normalized = dict(policy)
        for field in ("allowed_domains", "ignored_domains", "ignored_processes", "ignored_ips"):
            values = normalized.get(field, [])
            if values is None:
                values = []
            if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
                raise ValueError(f"{field} 必须是字符串数组")
            normalized[field] = list(values)
        grades = normalized.get("process_grades") or {}
        if not isinstance(grades, dict):
            raise ValueError("process_grades 必须是 JSON 对象")
        normalized["process_grades"] = {
            "interactive": [str(p).lower() for p in grades.get("interactive", DEFAULT_INTERACTIVE_PROCS)],
            "system": [str(p).lower() for p in grades.get("system", DEFAULT_SYSTEM_PROCS)],
        }
        hr = normalized.get("high_risk") or {}
        if not isinstance(hr, dict):
            raise ValueError("high_risk 必须是 JSON 对象")
        normalized["high_risk"] = {
            "flag_direct_ip": bool(hr.get("flag_direct_ip", True)),
            "flag_nonstandard_port": bool(hr.get("flag_nonstandard_port", True)),
            "suspicious_tlds": [str(t).lower() for t in hr.get("suspicious_tlds", DEFAULT_SUSPICIOUS_TLDS)],
        }
        try:
            version = int(normalized.get("version", 1))
        except (TypeError, ValueError):
            raise ValueError("version 必须是整数")
        normalized["version"] = max(1, version)
        if venue:
            normalized["venue"] = venue
        normalized["updated_at"] = str(normalized.get("updated_at", "")).strip() or utc_now()
        return normalized

    def update_policy(self, policy: Any) -> Tuple[Dict[str, Any], int]:
        """Validate, persist, and hot-apply a new collector policy."""
        normalized = self.normalize_policy(policy, self.venue)
        normalized["updated_at"] = utc_now()
        with self.lock:
            self.policy = normalized
            regraded = self.regrade_incidents()
            self.dirty = True
            atomic_json(self.policy_file, normalized)
        return normalized, regraded

    def regrade_incidents(self) -> int:
        """Re-evaluate grade and high-risk flags for incidents currently in memory."""
        regraded = 0
        for inc in self.incidents.values():
            etype = str(inc.get("type", ""))
            if etype == "health":
                inc["grade"] = "system"
            else:
                inc["grade"] = self._grade_process(str(inc.get("process", "")))
                flags: Set[str] = set()
                for raw in inc.get("events", []):
                    if isinstance(raw, dict):
                        flags.update(self._high_risk_flags(etype, str(inc.get("target", "")), raw))
                inc["high_risk"] = sorted(flags)
            regraded += 1
        return regraded

    def load_state(self) -> None:
        state = read_json(self.state_file, {})
        if not isinstance(state, dict):
            return
        machines = state.get("machines") or {}
        if isinstance(machines, dict):
            self.machines = machines
        seq = state.get("last_seq") or {}
        if isinstance(seq, dict):
            self.last_seq = {k: int(v) for k, v in seq.items() if str(k).strip()}
        for attr in ("key_errors", "unknown", "sessions"):
            value = state.get(attr) or {}
            if isinstance(value, dict):
                setattr(self, attr, value)
        history = state.get("ip_history") or {}
        if isinstance(history, dict):
            self.ip_history = history
        log(f"状态恢复：{len(self.machines)} 台机器，{len(self.sessions)} 个会话")

    def load_incidents(self) -> None:
        if not self.incidents_file.exists():
            return
        count = 0
        with self.incidents_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if isinstance(item, dict) and item.get("id"):
                    self.incidents[str(item["id"])] = item
                    count += 1
        log(f"事件聚合恢复：{count} 条")

    # ---------- persistence ----------

    _MACHINE_KEEP = ("last_seen", "last_ip", "last_type", "hostname", "version", "session",
                     "agent_stopped", "guard", "guard_restarts", "collector_ip", "config_hash",
                     "key_conflict", "uptime_seconds", "queue_depth", "watermark", "hb_seconds")

    def save_state(self, force: bool = False) -> None:
        with self.lock:
            if not force and not self.dirty:
                return
            trimmed = {mid: {k: m.get(k) for k in self._MACHINE_KEEP if k in m}
                       for mid, m in self.machines.items()}
            atomic_json(self.state_file, {
                "version": VERSION,
                "saved_at": utc_now(),
                "machines": trimmed,
                "last_seq": self.last_seq,
                "key_errors": self.key_errors,
                "ip_history": self.ip_history,
                "unknown": self.unknown,
                "sessions": self.sessions,
            })
            if self.dirty:
                atomic_json(self.incidents_file, list(self.incidents.values()))
            self.dirty = False

    def sweep_retention(self) -> None:
        with self.lock:
            cutoff = time.time() - self.retain_days * 86400
            dropped = 0
            for iid in list(self.incidents):
                item = self.incidents[iid]
                if parse_iso_time(item.get("last_seen"), 0) < cutoff:
                    del self.incidents[iid]
                    dropped += 1
            if dropped:
                atomic_json(self.incidents_file, list(self.incidents.values()))
            removed_logs = 0
            for path in self.logs_dir.glob("*.jsonl"):
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                        removed_logs += 1
                except OSError:
                    pass
            self.last_sweep = time.time()
            if dropped or removed_logs:
                log(f"保留期清理：删除 {dropped} 条事件、{removed_logs} 个日志文件（保留 {self.retain_days} 天）")

    # ---------- ingest ----------

    def _venue_of(self, machine_id: str) -> str:
        return str(self.roster.get(machine_id, {}).get("venue", ""))

    def record_verify_error(self, reason: str, data: bytes, addr: Tuple[str, int]) -> None:
        with self.lock:
            self.counters[f"reject_{reason}"] = self.counters.get(f"reject_{reason}", 0) + 1
            machine = ""
            try:
                parsed = json.loads(data.decode("utf-8"))
                if isinstance(parsed, dict):
                    machine = str(parsed.get("machine", ""))
            except (UnicodeDecodeError, ValueError):
                pass
            if machine and reason == "hmac_fail":
                entry = self.key_errors.setdefault(machine, {"count": 0, "last_ip": "", "last_at": 0.0})
                entry["count"] = int(entry.get("count", 0)) + 1
                entry["last_ip"] = addr[0]
                entry["last_at"] = time.time()
                self.dirty = True
            if self.counters[f"reject_{reason}"] % 20 == 1:
                log(f"拒绝包：{reason} from {addr[0]} machine={machine or '?'}")

    def record(self, payload: Dict[str, Any], addr: Tuple[str, int], received_at: float) -> None:
        machine = str(payload.get("machine", ""))
        itype = str(payload.get("type", ""))
        with self.lock:
            if self.roster and machine not in self.roster:
                self.counters["reject_not_in_roster"] = self.counters.get("reject_not_in_roster", 0) + 1
                return
            if self.venue and self.roster and self._venue_of(machine) != self.venue:
                self.counters["reject_other_venue"] = self.counters.get("reject_other_venue", 0) + 1
                return
            if not self.roster:
                self.roster[machine] = {"account": machine, "name": "", "venue": self.venue}
                self.accounts.setdefault(machine, {"name": "", "venue": self.venue, "machine_ids": [machine]})
            event_time = parse_iso_time(payload.get("time"), received_at)
            m = self.machines.setdefault(machine, {})
            m.update({
                "last_seen": received_at,
                "last_ip": addr[0],
                "last_type": itype,
                "last_event_time": event_time,
            })
            for key in ("version", "hostname", "session", "uptime_seconds", "queue_depth",
                        "watermark", "hb_seconds", "collector_ip", "config_hash"):
                if key in payload:
                    m[key] = payload[key]
            if "guard" in payload:
                m["guard"] = bool(payload.get("guard"))
            if "guard_restarts" in payload:
                m["guard_restarts"] = int(payload.get("guard_restarts", 0) or 0)
            seq = int(payload.get("seq", 0) or 0)
            if seq:
                prev = self.last_seq.get(machine, 0)
                if seq <= prev:
                    self.counters["replayed_seq"] = self.counters.get("replayed_seq", 0) + 1
                self.last_seq[machine] = max(prev, seq)
            # key_conflict: same machine_id seen from 2 distinct IPs within the window
            history = self.ip_history.setdefault(machine, [])
            history.append({"ip": addr[0], "at": received_at})
            del history[:-12]
            recent_ips = {h["ip"] for h in history if received_at - h["at"] <= CONFLICT_WINDOW}
            if len(recent_ips) > 1:
                m["key_conflict"] = True
            # session bookkeeping (§8.6)
            account = self.roster[machine]["account"]
            sess = self.sessions.setdefault(account, {"first_seen": utc_now(), "last_seen": utc_now(), "machine_ids": []})
            if machine not in sess["machine_ids"]:
                sess["machine_ids"].append(machine)
            sess["last_seen"] = utc_now()
            if itype == "heartbeat":
                self.dirty = True
                return  # heartbeats are never written to JSONL (§8.3)
            if itype == "agent_started":
                m["agent_stopped"] = False
                self.counters["agent_started"] = self.counters.get("agent_started", 0) + 1
            elif itype == "agent_stopped":
                m["agent_stopped"] = True
                self.counters["agent_stopped"] = self.counters.get("agent_stopped", 0) + 1
            self._append_jsonl(payload, received_at)
            if itype in ("agent_stats",):
                self.dirty = True
                return
            self._update_incident(payload, machine, account, event_time)
            self.dirty = True

    def _append_jsonl(self, payload: Dict[str, Any], received_at: float) -> None:
        day = datetime.fromtimestamp(received_at, tz=timezone.utc).strftime("%Y-%m-%d")
        path = self.logs_dir / f"{day}.jsonl"
        try:
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
        except OSError as exc:
            log(f"JSONL 写入失败：{exc}")

    def _grade_process(self, process: str) -> str:
        name = Path(process or "<unknown>").name.lower()
        grades = self.policy.get("process_grades", {})
        if name in grades.get("interactive", []):
            return "interactive"
        if name in grades.get("system", []):
            return "system"
        return "unknown"

    def _high_risk_flags(self, etype: str, target: str, extra: Dict[str, Any]) -> List[str]:
        hr = self.policy.get("high_risk", {})
        flags: List[str] = []
        if etype == "dns":
            if hr.get("flag_direct_ip", True) and is_ip_address(target):
                flags.append("direct_ip")
            tld = tld_of_domain(target)
            if tld and tld in hr.get("suspicious_tlds", DEFAULT_SUSPICIOUS_TLDS):
                flags.append("suspicious_tld")
        elif etype == "tcp":
            try:
                port = int(str(extra.get("remote_port", "") or 0))
            except ValueError:
                port = 0
            if hr.get("flag_nonstandard_port", True) and port and port not in (80, 443):
                flags.append("nonstandard_port")
        return flags

    def _update_incident(self, payload: Dict[str, Any], machine: str, account: str, event_time: float) -> None:
        itype = str(payload.get("type", ""))
        if itype.startswith("dns"):
            etype, target = "dns", str(payload.get("domain", ""))
        elif itype == "tcp_unmapped_ip":
            etype, target = "tcp", str(payload.get("remote_ip", ""))
        else:
            etype, target = "health", str(payload.get("detail", ""))[:160]
        process = str(payload.get("process", "<unknown>")) if etype != "health" else ""
        key = f"{account}|{etype}|{target}|{process}"
        iid = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        inc = self.incidents.get(iid)
        if inc is None:
            row = self.roster.get(machine, {})
            inc = {
                "id": iid,
                "account": account,
                "name": row.get("name", ""),
                "venue": row.get("venue", "") or self.venue,
                "type": etype,
                "event_type": itype,
                "target": target,
                "process": process,
                "grade": self._grade_process(process) if etype != "health" else "system",
                "high_risk": [],
                "count": 0,
                "first_seen": datetime.fromtimestamp(event_time, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "last_seen": datetime.fromtimestamp(event_time, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "ack": False,
                "acked_at": None,   # D40: no handler name is recorded
                "machine_ids": [],
                "events": [],
            }
            self.incidents[iid] = inc
        inc["count"] = int(inc.get("count", 0)) + 1
        ev_iso = datetime.fromtimestamp(event_time, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        inc["last_seen"] = max(inc.get("last_seen", ""), ev_iso)
        if inc["first_seen"] > ev_iso:
            inc["first_seen"] = ev_iso
        if machine not in inc["machine_ids"]:
            inc["machine_ids"].append(machine)
        flags = self._high_risk_flags(etype, target, payload)
        for flag in flags:
            if flag not in inc["high_risk"]:
                inc["high_risk"].append(flag)
        raw = {k: v for k, v in payload.items() if k != "hmac"}
        raw["_received"] = utc_now()
        events = inc.setdefault("events", [])
        events.append(raw)
        del events[:-MAX_EVENTS_PER_INCIDENT]

    # ---------- queries ----------

    def account_status(self, venue: str = "") -> Dict[str, Any]:
        now = time.time()
        counts = {"online": 0, "late": 0, "offline": 0, "stopped": 0, "key_error": 0, "never": 0}
        rows: List[Dict[str, Any]] = []
        health: List[Dict[str, Any]] = []
        all_rows: List[Dict[str, Any]] = []
        all_health: List[Dict[str, Any]] = []
        for account, info in sorted(self.accounts.items()):
            mids = list(info.get("machine_ids", []))
            entries = [self.machines.get(mid) for mid in mids if self.machines.get(mid)]
            recent = [e for e in entries if now - float(e.get("last_seen", 0)) <= LATE_SECONDS]
            recent_key_err = False
            for mid in mids:
                err = self.key_errors.get(mid)
                if err and now - float(err.get("last_at", 0)) <= KEY_ERROR_WINDOW:
                    recent_key_err = True
            if not entries and not recent_key_err:
                status = "never"
            elif recent_key_err and not recent:
                status = "key_error"
            elif any(e.get("agent_stopped") for e in recent):
                status = "stopped"
            else:
                last = max(float(e.get("last_seen", 0)) for e in entries)
                delta = now - last
                status = "online" if delta <= ONLINE_SECONDS else ("late" if delta <= LATE_SECONDS else "offline")
            counts[status] = counts.get(status, 0) + 1
            conflict = any(e.get("key_conflict") for e in entries)
            multi = len(mids) >= 2
            machine_rows = []
            for mid in mids:
                e = self.machines.get(mid) or {}
                machine_rows.append({
                    "machine_id": mid,
                    "ip": e.get("last_ip", ""),
                    "hostname": e.get("hostname", ""),
                    "version": e.get("version", ""),
                    "guard": e.get("guard"),
                    "guard_restarts": e.get("guard_restarts", 0),
                    "agent_stopped": bool(e.get("agent_stopped")),
                    "last_seen": utc_iso(e.get("last_seen")) if e.get("last_seen") else "",
                    "uptime_seconds": e.get("uptime_seconds"),
                    "queue_depth": e.get("queue_depth"),
                    "collector_ip": e.get("collector_ip", ""),
                    "config_hash": e.get("config_hash", ""),
                })
            row = {
                "account": account,
                "name": info.get("name", ""),
                "venue": info.get("venue", ""),
                "status": status,
                "last_seen": utc_iso(max((float(e.get("last_seen", 0)) for e in entries), default=0)) if entries else "",
                "multi_machine": multi,
                "key_conflict": conflict,
                "machine_ids": mids,
                "machines": machine_rows,
            }
            all_rows.append(row)
            if multi:
                health.append({"kind": "multi_machine", "level": "info", "account": account,
                               "detail": f"同一账号 {len(mids)} 台机器在报数：{', '.join(mids)}"})
            if conflict:
                health.append({"kind": "key_conflict", "level": "warn", "account": account,
                               "detail": "同一 machine_id 在 90 秒内出现多个来源 IP，疑似密钥/机器号复制"})
            if status == "key_error":
                health.append({"kind": "key_error", "level": "warn", "account": account,
                               "detail": "近期收到 HMAC 校验失败的包，密钥可能不一致"})
            for mid, e in zip(mids, entries):
                if e.get("guard") is False and now - float(e.get("last_seen", 0)) <= LATE_SECONDS:
                    health.append({"kind": "guard_down", "level": "warn", "account": account,
                                   "detail": f"心跳显示 guard.py 不在运行（machine={mid}）"})
                if e.get("agent_stopped") and now - float(e.get("last_seen", 0)) <= LATE_SECONDS:
                    health.append({"kind": "agent_stopped", "level": "warn", "account": account,
                                   "detail": "agent 上报了主动停止"})
        for mid, err in self.key_errors.items():
            if now - float(err.get("last_at", 0)) <= KEY_ERROR_WINDOW and mid not in self.roster:
                health.append({"kind": "key_error", "level": "warn", "account": mid,
                               "detail": f"未知机器 {mid} 的包 HMAC 校验失败"})
        for mid, info in self.unknown.items():
            if now - float(info.get("last_seen", 0)) <= LATE_SECONDS:
                health.append({"kind": "unknown_machine", "level": "warn", "account": mid,
                               "detail": f"收到不在名册中的机器 {mid} 的有效包（IP {info.get('last_ip', '')}）"})
        # Venue filtering is additive: unknown machines/key errors still stay visible
        # so an operator can diagnose provisioning mistakes in a combined collector.
        rows = all_rows
        health = all_health
        if venue:
            rows = [r for r in all_rows if str(r.get("venue", "")) == venue]
            row_accounts = {str(r.get("account", "")) for r in rows}
            health = [h for h in all_health
                      if str(h.get("kind", "")) == "unknown_machine" or str(h.get("account", "")) in row_accounts]
            counts = {key: sum(1 for r in rows if r.get("status") == key) for key in counts}
        return {"now": utc_now(), "venue": venue or self.venue, "venues": sorted({str(v.get("venue", "")) for v in self.accounts.values()}),
                "counts": counts, "accounts": rows, "health": health}

    def incidents_query(self, itype: str = "", grade: str = "", include_acked: bool = False,
                        search: str = "", venue: str = "") -> Dict[str, Any]:
        items: List[Dict[str, Any]] = []
        needle = search.strip().lower()
        count_base = [inc for inc in self.incidents.values() if not venue or inc.get("venue", "") == venue]
        for inc in self.incidents.values():
            if not include_acked and inc.get("ack"):
                continue
            if itype and inc.get("type") != itype:
                continue
            if grade and inc.get("grade") != grade:
                continue
            if venue and inc.get("venue", "") != venue:
                continue
            if needle:
                haystack = " ".join([str(inc.get(k, "")) for k in ("account", "name", "target", "process", "event_type")]).lower()
                if needle not in haystack:
                    continue
            items.append(inc)
        items.sort(key=lambda x: (x.get("last_seen", ""), x.get("id", "")), reverse=True)
        unacked = sum(1 for inc in count_base if not inc.get("ack"))
        high = sum(1 for inc in count_base if inc.get("high_risk") and not inc.get("ack"))
        return {"now": utc_now(), "venue": venue or self.venue, "venues": sorted({str(v.get("venue", "")) for v in self.accounts.values()}),
                "total": len(self.incidents), "unacked": unacked, "high_risk_unacked": high,
                "items": items}

    def ack_incident(self, incident_id: str, acked: bool) -> bool:
        with self.lock:
            inc = self.incidents.get(incident_id)
            if inc is None:
                return False
            inc["ack"] = bool(acked)
            inc["acked_at"] = utc_now() if acked else None
            self.dirty = True
            return True

    def export_csv(self, itype: str = "", grade: str = "", include_acked: bool = True, venue: str = "") -> bytes:
        query = self.incidents_query(itype=itype, grade=grade, include_acked=include_acked, venue=venue)
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\r\n")
        writer.writerow(["id", "账号", "姓名", "场地", "类型", "事件类型", "目标", "进程", "等级",
                         "高危标记", "次数", "首次", "最近", "已确认", "确认时间"])
        for inc in query["items"]:
            writer.writerow([
                inc.get("id", ""), inc.get("account", ""), inc.get("name", ""), inc.get("venue", ""),
                inc.get("type", ""), inc.get("event_type", ""), inc.get("target", ""), inc.get("process", ""),
                inc.get("grade", ""), ";".join(inc.get("high_risk", [])), inc.get("count", 0),
                inc.get("first_seen", ""), inc.get("last_seen", ""),
                "是" if inc.get("ack") else "否", inc.get("acked_at") or "",
            ])
        return b"\xef\xbb\xbf" + buf.getvalue().encode("utf-8")


def utc_iso(epoch: float) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------- web layer

LOGIN_PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 - 赛场采集看板</title>
<style>body{font-family:"Segoe UI",system-ui,sans-serif;background:#1f2d3d;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#fff;padding:32px 36px;border-radius:10px;width:300px;box-shadow:0 8px 30px rgba(0,0,0,.3)}
h1{font-size:17px;margin:0 0 18px;text-align:center}
input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #cbd5e1;border-radius:6px;font-size:14px}
button{width:100%;margin-top:12px;padding:9px;background:#2563eb;color:#fff;border:0;border-radius:6px;font-size:14px;cursor:pointer}
.err{color:#b91c1c;font-size:12px;margin-top:10px;text-align:center;min-height:14px}
</style></head><body><div class="box"><h1>赛场采集看板</h1>
<form method="post" action="/login"><input type="password" name="password" placeholder="访问口令" autofocus>
<button type="submit">登录</button><div class="err">__ERROR__</div></form></div></body></html>"""

DASHBOARD_PAGE = """<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>__TITLE__</title>
<style>
body{font-family:"Segoe UI",system-ui,sans-serif;margin:0;background:#f5f6f8;color:#1c2733}
header{display:flex;align-items:center;gap:16px;padding:10px 20px;background:#1f2d3d;color:#fff}
header h1{font-size:17px;margin:0;flex:1}
#conn{font-size:12px;opacity:.8}
main{padding:14px 20px;max-width:1500px;margin:0 auto}
#cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}
.card{background:#fff;border-radius:8px;padding:10px 16px;min-width:104px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card .num{font-size:24px;font-weight:600}
.card .lbl{font-size:12px;color:#5a6b7b}
.st-online{color:#1a7f37}.st-late{color:#b45309}.st-offline{color:#6b7280}.st-stopped{color:#b91c1c}.st-key_error{color:#b91c1c}.st-never{color:#9ca3af}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:18px}
th,td{padding:7px 10px;border-bottom:1px solid #e5e9ef;font-size:13px;text-align:left}
th{background:#eef1f5;font-size:12px;white-space:nowrap}
td.wrap{white-space:normal;word-break:break-all}
tr:hover td{background:#f8fafc}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;white-space:nowrap}
.b-high{background:#fee2e2;color:#b91c1c}.b-info{background:#dbeafe;color:#1e40af}
.b-warn{background:#fef3c7;color:#92400e}.b-grade-i{background:#dcfce7;color:#166534}
.b-grade-s{background:#e0e7ff;color:#3730a3}.b-grade-u{background:#f3f4f6;color:#4b5563}
.toolbar{display:flex;gap:8px;align-items:center;margin:8px 0;flex-wrap:wrap}
input,select,button{padding:5px 9px;border:1px solid #cbd5e1;border-radius:6px;font-size:13px}
button{cursor:pointer;background:#fff}
button.primary{background:#2563eb;color:#fff;border-color:#2563eb}
h2{font-size:15px;margin:16px 0 4px}
details{margin:0}
details pre{white-space:pre-wrap;word-break:break-all;font-size:11px;background:#f1f5f9;padding:6px;border-radius:6px;max-height:220px;overflow:auto;margin:4px 0}
.muted{color:#9ca3af}
.policy-msg{font-size:13px}
.policy-msg.ok{color:#166534}.policy-msg.err{color:#b91c1c}
</style></head><body>
<header><h1>__TITLE__</h1><span id="conn"></span><button onclick="location='/logout'">退出登录</button></header>
<main>
<div id="cards"></div>
<h2>策略热更新</h2>
<div class="toolbar">
<input type="file" id="policy_file" accept=".json,application/json" hidden>
<button class="primary" onclick="$('policy_file').click()">选择 policy.json</button>
<span id="policy_msg" class="policy-msg muted">选择文件后立即导入，无需重启采集器</span>
</div>
<h2>连接状态</h2>
<div class="toolbar"><select id="f_venue" title="场地"><option value="">全部场地</option></select>
<input id="q1" placeholder="搜索 账号/姓名/IP/主机名" style="min-width:230px">
<label><input type="checkbox" id="onlybad1"> 只看异常</label></div>
<table id="t_status"><thead><tr><th>状态</th><th>账号</th><th>姓名</th><th>场地</th><th>最近报数</th><th>来源 IP</th><th>主机名</th><th>guard</th><th>重启次数</th><th>机器数</th><th>备注</th></tr></thead><tbody></tbody></table>
<h2>事件（未加白名单的 DNS / 未关联的公网 TCP）</h2>
<div class="toolbar">
<select id="f_type"><option value="">全部类型</option><option value="dns">DNS</option><option value="tcp">TCP</option><option value="health">健康</option></select>
<select id="f_grade"><option value="">全部等级</option><option value="interactive">interactive</option><option value="system">system</option><option value="unknown">unknown</option></select>
<label><input type="checkbox" id="f_acked"> 含已确认</label>
<input id="q2" placeholder="搜索 账号/目标/进程" style="min-width:200px">
<button class="primary" onclick="exportCsv()">导出 CSV</button>
<span id="inc_summary" class="muted"></span></div>
<table id="t_inc"><thead><tr><th>确认</th><th>账号</th><th>姓名</th><th>类型</th><th>目标</th><th>进程</th><th>等级</th><th>高危</th><th>次数</th><th>首次</th><th>最近</th><th>原始事件</th></tr></thead><tbody></tbody></table>
<h2>健康异常</h2>
<table id="t_health"><thead><tr><th>级别</th><th>类型</th><th>账号</th><th>说明</th></tr></thead><tbody></tbody></table>
</main>
<script>
"use strict";
const $=id=>document.getElementById(id);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const fmtT=s=>{if(!s)return"—";const d=new Date(s);if(isNaN(d))return String(s).replace("T"," ").slice(0,19);const p=n=>String(n).padStart(2,"0");return d.getFullYear()+"-"+p(d.getMonth()+1)+"-"+p(d.getDate())+" "+p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds())};
const ST_LABEL={online:"在线",late:"迟到",offline:"离线",stopped:"已停止",key_error:"密钥异常",never:"从未报数"};
async function jget(u){const r=await fetch(u,{cache:"no-store"});if(r.status===401){location="/login";throw new Error("unauthorized")}if(!r.ok)throw new Error(r.status);return r.json()}
function badge(text,cls){return '<span class="badge '+cls+'">'+esc(text)+"</span>"}
function stBadge(s){return badge(ST_LABEL[s]||s,"st-"+s)}
function renderCards(st){const c=st.counts||{};const inc=INC||{};const cards=[
 {lbl:"在线",num:c.online||0,cls:"st-online"},{lbl:"迟到",num:c.late||0,cls:"st-late"},
 {lbl:"离线",num:c.offline||0,cls:"st-offline"},{lbl:"已停止",num:c.stopped||0,cls:"st-stopped"},
 {lbl:"密钥异常",num:c.key_error||0,cls:"st-key_error"},{lbl:"从未报数",num:c.never||0,cls:"st-never"},
 {lbl:"未确认事件",num:inc.unacked||0,cls:"st-late"},{lbl:"高危未确认",num:inc.high_risk_unacked||0,cls:"st-stopped"}];
 $("cards").innerHTML=cards.map(x=>'<div class="card"><div class="num '+x.cls+'">'+x.num+'</div><div class="lbl">'+x.lbl+"</div></div>").join("")}
function renderStatus(){const q=($("q1").value||"").toLowerCase();const bad=$("onlybad1").checked;const tb=$("t_status").querySelector("tbody");let rows=(STATUS&&STATUS.accounts)||[];
 if(q)rows=rows.filter(r=>(r.account+" "+r.name+" "+r.venue+" "+(r.machines||[]).map(m=>(m.ip||"")+" "+(m.hostname||"")).join(" ")).toLowerCase().includes(q));
 if(bad)rows=rows.filter(r=>["late","offline","stopped","key_error"].includes(r.status)||r.multi_machine||r.key_conflict);
 tb.innerHTML=rows.map(r=>{const m=(r.machines&&r.machines[0])||{};const notes=[];if(r.multi_machine)notes.push(badge("多机","b-info"));if(r.key_conflict)notes.push(badge("机器号冲突","b-high"));
  return "<tr><td>"+stBadge(r.status)+"</td><td>"+esc(r.account)+"</td><td>"+esc(r.name)+"</td><td>"+esc(r.venue)+"</td><td>"+fmtT(r.last_seen)+"</td><td>"+esc(m.ip||"—")+"</td><td>"+esc(m.hostname||"—")+"</td><td>"+(m.guard===true?"是":m.guard===false?badge("否","b-high"):"—")+"</td><td>"+esc(m.guard_restarts??"—")+"</td><td>"+(r.machine_ids||[]).length+"</td><td>"+notes.join(" ")+"</td></tr>"}).join("")||'<tr><td colspan="11" class="muted">暂无数据</td></tr>'}
function renderInc(){const tb=$("t_inc").querySelector("tbody");let rows=(INC&&INC.items)||[];
 tb.innerHTML=rows.map(r=>{const hr=(r.high_risk||[]).map(f=>badge(f,"b-high")).join(" ");
  const raw=(r.events||[]).map(e=>esc(JSON.stringify(e))).join("\\n");
  return "<tr><td><input type=\\"checkbox\\" "+(r.ack?"checked":"")+" onchange=\\"ackInc('"+r.id+"',this.checked)\\"></td><td>"+esc(r.account)+"</td><td>"+esc(r.name)+"</td><td>"+esc(r.type)+"</td><td class=\\"wrap\\">"+esc(r.target)+"</td><td>"+esc(r.process)+"</td><td>"+badge(r.grade,"b-grade-"+(r.grade||"u")[0])+"</td><td>"+hr+"</td><td>"+r.count+"</td><td>"+fmtT(r.first_seen)+"</td><td>"+fmtT(r.last_seen)+"</td><td><details"+(OPEN_RAW.has(r.id)?" open":"")+" ontoggle=\\"this.open?OPEN_RAW.add('"+r.id+"'):OPEN_RAW.delete('"+r.id+"')\\"><summary>"+(r.events||[]).length+" 条</summary><pre>"+raw+"</pre></details></td></tr>"}).join("")||'<tr><td colspan="12" class="muted">暂无事件</td></tr>';
 $("inc_summary").textContent="共 "+(INC?INC.total:0)+" 条，未确认 "+(INC?INC.unacked:0)+" 条"}
function renderHealth(){const tb=$("t_health").querySelector("tbody");const rows=(STATUS&&STATUS.health)||[];
 tb.innerHTML=rows.map(r=>"<tr><td>"+badge(r.level==="info"?"提示":"警告",r.level==="info"?"b-info":"b-warn")+"</td><td>"+esc(r.kind)+"</td><td>"+esc(r.account)+"</td><td class=\\"wrap\\">"+esc(r.detail)+"</td></tr>").join("")||'<tr><td colspan="4" class="muted">无异常</td></tr>'}
async function ackInc(id,checked){try{await fetch("/api/incidents/"+id+"/ack",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ack:checked})})}catch(e){}poll()}
async function importPolicy(file){
 const msg=$("policy_msg");msg.className="policy-msg muted";msg.textContent="导入中…";
 try{
  const text=await file.text();
  const r=await fetch("/api/policy/import",{method:"POST",headers:{"Content-Type":"application/json"},body:text});
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(data.error||("HTTP "+r.status));
  msg.className="policy-msg ok";
  msg.textContent="已导入 policy v"+data.version+"，已重算 "+data.incidents_regraded+" 条现有事件";
 }catch(e){msg.className="policy-msg err";msg.textContent="导入失败："+e.message}
}
function incParams(){const p=new URLSearchParams();if($("f_venue").value)p.set("venue",$("f_venue").value);if($("f_type").value)p.set("type",$("f_type").value);if($("f_grade").value)p.set("grade",$("f_grade").value);p.set("include_acked",$("f_acked").checked?"1":"0");return p}
function exportCsv(){const p=incParams();p.set("q",$("q2").value);window.open("/api/export.csv?"+p.toString())}
function syncVenues(){const wanted=new Set();for(const r of((STATUS&&STATUS.venues)||[]))wanted.add(String(r));for(const r of((STATUS&&STATUS.accounts)||[]))if(r.venue)wanted.add(String(r.venue));for(const r of((INC&&INC.venues)||[]))wanted.add(String(r));const sel=$("f_venue");const current=sel.value;const desired=["",...[...wanted].sort()];if(sel.options.length!==desired.length||[...sel.options].some((o,i)=>o.value!==desired[i])){sel.innerHTML="";for(const v of desired){const o=document.createElement("option");o.value=v;o.textContent=v?esc(v):"全部场地";sel.appendChild(o)}}sel.value=current;saveFilters()}
const FILTER_IDS=["f_venue","f_type","f_grade","f_acked","q1","onlybad1","q2"];
const FILTER_KEY="nl_dashboard_filters_v1";
function saveFilters(){try{const data={};for(const id of FILTER_IDS){const el=$(id);data[id]=el.type==="checkbox"?el.checked:el.value}localStorage.setItem(FILTER_KEY,JSON.stringify(data))}catch(e){}}
function restoreFilters(){try{const raw=localStorage.getItem(FILTER_KEY);if(!raw)return;const data=JSON.parse(raw);for(const id of FILTER_IDS){const el=$(id);if(!(id in data))continue;if(el.type==="checkbox")el.checked=!!data[id];else el.value=String(data[id]||"")}}catch(e){}}
let STATUS=null,INC=null;const OPEN_RAW=new Set();
async function poll(){try{const p=incParams();const sp=new URLSearchParams();if($("f_venue").value)sp.set("venue",$("f_venue").value);const[s,i]=await Promise.all([jget("/api/status?"+sp.toString()),jget("/api/incidents?"+p.toString())]);STATUS=s;INC=i;
 syncVenues();renderCards(s);renderStatus();renderInc();renderHealth();
 $("conn").textContent="已连接 · 更新于 "+new Date().toLocaleTimeString()}catch(e){$("conn").textContent="连接失败，重试中…"}}
["f_venue","f_type","f_grade","f_acked"].forEach(id=>$(id).addEventListener("change",()=>{saveFilters();poll()}));
["q1","onlybad1"].forEach(id=>$(id).addEventListener("input",()=>{saveFilters();renderStatus()}));
$("q2").addEventListener("input",()=>{clearTimeout(window.__qt);window.__qt=setTimeout(()=>{saveFilters();poll()},400)});
$("policy_file").addEventListener("change",e=>{const file=e.target.files[0];if(file)importPolicy(file);e.target.value=""});
window.addEventListener("beforeunload",saveFilters);
restoreFilters();
window.addEventListener("beforeunload",saveFilters);
restoreFilters();
setInterval(poll,2000);poll();
</script></body></html>"""


class CollectorHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, store: Store, https: bool):
        super().__init__(addr, handler)
        self.store = store
        self.https = https
        self.sessions: Dict[str, float] = {}
        self.login_fails: Dict[str, Dict[str, float]] = {}
        self.dashboard_file = store.base / "dashboard.json"


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NLCollector/" + VERSION

    # ---------- plumbing ----------

    def log_message(self, fmt, *args):  # quiet default access log
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: Optional[List[Tuple[str, str]]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(self, obj: Any, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _redirect(self, location: str, cookie: Optional[str] = None) -> None:
        extra = [("Location", location)]
        if cookie:
            extra.append(("Set-Cookie", cookie))
        self._send(303, b"", "text/plain; charset=utf-8", extra)

    def _cookie_token(self) -> str:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == "NLSESS":
                    return v.strip()
        return ""

    def _authed(self) -> bool:
        srv = self.server  # type: CollectorHTTPServer
        token = self._cookie_token()
        if not token:
            return False
        expiry = srv.sessions.get(token)
        if not expiry or expiry < time.time():
            srv.sessions.pop(token, None)
            return False
        return True

    def _client_ip(self) -> str:
        return self.client_address[0]

    # ---------- password ----------

    @staticmethod
    def hash_password(password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
        return "pbkdf2_sha256$200000$%s$%s" % (salt.hex(), digest.hex())

    @staticmethod
    def check_password(password: str, stored: str) -> bool:
        try:
            algo, iters, salt_hex, hash_hex = stored.split("$")
            if algo != "pbkdf2_sha256":
                return False
            digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iters))
            return hmac.compare_digest(digest.hex(), hash_hex)
        except (ValueError, TypeError):
            return False

    def ensure_password(self) -> Tuple[str, bool]:
        """Returns (stored_hash, generated_now). Creates a random password on first run."""
        srv = self.server  # type: CollectorHTTPServer
        data = read_json(srv.dashboard_file, {})
        if not isinstance(data, dict):
            data = {}
        # A provision host without SHA256 PBKDF2 (.NET < 4.7.2) leaves the plain
        # password in "password_pending"; hash it on first collector start.
        pending = str(data.get("password_pending", ""))
        if pending:
            stored = self.hash_password(pending)
            data.pop("password_pending", None)
            data["password_hash"] = stored
            data["password_updated_at"] = utc_now()
            atomic_json(srv.dashboard_file, data)
            log("已将发放包预置的看板口令完成哈希写入 dashboard.json")
            return stored, False
        stored = str(data.get("password_hash", ""))
        if stored:
            return stored, False
        alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
        password = "".join(secrets.choice(alphabet) for _ in range(10))
        stored = self.hash_password(password)
        atomic_json(srv.dashboard_file, {"password_hash": stored, "password_updated_at": utc_now()})
        log(f"首次运行已生成看板口令：{password}（已写入 dashboard.json，请立即记录并转告监考老师）")
        return stored, True

    # ---------- routes ----------

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        srv = self.server  # type: CollectorHTTPServer
        if path == "/login":
            error = "口令不正确，请重试" if "error=1" in (parsed.query or "") else ""
            body = LOGIN_PAGE.replace("__ERROR__", error).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path == "/logout":
            self._redirect("/login", "NLSESS=; HttpOnly; Path=/; Max-Age=0")
            return
        if path == "/":
            if not self._authed():
                self._redirect("/login")
                return
            store = srv.store
            title = f"赛场采集看板{(' · ' + store.venue) if store.venue else ''}"
            body = DASHBOARD_PAGE.replace("__TITLE__", title).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path.startswith("/api/"):
            if not self._authed():
                self._send_json({"error": "unauthorized"}, 401)
                return
            store = srv.store
            query = urllib.parse.parse_qs(parsed.query)
            if path == "/api/status":
                self._send_json(store.account_status(
                    venue=(query.get("venue", [""])[0]),
                ))
            elif path == "/api/incidents":
                self._send_json(store.incidents_query(
                    itype=(query.get("type", [""])[0]),
                    grade=(query.get("grade", [""])[0]),
                    include_acked=(query.get("include_acked", ["0"])[0] == "1"),
                    search=(query.get("q", [""])[0]),
                    venue=(query.get("venue", [""])[0]),
                ))
            elif path == "/api/export.csv":
                data = store.export_csv(
                    itype=(query.get("type", [""])[0]),
                    grade=(query.get("grade", [""])[0]),
                    include_acked=(query.get("include_acked", ["1"])[0] == "1"),
                    venue=(query.get("venue", [""])[0]),
                )
                self._send(200, data, "text/csv; charset=utf-8",
                           [("Content-Disposition", "attachment; filename=incidents.csv")])
            elif path == "/api/roster":
                self._send_json({"roster": list(store.roster.values()), "accounts": store.accounts})
            elif path == "/api/policy":
                self._send_json(store.policy)
            else:
                self._send_json({"error": "not_found"}, 404)
            return
        self._send_json({"error": "not_found"}, 404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        srv = self.server  # type: CollectorHTTPServer
        if path == "/login":
            length = int(self.headers.get("Content-Length", 0) or 0)
            form = urllib.parse.parse_qs(self.rfile.read(min(length, 8192)).decode("utf-8", "replace"))
            password = (form.get("password", [""])[0] or "").strip()
            ip = self._client_ip()
            fails = srv.login_fails.setdefault(ip, {"count": 0, "locked_until": 0.0})
            now = time.time()
            if now < fails["locked_until"]:
                retry = int(fails["locked_until"] - now) + 1
                self._send(429, f"尝试过于频繁，请 {retry} 秒后重试".encode("utf-8"), "text/plain; charset=utf-8")
                return
            stored, _ = self.ensure_password()
            if self.check_password(password, stored):
                srv.login_fails.pop(ip, None)
                token = secrets.token_urlsafe(32)
                srv.sessions[token] = time.time() + SESSION_TTL
                for t in [t for t, exp in srv.sessions.items() if exp < now]:
                    srv.sessions.pop(t, None)
                cookie = "NLSESS=%s; HttpOnly; Path=/; Max-Age=%d; SameSite=Strict" % (token, SESSION_TTL)
                if srv.https:
                    cookie += "; Secure"
                self._redirect("/", cookie)
            else:
                fails["count"] = int(fails["count"]) + 1
                if fails["count"] >= LOGIN_MAX_FAILS:
                    fails["locked_until"] = now + LOGIN_LOCK_SECONDS
                    fails["count"] = 0
                    log(f"IP {ip} 连续登录失败 {LOGIN_MAX_FAILS} 次，锁定 {LOGIN_LOCK_SECONDS} 秒")
                self._redirect("/login?error=1")
            return
        if path.startswith("/api/incidents/") and path.endswith("/ack"):
            if not self._authed():
                self._send_json({"error": "unauthorized"}, 401)
                return
            iid = path[len("/api/incidents/"):-len("/ack")]
            length = int(self.headers.get("Content-Length", 0) or 0)
            try:
                body = json.loads(self.rfile.read(min(length, 4096)).decode("utf-8") or "{}")
            except ValueError:
                body = {}
            acked = bool(body.get("ack", True))
            if srv.store.ack_incident(iid, acked):
                self._send_json({"ok": True, "id": iid, "ack": acked})
            else:
                self._send_json({"error": "not_found"}, 404)
            return
        if path == "/api/policy/import":
            if not self._authed():
                self._send_json({"error": "unauthorized"}, 401)
                return
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length <= 0 or length > 1024 * 1024:
                self._send_json({"error": "policy_file_too_large"}, 413)
                return
            try:
                policy = json.loads(self.rfile.read(length).decode("utf-8", "strict"))
                normalized, regraded = srv.store.update_policy(policy)
            except (UnicodeDecodeError, ValueError) as exc:
                self._send_json({"error": "invalid_policy", "detail": str(exc)}, 400)
                return
            self._send_json({
                "ok": True,
                "version": normalized.get("version", 1),
                "updated_at": normalized.get("updated_at", ""),
                "incidents_regraded": regraded,
            })
            return
        self._send_json({"error": "not_found"}, 404)


# ---------------------------------------------------------------- servers

def try_generate_cert(cert_dir: Path) -> bool:
    """Best-effort self-signed cert via openssl on PATH (stdlib cannot sign X.509)."""
    cert, key = cert_dir / "server.crt", cert_dir / "server.key"
    if cert.exists() and key.exists():
        return True
    exe = None
    for candidate in ("openssl.exe", "openssl"):
        try:
            probe = subprocess.run([candidate, "version"], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=10)
            if probe.returncode == 0:
                exe = candidate
                break
        except (OSError, subprocess.SubprocessError):
            continue
    if not exe:
        return False
    cert_dir.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825",
           "-subj", "/CN=contest-collector", "-keyout", str(key), "-out", str(cert)]
    try:
        cp = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        return cp.returncode == 0 and cert.exists() and key.exists()
    except (OSError, subprocess.SubprocessError):
        return False


def udp_loop(host: str, port: int, store: Store, secrets_map: Dict[str, str], stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    sock.bind((host, port))
    sock.settimeout(1.0)
    log(f"UDP 采集端口已监听: {host}:{port}（{len(secrets_map)} 台机器的密钥）")
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        payload, err = verify_packet(data, secrets_map)
        if err:
            store.record_verify_error(err, data, addr)
            continue
        try:
            store.record(payload, addr, time.time())
        except Exception as exc:  # one bad packet must not kill the loop
            log(f"处理包异常：{type(exc).__name__}: {exc}")


def acquire_mutex(name: str) -> Optional[int]:
    """Single instance via named mutex (Windows). None means another instance runs."""
    if os.name != "nt":
        return 1
    try:
        import ctypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.CreateMutexW(None, False, name)
        if not handle:
            return 1
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return None
        return handle
    except Exception:
        return 1


def acquire_lock(run_dir: Path, port: int) -> Optional[Any]:
    """Single instance across platforms (v1.5: the collector runs on Linux too).

    Windows: named mutex Local\\NLCollector_<port>. POSIX: an exclusive non-blocking
    flock on <run_dir>/.collector.lock; the file object must stay referenced for the
    process lifetime, so the handle is returned and held by the caller.
    Returns None when another instance already holds the lock.
    """
    if os.name == "nt":
        return acquire_mutex("Local\\NLCollector_%d" % port)
    try:
        import fcntl
        run_dir.mkdir(parents=True, exist_ok=True)
        lock_path = run_dir / ".collector.lock"
        f = open(lock_path, "w")
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            return None
        f.seek(0)
        f.truncate()
        f.write(str(os.getpid()) + "\n")
        f.flush()
        return f
    except Exception:
        return 1  # lock mechanism unavailable; do not block startup on it


def start_web(store: Store, web_port: int, http_port: int) -> List[Tuple[CollectorHTTPServer, str]]:
    servers: List[Tuple[CollectorHTTPServer, str]] = []
    cert_dir = store.base / "certs"
    have_cert = try_generate_cert(cert_dir)
    if have_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(str(cert_dir / "server.crt"), str(cert_dir / "server.key"))
        srv = CollectorHTTPServer(("0.0.0.0", web_port), Handler, store, https=True)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append((srv, f"https://0.0.0.0:{web_port}（自签名证书，浏览器需选择“继续访问”）"))
        log(f"看板已监听: https://0.0.0.0:{web_port}")
    else:
        log("未找到 certs/server.crt 且无法生成自签名证书（需要 openssl），看板退回 HTTP 模式")
    http_port_eff = http_port if http_port > 0 else (0 if have_cert else DEFAULT_HTTP_PORT)
    if http_port_eff > 0:
        srv = CollectorHTTPServer(("0.0.0.0", http_port_eff), Handler, store, https=False)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append((srv, f"http://0.0.0.0:{http_port_eff}"))
        log(f"看板已监听: http://0.0.0.0:{http_port_eff}（明文，仅限应急）")
    if not servers:
        raise RuntimeError("看板未能监听任何端口")
    return servers


# ---------------------------------------------------------------- self-test

def self_test() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        roster = [
            {"account": "stu001", "name": "张三", "venue": "A", "machine_id": "m1111111111"},
            {"account": "stu002", "name": "李四", "venue": "A", "machine_id": "m2222222222"},
            {"account": "stu003", "name": "王五", "venue": "B", "machine_id": "m3333333333"},
        ]
        secrets_map = {"m1111111111": secrets.token_urlsafe(45), "m2222222222": secrets.token_urlsafe(45),
                       "m3333333333": secrets.token_urlsafe(45)}
        atomic_json(base / "roster.json", roster)
        atomic_json(base / "secrets.json", secrets_map)
        store = Store(base, retain_days=7, venue="A")

        def pkt(machine, itype, fields, seq=1):
            return make_signed({"schema": 1, "machine": machine, "session": "s1", "seq": seq,
                                "time": utc_now(), "type": itype, **fields}, secrets_map[machine])

        # 1. valid packet verifies
        payload, err = verify_packet(pkt("m1111111111", "heartbeat", {"hb_seconds": 15}), secrets_map)
        assert err is None and payload["type"] == "heartbeat", err
        # 2. tampered hmac rejected
        bad = bytearray(pkt("m1111111111", "heartbeat", {}))
        bad[-4] = ord("0") if bad[-4] != ord("0") else ord("1")
        _, err = verify_packet(bytes(bad), secrets_map)
        assert err == "hmac_fail", err
        # 3. unknown machine rejected
        unknown = make_signed({"schema": 1, "machine": "m9999999999", "session": "s1", "seq": 1,
                               "time": utc_now(), "type": "heartbeat"}, "some-other-secret")
        _, err = verify_packet(unknown, secrets_map)
        assert err == "unknown_machine", err
        # 4. heartbeat updates machine, never written to JSONL
        store.record(payload, ("10.1.1.1", 1111), time.time())
        assert store.machines["m1111111111"]["last_ip"] == "10.1.1.1"
        # 5. DNS incident aggregation
        for i in range(3):
            p, _ = verify_packet(pkt("m1111111111", "dns_unlisted", {"domain": "evil.top", "process": "chrome.exe"}, seq=10 + i), secrets_map)
            store.record(p, ("10.1.1.1", 1111), time.time())
        incs = store.incidents_query()
        assert len(incs["items"]) == 1 and incs["items"][0]["count"] == 3, incs
        assert incs["items"][0]["grade"] == "interactive"
        assert "suspicious_tld" in incs["items"][0]["high_risk"]
        # 6. TCP incident with nonstandard port
        p, _ = verify_packet(pkt("m2222222222", "tcp_unmapped_ip", {"remote_ip": "1.2.3.4", "remote_port": "8443", "process": "game.exe"}, seq=5), secrets_map)
        store.record(p, ("10.1.1.2", 1112), time.time())
        incs = store.incidents_query(itype="tcp")
        assert len(incs["items"]) == 1 and "nonstandard_port" in incs["items"][0]["high_risk"]
        # 7. venue filter: venue B machine rejected when collector is venue A
        p, _ = verify_packet(pkt("m3333333333", "dns_unlisted", {"domain": "x.com", "process": "chrome.exe"}, seq=1), secrets_map)
        store.record(p, ("10.1.1.3", 1113), time.time())
        assert "m3333333333" not in store.machines
        # 8. key_conflict: same machine from 2 IPs within window
        p, _ = verify_packet(pkt("m2222222222", "heartbeat", {}, seq=6), secrets_map)
        store.record(p, ("10.9.9.9", 1112), time.time())
        assert store.machines["m2222222222"].get("key_conflict") is True
        # 9. status thresholds
        store.machines["m1111111111"]["last_seen"] = time.time() - 10
        store.machines["m2222222222"]["last_seen"] = time.time() - 60
        status = store.account_status()
        by_account = {r["account"]: r for r in status["accounts"]}
        assert by_account["stu001"]["status"] == "online"
        assert by_account["stu002"]["status"] == "late"
        assert by_account["stu003"]["status"] == "never"
        assert by_account["stu002"]["key_conflict"] is True
        # 10. ack + export
        iid = incs["items"][0]["id"]
        assert store.ack_incident(iid, True)
        assert all(inc["id"] != iid for inc in store.incidents_query(include_acked=False)["items"])
        assert any(inc["id"] == iid for inc in store.incidents_query(include_acked=True)["items"])
        csv_bytes = store.export_csv()
        assert csv_bytes.startswith(b"\xef\xbb\xbf") and "stu002".encode() in csv_bytes
        # policy hot update persists and regrades existing incidents immediately
        tcp_item = next(i for i in store.incidents.values() if i["type"] == "tcp")
        policy, regraded = store.update_policy({
            "version": 2,
            "allowed_domains": [],
            "ignored_domains": [],
            "ignored_processes": [],
            "ignored_ips": [],
            "process_grades": {"interactive": ["chrome.exe"], "system": ["game.exe"]},
            "high_risk": {"flag_direct_ip": False, "flag_nonstandard_port": False,
                          "suspicious_tlds": ["evil"]},
        })
        assert policy["version"] == 2 and regraded > 0
        assert tcp_item["grade"] == "system"
        assert "nonstandard_port" not in tcp_item["high_risk"]
        # 11. retention sweep drops old incidents
        old_id = list(store.incidents)[0]
        store.incidents[old_id]["last_seen"] = "2020-01-01T00:00:00.000Z"
        store.sweep_retention()
        assert old_id not in store.incidents
        # 12. state round-trip
        store.save_state(force=True)
        store2 = Store(base, retain_days=7, venue="A")
        assert store2.policy["version"] == 2
        assert "m1111111111" in store2.machines
        store_all = Store(base, retain_days=7, venue="")
        assert len(store_all.account_status()["accounts"]) == 3
        assert len(store_all.account_status(venue="A")["accounts"]) == 2
        assert len(store_all.account_status(venue="B")["accounts"]) == 1
    print("self-test OK")
    return 0


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description="赛场 DNS 采集器（UDP + HMAC + 看板）")
    ap.add_argument("--dir", default="", help="数据目录（默认 collector.py 所在目录）")
    ap.add_argument("--host", default="0.0.0.0", help="UDP 监听地址")
    ap.add_argument("--port", type=int, default=DEFAULT_UDP_PORT, help="UDP 采集端口（默认 48123）")
    ap.add_argument("--web-port", type=int, default=DEFAULT_WEB_PORT, help="看板 HTTPS 端口（默认 8443）")
    ap.add_argument("--http-port", type=int, default=0, help="额外明文 HTTP 端口（0=仅 HTTPS 不可用时退回 8080）")
    ap.add_argument("--venue", default="", help="只接受该场地名册中的机器（D36）")
    ap.add_argument("--retain-days", type=int, default=7, help="日志/事件保留天数（默认 7）")
    ap.add_argument("--genkey", type=int, default=0, metavar="N", help="生成 N 个随机密钥后退出")
    ap.add_argument("--reset-password", action="store_true", help="重置看板口令为新的随机口令")
    ap.add_argument("--self-test", action="store_true", help="运行内置自检后退出")
    args = ap.parse_args()
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if args.genkey > 0:
        for _ in range(args.genkey):
            print(secrets.token_urlsafe(45))
        return 0
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
    else:
        base = Path(__file__).resolve().parent
    run_dir = Path(args.dir).resolve() if args.dir else base
    run_dir.mkdir(parents=True, exist_ok=True)

    if args.self_test:
        return self_test()

    if args.reset_password:
        dashboard = run_dir / "dashboard.json"
        alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
        password = "".join(secrets.choice(alphabet) for _ in range(10))
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
        atomic_json(dashboard, {"password_hash": "pbkdf2_sha256$200000$%s$%s" % (salt.hex(), digest.hex()),
                                "password_updated_at": utc_now()})
        log(f"看板口令已重置为：{password}（请立即记录）")
        return 0

    lock = acquire_lock(run_dir, args.port)
    if lock is None:
        log("collector 已有实例在运行（单实例锁已存在），本次退出")
        return 0

    secrets_map = read_json(run_dir / "secrets.json", {})
    if not isinstance(secrets_map, dict):
        secrets_map = {}
    secrets_map = {str(k): str(v) for k, v in secrets_map.items() if k != "*" and v}
    if not secrets_map:
        log(f"警告：{run_dir / 'secrets.json'} 为空或不存在，所有包都会因 unknown_machine 被拒绝")

    store = Store(run_dir, retain_days=args.retain_days, venue=args.venue)
    stop = threading.Event()
    udp_thread = threading.Thread(target=udp_loop, args=(args.host, args.port, store, secrets_map, stop), daemon=True)
    udp_thread.start()
    web_servers = start_web(store, args.web_port, args.http_port)

    log(f"collector v{VERSION} 运行中：dir={run_dir} venue={args.venue or '(全部)'} retain={args.retain_days}d")
    log("看板入口：" + "；".join(desc for _, desc in web_servers))
    try:
        while True:
            time.sleep(10)
            store.save_state()
            if time.time() - store.last_sweep > 300:
                store.sweep_retention()
    except KeyboardInterrupt:
        log("收到停止请求，保存状态后退出")
        store.save_state(force=True)
        stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
