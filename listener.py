#!/usr/bin/env python3
"""Visible DNS Client Operational log monitor. Standard library only."""
import argparse
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

CHANNEL = "Microsoft-Windows-DNS-Client/Operational"
DEFAULT_CONFIG = "config.json"
SYSTEM_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32"}
VERSION = "1.5"
GUARD_SCRIPT = "guard.py"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# QueryStatus 87 (0x57 = ERROR_INVALID_PARAMETER) comes from the local resolver
# rejecting its own parameters; it is not a blocked or denied lookup and must not
# be used to claim a domain was interfered with.
RESOLVER_ERROR_STATUSES = {"87", "0x57"}

# Default noise filter: Microsoft/Edge/OCSP traffic that has nothing to do with the
# contest. Entries are either exact hosts or "*.suffix" (root + subdomains).
# Deliberately NOT "*.microsoft.com": that would also hide learn./support.microsoft.com.
DEFAULT_IGNORED_DOMAINS = [
    "wpad",
    "*.msedge.net",
    "*.footprintdns.com",
    "*.azurefd.net",
    "go.microsoft.com",
    "www.microsoft.com",
    "edge.microsoft.com",
    "ieonline.microsoft.com",
    "checkappexec.microsoft.com",
    "oneocsp.microsoft.com",
    "crl.microsoft.com",
    "ocsp.digicert.com",
]

# Counters that must add up to events_seen. "failed" is informative (a subset of
# emitted), so it is not part of the reconciliation sum.
STATS_SKIP_KEYS = (
    "allowed",
    "ignored_domain",
    "ignored_process",
    "ignored_ip",
    "ignored_sid",
    "not_fqdn",
    "ignored_failed_dns",
    "resolver_local_error",
)
STATS_KEYS = ("events_seen",) + STATS_SKIP_KEYS + ("emitted", "failed")

# Supported source range: Win7 tops out at CPython 3.8; current Win10/11 images may ship 3.13+.
MIN_PYTHON = (3, 8)
MAX_TESTED = (3, 14)


def check_runtime() -> None:
    """Fail fast with an actionable message instead of an ImportError/SyntaxError."""
    if sys.version_info < MIN_PYTHON:
        raise SystemExit(
            "需要 Python %d.%d 或更高版本；当前为 %s。"
            % (MIN_PYTHON[0], MIN_PYTHON[1], platform.python_version())
        )


def configure_output() -> None:
    """Make console output safe on legacy code pages instead of crashing with UnicodeEncodeError."""
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def utc_now() -> str:
    # datetime.utcnow() is deprecated from 3.12; timezone-aware now() works on 3.8 too.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(message: str) -> None:
    print(f"[{utc_now()}] {message}", flush=True)


def read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            return json.load(f)
    except IOError:
        return default


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(str(path) + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def scratch_dir(prefix: str) -> Path:
    """Create a scratch directory that is proven writable, or raise.

    %TEMP% is normally fine, but a locked-down or sandboxed environment can hand back
    a directory that rejects writes, so fall back to the working directory and probe.
    """
    import tempfile
    candidates: List[Path] = []
    try:
        candidates.append(Path(tempfile.gettempdir()))
    except Exception:
        pass
    candidates.append(Path.cwd())
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if local_appdata:
        candidates.append(Path(local_appdata) / "Temp")
    for base in candidates:
        try:
            path = Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))
        except OSError:
            continue
        try:
            probe = path / ".write-probe"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return path
        except OSError:
            continue
    raise OSError("找不到可写临时目录；请用 --data-dir 指定一个可写目录")


def load_config(path: Path) -> Dict[str, Any]:
    cfg = read_json(path, None)
    if not isinstance(cfg, dict):
        raise ValueError(f"配置文件不存在或不是 JSON 对象: {path}")
    cfg.setdefault("machine_id", socket.gethostname())
    if not str(cfg.get("machine_id", "")).strip():
        cfg["machine_id"] = socket.gethostname()
    cfg.setdefault("collector_host", "")
    cfg.setdefault("collector_port", 48123)
    cfg.setdefault("collector_ip", "")
    cfg.setdefault("collector_resolve_seconds", 300)
    cfg.setdefault("heartbeat_seconds", 15)
    cfg.setdefault("shared_secret", "")
    cfg.setdefault("poll_seconds", 3)
    cfg.setdefault("state_file", "state.json")
    cfg.setdefault("local_log", "alerts.jsonl")
    cfg.setdefault("local_log_max_mb", 16)
    cfg.setdefault("local_log_backups", 5)
    cfg.setdefault("outbox_file", "outbox.jsonl")
    cfg.setdefault("guard_file", "guard.json")
    cfg.setdefault("data_dir", "")
    cfg.setdefault("tcp_watch", {"enabled": False, "interval_seconds": 30, "known_ip_minutes": 30})
    cfg.setdefault("report_failed_dns", True)
    # Local resolver errors (QueryStatus 87) are not evidence of blocking; keep them
    # out of the alert stream unless the operator explicitly asks for them.
    cfg.setdefault("report_resolver_errors", False)
    cfg.setdefault("stats_interval_seconds", 600)
    cfg.setdefault("ignore_system_accounts", True)
    cfg.setdefault("ignored_processes", ["svchost.exe", "services.exe", "System"])
    cfg.setdefault("ignored_domains", list(DEFAULT_IGNORED_DOMAINS))
    cfg.setdefault("ignored_ips", [])
    cfg.setdefault("allowed_domains", [])
    if not 1 <= int(cfg["poll_seconds"]) <= 300:
        raise ValueError("poll_seconds 必须在 1..300 之间")
    if not 1 <= int(cfg["collector_port"]) <= 65535:
        raise ValueError("collector_port 必须在 1..65535 之间")
    if not 5 <= int(cfg["heartbeat_seconds"]) <= 60:
        raise ValueError("heartbeat_seconds 必须在 5..60 之间")
    if not 30 <= int(cfg["collector_resolve_seconds"]) <= 3600:
        raise ValueError("collector_resolve_seconds 必须在 30..3600 之间")
    if not 60 <= int(cfg["stats_interval_seconds"]) <= 3600:
        raise ValueError("stats_interval_seconds 必须在 60..3600 之间")
    if not isinstance(cfg["allowed_domains"], list):
        raise ValueError("allowed_domains 必须是数组")
    if not isinstance(cfg["ignored_domains"], list):
        raise ValueError("ignored_domains 必须是数组")
    if not isinstance(cfg["ignored_processes"], list):
        raise ValueError("ignored_processes 必须是数组")
    if not isinstance(cfg["ignored_ips"], list):
        raise ValueError("ignored_ips 必须是数组")
    return cfg


def norm_domain(name: str) -> str:
    name = name.strip().rstrip(".").lower()
    if not name:
        return ""
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def domain_allowed(host: str, entries: List[str]) -> bool:
    host = norm_domain(host)
    if not host:
        return True
    for item in entries:
        rule = norm_domain(str(item).strip())
        if not rule:
            continue
        suffix = rule[2:] if rule.startswith("*.") else rule
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def domain_in_list(host: str, entries: List[str]) -> bool:
    """Noise-filter match: "*.suffix" covers root+subdomains, plain entries are exact.

    Deliberately stricter than domain_allowed(): an exact host never implied a suffix,
    so a typo cannot silently widen the ignore list.
    """
    host = norm_domain(host)
    if not host:
        return False
    for item in entries:
        rule = str(item).strip().lower().rstrip(".")
        if not rule:
            continue
        if rule.startswith("*."):
            suffix = norm_domain(rule[2:])
            if suffix and (host == suffix or host.endswith("." + suffix)):
                return True
        elif host == norm_domain(rule):
            return True
    return False


def is_global_ip(text: str) -> bool:
    """True only for globally routable addresses; loopback/link-local/private are noise."""
    raw = text.strip()
    if raw.lower().startswith("::ffff:"):
        raw = raw[7:]
    try:
        ip = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    # is_private also covers private IPv4 ranges and unique-local IPv6 on modern Pythons.
    return not ip.is_private


def parse_event_epoch(value: str) -> Optional[float]:
    """Parse an event SystemTime (UTC) into epoch seconds; None when unparsable."""
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def list_hash(entries: List[str]) -> str:
    items = sorted({str(x).strip().lower() for x in entries if str(x).strip()})
    return hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()[:16]


def config_hash(cfg: Dict[str, Any]) -> str:
    """Stable short hash of the connection-relevant config subset."""
    subset = {
        "machine_id": cfg.get("machine_id", ""),
        "collector_host": cfg.get("collector_host", ""),
        "collector_port": cfg.get("collector_port", 0),
        "allowed_domains": cfg.get("allowed_domains", []),
        "ignored_domains": cfg.get("ignored_domains", []),
        "ignored_processes": cfg.get("ignored_processes", []),
        "ignored_ips": cfg.get("ignored_ips", []),
        "heartbeat_seconds": cfg.get("heartbeat_seconds", 15),
    }
    canonical = json.dumps(subset, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


class ResolverCache:
    """Resolve collector_host once, cache the IPv4 answer, re-resolve on a timer.

    The old code called sendto(hostname) for every packet, i.e. one getaddrinfo
    per event. D33: resolve at startup, send to the cached IP, and re-resolve
    every collector_resolve_seconds or immediately after consecutive failures.
    """

    def __init__(self, host: str, override_ip: str = "", refresh_seconds: int = 300):
        self.host = str(host).strip()
        self.override_ip = str(override_ip).strip()
        self.refresh_seconds = max(30, int(refresh_seconds))
        self.ip = ""          # cached IPv4 actually used for sending
        self.resolved_at = 0.0
        self.fail_streak = 0
        self.last_error = ""

    def resolve(self, force: bool = False) -> str:
        now = time.time()
        if self.override_ip:
            self.ip = self.override_ip
            return self.ip
        if not self.host:
            return ""
        if self.ip and not force and now - self.resolved_at < self.refresh_seconds:
            return self.ip
        try:
            infos = socket.getaddrinfo(self.host, None, socket.AF_INET, socket.SOCK_DGRAM)
            ip = str(infos[0][4][0]) if infos else ""
        except OSError as exc:
            self.fail_streak += 1
            self.last_error = str(exc)
            # Backoff: retry at 5s -> 30s -> 60s instead of hammering a broken DNS.
            self.resolved_at = now - max(0, self.refresh_seconds - (5 if self.fail_streak == 1
                                        else 30 if self.fail_streak == 2 else 60))
            return self.ip
        if ip:
            if self.ip and ip != self.ip:
                log(f"collector 地址变更: {self.ip} -> {ip}")
            self.ip = ip
            self.resolved_at = now
            self.fail_streak = 0
            self.last_error = ""
        return self.ip


def read_guard_state(path: Path) -> Dict[str, Any]:
    """guard.json written by guard.py; missing file means the guard is not reporting."""
    data = read_json(path, None)
    return data if isinstance(data, dict) else {}


def process_running_by_name(name: str) -> bool:
    """True when at least one process with this exact image name exists."""
    if os.name != "nt":
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessTable._PROCESSENTRY32W)]
        kernel32.Process32FirstW.restype = ctypes.c_int
        kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessTable._PROCESSENTRY32W)]
        kernel32.Process32NextW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        snapshot = kernel32.CreateToolhelp32Snapshot(ProcessTable.TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            return False
        try:
            entry = ProcessTable._PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(ProcessTable._PROCESSENTRY32W)
            ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                if os.path.basename(entry.szExeFile or "").lower() == name.lower():
                    return True
                ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(snapshot))
    except Exception:
        return False
    return False


def process_name_by_pid(pid: int) -> str:
    """Image basename for a PID, or "" when the PID is gone (v1.5: .py watchdogs)."""
    if os.name != "nt" or not pid or pid <= 0:
        return ""
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessTable._PROCESSENTRY32W)]
        kernel32.Process32FirstW.restype = ctypes.c_int
        kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ProcessTable._PROCESSENTRY32W)]
        kernel32.Process32NextW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        snapshot = kernel32.CreateToolhelp32Snapshot(ProcessTable.TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            return ""
        try:
            entry = ProcessTable._PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(ProcessTable._PROCESSENTRY32W)
            ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                if int(entry.th32ProcessID) == int(pid):
                    return os.path.basename(entry.szExeFile or "")
                ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(ctypes.c_void_p(snapshot))
    except Exception:
        return ""
    return ""


def pythonw_preferred() -> str:
    """Interpreter to spawn background children from: pythonw.exe when available.

    Running the watchdog under pythonw keeps no console window on the student
    desktop; when only python.exe exists we fall back to it (deploy hides it).
    """
    exe = sys.executable or ""
    if not exe:
        return "pythonw"
    base = os.path.basename(exe).lower()
    if base == "pythonw.exe":
        return exe
    sibling = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.isfile(sibling):
        return sibling
    return exe


def decode_system_output(data: bytes) -> str:
    if data is None:
        return ""
    # Windows console tools can emit either OEM or UTF-16 output depending on OS/build.
    try:
        text = data.decode("utf-8-sig")
        if "\ufffd" not in text and "\x00" not in text:
            return text
    except Exception:
        pass
    try:
        text = data.decode("utf-16")
        if "\x00" not in text:
            return text
    except Exception:
        pass
    for enc in ("mbcs", "cp850", "latin-1"):
        try:
            return data.decode(enc, "replace")
        except Exception:
            pass
    return data.decode("latin-1", "replace")


def run_wevtutil(args: List[str], timeout: int = 20) -> str:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wevtutil.exe")
    cp = subprocess.run([exe] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        creationflags=CREATE_NO_WINDOW, timeout=timeout)
    if cp.returncode:
        raise RuntimeError((decode_system_output(cp.stderr) or decode_system_output(cp.stdout) or
                            "wevtutil exit=%s" % cp.returncode).strip())
    return decode_system_output(cp.stdout)


def parse_event_xml(raw: str) -> List[ET.Element]:
    raw = raw.lstrip("\ufeff\x00\r\n \t")
    # wevtutil concatenates XML Event nodes without a shared root.
    raw = re.sub(r"<\?xml[^>]*\?>", "", raw)
    if not raw.strip():
        return []
    root = ET.fromstring("<Events>" + raw + "</Events>")
    return list(root)


def event_fields(elem: ET.Element) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for child in elem.iter():
        if child.tag.endswith("EventID"):
            fields["EventID"] = child.text or ""
        elif child.tag.endswith("EventRecordID"):
            fields["EventRecordID"] = child.text or "0"
        elif child.tag.endswith("TimeCreated"):
            fields["TimeCreated"] = child.attrib.get("SystemTime", "")
        elif child.tag.endswith("Execution"):
            fields["ProcessID"] = child.attrib.get("ProcessID", "")
        elif child.tag.endswith("Security"):
            fields["UserID"] = child.attrib.get("UserID", "")
        elif child.tag.endswith("Data"):
            fields[child.attrib.get("Name", "")] = child.text or ""
    return fields


def query_events_after(rid: int, limit: int = 1000) -> List[Dict[str, str]]:
    xpath = f"*[System[(EventRecordID > {int(rid)})]]"
    raw = run_wevtutil(["qe", CHANNEL, "/q:" + xpath, f"/c:{limit}", "/rd:false", "/f:xml"])
    return [event_fields(e) for e in parse_event_xml(raw)]


def latest_record_id(reverse: bool = True) -> int:
    raw = run_wevtutil(["qe", CHANNEL, "/c:1", "/rd:" + ("true" if reverse else "false"), "/f:xml"])
    events = parse_event_xml(raw)
    return int(event_fields(events[0]).get("EventRecordID", "0")) if events else 0


def process_name(pid_text: str) -> str:
    if os.name != "nt" or not pid_text.isdigit():
        return "unknown"
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid_text))
    if not handle:
        return "unknown"
    try:
        buf = ctypes.create_unicode_buffer(32768)
        size = ctypes.c_ulong(len(buf))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return os.path.basename(buf.value)
    except Exception:
        pass
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    return "unknown"


def process_create_time(pid: int) -> Optional[float]:
    """Process creation time as epoch seconds, or None when it cannot be queried."""
    if os.name != "nt" or pid <= 0:
        return None
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4
    kernel32.GetProcessTimes.restype = ctypes.c_int
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return None
    created = ctypes.c_ulonglong(0)
    exited = ctypes.c_ulonglong(0)
    kernel_kernel = ctypes.c_ulonglong(0)
    kernel_user = ctypes.c_ulonglong(0)
    try:
        if kernel32.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                    ctypes.byref(kernel_kernel), ctypes.byref(kernel_user)):
            # FILETIME counts 100 ns ticks since 1601-01-01 UTC.
            return (created.value - 116444736000000000) / 10000000.0
    except Exception:
        pass
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    return None


class ProcessTable:
    """PID -> (exe name, create time) snapshot.

    Attribution happens at collection time, seconds after the DNS event, so a bare
    PID lookup can name the wrong process after PID reuse or miss short-lived ones.
    The snapshot keeps the mapping and its creation time; callers reject an entry
    whose creation time is later than the event.
    """

    TH32CS_SNAPPROCESS = 0x00000002

    class _PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    def __init__(self, refresh_seconds: float = 5.0):
        self.interval = max(1.0, float(refresh_seconds))
        self.map = {}  # type: Dict[int, tuple]
        self.built_at = 0.0
        self.usable = os.name == "nt"

    def refresh(self, force: bool = False) -> None:
        now = time.time()
        if not self.usable or (not force and now - self.built_at < self.interval):
            return
        self.built_at = now
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
            kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
            kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(self._PROCESSENTRY32W)]
            kernel32.Process32FirstW.restype = ctypes.c_int
            kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(self._PROCESSENTRY32W)]
            kernel32.Process32NextW.restype = ctypes.c_int
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            snapshot = kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPPROCESS, 0)
            if not snapshot or snapshot == ctypes.c_void_p(-1).value:
                return
            try:
                entry = self._PROCESSENTRY32W()
                entry.dwSize = ctypes.sizeof(self._PROCESSENTRY32W)
                fresh = {}  # type: Dict[int, tuple]
                ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
                while ok:
                    pid = int(entry.th32ProcessID)
                    fresh[pid] = (os.path.basename(entry.szExeFile or "") or "unknown", None)
                    ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
                self.map = fresh
            finally:
                kernel32.CloseHandle(ctypes.c_void_p(snapshot))
        except Exception:
            # Never let attribution break collection; fall back to on-demand lookups.
            self.usable = False

    def get(self, pid: int) -> Optional[tuple]:
        return self.map.get(pid)

    def add_created(self, pid: int, created: Optional[float]) -> None:
        item = self.map.get(pid)
        if item is not None:
            self.map[pid] = (item[0], created)


def resolve_ips(result: str) -> List[str]:
    out: List[str] = []
    for token in re.split(r"[;,\s]+", result.strip()):
        token = token.strip()
        if not token:
            continue
        if token.lower().startswith("::ffff:"):
            token = token[7:]
        try:
            ip = ipaddress.ip_address(token.split("%", 1)[0])
            out.append(str(ip))
        except ValueError:
            continue
    return out


def make_signed(payload: Dict[str, Any], secret: str) -> bytes:
    body = dict(payload)
    body.pop("hmac", None)
    if secret:
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        body["hmac"] = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class Agent:
    def __init__(self, cfg: Dict[str, Any], config_path: Path, dry_run: bool = False):
        self.cfg = cfg
        self.base = config_path.parent
        self.state_path = self._path(cfg["state_file"])
        self.local_path = self._path(cfg["local_log"])
        self.outbox_path = self._path(cfg["outbox_file"])
        self.guard_path = self._path(cfg.get("guard_file", "guard.json"))
        self.resolver = ResolverCache(str(cfg.get("collector_host", "")),
                                      str(cfg.get("collector_ip", "")),
                                      int(cfg.get("collector_resolve_seconds", 300)))
        self.started_at = time.time()
        self.cfg_hash = config_hash(cfg)
        # dry_run still tracks sequence/statistics but writes no files and sends nothing;
        # used by --self-test and --replay so neither touches a live deployment.
        self.dry_run = dry_run
        self.replay_mode = False
        self.sink: List[Dict[str, Any]] = []
        self.state = read_json(self.state_path, {})
        self.state.setdefault("seq", 0)
        self.state.setdefault("session", str(uuid.uuid4()))
        self.state.setdefault("known_ips", {})
        self.state.setdefault("last_tcp_scan", 0.0)
        self.state.setdefault("stats", self.empty_stats())
        self.state.setdefault("stats_since", utc_now())
        # v1.5: the watchdog finds us by PID (guard.py reads state.json), so the pid
        # is always overwritten on start — a stale pid from a previous run must not
        # survive a crash.
        self.state["pid"] = os.getpid()
        self.sock = None  # type: Optional[socket.socket]
        self.mutex_handle = None
        self.last_error_emit = 0.0
        self.last_stats_emit = 0.0
        self.last_heartbeat_emit = 0.0
        self.dedupe: Dict[str, float] = {}
        self.state_dirty = False
        self.proc_table = ProcessTable()
        self.use_win7_query_fallback = self._is_windows_7()
        self.tcp_enabled = bool(cfg.get("tcp_watch", {}).get("enabled", False))

    @staticmethod
    def empty_stats() -> Dict[str, int]:
        return {key: 0 for key in STATS_KEYS}

    def _count(self, key: str, amount: int = 1) -> None:
        stats = self.state.setdefault("stats", self.empty_stats())
        stats[key] = int(stats.get(key, 0)) + amount
        self.state_dirty = True

    def lookup_process(self, pid_text: str, event_time: str = "") -> tuple:
        """Return (name, source) using the PID snapshot and the event time.

        A process whose creation time is later than the event cannot have produced
        it, so PID reuse yields "<unknown>" instead of a misattributed name.
        """
        if not str(pid_text).isdigit():
            return ("<unknown>", "no_pid")
        pid = int(pid_text)
        event_epoch = parse_event_epoch(event_time)
        self.proc_table.refresh()
        item = self.proc_table.get(pid)
        if item is None:
            # The snapshot may predate the process; one forced refresh covers short-lived ones.
            self.proc_table.refresh(force=True)
            item = self.proc_table.get(pid)
        if item is not None:
            name, created = item
            if created is None and name != "unknown":
                created = process_create_time(pid)
                self.proc_table.add_created(pid, created)
            if created is not None and event_epoch is not None and created > event_epoch + 2.0:
                return ("<unknown>", "pid_reused")
            return (name or "<unknown>", "snapshot")
        name = process_name(str(pid))
        if name != "unknown":
            created = process_create_time(pid)
            if created is not None and event_epoch is not None and created > event_epoch + 2.0:
                return ("<unknown>", "pid_reused")
            return (name, "live")
        return ("<unknown>", "unknown")

    def filter_hashes(self) -> Dict[str, str]:
        return {
            "allowlist_sha256": list_hash(self.cfg.get("allowed_domains", [])),
            "filter_sha256": list_hash(list(self.cfg.get("ignored_domains", [])) +
                                       list(self.cfg.get("ignored_processes", []))),
        }

    def stats_payload(self) -> Dict[str, Any]:
        stats = dict(self.state.get("stats", self.empty_stats()))
        accounted = sum(int(stats.get(key, 0)) for key in STATS_SKIP_KEYS) + int(stats.get("emitted", 0))
        payload: Dict[str, Any] = {
            "stats": stats,
            "stats_since": self.state.get("stats_since", ""),
            "seen": int(stats.get("events_seen", 0)),
            "accounted": accounted,
            "balanced": accounted == int(stats.get("events_seen", 0)),
            "watermark": int(self.state.get("watermark", -1)),
            "tcp_watch": self.tcp_enabled,
        }
        payload.update(self.filter_hashes())
        return payload

    def maybe_emit_stats(self) -> None:
        interval = max(60, int(self.cfg.get("stats_interval_seconds", 600)))
        now = time.time()
        if now - self.last_stats_emit < interval:
            return
        self.last_stats_emit = now
        self.emit("agent_stats", self.stats_payload())

    def heartbeat_payload(self) -> Dict[str, Any]:
        """§7.7 heartbeat fields; guard status comes from guard.py's guard.json."""
        guard = read_guard_state(self.guard_path)
        # v1.5: guard runs as guard.py under the machine's Python, so liveness is
        # checked by the PID recorded in guard.json, not by an image name.
        guard_alive = False
        try:
            gpid = int(guard.get("guard_pid", 0))
        except (TypeError, ValueError):
            gpid = 0
        if gpid:
            guard_alive = process_name_by_pid(gpid).lower().startswith("pyth")
        queue_depth = 0
        try:
            if self.outbox_path.exists():
                with self.outbox_path.open("rb") as f:
                    queue_depth = sum(1 for _ in f)
        except OSError:
            queue_depth = -1
        return {
            "version": VERSION,
            "hostname": socket.gethostname(),
            "uptime_seconds": int(time.time() - self.started_at),
            "queue_depth": queue_depth,
            "watermark": int(self.state.get("watermark", -1)),
            "hb_seconds": int(self.cfg.get("heartbeat_seconds", 15)),
            "guard": bool(guard_alive),
            "guard_restarts": int(guard.get("restarts", 0)),
            "collector_ip": self.resolver.ip,
            "config_hash": self.cfg_hash,
            "tcp_watch": self.tcp_enabled,
        }

    def maybe_emit_heartbeat(self) -> None:
        interval = max(5, int(self.cfg.get("heartbeat_seconds", 15)))
        now = time.time()
        if now - self.last_heartbeat_emit < interval:
            return
        self.last_heartbeat_emit = now
        # Heartbeats carry connection state only; they are not written to the local
        # alerts JSONL and the collector keeps them out of the daily event log too.
        self.emit("heartbeat", self.heartbeat_payload(), send=True, local=False)

    def watch_guard(self) -> None:
        """Mutual watchdog (D17): if guard.py died, start it again."""
        if self.dry_run or os.name != "nt":
            return
        # v1.5: guard is guard.py under the machine's Python; liveness by PID from
        # guard.json (a missing/stale pid means it is not running).
        guard = read_guard_state(self.guard_path)
        try:
            gpid = int(guard.get("guard_pid", 0))
        except (TypeError, ValueError):
            gpid = 0
        if gpid and process_name_by_pid(gpid).lower().startswith("pyth"):
            return
        script = self.base / GUARD_SCRIPT
        if not script.exists():
            return
        try:
            subprocess.Popen([pythonw_preferred(), str(script), "--config", str(self.base / "config.json")],
                             cwd=str(self.base), creationflags=CREATE_NO_WINDOW,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL)
            log("guard.py 未在运行，已重新拉起")
        except OSError as exc:
            log(f"guard.py 拉起失败：{exc}")


    @staticmethod
    def _is_windows_7() -> bool:
        if os.name != "nt":
            return False
        try:
            version = sys.getwindowsversion()
            return version.major == 6 and version.minor == 1
        except Exception:
            return False

    def _path(self, value: str) -> Path:
        p = Path(value)
        return p if p.is_absolute() else self.base / p

    def save_state(self, force: bool = False) -> None:
        if self.dry_run and not force:
            return
        if not force and not self.state_dirty:
            return
        atomic_json(self.state_path, self.state)
        self.state_dirty = False

    def start_socket(self) -> None:
        host = str(self.cfg.get("collector_host", "")).strip()
        if not host and not str(self.cfg.get("collector_ip", "")).strip():
            log("未配置 collector_host：只写本机 alerts.jsonl，不发送 UDP")
            return
        secret = str(self.cfg.get("shared_secret", ""))
        if len(secret) < 32 or secret.lower().startswith("change-me"):
            raise ValueError("已配置 collector_host，但 shared_secret 需要至少 32 个 ASCII 字符的随机密钥；"
                             "推荐每机一份独立的 60 字符密钥，不要多机共用")
        if len(secret) < 60:
            log("提示：shared_secret 短于 60 字符；建议每机使用独立的 60 字符密钥")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = self.resolver.resolve(force=True)
        if ip:
            log(f"collector 解析成功: {self.resolver.host or self.resolver.override_ip} -> {ip}")
        else:
            # D33: a broken DNS must not stop the agent; it retries with backoff and
            # queues packets in the outbox until an address is available.
            log(f"collector 解析失败（将退避重试）: {self.resolver.last_error}")

    def _append_local(self, payload: Dict[str, Any]) -> None:
        self.local_path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        max_bytes = max(1, int(self.cfg.get("local_log_max_mb", 16))) * 1024 * 1024
        backups = max(1, min(20, int(self.cfg.get("local_log_backups", 5))))
        if self.local_path.exists() and self.local_path.stat().st_size + len(line.encode("utf-8")) > max_bytes:
            oldest = self.local_path.with_name(self.local_path.name + f".{backups}")
            if oldest.exists():
                oldest.unlink()
            for index in range(backups - 1, 0, -1):
                src = self.local_path.with_name(self.local_path.name + f".{index}")
                if src.exists():
                    os.replace(src, self.local_path.with_name(self.local_path.name + f".{index + 1}"))
            os.replace(self.local_path, self.local_path.with_name(self.local_path.name + ".1"))
        with self.local_path.open("a", encoding="utf-8") as f:
            f.write(line)
            f.flush()

    def emit(self, kind: str, fields: Dict[str, Any], send: bool = True, local: bool = True) -> None:
        self.state["seq"] = int(self.state.get("seq", 0)) + 1
        self.state_dirty = True
        payload: Dict[str, Any] = {
            "schema": 1,
            "machine": self.cfg["machine_id"],
            "session": self.state["session"],
            "seq": self.state["seq"],
            "time": utc_now(),
            "type": kind,
            **fields,
        }
        if self.dry_run:
            self.sink.append(payload)
            return
        if local:
            self._append_local(payload)
        if send and self.sock is not None:
            packet = make_signed(payload, str(self.cfg["shared_secret"]))
            if len(packet) > 1200:
                payload["detail_truncated"] = True
                for key in ("query_results", "process_path", "detail"):
                    if key in payload:
                        payload[key] = str(payload[key])[:128]
                packet = make_signed(payload, str(self.cfg["shared_secret"]))
            if len(packet) > 1200:
                log("UDP 事件超过安全包长，跳过发送；本地 JSONL 仍保留完整事件")
                return
            # D33: send to the cached IP; re-resolve on the timer or after failures.
            ip = self.resolver.resolve()
            if not ip:
                self._queue(packet)
                if time.time() - self.last_error_emit >= 60:
                    self.last_error_emit = time.time()
                    log(f"collector 地址不可用，事件写入 outbox：{self.resolver.last_error}")
                return
            try:
                self.sock.sendto(packet, (ip, int(self.cfg["collector_port"])))
            except OSError as exc:
                self._queue(packet)
                log(f"UDP 发送失败，已写入本机 outbox：{exc}")
        log(f"{kind}: {fields}")

    def _queue(self, packet: bytes) -> None:
        self.outbox_path.parent.mkdir(parents=True, exist_ok=True)
        with self.outbox_path.open("ab") as f:
            f.write(packet + b"\n")
            f.flush()

    def retry_outbox(self) -> None:
        if self.sock is None or not self.outbox_path.exists():
            return
        ip = self.resolver.resolve()
        if not ip:
            return
        try:
            lines = self.outbox_path.read_bytes().splitlines()
            keep: List[bytes] = []
            for line in lines:
                try:
                    self.sock.sendto(line, (ip, int(self.cfg["collector_port"])))
                except OSError:
                    keep.append(line)
            if keep:
                temp = Path(str(self.outbox_path) + ".tmp")
                temp.write_bytes(b"\n".join(keep) + b"\n")
                os.replace(temp, self.outbox_path)
            else:
                if self.outbox_path.exists():
                    self.outbox_path.unlink()
        except OSError as exc:
            log(f"outbox 处理失败：{exc}")

    def scan_events(self) -> None:
        current = int(self.state.get("watermark", -1))
        if current < 0:
            latest = latest_record_id(True)
            # Seed the optional TCP correlation cache from recent DNS results without emitting
            # historical alerts. Skipped entirely when tcp_watch is off: a disabled watcher
            # must not keep growing known_ips.
            if self.tcp_enabled and latest > 0:
                try:
                    for old in query_events_after(max(0, latest - 5000), 5000):
                        if old.get("EventID") == "3008":
                            for resolved_ip in resolve_ips(old.get("QueryResults", "")):
                                if is_global_ip(resolved_ip):
                                    self.state.setdefault("known_ips", {})[resolved_ip] = time.time()
                    self.state_dirty = True
                except Exception as exc:
                    log(f"TCP 初始 DNS 映射预热失败（会有额外误报）：{exc}")
            self.state["watermark"] = latest
            self.state_dirty = True
            self.save_state()
            log(f"首次启动：从 EventRecordID={latest} 之后开始，不回放历史告警")
            return

        # Detect a cleared channel (newest RID fell below our cursor) or circular overwrite.
        oldest = latest_record_id(False)
        newest = latest_record_id(True)
        if current and newest and newest < current:
            self.emit("event_log_gap", {"previous_watermark": current, "oldest_retained_record_id": oldest,
                                         "newest_record_id": newest,
                                         "detail": "事件日志已清空/重建，RID 已回退；无法恢复缺失事件"})
            current = max(0, oldest - 1)
        elif current > 0 and oldest == newest and newest == current + 1:
            # The channel contains only one new record; do not mistake this normal state for a gap.
            pass
        elif oldest and current and oldest > current + 1:
            self.emit("event_log_gap", {"previous_watermark": current, "oldest_retained_record_id": oldest,
                                         "newest_record_id": newest,
                                         "detail": "日志已回卷或记录缺口；不能恢复缺失事件"})
            current = oldest - 1

        for _ in range(10):
            records = query_events_after(current, 1000)
            if not records:
                break
            max_rid = current
            for data in records:
                try:
                    rid = int(data.get("EventRecordID", "0"))
                except ValueError:
                    rid = 0
                max_rid = max(max_rid, rid)
                event_id = data.get("EventID")
                if event_id == "3008":
                    # Learn address mappings from completed queries, only for a live TCP watcher
                    # and only for globally routable addresses.
                    if self.tcp_enabled:
                        for resolved_ip in resolve_ips(data.get("QueryResults", "")):
                            if is_global_ip(resolved_ip):
                                self.state.setdefault("known_ips", {})[resolved_ip] = time.time()
                                self.state_dirty = True
                    self.handle_dns(data, completed=True)
                elif event_id == "3006" and self.use_win7_query_fallback:
                    # Windows 7 may not emit the later completion event 3008 reliably.
                    # Event 3006 records a resolver API query request, not a proven network
                    # lookup or successful answer; explicitly label it as an attempt.
                    self.handle_dns(data, completed=False)
            if max_rid <= current:
                break
            current = max_rid
            self.state["watermark"] = current
            self.state_dirty = True
            self.save_state()
            if len(records) < 1000:
                break

    def handle_dns(self, e: Dict[str, str], completed: bool = True) -> None:
        # Every DNS event is counted exactly once so that stats can be reconciled
        # against the event log (seen == allowed + ignored_* + emitted).
        self._count("events_seen")
        host = norm_domain(e.get("QueryName", ""))
        if not host:
            self._count("not_fqdn")
            return
        if domain_allowed(host, self.cfg["allowed_domains"]):
            self._count("allowed")
            return
        if "." not in host:
            # "wpad", "localhost" and other non-FQDN lookups have no contest relevance.
            self._count("not_fqdn")
            return
        if domain_in_list(host, self.cfg.get("ignored_domains", [])):
            self._count("ignored_domain")
            return
        sid = e.get("UserID", "")
        if self.cfg.get("ignore_system_accounts", True) and sid in SYSTEM_SIDS:
            self._count("ignored_sid")
            return
        pid = e.get("ProcessID", "")
        if self.replay_mode:
            proc, proc_source = str(e.get("process") or "<unknown>"), "recorded"
        else:
            proc, proc_source = self.lookup_process(pid, e.get("TimeCreated", ""))
        ignored = {str(x).lower() for x in self.cfg.get("ignored_processes", [])}
        # Filtering is opt-in: do not hide a query merely because process-name lookup failed.
        if proc.lower() in ignored:
            self._count("ignored_process")
            return
        status = e.get("QueryStatus", "") if completed else "unknown"
        if status in {"", "0", "0x0"}:
            status_class = "ok"
        elif status.lower() in RESOLVER_ERROR_STATUSES:
            status_class = "resolver_local_error"
        else:
            status_class = "failed"
        if completed and status_class == "resolver_local_error" and not self.cfg.get("report_resolver_errors", False):
            self._count("resolver_local_error")
            return
        if completed and status_class == "failed" and not self.cfg.get("report_failed_dns", True):
            self._count("ignored_failed_dns")
            return
        event_time = e.get("TimeCreated", "")
        if not completed:
            event_type = "dns_query_attempt_unlisted"
        else:
            event_type = "dns_unlisted" if status_class == "ok" else "dns_failed_unlisted"
        self.emit(event_type, {
            "domain": host,
            "query_type": e.get("QueryType", ""),
            "query_status": status,
            "status_class": status_class,
            "query_results": e.get("QueryResults", "")[:256],
            "observation": "query_attempt_only" if not completed else "query_completed",
            "event_time": event_time,
            "process_id": pid,
            "process": proc,
            "process_source": proc_source,
            "user_sid": sid,
            "event_record_id": e.get("EventRecordID", ""),
        })
        self._count("emitted")
        if status_class == "failed":
            self._count("failed")

    @staticmethod
    def _endpoint_ip(endpoint: str) -> str:
        endpoint = endpoint.strip()
        if endpoint.startswith("[") and "]" in endpoint:
            raw = endpoint[1:endpoint.index("]")]
        else:
            raw = endpoint.rsplit(":", 1)[0]
        return raw.split("%", 1)[0]

    def scan_tcp(self) -> None:
        opts = self.cfg.get("tcp_watch", {})
        if not opts.get("enabled", False):
            return
        interval = max(10, int(opts.get("interval_seconds", 30)))
        now = time.time()
        if now - float(self.state.get("last_tcp_scan", 0)) < interval:
            return
        self.state["last_tcp_scan"] = now
        self.state_dirty = True
        try:
            cp = subprocess.run(["netstat.exe", "-ano", "-p", "tcp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 universal_newlines=True, encoding="utf-8", errors="replace",
                                 creationflags=CREATE_NO_WINDOW, timeout=20)
            if cp.returncode:
                return
        except (OSError, subprocess.SubprocessError) as exc:
            log(f"netstat 读取失败：{exc}")
            return
        known = self.state.setdefault("known_ips", {})
        ttl = max(1, int(opts.get("known_ip_minutes", 30))) * 60
        # Prune every round: expired entries plus anything that is not a global address
        # (an older build learned ::1/127.0.0.1/fe80::/private IPs and never removed them).
        stale = [ip for ip, seen in known.items() if now - float(seen) > ttl or not is_global_ip(ip)]
        for ip in stale:
            known.pop(ip, None)
        if stale:
            self.state_dirty = True
        if len(known) > 10000:
            oldest_first = sorted(known.items(), key=lambda kv: float(kv[1]))
            for ip, _seen in oldest_first[:len(known) - 10000]:
                known.pop(ip, None)
            self.state_dirty = True
        for line in cp.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0].upper() != "TCP" or parts[-2].upper() != "ESTABLISHED":
                continue
            remote, pid = parts[2], parts[-1]
            raw_ip = self._endpoint_ip(remote)
            # Port is needed by the collector's nonstandard-port high-risk flag.
            if remote.startswith("[") and "]:" in remote:
                port_text = remote.rsplit("]:", 1)[1]
            elif ":" in remote:
                port_text = remote.rsplit(":", 1)[1]
            else:
                port_text = ""
            try:
                ip = ipaddress.ip_address(raw_ip)
                if isinstance(ip, ipaddress.IPv6Address) and str(ip).lower().startswith("::ffff:"):
                    # Avoid IPv6Address.ipv4_mapped so the code remains compatible with
                    # older Python 3.8 standard-library variants.
                    ip = ipaddress.ip_address(str(ip)[7:])
                # Implement global-unicast filtering ourselves; IPv6Address.is_global is not
                # consistently available/consistent in the oldest Python 3.8 builds.
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                    continue
            except ValueError:
                continue
            key = str(ip)
            if key in {str(x).strip() for x in self.cfg.get("ignored_ips", []) if str(x).strip()}:
                self._count("ignored_ip")
                continue
            if key in known:
                continue
            dedupe_key = f"{key}:{pid}"
            if now - self.dedupe.get(dedupe_key, 0) < 600:
                continue
            self.dedupe[dedupe_key] = now
            self.emit("tcp_unmapped_ip", {
                "remote_ip": key,
                "remote_port": port_text,
                "process_id": pid,
                "process": self.lookup_process(pid, "")[0],
                "detail": "已建立的公网 TCP 连接未与近期 DNS 结果关联；不能据此推断具体域名",
            })

    def acquire_mutex(self) -> bool:
        """Single instance via a named mutex (§6.1). False when another instance runs."""
        if os.name != "nt":
            return True
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
            kernel32.CreateMutexW.restype = ctypes.c_void_p
            safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(self.cfg["machine_id"]))
            name = "Local\\NLListener_" + safe
            handle = kernel32.CreateMutexW(None, False, name)
            if not handle:
                return True  # mutex creation failed; do not block the agent on it
            if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
                kernel32.CloseHandle(ctypes.c_void_p(handle))
                return False
            self.mutex_handle = handle
        except Exception:
            pass
        return True

    def run(self) -> None:
        if os.name != "nt":
            raise RuntimeError("此监听器仅支持 Windows")
        if not self.acquire_mutex():
            log("listener 已有实例在运行（互斥体已存在），本次退出")
            return
        self.start_socket()
        # Always print the resolved absolute paths: console output never proves where files went.
        log(f"数据文件：state={self.state_path} | log={self.local_path} | outbox={self.outbox_path}")
        log(f"启动：machine={self.cfg['machine_id']} channel={CHANNEL} poll={self.cfg['poll_seconds']}s win7_3006_fallback={self.use_win7_query_fallback}")
        # Emit visible status locally and to collector: the filter/allowlist hashes make a
        # mismatch between what a machine runs and what the teacher configured detectable.
        started_fields: Dict[str, Any] = {
            "version": VERSION,
            "python": platform.python_version(),
            "hostname": socket.gethostname(),
            "collector_host": str(self.cfg.get("collector_host", "")),
            "collector_ip": self.resolver.ip,
            "heartbeat_seconds": int(self.cfg.get("heartbeat_seconds", 15)),
            "config_hash": self.cfg_hash,
            "tcp_watch": self.tcp_enabled,
            "report_failed_dns": bool(self.cfg.get("report_failed_dns", True)),
            "report_resolver_errors": bool(self.cfg.get("report_resolver_errors", False)),
            "stats_interval_seconds": int(self.cfg.get("stats_interval_seconds", 600)),
        }
        started_fields.update(self.filter_hashes())
        self.emit("agent_started", started_fields)
        reason = "unknown"
        # v1.5: deploy's self-check reads state.json freshness (≤30s), so the state
        # file is force-saved at least once per heartbeat interval even when idle.
        state_save_interval = max(5, int(self.cfg.get("heartbeat_seconds", 15)))
        last_state_save = time.time()
        try:
            while True:
                try:
                    self.watch_guard()
                    self.scan_events()
                    self.scan_tcp()
                    self.retry_outbox()
                    self.maybe_emit_heartbeat()
                    self.maybe_emit_stats()
                    self.save_state()
                    if time.time() - last_state_save >= state_save_interval:
                        self.save_state(force=True)
                        last_state_save = time.time()
                except KeyboardInterrupt:
                    reason = "keyboard_interrupt"
                    raise
                except Exception as exc:
                    log(f"轮询错误（稍后重试）：{type(exc).__name__}: {exc}")
                    if time.time() - self.last_error_emit >= 60:
                        self.last_error_emit = time.time()
                        self.emit("agent_error", {"detail": f"{type(exc).__name__}: {exc}"}, send=True)
                time.sleep(int(self.cfg["poll_seconds"]))
        except KeyboardInterrupt:
            log("收到停止请求")
        finally:
            # Session boundary: without agent_stopped a truncated run is indistinguishable
            # from a machine that simply stopped producing events.
            last_seq = int(self.state.get("seq", 0))
            try:
                self.emit("agent_stopped", {"last_seq": last_seq, "reason": reason,
                                             "watermark": int(self.state.get("watermark", -1))})
            except Exception as exc:
                log(f"退出事件写入失败：{type(exc).__name__}: {exc}")
            self.save_state(force=True)
            if self.sock:
                self.sock.close()


def self_test(config: Dict[str, Any]) -> None:
    # Keep the fixture independent of the deployment whitelist: a real config.json
    # legitimately lists other domains, and --self-test must still pass there.
    allowlist = ["contest.example.edu", "*.static.example.edu"]
    assert domain_allowed("contest.example.edu", allowlist)
    assert domain_allowed("static.contest.example.edu", allowlist)
    assert domain_allowed("a.static.example.edu", allowlist)
    assert not domain_allowed("notallowed.invalid", allowlist)
    xml = "<Event xmlns='urn:test'><System><EventID>3008</EventID><EventRecordID>9</EventRecordID><TimeCreated SystemTime='2026-01-01T00:00:00Z'/><Execution ProcessID='123'/><Security UserID='S-1-5-21-1'/></System><EventData><Data Name='QueryName'>notallowed.invalid</Data><Data Name='QueryType'>1</Data><Data Name='QueryStatus'>0</Data><Data Name='QueryResults'>192.0.2.1;</Data></EventData></Event>"
    e = event_fields(parse_event_xml(xml)[0])
    assert e["EventID"] == "3008" and e["QueryName"] == "notallowed.invalid" and e["ProcessID"] == "123"
    xml_attempt = xml.replace("<EventID>3008</EventID>", "<EventID>3006</EventID>").replace(
        "<Data Name='QueryStatus'>0</Data><Data Name='QueryResults'>192.0.2.1;</Data>",
        "<Data Name='ServerList'></Data><Data Name='IsNetworkQuery'>0</Data>")
    e_attempt = event_fields(parse_event_xml(xml_attempt)[0])
    assert e_attempt["EventID"] == "3006" and e_attempt["QueryName"] == "notallowed.invalid"
    packet = make_signed({"schema": 1, "test": "ok"}, "test-secret-123456")
    obj = json.loads(packet)
    sig = obj.pop("hmac")
    expected = hmac.new(b"test-secret-123456", json.dumps(obj, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    assert hmac.compare_digest(sig, expected)
    # Noise filter: plain entries are exact, "*.x" covers root and subdomains, and a
    # broader suffix must not be inferred (guard against "*.microsoft.com" style mistakes).
    noise = ["wpad", "*.msedge.net", "go.microsoft.com", "ocsp.digicert.com"]
    assert domain_in_list("wpad", noise)
    assert domain_in_list("msedge.net", noise)
    assert domain_in_list("l-ring.msedge.net", noise)
    assert domain_in_list("go.microsoft.com", noise)
    assert not domain_in_list("learn.microsoft.com", noise)
    assert not domain_in_list("microsoft.com", noise)
    assert not domain_in_list("www.baidu.com", noise)
    assert is_global_ip("13.107.42.254") and not is_global_ip("::1")
    assert not is_global_ip("127.0.0.1") and not is_global_ip("192.168.58.128") and not is_global_ip("fe80::1")
    assert not is_global_ip("not-an-ip")
    # Filter-chain accounting: the counters live in memory, so the scratch directory is
    # only needed for the state-persistence check; a sandboxed shell can still run the rest.
    import shutil
    import tempfile

    try:
        selftest_tmp = scratch_dir("dnsmon-selftest-")
        writable = True
    except OSError as exc:
        print(f"SKIP 计数落盘测试：{exc}")
        selftest_tmp = Path(tempfile.gettempdir()) / ("dnsmon-selftest-" + uuid.uuid4().hex[:8])
        writable = False

    def _accounting(tmp):
        fixture = dict(config)
        fixture.update({
            "machine_id": "SELFTEST-PC",
            "collector_host": "",
            "state_file": str(tmp / "state.json"),
            "local_log": str(tmp / "alerts.jsonl"),
            "outbox_file": str(tmp / "outbox.jsonl"),
            "allowed_domains": ["*.seuoj.best"],
            "ignored_domains": list(noise),
            "ignored_processes": ["svchost.exe"],
            "tcp_watch": {"enabled": False},
        })
        agent = Agent(fixture, tmp / "config.json", dry_run=True)
        agent.replay_mode = True

        def feed(domain, status="0", proc="chrome.exe", sid="S-1-5-21-9", completed=True):
            event = {"QueryName": domain, "QueryType": "1", "QueryStatus": status,
                     "QueryResults": "192.0.2.1;", "TimeCreated": "2026-01-01T00:00:00.000Z",
                     "ProcessID": "4242", "UserID": sid, "EventRecordID": "1", "process": proc}
            agent.handle_dns(event, completed=completed)

        feed("a.seuoj.best")                    # whitelisted
        feed("wpad", "1460")                    # not FQDN
        feed("l-ring.msedge.net")               # noise domain
        feed("www.baidu.com", "87")             # resolver-local error, suppressed by default
        feed("www.baidu.com", "0")              # real signal, emitted
        feed("ads.example.net", "0", "svchost.exe")  # ignored process
        stats = agent.state["stats"]
        assert stats["allowed"] == 1 and stats["not_fqdn"] == 1, stats
        assert stats["ignored_domain"] == 1 and stats["resolver_local_error"] == 1, stats
        assert stats["ignored_process"] == 1 and stats["emitted"] == 1 and stats["failed"] == 0, stats
        assert [row["domain"] for row in agent.sink] == ["www.baidu.com"], agent.sink
        assert agent.sink[0]["status_class"] == "ok"
        payload = agent.stats_payload()
        assert payload["balanced"], payload
        if writable:
            agent.save_state(force=True)
            saved = json.loads((tmp / "state.json").read_text(encoding="utf-8"))
            assert saved["stats"]["emitted"] == 1 and saved["stats"]["events_seen"] == 6, saved["stats"]
        # Explicit opt-in still surfaces resolver-local errors, labelled as such.
        fixture["report_resolver_errors"] = True
        strict = Agent(fixture, tmp / "config.json", dry_run=True)
        strict.replay_mode = True
        strict.handle_dns({"QueryName": "www.baidu.com", "QueryStatus": "87", "ProcessID": "7",
                           "TimeCreated": "2026-01-01T00:00:00.000Z", "process": "chrome.exe"})
        assert strict.sink[0]["status_class"] == "resolver_local_error", strict.sink

    try:
        _accounting(selftest_tmp)
    finally:
        if writable:
            shutil.rmtree(selftest_tmp, ignore_errors=True)
    print("SELF-TEST OK: XML、白名单后缀、IP 解析、HMAC、噪声过滤与计数对账均通过")


def replay_alerts(path: Path, config: Dict[str, Any]) -> int:
    """Re-run a recorded alerts.jsonl through the current filter chain; writes nothing."""
    import shutil
    import tempfile
    try:
        tmp = scratch_dir("dnsmon-replay-")
        owned = True
    except OSError:
        # Replay writes nothing; the path is only a namespace for state/log file names.
        tmp = Path(tempfile.gettempdir()) / ("dnsmon-replay-" + uuid.uuid4().hex[:8])
        owned = False
    cfg = dict(config)
    cfg.update({
        "state_file": str(tmp / "state.json"),
        "local_log": str(tmp / "alerts.jsonl"),
        "outbox_file": str(tmp / "outbox.jsonl"),
    })
    try:
        agent = Agent(cfg, tmp / "config.json", dry_run=True)
        agent.replay_mode = True
        total = 0
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            total += 1
            if not str(row.get("type", "")).startswith("dns"):
                continue
            event = {
                "QueryName": row.get("domain", ""),
                "QueryType": row.get("query_type", ""),
                "QueryStatus": row.get("query_status", ""),
                "QueryResults": row.get("query_results", ""),
                "TimeCreated": row.get("event_time", ""),
                "ProcessID": row.get("process_id", ""),
                "UserID": row.get("user_sid", ""),
                "EventRecordID": row.get("event_record_id", ""),
                "process": row.get("process", ""),
            }
            agent.handle_dns(event, completed=row.get("observation") != "query_attempt_only")
        payload = agent.stats_payload()
        stats = payload["stats"]
        noise = [row for row in agent.sink if domain_in_list(row.get("domain", ""), cfg.get("ignored_domains", []))]
        resolver_errors = [row for row in agent.sink if row.get("status_class") == "resolver_local_error"]
        print(f"重放 {path}: 共 {total} 行，DNS 事件 {stats['events_seen']} 条")
        print("过滤计数: " + json.dumps(stats, ensure_ascii=False, sort_keys=True))
        print(f"对账: seen={payload['seen']} accounted={payload['accounted']} balanced={payload['balanced']}")
        print(f"残留噪声域名: {len(noise)} 条")
        print(f"仍上报的 87 类本地解析错误: {len(resolver_errors)} 条")
        for row in agent.sink:
            print(f"  保留 {row.get('type')} {row.get('domain')} status={row.get('query_status')} "
                  f"class={row.get('status_class')} process={row.get('process')}")
        return 0 if payload["balanced"] and not noise and not resolver_errors else 3
    finally:
        if owned:
            shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Visible Windows DNS Client Operational monitor")
    ap.add_argument("--config", default="", help="JSON 配置路径（默认取程序所在目录的 config.json）")
    ap.add_argument("--data-dir", default="", help="状态、日志、outbox 的可写目录；为空时用配置文件目录")
    ap.add_argument("--self-test", action="store_true", help="运行本地无系统改动的基础测试")
    ap.add_argument("--check", action="store_true", help="检查日志通道是否启用并显示最新记录号")
    ap.add_argument("--compat", action="store_true", help="打印解释器与兼容范围，不读日志、不发网络包")
    ap.add_argument("--replay", default="", help="把历史 alerts.jsonl 重新过一遍当前过滤链并核对计数，不写任何文件")
    args = ap.parse_args()
    check_runtime()
    if args.compat:
        import struct
        frozen = "是" if getattr(sys, "frozen", False) else "否"
        print("解释器版本: %s" % platform.python_version())
        print("解释器架构: %d-bit" % (struct.calcsize("P") * 8))
        print("冻结为 EXE: %s" % frozen)
        print("源码兼容下限: %d.%d；已测试上限: %d.%d"
              % (MIN_PYTHON[0], MIN_PYTHON[1], MAX_TESTED[0], MAX_TESTED[1]))
        print("Windows: %s" % platform.version())
        return 0
    if args.config:
        config_path = Path(args.config).resolve()
    else:
        frozen_dir = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
        config_path = frozen_dir / DEFAULT_CONFIG
    try:
        cfg = load_config(config_path)
        # Data directory precedence: --data-dir > config.json data_dir > config file dir.
        data_dir = Path(args.data_dir).resolve() if args.data_dir else (
            Path(str(cfg.get("data_dir", ""))).resolve() if str(cfg.get("data_dir", "")).strip() else config_path.parent)
        if data_dir != config_path.parent:
            data_dir.mkdir(parents=True, exist_ok=True)
            cfg["state_file"] = str(data_dir / Path(cfg["state_file"]).name)
            cfg["local_log"] = str(data_dir / Path(cfg["local_log"]).name)
            cfg["outbox_file"] = str(data_dir / Path(cfg["outbox_file"]).name)
            cfg["guard_file"] = str(data_dir / Path(cfg.get("guard_file", "guard.json")).name)
        if args.self_test:
            self_test(cfg)
            return 0
        if args.replay:
            return replay_alerts(Path(args.replay).resolve(), cfg)
        if args.check:
            raw = run_wevtutil(["gl", CHANNEL])
            enabled = re.search(r"(?m)^enabled:\s*true\s*$", raw, re.I) is not None
            print(f"Windows={platform.platform()} enabled={enabled} latest_record_id={latest_record_id(True)}")
            return 0 if enabled else 2
        Agent(cfg, config_path).run()
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    configure_output()
    check_runtime()
    raise SystemExit(main())
