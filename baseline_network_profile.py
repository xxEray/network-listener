# baseline_network_profile.py v1.1
# Pre-provision network baseline for Windows student machines.
#
# Goal: run on ONE representative student machine before listener deployment,
# record DNS lookups and network connections, then produce a config patch with
# only low-risk operating-system/background traffic.  The output is reviewed by
# the operator and merged into every provisioned listener config by provision.ps1.
#
# Recommended usage (administrator PowerShell):
#   python baseline_network_profile.py --minutes 30 --out-dir network-baseline
#   python baseline_network_profile.py --minutes 30 --tools "code.exe,python.exe"
#
# Output:
#   config-patch.json     mergeable listener whitelist/ignore patch
#   baseline-report.json  complete machine-local profile and statistics
#   events.jsonl          raw DNS/connection observations for audit
#   review-domains.csv    domains needing a human decision
#   review-ips.csv        public IPs needing a human decision
#   review-processes.csv  processes not auto-whitelisted
from __future__ import annotations

import argparse
import csv
import ctypes
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET

VERSION = "1.1"
CHANNEL = "Microsoft-Windows-DNS-Client/Operational"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

# These are Windows/background components.  Do not put ordinary user processes or
# browsers here: a broad ignore by browser process name would hide real cheating.
SYSTEM_PROCESSES = {
    "system", "idle", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "spoolsv.exe", "taskhostw.exe",
    "audiodg.exe", "fontdrvhost.exe", "dwm.exe", "sihost.exe", "conhost.exe",
    "searchindexer.exe", "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
    "wudfhost.exe", "wmidcprv.exe", "wmiapsrv.exe", "wmiprvse.exe", "dllhost.exe",
    "ctfmon.exe", "runtimebroker.exe", "shellexperiencehost.exe", "windowsdefendermp.exe",
    "msseces.exe", "onedrive.exe", "onedrivesetup.exe", "onedrivestandaloneupdater.exe",
}

# Contest tools often talk to package/CDN/IDE endpoints while a student may also use
# them to browse.  Their domains therefore go to the review file unless the operator
# enables --auto-tool-ignore.
TOOL_PROCESSES = {
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe",
    "vivaldi.exe", "360se.exe", "360chrome.exe", "qqbrowser.exe", "sogouexplorer.exe",
    "maxthon.exe", "python.exe", "pythonw.exe", "java.exe", "javaw.exe", "javaws.exe",
    "code.exe", "codew.exe", "sublime_text.exe", "notepad++.exe", "devenv.exe",
    "gcc.exe", "g++.exe", "clang.exe", "clang++.exe", "cl.exe", "cargo.exe",
    "rustc.exe", "gdb.exe", "lldb.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
}

# Mirror the collector default so baseline reports flag the same TLDs before
# an operator changes policy.json.
DEFAULT_SUSPICIOUS_TLDS = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "work"}

# Broad domain suffixes that are infrastructure, not useful content.  Plain DNS hosts
# are always kept exact; these suffix rules deliberately do not include search or
# general web domains.
AUTO_DOMAIN_SUFFIXES = {
    "*.microsoft.com", "*.windowsupdate.com", "*.windows.com", "*.msedge.net",
    "*.azurefd.net", "*.azureedge.net", "*.footprintdns.com", "*.wns.windows.com",
    "*.delivery.mp.microsoft.com", "*.symantec.com", "*.digicert.com", "*.entrust.net",
    "*.sectigo.com", "*.amazontrust.com", "*.thawte.com", "*.geotrust.com",
    "*.ocsp-certum.com", "*.identrust.com",
}

TOOL_PUBLIC_SUFFIXES = {
    "*.gstatic.com", "*.googleapis.com", "*.cdn.mozilla.net", "*.mozilla.org",
    "*.pythonhosted.org", "*.pypi.org", "*.python.org", "*.jsdelivr.net",
    "*.unpkg.com", "*.cloudflare.com", "*.akamaihd.net", "*.amazonaws.com",
    "*.visualstudio.com", "*.vsls.experiments.appspot.com", "*.gallerycdn.vsassets.io",
}

UTC = dt.timezone.utc


def configure_output() -> None:
    """Make argparse/help readable on Windows legacy code pages."""
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
    return dt.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def iso_local(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(message: str) -> None:
    print(f"[{utc_now()}] {message}", flush=True)


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(str(path) + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, path)


def norm_domain(name: str) -> str:
    name = (name or "").strip().rstrip(".").lower()
    if not name:
        return ""
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def domain_matches_suffix(host: str, rule: str) -> bool:
    host = norm_domain(host)
    rule = norm_domain(rule[2:]) if rule.startswith("*.") else norm_domain(rule)
    return bool(host and rule and (host == rule or host.endswith("." + rule)))


def is_global_ip(text: str) -> bool:
    raw = (text or "").strip().split("%", 1)[0]
    if raw.lower().startswith("::ffff:"):
        raw = raw[7:]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return not any((ip.is_loopback, ip.is_link_local, ip.is_multicast,
                    ip.is_reserved, ip.is_unspecified, ip.is_private))


def decode_console(data: Optional[bytes]) -> str:
    if not data:
        return ""
    for encoding in ("utf-8-sig", "utf-16"):
        try:
            text = data.decode(encoding)
            if "\ufffd" not in text:
                return text
        except (UnicodeDecodeError, ValueError):
            pass
    try:
        return data.decode("mbcs", "replace")
    except (LookupError, ValueError):
        return data.decode("latin-1", "replace")


def run_command(args: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    cp = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        creationflags=CREATE_NO_WINDOW, timeout=timeout)
    return cp.returncode, decode_console(cp.stdout), decode_console(cp.stderr)


def event_fields(elem: ET.Element) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    for child in elem.iter():
        tag = child.tag.lower()
        if tag.endswith("eventid"):
            fields["EventID"] = child.text or ""
        elif tag.endswith("eventrecordid"):
            fields["EventRecordID"] = child.text or "0"
        elif tag.endswith("timecreated"):
            fields["TimeCreated"] = child.attrib.get("SystemTime", "")
        elif tag.endswith("security"):
            fields["UserID"] = child.attrib.get("UserID", "")
        elif tag.endswith("data"):
            fields[child.attrib.get("Name", "")] = child.text or ""
    return fields


def parse_wevtutil_xml(raw: str) -> List[Dict[str, str]]:
    raw = raw.lstrip("\ufeff\x00\r\n \t")
    raw = re.sub(r"<\?xml[^>]*\?>", "", raw)
    if not raw.strip():
        return []
    root = ET.fromstring("<Events>" + raw + "</Events>")
    return [event_fields(e) for e in root]


class ProcessLookup:
    """Maps a PID to its image basename and path, with a small TTL cache."""

    def __init__(self, ttl_seconds: int = 60):
        self.ttl = max(5, ttl_seconds)
        self.cache: Dict[int, Tuple[float, str, str]] = {}
        self.unknown_count = 0

    def query_full_path(self, pid: int) -> Tuple[str, str]:
        if pid <= 0:
            return "unknown", ""
        now = time.time()
        cached = self.cache.get(pid)
        if cached and now - cached[0] < self.ttl:
            return cached[1], cached[2]
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_ulong),
        ]
        kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = None
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            self.unknown_count += 1
            return "unknown", ""
        try:
            buf = ctypes.create_unicode_buffer(32768)
            size = ctypes.c_ulong(len(buf))
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                full_path = buf.value
                self.cache[pid] = (now, os.path.basename(full_path), full_path)
                return self.cache[pid][1:]
            self.unknown_count += 1
            return "unknown", ""
        except Exception:
            self.unknown_count += 1
            return "unknown", ""
        finally:
            kernel32.CloseHandle(handle)

    def refresh(self, pids: Iterable[int]) -> None:
        for pid in list(pids):
            self.query_full_path(int(pid))


class DnsWatcher:
    """Reads only DNS records that occur after the watcher starts."""

    def __init__(self, cursor: int):
        self.cursor = max(0, cursor)
        self.errors = 0
        self.last_error = ""

    def poll(self) -> List[Dict[str, str]]:
        args = ["wevtutil.exe", "qe", CHANNEL,
                "/q:*[System[(EventRecordID > " + str(self.cursor) + ")]]",
                "/c:1000", "/rd:false", "/f:xml"]
        try:
            code, out, err = run_command(args, 20)
            if code:
                self.errors += 1
                self.last_error = (err or out or "wevtutil exit=%d" % code).strip()
                return []
            rows = parse_wevtutil_xml(out)
            max_rid = self.cursor
            result: List[Dict[str, str]] = []
            for row in rows:
                try:
                    rid = int(row.get("EventRecordID", "0"))
                except ValueError:
                    continue
                max_rid = max(max_rid, rid)
                if row.get("EventID") in ("3008", "3006"):
                    result.append(row)
            self.cursor = max(self.cursor, max_rid)
            return result
        except (OSError, subprocess.SubprocessError, ET.ParseError) as exc:
            self.errors += 1
            self.last_error = str(exc)
            return []


def endpoint_ip(remote: str) -> str:
    remote = remote.strip()
    if remote.startswith("[") and "]:" in remote:
        return remote.split("]:", 1)[0][1:]
    return remote.rsplit(":", 1)[0]


def endpoint_port(remote: str) -> str:
    remote = remote.strip()
    if remote.startswith("[") and "]:" in remote:
        return remote.rsplit("]:", 1)[1]
    if ":" in remote:
        return remote.rsplit(":", 1)[1]
    return ""


def parse_netstat(text: str, process_lookup: ProcessLookup, snapshot_time: float) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0].upper() not in ("TCP", "UDP"):
            continue
        proto = parts[0].upper()
        if proto == "TCP":
            if len(parts) < 5 or parts[-2].upper() != "ESTABLISHED":
                continue
            remote, pid_text = parts[2], parts[-1]
            state = parts[-2]
        else:
            if len(parts) < 4:
                continue
            remote, pid_text = parts[2], parts[-1]
            state = ""
        if not pid_text.isdigit():
            continue
        pid = int(pid_text)
        proc, path = process_lookup.query_full_path(pid)
        raw_ip = endpoint_ip(remote)
        remote_port = endpoint_port(remote)
        try:
            ip_obj = ipaddress.ip_address(raw_ip.split("%", 1)[0])
            scope = "loopback" if ip_obj.is_loopback else (
                "link_local" if ip_obj.is_link_local else
                "multicast" if ip_obj.is_multicast else
                "private" if ip_obj.is_private else "public")
        except ValueError:
            ip_obj = None
            scope = "invalid"
        rows.append({
            "at": iso_local(snapshot_time),
            "protocol": proto,
            "local": parts[1],
            "remote": remote,
            "remote_ip": raw_ip,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
            "process": proc,
            "process_path": path,
            "scope": scope,
        })
    return rows


def resolve_dns_ips(value: str) -> List[str]:
    out: List[str] = []
    for token in re.split(r"[;,\s]+", (value or "").strip()):
        token = token.strip()
        if not token:
            continue
        try:
            out.append(str(ipaddress.ip_address(token.split("%", 1)[0])))
        except ValueError:
            pass
    return out


def unique_sorted(values: Iterable[str]) -> List[str]:
    return sorted({str(v).strip().lower() for v in values if str(v).strip()})


def merged_suffix_rule(host: str, process: str, auto_tool_domains: bool) -> Optional[str]:
    host = norm_domain(host)
    if not host or "." not in host:
        return None
    for rule in AUTO_DOMAIN_SUFFIXES:
        if domain_matches_suffix(host, rule):
            return rule
    if auto_tool_domains:
        # The explicit flag is intentionally required; a broad suffix is not inferred
        # from a browser or IDE just because it appeared in the baseline.
        for rule in TOOL_PUBLIC_SUFFIXES:
            if domain_matches_suffix(host, rule):
                return rule
    return None


def write_csv(path: Path, headers: List[str], rows: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f, lineterminator="\r\n")
        writer.writerow(headers)
        for row in rows:
            writer.writerow([row.get(h, "") for h in headers])


def main() -> int:
    configure_output()
    parser = argparse.ArgumentParser(
        description="Run a pre-provision network baseline on one Windows student machine.")
    parser.add_argument("--minutes", type=int, default=30, help="观测时长，默认 30 分钟")
    parser.add_argument("--out-dir", default="network-baseline", help="输出目录")
    parser.add_argument("--tools", default="", help="赛时工具进程名，逗号分隔，例如 code.exe,python.exe")
    parser.add_argument("--auto-tool-ignore", action="store_true",
                        help="把命中基础设施后缀的赛时工具 DNS 也写入 ignored_domains")
    parser.add_argument("--no-restore-dns-channel", action="store_true",
                        help="退出时不还原 DNS 事件通道原有开关状态")
    parser.add_argument("--no-enable-dns-channel", action="store_true",
                        help="不启用 DNS 事件通道；通常不建议，除非通道已启用")
    args = parser.parse_args()
    if os.name != "nt":
        print("此脚本只支持 Windows 学生机。", file=sys.stderr)
        return 2
    if args.minutes < 1 or args.minutes > 240:
        parser.error("--minutes 必须在 1..240")
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        admin = False
    if not admin:
        print("请用管理员权限运行：启用/读取 DNS 事件日志需要管理员权限。", file=sys.stderr)
        return 2

    extra_tools = {p.strip().lower() for p in re.split(r"[,\s;]+", args.tools or "") if p.strip()}
    system_processes = {p.lower() for p in SYSTEM_PROCESSES}
    tool_processes = {p.lower() for p in TOOL_PROCESSES} | extra_tools

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = out_dir / "events.jsonl"
    report_path = out_dir / "baseline-report.json"
    patch_path = out_dir / "config-patch.json"

    channel_state_before: Dict[str, Any] = {}
    code, out, err = run_command(["wevtutil.exe", "gl", CHANNEL], 10)
    if code == 0:
        for line in out.splitlines():
            if line.lower().startswith("enabled:"):
                channel_state_before["enabled"] = line.split(":", 1)[1].strip().lower()
            elif line.lower().startswith("maxsize:"):
                channel_state_before["max_size"] = line.split(":", 1)[1].strip()
    else:
        log(f"读取 DNS 通道状态失败：{(err or out).strip()}")

    if channel_state_before.get("enabled") == "false":
        if args.no_enable_dns_channel:
            log("警告：DNS 事件通道当前是关闭的，且未要求启用；DNS 白名单将严重不完整。")
        else:
            code, out, err = run_command(["wevtutil.exe", "sl", CHANNEL, "/e:true"], 10)
            if code:
                log(f"启用 DNS 事件通道失败：{(err or out).strip()}")
                return 2
            log("已启用 DNS 事件通道（结束后将恢复原状态）")

    try:
        code, out, err = run_command(["wevtutil.exe", "qe", CHANNEL, "/c:1", "/rd:true", "/f:xml"], 10)
        if code:
            log(f"读取 DNS 事件起点失败：{(err or out).strip()}")
            if not args.no_restore_dns_channel and channel_state_before.get("enabled") == "false":
                run_command(["wevtutil.exe", "sl", CHANNEL, "/e:false"], 10)
                log("已恢复 DNS 事件通道为关闭状态")
            return 2
        rows = parse_wevtutil_xml(out)
        start_cursor = int(rows[0].get("EventRecordID", "0")) if rows else 0
        watcher = DnsWatcher(start_cursor)
        log(f"开始基线：{args.minutes} 分钟，从 DNS EventRecordID={start_cursor} 之后记录")
    except (OSError, subprocess.SubprocessError, ET.ParseError) as exc:
        log(f"读取 DNS 事件起点失败：{exc}")
        return 2

    dns_rows: List[Dict[str, Any]] = []
    dns_by_key: Dict[str, Dict[str, Any]] = {}
    conn_rows: List[Dict[str, Any]] = []
    process_lookup = ProcessLookup()
    ip_to_domain: Dict[str, str] = {}
    raw_file = raw_path.open("a", encoding="utf-8", newline="")
    start_time = time.time()
    deadline = start_time + args.minutes * 60
    next_dns = start_time
    next_conn = start_time
    next_process_refresh = start_time + 60
    next_progress = start_time + 60
    stats = {
        "dns_events": 0,
        "connection_snapshots": 0,
        "connections_seen": 0,
        "public_connections_seen": 0,
        "watcher_errors": 0,
    }

    def append_raw(kind: str, data: Dict[str, Any]) -> None:
        raw_file.write(json.dumps({"kind": kind, "received_at": utc_now(), **data},
                                  ensure_ascii=False, separators=(",", ":")) + "\n")
        raw_file.flush()

    def record_dns(rows: List[Dict[str, str]]) -> None:
        for row in rows:
            try:
                rid = int(row.get("EventRecordID", "0"))
            except ValueError:
                continue
            host = norm_domain(row.get("QueryName", ""))
            event_id = row.get("EventID", "")
            pid_text = str(row.get("ProcessID", "0") or "0")
            pid = int(pid_text) if pid_text.isdigit() else 0
            proc, proc_path = process_lookup.query_full_path(pid)
            status = row.get("QueryStatus", "")
            resolved = resolve_dns_ips(row.get("QueryResults", ""))
            rec = {
                "event_record_id": rid,
                "event_id": event_id,
                "time": row.get("TimeCreated", ""),
                "received": utc_now(),
                "domain": host,
                "query_status": status,
                "resolved_ips": resolved,
                "process_id": pid,
                "process": proc,
                "process_path": proc_path,
                "user_id": row.get("UserID", ""),
                "observation": "completed" if event_id == "3008" else "query_attempt_only",
            }
            dns_rows.append(rec)
            append_raw("dns", rec)
            if event_id != "3008":
                continue
            stats["dns_events"] += 1
            key = f"{host}|{proc}|{status}"
            item = dns_by_key.setdefault(key, {
                "domain": host, "process": proc, "process_path": proc_path,
                "status": status, "count": 0, "resolved_ips": set(),
                "process_id": pid, "event_ids": set(),
            })
            item["count"] += 1
            item["resolved_ips"].update(resolved)
            item["event_ids"].add(event_id)
            for ip in resolved:
                if is_global_ip(ip) and ip not in ip_to_domain:
                    ip_to_domain[ip] = host

    def record_connections() -> None:
        code, out, err = run_command(["netstat.exe", "-ano"], 25)
        at = time.time()
        if code:
            log(f"netstat 读取失败：{(err or out).strip()}")
            return
        rows = parse_netstat(out, process_lookup, at)
        conn_rows.extend(rows)
        stats["connection_snapshots"] += 1
        stats["connections_seen"] += len(rows)
        stats["public_connections_seen"] += sum(1 for r in rows if r["scope"] == "public")
        append_raw("connections", {"count": len(rows), "rows": rows})

    try:
        while time.time() < deadline:
            now = time.time()
            if now >= next_dns:
                rows = watcher.poll()
                if rows:
                    record_dns(rows)
                next_dns = time.time() + 2
            if now >= next_conn:
                record_connections()
                next_conn = time.time() + 10
            if now >= next_process_refresh:
                pids: Set[int] = set()
                for row in dns_by_key.values():
                    if row["process"] == "unknown" and row.get("process_path", "") == "":
                        pass
                process_lookup.refresh([r["process_id"] for r in dns_rows[-1000:]])
                for row in conn_rows[-200:]:
                    process_lookup.query_full_path(row["pid"])
                next_process_refresh = time.time() + 60
            if now >= next_progress:
                remaining = max(0, int(deadline - time.time()))
                log(f"进行中：DNS={stats['dns_events']}，连接快照={stats['connection_snapshots']}，"
                    f"剩余 {remaining // 60} 分 {remaining % 60} 秒")
                next_progress = time.time() + 60
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("收到 Ctrl+C，提前结束并生成报告")
    finally:
        raw_file.close()
        if (not args.no_restore_dns_channel and
                channel_state_before.get("enabled") == "false"):
            run_command(["wevtutil.exe", "sl", CHANNEL, "/e:false"], 10)
            log("已恢复 DNS 事件通道为关闭状态")

    # Complete process attributes after the observation window; short-lived PIDs may
    # disappear, which is recorded as unknown rather than guessed.
    for row in dns_by_key.values():
        if row.get("process_id"):
            proc, proc_path = process_lookup.query_full_path(row["process_id"])
            row["process"] = row["process"] if row["process"] != "unknown" else proc
            row["process_path"] = row["process_path"] or proc_path

    # Build the profile, auto-whitelists, and review lists.
    review_domains: List[Dict[str, Any]] = []
    ignored_domains: Set[str] = set()
    ignored_processes: Set[str] = set()
    ignored_ips: Set[str] = set()
    review_ips: List[Dict[str, Any]] = []
    review_processes: Dict[str, Dict[str, Any]] = {}

    for row in dns_by_key.values():
        proc = row["process"].lower()
        host = row["domain"]
        resolved = sorted(row["resolved_ips"])
        if not host or "." not in host:
            continue
        suffix_rule = merged_suffix_rule(host, proc, bool(args.auto_tool_ignore))
        if proc in system_processes:
            ignored_processes.add(row["process"])
            if suffix_rule:
                ignored_domains.add(suffix_rule)
            else:
                ignored_domains.add(host)
            for ip in resolved:
                if is_global_ip(ip):
                    ignored_ips.add(ip)
            continue
        if proc in tool_processes:
            if suffix_rule:
                ignored_domains.add(suffix_rule)
            else:
                review_domains.append({
                    "domain": host, "process": row["process"],
                    "process_path": row["process_path"], "count": row["count"],
                    "resolved_ips": ";".join(resolved),
                    "reason": "赛时工具访问，未命中已知基础设施后缀",
                })
                for ip in resolved:
                    if is_global_ip(ip):
                        review_ips.append({
                            "ip": ip, "domain": host, "process": row["process"],
                            "remote_ports": "", "count": row["count"],
                            "reason": "由赛时工具解析，未自动加入忽略名单",
                        })
            continue
        info = review_processes.setdefault(row["process"], {
            "process": row["process"], "process_path": row["process_path"],
            "dns_domains": set(), "count": 0,
        })
        info["dns_domains"].add(host)
        info["count"] += row["count"]
        review_domains.append({
            "domain": host, "process": row["process"],
            "process_path": row["process_path"], "count": row["count"],
            "resolved_ips": ";".join(resolved),
            "reason": "未识别进程访问，需要人工判断",
        })

    seen_review_ips: Set[str] = set()
    tcp_conn_by_ip: Dict[str, Dict[str, Any]] = {}
    for row in conn_rows:
        if row["scope"] != "public":
            continue
        ip = row["remote_ip"].split("%", 1)[0]
        info = tcp_conn_by_ip.setdefault(ip, {
            "ip": ip, "processes": set(), "ports": set(), "count": 0, "domains": set(),
        })
        info["processes"].add(row["process"])
        info["ports"].add(row["remote_port"])
        info["count"] += 1
        domain = ip_to_domain.get(ip, "")
        if domain:
            info["domains"].add(domain)
        proc = row["process"].lower()
        if proc in system_processes or ip in ignored_ips:
            ignored_ips.add(ip)
        elif ip not in seen_review_ips:
            seen_review_ips.add(ip)

    for ip, info in tcp_conn_by_ip.items():
        if ip in ignored_ips:
            continue
        proc = next(iter(info["processes"]), "unknown").lower()
        reason = "公网 TCP 未由白名单 DNS 解释，需要人工判断"
        if proc in tool_processes:
            reason = "赛时工具的公网连接，未自动加入忽略名单"
        review_ips.append({
            "ip": ip, "domain": ";".join(sorted(info["domains"])),
            "process": ";".join(sorted(info["processes"])),
            "remote_ports": ";".join(sorted(info["ports"])),
            "count": info["count"], "reason": reason,
        })

    # Deduplicate and make the patch stable.
    ignored_domains = unique_sorted(ignored_domains)
    ignored_processes = unique_sorted(ignored_processes)
    ignored_ips = unique_sorted(ignored_ips)
    review_domains.sort(key=lambda r: (str(r["domain"]), str(r["process"])))
    review_domains_unique: Dict[str, Dict[str, Any]] = {}
    for row in review_domains:
        key = f"{row['domain']}|{row['process']}"
        if key in review_domains_unique:
            old = review_domains_unique[key]
            old["count"] += row["count"]
            old["resolved_ips"] = ";".join(sorted(set(
                [old["resolved_ips"], row["resolved_ips"]]) - {""}))
        else:
            review_domains_unique[key] = row
    review_domains = list(review_domains_unique.values())
    review_ips_unique: Dict[str, Dict[str, Any]] = {}
    for row in review_ips:
        key = row["ip"]
        if key in review_ips_unique:
            old = review_ips_unique[key]
            old["count"] = int(old.get("count", 0) or 0) + int(row.get("count", 0) or 0)
            old["remote_ports"] = ";".join(sorted(set(
                [old.get("remote_ports", ""), row.get("remote_ports", "")]) - {""}))
            old["process"] = ";".join(sorted(set(
                [old.get("process", ""), row.get("process", "")]) - {""}))
        else:
            review_ips_unique[key] = row
    review_ips = sorted(review_ips_unique.values(), key=lambda r: str(r["ip"]))

    process_summary: List[Dict[str, Any]] = []
    all_processes = [r["process"] for r in dns_by_key.values()] + [r["process"] for r in conn_rows]
    for proc in unique_sorted(all_processes):
        proc_lower = proc.lower()
        domains = sorted({r["domain"] for r in dns_by_key.values() if r["process"].lower() == proc_lower})
        paths = sorted({r["process_path"] for r in dns_by_key.values()
                        if r["process"].lower() == proc_lower and r["process_path"]})
        paths += sorted({r["process_path"] for r in conn_rows
                         if r["process"].lower() == proc_lower and r["process_path"]})
        matched_dns = [r for r in dns_by_key.values() if r["process"].lower() == proc_lower]
        matched_connections = [r for r in conn_rows if r["process"].lower() == proc_lower]
        remote_ips = sorted({r["remote_ip"] for r in matched_connections
                             if r["scope"] == "public" and r["remote_ip"]})
        remote_ports = sorted({r["remote_port"] for r in matched_connections
                               if r["scope"] == "public" and r["remote_port"]},
                              key=lambda value: (len(value), value))
        process_summary.append({
            "process": proc,
            "process_paths": sorted(set(paths)),
            "dns_domains": domains,
            "dns_events": sum(int(r["count"]) for r in matched_dns),
            "tcp_records": len(matched_connections),
            "public_tcp_records": sum(1 for r in matched_connections if r["scope"] == "public"),
            "remote_ips": remote_ips,
            "remote_ports": remote_ports,
            "category": "system" if proc_lower in system_processes else
                        ("tool" if proc_lower in tool_processes else "unknown"),
        })

    dns_domain_rows: Dict[str, List[Dict[str, str]]] = {}
    for row in dns_rows:
        if row.get("event_id") != "3008":
            continue
        key = f"{row.get('domain', '')}|{row.get('process', '')}|{row.get('query_status', '')}"
        dns_domain_rows.setdefault(key, []).append(row)

    domain_summary = []
    for key, row in sorted(dns_by_key.items()):
        key_rows = dns_domain_rows.get(key, [])
        times = sorted(str(r.get("time", "")) for r in key_rows if r.get("time"))
        domain_summary.append({
            "domain": row["domain"], "process": row["process"],
            "process_path": row["process_path"], "status": row["status"],
            "count": row["count"], "resolved_ips": sorted(row["resolved_ips"]),
            "first_seen": times[0] if times else "",
            "last_seen": times[-1] if times else "",
        })

    ip_evidence: Dict[str, Dict[str, Any]] = {}
    for row in dns_by_key.values():
        for ip in row.get("resolved_ips", []):
            if not is_global_ip(ip):
                continue
            evidence = ip_evidence.setdefault(ip, {
                "ip": ip,
                "resolved_domains": set(),
                "connection_domains": set(),
                "processes": set(),
                "remote_ports": set(),
                "dns_events": 0,
                "tcp_records": 0,
            })
            evidence["resolved_domains"].add(row["domain"])
            evidence["processes"].add(row["process"])
            evidence["dns_events"] += int(row["count"])
    for row in conn_rows:
        if row["scope"] != "public":
            continue
        ip = row["remote_ip"]
        evidence = ip_evidence.setdefault(ip, {
            "ip": ip,
            "resolved_domains": set(),
            "connection_domains": set(),
            "processes": set(),
            "remote_ports": set(),
            "dns_events": 0,
            "tcp_records": 0,
        })
        evidence["processes"].add(row["process"])
        evidence["remote_ports"].add(row["remote_port"])
        evidence["tcp_records"] += 1
        domain = ip_to_domain.get(ip, "")
        if domain:
            evidence["connection_domains"].add(domain)

    patch = {
        "schema": "network_baseline_config_patch_v1",
        "generated_at": utc_now(),
        "host": platform.node(),
        "duration_seconds": round(time.time() - start_time, 3),
        "tools_cli": sorted(extra_tools),
        "ignored_domains": ignored_domains,
        "ignored_processes": ignored_processes,
        "ignored_ips": ignored_ips,
        "review": {
            "domains": review_domains,
            "ips": review_ips,
            "processes": [
                {"process": k, "process_path": v["process_path"],
                 "dns_domains": sorted(v["dns_domains"]), "count": v["count"]}
                for k, v in sorted(review_processes.items())
            ],
        },
        "warnings": [],
    }
    if stats["dns_events"] == 0:
        patch["warnings"].append("本次没有捕获到已完成的 DNS 事件，DNS 忽略名单不完整。")
    if stats["connection_snapshots"] == 0:
        patch["warnings"].append("本次没有捕获到网络连接快照，TCP 忽略名单不完整。")
    if not ignored_domains and not ignored_processes and not ignored_ips:
        patch["warnings"].append("未生成任何自动忽略项，请在人工复核后手工补充。")

    def ip_evidence_json(ip: str) -> Dict[str, Any]:
        evidence = ip_evidence[ip]
        return {
            "resolved_domains": sorted(evidence["resolved_domains"]),
            "connection_domains": sorted(evidence["connection_domains"]),
            "processes": sorted(evidence["processes"]),
            "remote_ports": sorted(evidence["remote_ports"],
                                   key=lambda value: (len(value), value)),
            "dns_events": evidence["dns_events"],
            "tcp_records": evidence["tcp_records"],
        }

    ignored_domain_analysis: List[Dict[str, Any]] = []
    for rule in ignored_domains:
        matched = [row for row in domain_summary
                   if row["domain"] == rule or domain_matches_suffix(row["domain"], rule)]
        ignored_domain_analysis.append({
            "rule": rule,
            "matched_domains": matched,
            "dns_events": sum(int(row["count"]) for row in matched),
            "resolved_ips": sorted({ip for row in matched for ip in row["resolved_ips"]}),
            "processes": sorted({row["process"] for row in matched}),
        })

    ignored_process_analysis = [row for row in process_summary
                                if row["process"].lower() in ignored_processes]
    ignored_ip_analysis = [
        {"ip": ip, "policy": "ignored", "evidence": ip_evidence_json(ip)}
        for ip in ignored_ips if ip in ip_evidence
    ]
    allowed_domain_candidates = [
        row for row in domain_summary
        if row["domain"] not in ignored_domains and
        not any(domain_matches_suffix(row["domain"], rule) for rule in ignored_domains)
    ]

    tld_counts: Dict[str, int] = {}
    for row in domain_summary:
        host = norm_domain(row["domain"])
        if not host or "." not in host:
            continue
        tld = host.rsplit(".", 1)[-1]
        tld_counts[tld] = tld_counts.get(tld, 0) + int(row["count"])
    suspicious_tld_candidates = [
        {"tld": tld, "dns_events": count,
         "domains": [row for row in domain_summary if
                     norm_domain(row["domain"]).rsplit(".", 1)[-1] == tld]}
        for tld, count in sorted(tld_counts.items(), key=lambda item: item[0])
        if tld in DEFAULT_SUSPICIOUS_TLDS
    ]
    direct_ip_dns_candidates = [
        row for row in domain_summary
        if row["domain"].count(".") == 3 and
        all(part.isdigit() and 0 <= int(part) <= 255 for part in row["domain"].split("."))
    ]
    nonstandard_port_candidates = []
    for ip in sorted(ip_evidence):
        evidence = ip_evidence[ip]
        ports = sorted({port for port in evidence["remote_ports"] if str(port) not in ("80", "443")},
                       key=lambda value: (len(value), value))
        if ports:
            nonstandard_port_candidates.append({
                "remote_ports": ports,
                "evidence": ip_evidence_json(ip),
            })

    policy_analysis = {
        "note": "以下证据按 policy.json 字段分组，供复核后直接更新 policy.json。",
        "allowed_domains": allowed_domain_candidates,
        "ignored_domains": ignored_domain_analysis,
        "ignored_processes": ignored_process_analysis,
        "ignored_ips": ignored_ip_analysis,
        "process_grades": {
            "interactive": [row for row in process_summary if row["category"] == "tool"],
            "system": [row for row in process_summary if row["category"] == "system"],
            "unknown": [row for row in process_summary if row["category"] == "unknown"],
        },
        "high_risk": {
            "flag_direct_ip": {
                "direct_ip_dns_candidates": direct_ip_dns_candidates,
            },
            "flag_nonstandard_port": {
                "nonstandard_port_candidates": nonstandard_port_candidates,
            },
            "suspicious_tlds": {
                "observed_tlds": tld_counts,
                "suspicious_tld_candidates": suspicious_tld_candidates,
            },
        },
    }

    report = {
        "schema": "network_baseline_report_v1",
        "version": VERSION,
        "generated_at": patch["generated_at"],
        "host": patch["host"],
        "duration_seconds": patch["duration_seconds"],
        "arguments": {
            "minutes": args.minutes,
            "out_dir": str(out_dir),
            "tools_cli": sorted(extra_tools),
            "auto_tool_ignore": bool(args.auto_tool_ignore),
        },
        "dns_channel": {
            "name": CHANNEL,
            "state_before": channel_state_before,
            "cursor_start": start_cursor,
            "cursor_end": watcher.cursor,
            "errors": watcher.errors,
            "last_error": watcher.last_error,
        },
        "stats": {
            **stats,
            "unique_dns": len(domain_summary),
            "unique_processes": len(process_summary),
            "auto_ignored_domains": len(ignored_domains),
            "auto_ignored_processes": len(ignored_processes),
            "auto_ignored_ips": len(ignored_ips),
            "review_domains": len(review_domains),
            "review_ips": len(review_ips),
        },
        "processes": process_summary,
        "domains": domain_summary,
        "policy_analysis": policy_analysis,
        "connections": {
            "total_records": len(conn_rows),
            "public_records": sum(1 for r in conn_rows if r["scope"] == "public"),
            "records": conn_rows,
        },
        "dns_events": dns_rows,
    }

    atomic_json(patch_path, patch)
    atomic_json(report_path, report)
    write_csv(out_dir / "review-domains.csv",
              ["domain", "process", "process_path", "count", "resolved_ips", "reason"],
              review_domains)
    write_csv(out_dir / "review-ips.csv",
              ["ip", "domain", "process", "remote_ports", "count", "reason"],
              review_ips)
    write_csv(out_dir / "review-processes.csv",
              ["process", "process_path", "dns_domains", "count"],
              [{"process": k, "process_path": v["process_path"],
                "dns_domains": ";".join(sorted(v["dns_domains"])), "count": v["count"]}
               for k, v in sorted(review_processes.items())])
    (out_dir / "config-patch.txt").write_text(
        "ignored_domains:\n" + "\n".join(ignored_domains) +
        "\n\nignored_processes:\n" + "\n".join(ignored_processes) +
        "\n\nignored_ips:\n" + "\n".join(ignored_ips) + "\n",
        encoding="utf-8")
    log(f"基线完成：{out_dir}")
    log(f"输出补丁：{patch_path}")
    log(f"自动忽略 DNS={len(ignored_domains)} 进程={len(ignored_processes)} 公网IP={len(ignored_ips)}；"
        f"待复核 DNS={len(review_domains)} 公网IP={len(review_ips)}")
    log("请复核 review-*.csv 后，把 config-patch.json 传给 provision.ps1 的 -NetworkProfile。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
