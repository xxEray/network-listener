#!/usr/bin/env python3
"""guard.py: dual-process watchdog for listener.py (D17, §6).

Standard library only, Python 3.8+ (Win7 compatible). Behaviour:
- single instance via a named mutex;
- starts listener.py with the machine's Python when it is not running;
- checks every 3 seconds, restarts with backoff 2s -> 5s -> 10s (cap 30s);
- stops restarting after 10 consecutive failures but keeps running and reporting;
- writes guard.json into the data directory so listener.py can report
  {"guard": true, "guard_restarts": N} in its heartbeat (§6.2);
- listener.py watches guard.py the same way, so killing either one gets the
  other to restart it within seconds.

v1.5: no PyInstaller exes anywhere — both sides run as .py from source, so
liveness is checked by PID (guard.json "guard_pid" / state.json "pid") instead
of by image name, and children are spawned with sys.executable.

No scheduled task is created (D22). The watchdog runs under pythonw.exe when
available so no console window appears on the student desktop (D26).
"""
import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

LISTENER_SCRIPT = "listener.py"
VERSION = "1.5"

BACKOFF_STEPS = [2, 5, 10]          # seconds; capped at 30 afterwards
BACKOFF_CAP = 30
MAX_CONSECUTIVE_FAILURES = 10
CHECK_INTERVAL = 3


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def log(message: str) -> None:
    print(f"[{utc_now()}] guard: {message}", flush=True)


def read_json(path: Path, default: Any) -> Any:
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            return json.load(f)
    except (IOError, ValueError):
        return default


def atomic_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = Path(str(path) + ".tmp")
    try:
        with temp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(temp, path)
    except OSError:
        pass


def process_running_by_name(name: str) -> bool:
    if os.name != "nt":
        return False
    TH32CS_SNAPPROCESS = 0x00000002

    class Entry(ctypes.Structure):
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

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Entry)]
        kernel32.Process32FirstW.restype = ctypes.c_int
        kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Entry)]
        kernel32.Process32NextW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            return False
        try:
            entry = Entry()
            entry.dwSize = ctypes.sizeof(Entry)
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
    TH32CS_SNAPPROCESS = 0x00000002

    class Entry(ctypes.Structure):
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

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Entry)]
        kernel32.Process32FirstW.restype = ctypes.c_int
        kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Entry)]
        kernel32.Process32NextW.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if not snapshot or snapshot == ctypes.c_void_p(-1).value:
            return ""
        try:
            entry = Entry()
            entry.dwSize = ctypes.sizeof(Entry)
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


def listener_alive(state_file: Path) -> bool:
    """v1.5 liveness: state.json "pid" must map to a running python* process."""
    state = read_json(state_file, {})
    try:
        pid = int(state.get("pid", 0))
    except (TypeError, ValueError):
        return False
    if not pid:
        return False
    return process_name_by_pid(pid).lower().startswith("pyth")


def acquire_mutex(name: str) -> Optional[int]:
    """Return the mutex handle, or None when another instance already holds it."""
    if os.name != "nt":
        return 1
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.CreateMutexW(None, False, name)
        if not handle:
            return 1  # creation failed; do not block on the mutex mechanism
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return None
        return handle
    except Exception:
        return 1


class Guard:
    def __init__(self, base: Path, config: Dict[str, Any], data_dir: Path):
        self.base = base
        self.listener_script = base / LISTENER_SCRIPT
        self.config_path = base / "config.json"
        self.data_dir = data_dir
        self.guard_file = data_dir / "guard.json"
        # state_file name comes from config.json so both sides agree on the path.
        self.state_file = data_dir / str(config.get("state_file", "state.json") or "state.json")
        safe = "".join(ch if ch.isalnum() or ch in "_-" else "_" for ch in str(config.get("machine_id", "default")))
        self.mutex_name = "Local\\NLGuard_" + safe
        self.restarts = int(read_json(self.guard_file, {}).get("restarts", 0))
        self.consecutive_failures = 0
        self.backoff_index = 0
        self.next_attempt = 0.0
        self.listener_running = False

    def write_state(self) -> None:
        atomic_json(self.guard_file, {
            "version": VERSION,
            "guard_pid": os.getpid(),
            "restarts": self.restarts,
            "listener_running": self.listener_running,
            "updated_at": utc_now(),
            "updated_epoch": time.time(),
        })

    def start_listener(self) -> bool:
        if not self.listener_script.exists():
            log(f"未找到 {self.listener_script}")
            return False
        try:
            CREATE_NO_WINDOW = 0x08000000
            subprocess.Popen(
                [sys.executable, str(self.listener_script), "--config", str(self.config_path),
                 "--data-dir", str(self.data_dir)],
                cwd=str(self.base), creationflags=CREATE_NO_WINDOW,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL)
            return True
        except OSError as exc:
            log(f"listener.py 启动失败：{exc}")
            return False

    def run(self) -> None:
        log(f"启动守护：base={self.base} data_dir={self.data_dir} restarts_so_far={self.restarts}")
        self.write_state()
        gave_up = False
        while True:
            now = time.time()
            alive = listener_alive(self.state_file)
            if alive:
                if not self.listener_running:
                    log("listener.py 在运行")
                self.listener_running = True
                self.consecutive_failures = 0
                self.backoff_index = 0
                gave_up = False
            elif not gave_up and now >= self.next_attempt:
                self.restarts += 1
                log(f"listener.py 不在运行，第 {self.restarts} 次拉起")
                ok = self.start_listener()
                self.listener_running = ok
                if ok:
                    self.consecutive_failures = 0
                    self.backoff_index = 0
                else:
                    self.consecutive_failures += 1
                    if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                        log(f"连续 {self.consecutive_failures} 次启动失败，停止拉起；守护进程保持运行")
                        gave_up = True
                    step = BACKOFF_STEPS[min(self.backoff_index, len(BACKOFF_STEPS) - 1)]
                    self.backoff_index += 1
                    delay = min(BACKOFF_CAP, step)
                    self.next_attempt = time.time() + delay
            self.write_state()
            time.sleep(CHECK_INTERVAL)


def self_test() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        # atomic_json round-trip
        payload = {"version": VERSION, "restarts": 3, "listener_running": True}
        atomic_json(base / "guard.json", payload)
        assert read_json(base / "guard.json", {}) == payload
        # process_running_by_name: this interpreter is running
        exe = Path(sys.executable).name.lower()
        assert process_running_by_name(exe), exe
        assert not process_running_by_name("definitely-not-a-real-process-xyz.exe")
        # process_name_by_pid: our own PID resolves to this interpreter's image
        own = process_name_by_pid(os.getpid()).lower()
        assert own == exe, (own, exe)
        assert process_name_by_pid(0) == "" and process_name_by_pid(-1) == ""
        # listener_alive: a state.json with our pid counts as alive; garbage does not
        state = {"pid": os.getpid()}
        atomic_json(base / "state.json", state)
        assert listener_alive(base / "state.json")
        atomic_json(base / "state.json", {"pid": 0})
        assert not listener_alive(base / "state.json")
        atomic_json(base / "state.json", {"pid": "not-a-number"})
        assert not listener_alive(base / "state.json")
        assert not listener_alive(base / "missing-state.json")
        # backoff sequence: 2/5/10 cap 30 (matches BACKOFF_STEPS/BACKOFF_CAP)
        delays = [min(BACKOFF_CAP, BACKOFF_STEPS[min(i, len(BACKOFF_STEPS) - 1)]) for i in range(6)]
        assert delays == [2.0, 5.0, 10.0, 10.0, 10.0, 10.0], delays
    print("SELF-TEST OK: 原子写、进程探测、退避序列均通过")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="listener.py watchdog")
    ap.add_argument("--config", default="", help="config.json 路径（默认取 guard.py 所在目录）")
    ap.add_argument("--data-dir", default="", help="guard.json 写入目录；默认用 config 的 data_dir 或配置目录")
    ap.add_argument("--self-test", action="store_true", help="运行内置自检后退出")
    args = ap.parse_args()
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
    if args.self_test:
        return self_test()
    if getattr(sys, "frozen", False):
        base = Path(sys.executable).resolve().parent
    else:
        base = Path(__file__).resolve().parent
    config_path = Path(args.config).resolve() if args.config else base / "config.json"
    config = read_json(config_path, {})
    if not isinstance(config, dict):
        config = {}
    if args.data_dir:
        data_dir = Path(args.data_dir).resolve()
    elif str(config.get("data_dir", "")).strip():
        data_dir = Path(str(config["data_dir"])).resolve()
    else:
        data_dir = base
    mutex = acquire_mutex(config_path.parent.name + "_" + str(config.get("machine_id", "")))
    if mutex is None:
        log("guard 已有实例在运行（互斥体已存在），本次退出")
        return 0
    try:
        Guard(base, config, data_dir).run()
    except KeyboardInterrupt:
        log("收到停止请求")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
