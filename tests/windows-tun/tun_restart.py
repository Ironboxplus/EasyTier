#!/usr/bin/env python3
"""Windows TUN identity black-box test (T2-5), on an administrator account with wintun.dll beside the core.

Five start/stop rounds of one easytier-core with no configured device name -- rounds 2 and 4 are
stopped by force, the others with Ctrl+C -- then two cores at once. Asserted:
  * the adapter is always `et_1` and keeps its GUID across the rounds;
  * the registry's network profile count does not grow after the first round;
  * a Ctrl+C stop exits with code 0;
  * two cores at once get `et_1` and `et_2`, with different GUIDs.
Usage: python tun_restart.py PATH\\easytier-core.exe OUT_DIR
"""
import ctypes
import json
import pathlib
import subprocess
import sys
import time
import winreg

CORE, OUT = sys.argv[1], pathlib.Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
evidence = {"rounds": [], "checks": []}
kernel32 = ctypes.windll.kernel32


def check(name, ok, **detail):
    evidence["checks"].append({"check": name, "ok": bool(ok), **detail})
    print(("PASS " if ok else "FAIL ") + name, detail if not ok else "", flush=True)
    if not ok:
        finish(1)


def finish(code):
    (OUT / "windows_tun.json").write_text(json.dumps(evidence, indent=1, default=str))
    sys.exit(code)


def powershell(command):
    return subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True,
                          timeout=120).stdout


def adapters():
    out = powershell("Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -like 'et_*' } | "
                     "Select-Object Name,InterfaceGuid,Status | ConvertTo-Json -Compress").strip()
    if not out:
        return {}
    rows = json.loads(out)
    rows = rows if isinstance(rows, list) else [rows]
    return {r["Name"]: {"guid": r["InterfaceGuid"], "status": str(r["Status"])} for r in rows}


def profile_count():
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles")
    return winreg.QueryInfoKey(key)[0]


def start(index, ip, rpc):
    log = open(OUT / f"core{index}.log", "ab")
    proc = subprocess.Popen(
        [CORE, "--no-listener", "--ipv4", ip, "--network-name", f"wt{index}", "--network-secret", "s",
         "--hostname", f"wt{index}", "--instance-name", f"wt{index}", "--rpc-portal", f"127.0.0.1:{rpc}",
         "--console-log-level", "info"],
        stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NEW_CONSOLE)
    return proc


def wait_adapters(count, secs=90):
    end, rows = time.time() + secs, {}
    while time.time() < end:
        rows = adapters()
        if len(rows) >= count and all(r["status"].lower() == "up" for r in rows.values()):
            return rows
        time.sleep(1)
    return rows


def ctrl_c(proc):
    """Ctrl+C into the child's console: attach to it, ignore the event ourselves, send it."""
    kernel32.FreeConsole()
    if not kernel32.AttachConsole(proc.pid):
        return False
    kernel32.SetConsoleCtrlHandler(None, True)
    kernel32.GenerateConsoleCtrlEvent(0, 0)
    time.sleep(1)
    kernel32.FreeConsole()
    kernel32.SetConsoleCtrlHandler(None, False)
    return True


def stop(proc, force):
    if force:
        proc.kill()
        proc.wait(30)
        return proc.returncode
    if not ctrl_c(proc):
        proc.kill()
        return None
    try:
        return proc.wait(60)
    except subprocess.TimeoutExpired:
        proc.kill()
        return None


check("no et_* adapter before the test", not adapters(), adapters=adapters())
first_guid, first_profiles = None, None
for i in range(1, 6):
    force = i in (2, 4)
    proc = start(1, "10.201.0.1/24", 15881)
    rows = wait_adapters(1)
    names = sorted(rows)
    record = {"round": i, "force": force, "adapters": rows, "profiles_running": profile_count()}
    check(f"round {i}: the adapter is et_1", names == ["et_1"], adapters=rows)
    guid = rows["et_1"]["guid"]
    first_guid = first_guid or guid
    check(f"round {i}: the GUID is the one of round 1", guid == first_guid, guid=guid, first=first_guid)
    code = stop(proc, force)
    time.sleep(3)
    record["exit_code"] = code
    record["profiles_after"] = profile_count()
    first_profiles = record["profiles_after"] if first_profiles is None else first_profiles
    evidence["rounds"].append(record)
    if not force:
        check(f"round {i}: Ctrl+C ends the core with exit code 0", code == 0, exit_code=code)
    check(f"round {i}: no network profile was added after round 1", record["profiles_after"] <= first_profiles,
          profiles=record["profiles_after"], first=first_profiles)

procs = [start(1, "10.201.0.1/24", 15881), start(2, "10.202.0.1/24", 15882)]
rows = wait_adapters(2)
evidence["pair"] = rows
check("two cores get et_1 and et_2", sorted(rows) == ["et_1", "et_2"], adapters=rows)
check("the two adapters have different GUIDs", len({r["guid"] for r in rows.values()}) == 2, adapters=rows)
for proc in procs:
    stop(proc, force=False)
time.sleep(3)
finish(0)
