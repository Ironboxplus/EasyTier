#!/usr/bin/env python3
"""Interface black-box and grey-box test: the real easytier-web (with the built front end) manages a
real easytier-core in the blackbox topology; a browser drives the status page and the config page.

Registers the scenario `s35_ui_e2e` in tests/blackbox/s3.py and runs it through that file's `main`:

    sudo unshare --pid --fork --mount-proc --mount --net --propagation private -- bash -c \
        "mkdir -p /run/netns; mount -t tmpfs netns /run/netns; ip link set lo up; \
         exec python3 tests/ui-e2e/ui_e2e.py --bin BIN --out OUT s35_ui_e2e"

BIN holds easytier-core, easytier-cli and easytier-web (built with the `embed` feature). The topology is
the one of `s34_hot_selection`: node A (managed by the web server, which runs in A's namespace) reaches
node B over two direct paths and a relay path. Everything the browser does is then checked against the
core: the same process, the same paths, the field's effect as the table says.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "blackbox"))
import s3  # noqa: E402

MACHINE_ID = "5b1c0a54-6f0d-4a65-9a43-3f6f8f1d2e77"
USER, PASSWORD = "uie2e", "ui-e2e-password"
WEB_PORT, API_PORT, CONFIG_PORT = 11210, 11211, 22020


class WebManagedCore(s3.Core):
    """A core that runs no network of its own: the web server starts it."""

    def __init__(self, run, name, ns, bin_dir=None):
        self.run, self.name, self.ns = run, name, ns
        self.peer_ids = {}
        self.dir = run.out / "nodes" / name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.bin = pathlib.Path(bin_dir or run.bin)
        self.start()

    def start(self):
        self.node_peer_id = None
        self.log = open(self.dir / "core.log", "ab")
        self.proc = subprocess.Popen(
            ["ip", "netns", "exec", self.ns, str(self.bin / "easytier-core"),
             "-w", f"udp://127.0.0.1:{CONFIG_PORT}/{USER}", "--machine-id", MACHINE_ID,
             "-r", s3.RPC, "--console-log-level", "warn"],
            stdout=self.log, stderr=subprocess.STDOUT)


def start_web(run):
    log = open(run.out / "web.log", "ab")
    db = run.out / "web.db"
    proc = subprocess.Popen(
        ["ip", "netns", "exec", "s3a", str(run.bin / "easytier-web"),
         "--db", str(db), "--api-server-port", str(API_PORT), "--web-server-port", str(WEB_PORT),
         "--config-server-port", str(CONFIG_PORT), "--api-host", f"http://127.0.0.1:{API_PORT}",
         "--allow-auto-create-user", "--console-log-level", "warn"],
        stdout=log, stderr=subprocess.STDOUT)
    return proc, db


def set_login(db):
    """The device's token created the user with a random password; the browser needs a known one.
    The web client sends the MD5 of the typed password, the server stores an Argon2 hash of that."""
    from argon2 import PasswordHasher
    digest = hashlib.md5(PASSWORD.encode()).hexdigest()
    hashed = PasswordHasher().hash(digest)
    end = time.time() + 120
    while time.time() < end:
        try:
            con = sqlite3.connect(db, timeout=10)
            cur = con.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, USER))
            con.commit()
            con.close()
            if cur.rowcount:
                return
        except sqlite3.Error:
            pass
        time.sleep(1)
    raise s3.Fail("the web server never saw the device's user")


def s35_ui_e2e(run, args):
    """The browser changes the running network through the web server; the core keeps its process and
    its paths for every hot change, restarts its instance once for a restart-only change, and the
    pages have no sideways scroll at 360, 390 and 1040 px."""
    def delay(net):
        for i in (1, 2):
            s3.sh("tc", "qdisc", "replace", "dev", f"ra{i}", "root", "netem", "delay", "10ms", ns="s3ra")

    net = run.topo(nics=2, dnat=True, public_a=True)
    delay(net)
    run.relay()
    mp = s3.mp_base(providers=["udp-direct", "relay-next-hop", "udp-punch"], kmax=1, data_plane={"enabled": True})
    run.core("b", "s3b", s3.B_VIP, listeners=["tcp://0.0.0.0:11010", "mpquic://0.0.0.0:11020"],
             peers=[f"tcp://{s3.RELAY}:11010"], mp=mp, bin_dir=run.b_bin)
    web, db = start_web(run)
    try:
        a = WebManagedCore(run, "a", "s3a")
        run.cores.append(a)
        set_login(db)
        config = {
            "network_name": "s3net", "network_secret": "s3secret", "hostname": "a", "dhcp": False,
            "virtual_ipv4": s3.A_VIP, "network_length": 24, "networking_method": "Manual",
            "peer_urls": [f"tcp://{s3.RELAY}:11010"], "listener_urls": [], "no_tun": True, "disable_upnp": True,
            "mp": {**mp, "egress_devices": ["a1", "a2"]},
        }
        out = run.out / "ui"
        out.mkdir(exist_ok=True)
        cmd = [sys.executable, str(HERE / "browser.py"), "--out", str(out), "--machine-id", MACHINE_ID,
               "--user", USER, "--password", PASSWORD, "--core-pid", str(a.proc.pid), "--bin", str(run.bin),
               "--web", f"http://127.0.0.1:{WEB_PORT}", "--api", f"http://127.0.0.1:{API_PORT}",
               "--config", json.dumps(config)]
        r = subprocess.run(["ip", "netns", "exec", "s3a"] + cmd, capture_output=True, text=True, timeout=1500)
        (run.out / "browser.stdout.txt").write_text(r.stdout)
        (run.out / "browser.stderr.txt").write_text(r.stderr)
        report = json.loads((out / "report.json").read_text()) if (out / "report.json").exists() else {}
        run.evidence["ui"] = report
        for check in report.get("checks", []):
            run.evidence["checks"].append(check)
        run.check("the browser script finished", r.returncode == 0,
                  returncode=r.returncode, tail=(r.stdout + r.stderr)[-1500:])
        failed = [c for c in report.get("checks", []) if not c.get("ok")]
        run.check("every interface check passed", not failed, failed=failed)
    finally:
        web.terminate()
        try:
            web.wait(10)
        except subprocess.TimeoutExpired:
            web.kill()


s3.SCENARIOS["s35_ui_e2e"] = s35_ui_e2e

if __name__ == "__main__":
    sys.exit(s3.main())
