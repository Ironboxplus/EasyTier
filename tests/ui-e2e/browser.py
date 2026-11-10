#!/usr/bin/env python3
"""The browser half of s35_ui_e2e. It runs in node A's namespace, next to the web server and the core.

It logs in through the page, starts the network through the web server's API, then on the status page
drags the path runway's handles and on the config page edits a hot field and a restart-only field.
After each step it asks the core (easytier-cli) what happened: same process, same paths, the selection
as expected. Evidence goes to <out>/report.json, screenshots to <out>/shots/.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import time
import uuid

from playwright.sync_api import sync_playwright

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "blackbox"))
import s3  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--out", required=True)
ap.add_argument("--machine-id", required=True)
ap.add_argument("--user", required=True)
ap.add_argument("--password", required=True)
ap.add_argument("--core-pid", required=True, type=int)
ap.add_argument("--bin", required=True)
ap.add_argument("--web", required=True)
ap.add_argument("--api", required=True)
ap.add_argument("--config", required=True)
args = ap.parse_args()

OUT = pathlib.Path(args.out)
SHOTS = OUT / "shots"
SHOTS.mkdir(parents=True, exist_ok=True)
CHECKS: list[dict] = []
API_LOG: list[str] = []
EVIDENCE: dict = {}
INSTANCE = str(uuid.uuid4())


def check(name, ok, **detail):
    CHECKS.append({"check": name, "ok": bool(ok), **detail})
    print(("ok   " if ok else "FAIL ") + name, detail if not ok else "", flush=True)


def save_report():
    (OUT / "report.json").write_text(json.dumps({"checks": CHECKS, "evidence": EVIDENCE, "api_tail": API_LOG[-60:]},
                                                 indent=1, default=str))


# ---------------------------------------------------------------- the core, as the CLI sees it

def cli(*a):
    r = subprocess.run([str(pathlib.Path(args.bin) / "easytier-cli"), "-p", s3.RPC, *a],
                       capture_output=True, text=True, timeout=30)
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return r.stdout


_B_ID: list[str] = []


def b_id():
    if not _B_ID:
        rows = json.loads(cli("-o", "json", "peer"))
        row = next((r for r in rows if r.get("hostname") == "b" and r.get("id")), None)
        if row is None:
            raise RuntimeError("node b is not a peer yet")
        _B_ID.append(str(row["id"]))
    return _B_ID[0]


def stats():
    """MP telemetry, narrowed to node B's session (the relay is a peer too)."""
    st = json.loads(cli("-o", "json", "stats", "mp"))
    st["mp_peers"] = [p for p in st.get("mp_peers") or [] if str(p.get("peer_id")) == b_id()]
    return st


def direct_addrs(st):
    """Local and remote endpoints of the direct paths: new ones after the instance starts again."""
    return {((pa.get("path") or {}).get("local_addr"), (pa.get("path") or {}).get("remote_addr"))
            for pa in s3.paths_of(st) if s3.kind_is(pa, "udp", "direct")}


def start_ticks():
    stat = pathlib.Path(f"/proc/{args.core_pid}/stat").read_text()
    return stat.rsplit(")", 1)[1].split()[19]


def selected(st):
    return sorted((pa.get("carrier_kind"), pa.get("egress_device") or "") for pa in s3.paths_of(st) if pa.get("selected"))


def identity(st):
    return s3.path_identity(st)


def peer(st):
    peers = st.get("mp_peers") or []
    return peers[0] if peers else {}


def wait_for(pred, secs=30, what="state"):
    end, last = time.time() + secs, None
    while time.time() < end:
        try:
            last = stats()
            if pred(last):
                return last
        except Exception as e:  # the core may be between two instances
            last = {"error": str(e)}
        time.sleep(1)
    check(f"timed out: {what}", False, last=json.dumps(last)[:600])
    raise SystemExit(1)


# ---------------------------------------------------------------- the page

def drag(page, locator, dx, dy):
    # The runway ignores a pointer while a change is still being applied.
    page.locator('[data-testid="path-runway"][aria-busy="false"]').wait_for(state="visible", timeout=30000)
    # A toast left from the step before would pass for this step's: wait until none is shown.
    page.locator(".p-toast-message").first.wait_for(state="detached", timeout=30000)
    locator.scroll_into_view_if_needed()
    box = locator.bounding_box()
    cx, cy = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    page.mouse.move(cx, cy)
    page.mouse.down()
    page.mouse.move(cx + dx / 2, cy + dy / 2, steps=8)
    page.mouse.move(cx + dx, cy + dy, steps=8)
    page.mouse.up()


def open_panel(page, title, probe):
    """Expand a collapsed panel of the config page: its toggle is clicked only while `probe` is hidden."""
    header = page.locator(".p-panel-header", has_text=title).first
    header.wait_for(state="visible", timeout=30000)
    page.wait_for_timeout(1000)
    for _ in range(3):
        if page.locator(probe).first.is_visible():
            break
        toggle = header.locator("button")
        (toggle.first if toggle.count() else header).click()
        page.wait_for_timeout(1000)
    try:
        page.locator(probe).first.wait_for(state="visible", timeout=10000)
    except Exception:
        page.screenshot(path=str(SHOTS / f"no-{title.replace(' ', '_')}.png"), full_page=True)
        raise


def device_url(instance=None):
    host = base64.b64encode(args.api.encode()).decode()
    tail = f"/{instance}" if instance else ""
    return f"{args.web}/#/h/{host}/deviceList/device/{args.machine_id}{tail}"


def toast_and_undo(page, what, undo=True):
    toast = page.locator('[data-testid="mp-undo-toast"]')
    try:
        toast.wait_for(state="visible", timeout=15000)
    except Exception:
        # Say what the page was doing: a picture, the visible toasts, the API calls so far.
        page.screenshot(path=str(SHOTS / f"no-toast-{what.replace(' ', '_')}.png"), full_page=True)
        EVIDENCE["no_toast"] = {
            "what": what,
            "toasts": page.locator(".p-toast-message").all_inner_texts(),
            "shield_handles": page.locator('[data-testid="runway-shield"]').count(),
            "busy": page.locator('[data-testid="path-runway"]').get_attribute("aria-busy"),
            "api": API_LOG[-12:],
            "paths": [(pa.get("carrier_kind"), pa.get("egress_device"), pa.get("tier"), pa.get("selected")) for pa in s3.paths_of(stats())],
        }
        raise
    check(f"{what}: the page says it applied the change", True)
    if undo:
        page.locator('[data-testid="mp-undo"]').first.click()
        page.wait_for_timeout(1500)


def no_sideways_scroll(page, label):
    width = page.evaluate("() => [document.documentElement.scrollWidth, window.innerWidth]")
    check(f"{label}: no sideways scroll", width[0] <= width[1] + 1, scroll_width=width[0], inner_width=width[1])


def peer_row(page):
    """The status page's row of node B (the first row is this node, the relay is another one)."""
    return page.locator('[data-testid="peer-row"]').filter(has=page.get_by_text("b", exact=True)).first


def open_runway(page):
    peer_row(page).click()
    page.locator('[data-testid="mp-step-paths"]').click()
    page.locator('[data-testid="path-runway"]').wait_for(state="visible", timeout=30000)
    page.wait_for_timeout(1000)


def run() -> None:
    config = json.loads(args.config)
    config["instance_id"] = INSTANCE
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        ctx = browser.new_context(viewport={"width": 1040, "height": 900}, locale="en-US")
        page = ctx.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)
        page.on("response", lambda r: API_LOG.append(f"{r.request.method} {r.url.split('/api/v1')[-1]} {r.status}"
                                                    + (f" {(r.request.post_data or '')[:1800]}" if r.request.method == "PATCH" else ""))
                if "/api/v1" in r.url else None)

        # ---- login through the page
        page.goto(f"{args.web}/#/auth")
        page.locator("#username").fill(args.user)
        page.locator('input[type="password"]').first.fill(args.password)
        page.locator('button[type="submit"]').click()
        page.wait_for_url("**/#/h/**", timeout=30000)
        check("login through the page", True)

        # ---- start the network through the web server (the page's own session)
        resp = ctx.request.post(f"{args.api}/api/v1/machines/{args.machine_id}/networks",
                                data={"config": config, "save": True})
        check("the web server starts the network", resp.ok, status=resp.status, body=resp.text()[:300])
        st = wait_for(lambda s: len([pa for pa in s3.paths_of(s) if s3.is_validated(pa) and s3.kind_is(pa, "udp", "direct")]) >= 2
                      and any(s3.kind_is(pa, "relay") and pa.get("tier") for pa in s3.paths_of(s)),
                      secs=240, what="two direct paths and the relay path")
        base_ticks, base_paths, base_direct = start_ticks(), identity(st), direct_addrs(st)
        EVIDENCE["baseline"] = {"selected": selected(st), "paths": len(base_paths)}

        def grey(step, same_paths=True):
            s = stats()
            now = identity(s)
            check(f"{step}: same process", start_ticks() == base_ticks)
            if same_paths:
                check(f"{step}: no path replaced", base_paths <= now, missing=sorted(base_paths - now))
            check(f"{step}: no reconnect asked", not peer(s).get("reconnect_required"))
            return s

        # ---- the status page
        page.goto(device_url(INSTANCE))
        peer_row(page).wait_for(state="visible", timeout=60000)
        no_sideways_scroll(page, "status page, 1040 px")
        open_runway(page)
        page.screenshot(path=str(SHOTS / "status-1040.png"))

        # threshold handle to the right, then undo
        before = peer(stats()).get("switch_threshold_micros")
        drag(page, page.locator('[data-testid="runway-shield"]').first, 60, 0)
        toast_and_undo(page, "threshold drag", undo=False)
        wait_for(lambda s: peer(s).get("switch_threshold_micros") != before, secs=30, what="a new switch threshold")
        s = grey("threshold drag")
        check("threshold drag: the core reports a new threshold", peer(s).get("switch_threshold_micros") != before,
              before=before, after=peer(s).get("switch_threshold_micros"))
        page.locator('[data-testid="mp-undo"]').first.click()
        wait_for(lambda s: peer(s).get("switch_threshold_micros") == before, secs=30, what="the threshold back after undo")
        grey("threshold undo")

        # split line down one row: the second direct path sends too, then undo
        check("kmax 1 at the start", len(selected(stats())) == 1, selected=selected(stats()))
        drag(page, page.locator('[data-testid="runway-kmax"]').first, 0, 40)
        toast_and_undo(page, "split line drag", undo=False)
        wait_for(lambda s: len(selected(s)) == 2, secs=30, what="two sending paths")
        grey("split line drag")
        page.locator('[data-testid="mp-undo"]').first.click()
        wait_for(lambda s: len(selected(s)) == 1, secs=30, what="one sending path after undo")
        grey("split line undo")

        # the relay dot into the primary lane, 30 px to the left, then undo
        relay = page.locator('[data-testid="runway-path"]:has(svg.lucide-waypoints) [data-testid="runway-dot"]').first
        page.locator('[data-testid="path-runway"][aria-busy="false"]').wait_for(state="visible", timeout=30000)
        relay.scroll_into_view_if_needed()
        lane = page.locator('[data-testid="runway-lane-primary"]').first.bounding_box()
        dot = relay.bounding_box()
        drag(page, relay, -30, lane["y"] + lane["height"] / 2 - (dot["y"] + dot["height"] / 2))
        toast_and_undo(page, "relay dot drag", undo=False)
        wait_for(lambda s: any(s3.kind_is(pa, "relay") and pa.get("tier") == "primary" for pa in s3.paths_of(s)),
                 secs=30, what="the relay reported as primary")
        grey("relay dot drag")
        page.locator('[data-testid="mp-undo"]').first.click()
        wait_for(lambda s: all(pa.get("tier") == "backup" for pa in s3.paths_of(s) if s3.kind_is(pa, "relay")),
                 secs=30, what="the relay back in the backup lane after undo")
        grey("relay dot undo")

        # ---- the config page: a hot field, then a restart-only field
        def open_config():
            page.goto(device_url(INSTANCE))
            page.locator('button:has(.pi-ellipsis-v)').first.click()
            page.get_by_text("Edit Network").first.click()
            open_panel(page, "Advanced Settings", "#hostname")

        open_config()
        no_sideways_scroll(page, "config page, 1040 px")
        page.locator("#hostname").fill("a-renamed")
        page.get_by_role("button", name="Run Network").click()
        page.wait_for_timeout(3000)
        check("hot field: no restart question", page.locator(".p-confirmdialog").count() == 0
              or not page.locator(".p-confirmdialog").first.is_visible())
        grey("hostname edit")
        node = json.loads(cli("-o", "json", "node"))
        node = node[0]["result"] if isinstance(node, list) else node
        check("hot field: the core has the new hostname", node.get("hostname") == "a-renamed", hostname=node.get("hostname"))

        open_config()
        open_panel(page, "Core switches", "input#multi_thread_count, #multi_thread_count input")
        threads = page.locator("#multi_thread_count input, input#multi_thread_count").first
        threads.fill("2")
        page.get_by_role("button", name="Run Network").click()
        page.locator(".p-confirmdialog").first.wait_for(state="visible", timeout=15000)
        check("restart-only field: asks once and names the field",
              "multi_thread_count" in page.locator(".p-confirmdialog").first.inner_text())
        page.get_by_role("button", name="Save and restart").click()
        wait_for(lambda s: len(direct_addrs(s)) >= 2 and direct_addrs(s).isdisjoint(base_direct), secs=240,
                 what="the instance running again on new direct paths")
        after = identity(stats())
        time.sleep(20)
        check("restart-only field: restarted exactly once", identity(stats()) == after)
        check("restart-only field: the process lives", start_ticks() == base_ticks)

        # ---- narrow screens: screenshots and no sideways scroll
        for width in (360, 390, 1040):
            page.set_viewport_size({"width": width, "height": 900})
            page.goto(device_url(INSTANCE))
            peer_row(page).wait_for(state="visible", timeout=60000)
            open_runway(page)
            no_sideways_scroll(page, f"status page, {width} px")
            page.screenshot(path=str(SHOTS / f"status-{width}.png"), full_page=True)
            open_config()
            no_sideways_scroll(page, f"config page, {width} px")
            page.screenshot(path=str(SHOTS / f"config-{width}.png"), full_page=True)
        check("the page raised no script error", not errors, errors=errors[:5])
        browser.close()


try:
    run()
except SystemExit:
    pass
except Exception as e:  # keep the evidence of what ran before the failure
    check(f"unexpected error: {type(e).__name__}", False, error=str(e)[:800])
finally:
    save_report()
sys.exit(0 if all(c["ok"] for c in CHECKS) else 1)
