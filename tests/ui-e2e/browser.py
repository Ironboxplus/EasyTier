#!/usr/bin/env python3
"""The browser half of s35_ui_e2e. It runs in node A's namespace, next to the web server and the core.

It logs in through the page, starts the network through the web server's API, then on the status page
uses the path map's controls and the MP settings card, and on the config page edits a hot field and a restart-only field.
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

def ready(page):
    # The path map takes no edit while a change is still being applied.
    page.locator('[data-testid="path-map"][aria-busy="false"]').wait_for(state="visible", timeout=30000)
    # A toast left from the step before would pass for this step's: wait until none is shown.
    page.locator(".p-toast-message").first.wait_for(state="detached", timeout=30000)


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
            "busy": page.locator('[data-testid="path-map"]').get_attribute("aria-busy"),
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


def effect_badges_fit(page, label):
    """Every effect badge is a small block inside the window, and so is every field the page shows
    (a card that clips its content leaves scrollWidth unchanged, so the boxes are measured)."""
    boxes = page.evaluate("""() => {
        const inner = window.innerWidth
        const rect = el => { const r = el.getBoundingClientRect(); return { left: r.left, right: r.right, width: r.width,
            visible: r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden' } }
        const out = { badges: [], fields: [], inner }
        document.querySelectorAll('.mp-effect').forEach(el => out.badges.push({ ...rect(el), text: el.textContent }))
        document.querySelectorAll('.p-inputtext, .p-select, .p-slider, .p-inputnumber').forEach(el =>
            out.fields.push({ ...rect(el), cls: el.className.toString().slice(0, 40) }))
        return out
    }""")
    inner = boxes["inner"]
    wide = [b for b in boxes["badges"] if b["visible"] and b["width"] >= 120]
    outside = [b for b in boxes["badges"] + boxes["fields"] if b["visible"] and (b["right"] > inner + 1 or b["left"] < -1)]
    check(f"{label}: every effect badge is under 120 px wide", not wide, wide=wide[:3], badges=len(boxes["badges"]))
    chain = []
    if outside:
        # Which box is wider than the window, from the first field outwards: where the width comes from.
        chain = page.evaluate("""() => {
            const inner = window.innerWidth
            const el = [...document.querySelectorAll('.p-select, .p-slider, .p-inputtext, .mp-effect')]
                .find(e => e.getBoundingClientRect().right > inner + 1)
            const out = []
            for (let n = el; n && n !== document.body; n = n.parentElement) {
                const r = n.getBoundingClientRect()
                out.push(`${n.tagName.toLowerCase()}.${String(n.className).slice(0, 60)} w=${Math.round(r.width)} sw=${n.scrollWidth}`)
            }
            return out
        }""")
    check(f"{label}: no badge or field sticks out of the window", not outside, outside=outside[:3], chain=chain)


def nothing_cut(page, label):
    """No pipeline step and no peer-row text is cut short (text wider than its box)."""
    cut = page.evaluate("""() => [...document.querySelectorAll('.mp-step b, .mp-step-name, [data-testid="peer-row"] *')]
        .filter(el => el.children.length === 0 && el.clientWidth > 0 && el.scrollWidth > el.clientWidth + 1)
        .map(el => ({ text: el.textContent.slice(0, 40), scroll: el.scrollWidth, client: el.clientWidth }))""")
    check(f"{label}: no text is cut short", not cut, cut=cut[:5])


def login(pg):
    pg.goto(f"{args.web}/#/auth")
    pg.locator("#username").fill(args.user)
    pg.locator('input[type="password"]').first.fill(args.password)
    pg.locator('button[type="submit"]').click()
    pg.wait_for_url("**/#/h/**", timeout=30000)


def shoot_status(pg, lang, width):
    """The status page as pictures: the window, the page at full height (the page scrolls inside its
    own container, so the window is made tall for a moment), and the path map, the peer list and the MP
    settings card each by themselves."""
    pg.screenshot(path=str(SHOTS / f"status-{lang}-{width}-window.png"))
    pg.set_viewport_size({"width": width, "height": 3200})
    pg.wait_for_timeout(800)
    pg.screenshot(path=str(SHOTS / f"status-{lang}-{width}-long.png"))
    pg.set_viewport_size({"width": width, "height": 900})
    pg.wait_for_timeout(500)
    for name, testid in (("paths", "path-map"), ("peers", "peer-list"), ("settings", "mp-live-settings")):
        target = pg.locator(f'[data-testid="{testid}"]').first
        if target.count() and target.is_visible():
            target.screenshot(path=str(SHOTS / f"status-{lang}-{width}-{name}.png"))
        else:
            check(f"{lang} {width} px: {name} is on the page", False)
    # Every path's numbers sit inside the map, clear of each other and of the two columns of exits.
    layout = pg.evaluate("""() => {
        const box = el => { const r = el.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom } }
        const map = document.querySelector('[data-testid="path-map"]')
        return { map: map && box(map),
                 pills: [...document.querySelectorAll('[data-testid="path-map-path"]')].map(box),
                 ports: [...document.querySelectorAll('[data-testid^="path-map-port"]')].map(box) }
    }""")
    m, pills, ports = layout["map"], layout["pills"], layout["ports"]
    hit = lambda a, b: a["l"] < b["r"] - 1 and b["l"] < a["r"] - 1 and a["t"] < b["b"] - 1 and b["t"] < a["b"] - 1
    check(f"{lang} {width} px: the path map shows every path inside it, nothing drawn over another",
          bool(m) and bool(pills)
          and all(p["l"] >= m["l"] and p["r"] <= m["r"] for p in pills)
          and not any(hit(a, b) for i, a in enumerate(pills) for b in pills[i + 1:])
          and not any(hit(p, q) for p in pills for q in ports),
          map=m, pills=pills[:6], ports=ports[:6])


def peer_row(page):
    """The status page's row of node B (the first row is this node, the relay is another one)."""
    return page.locator('[data-testid="peer-row"]').filter(has=page.get_by_text("b", exact=True)).first


def open_paths(page):
    peer_row(page).click()
    page.locator('[data-testid="mp-step-paths"]').click()
    page.locator('[data-testid="path-map"]').wait_for(state="visible", timeout=30000)
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
        open_paths(page)
        page.screenshot(path=str(SHOTS / "status-1040.png"))

        # the switching threshold in the MP settings card, then undo
        before = peer(stats()).get("switch_threshold_micros")
        ready(page)
        field = page.locator('[data-testid="mp-live-switch-min"] input').first
        field.scroll_into_view_if_needed()
        field.fill(str(int(int(before or 5000) / 1000) + 4))
        field.press("Enter")
        toast_and_undo(page, "threshold edit", undo=False)
        wait_for(lambda s: peer(s).get("switch_threshold_micros") != before, secs=30, what="a new switch threshold")
        s = grey("threshold edit")
        check("threshold edit: the core reports a new threshold", peer(s).get("switch_threshold_micros") != before,
              before=before, after=peer(s).get("switch_threshold_micros"))
        page.locator('[data-testid="mp-undo"]').first.click()
        wait_for(lambda s: peer(s).get("switch_threshold_micros") == before, secs=30, what="the threshold back after undo")
        grey("threshold undo")

        # one path more at once: the second direct path sends too, then undo
        check("kmax 1 at the start", len(selected(stats())) == 1, selected=selected(stats()))
        ready(page)
        page.locator('[data-testid="path-map-kmax-plus"]').first.click()
        toast_and_undo(page, "one path more", undo=False)
        wait_for(lambda s: len(selected(s)) == 2, secs=30, what="two sending paths")
        grey("one path more")
        page.locator('[data-testid="mp-undo"]').first.click()
        wait_for(lambda s: len(selected(s)) == 1, secs=30, what="one sending path after undo")
        grey("one path more undo")

        # every relay made a primary path from the relay's own popover, then undo
        ready(page)
        fold = page.locator('[data-testid="path-map-relays"]').first
        fold.scroll_into_view_if_needed()
        if fold.get_attribute("aria-expanded") != "true":
            fold.click()
        page.locator('[data-testid="path-map-path"][data-relay="true"]').first.click()
        page.locator('[data-testid="runway-detail"]').wait_for(state="visible", timeout=10000)
        tier = page.locator('[data-testid="runway-tier-primary"]').first
        try:
            tier.click(timeout=10000)
        except Exception:
            # What covers the button, where the popover is, and a picture.
            page.screenshot(path=str(SHOTS / "relay-tier-not-clickable.png"), full_page=True)
            EVIDENCE["relay_tier_click"] = page.evaluate("""() => {
                const b = document.querySelector('[data-testid="runway-tier-primary"]')
                const r = b.getBoundingClientRect(), x = r.left + r.width / 2, y = r.top + r.height / 2
                const top = document.elementFromPoint(x, y)
                const d = document.querySelector('[data-testid="runway-detail"]').getBoundingClientRect()
                return { button: [r.left, r.top, r.width, r.height], viewport: [innerWidth, innerHeight],
                         detail: [d.left, d.top, d.width, d.height],
                         on_top: top ? top.outerHTML.slice(0, 300) : null,
                         on_top_parents: (() => { const o = []; for (let n = top; n && o.length < 6; n = n.parentElement) o.push(n.tagName + '.' + String(n.className).slice(0, 60)); return o })() }
            }""")
            raise
        toast_and_undo(page, "relay made primary", undo=False)
        page.keyboard.press("Escape")
        wait_for(lambda s: any(s3.kind_is(pa, "relay") and pa.get("tier") == "primary" for pa in s3.paths_of(s)),
                 secs=30, what="the relay reported as primary")
        grey("relay made primary")
        page.locator('[data-testid="mp-undo"]').first.click()
        wait_for(lambda s: all(pa.get("tier") == "backup" for pa in s3.paths_of(s) if s3.kind_is(pa, "relay")),
                 secs=30, what="the relay a backup again after undo")
        grey("relay made primary undo")

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
        threads.fill("3")
        threads.press("Tab")
        page.get_by_role("button", name="Run Network").click()
        page.locator(".p-confirmdialog").first.wait_for(state="visible", timeout=15000)
        check("restart-only field: asks once and names the field",
              "multi_thread_count" in page.locator(".p-confirmdialog").first.inner_text())
        page.get_by_role("button", name="Save and restart").click()
        wait_for(lambda s: len(direct_addrs(s)) >= 2 and direct_addrs(s).isdisjoint(base_direct), secs=240,
                 what="the instance running again on new direct paths")
        st_after = stats()
        after = identity(st_after)
        time.sleep(20)
        st_later = stats()
        later = identity(st_later)
        # A direct path may still come up in those 20 s, and a relay path may retire once the direct
        # ones carry the route; a second restart would give every direct path a new local port.
        def validated_direct(st):
            return {((pa.get("path") or {}).get("local_addr"), (pa.get("path") or {}).get("remote_addr"))
                    for pa in s3.paths_of(st) if s3.kind_is(pa, "udp", "direct") and s3.is_validated(pa)}

        direct_after, direct_later = validated_direct(st_after), validated_direct(st_later)
        EVIDENCE["restart"] = {"after": sorted(map(str, after)), "later": sorted(map(str, later)),
                               "direct_after": sorted(map(str, direct_after)), "direct_later": sorted(map(str, direct_later))}
        check("restart-only field: restarted exactly once", direct_after <= direct_later,
              lost=sorted(map(str, direct_after - direct_later)), lost_any_kind=sorted(map(str, after - later)))
        check("restart-only field: the process lives", start_ticks() == base_ticks)

        # ---- narrow screens: screenshots and no sideways scroll
        for width in (360, 390, 1040):
            page.set_viewport_size({"width": width, "height": 900})
            # The edit dialog of the step before is still open: a hash-only goto would keep it.
            page.goto("about:blank")
            page.goto(device_url(INSTANCE))
            peer_row(page).wait_for(state="visible", timeout=60000)
            open_paths(page)
            no_sideways_scroll(page, f"status page, {width} px")
            effect_badges_fit(page, f"status page, {width} px")
            nothing_cut(page, f"status page, {width} px")
            shoot_status(page, "en", width)
            open_config()
            no_sideways_scroll(page, f"config page, {width} px")
            effect_badges_fit(page, f"config page, {width} px")
            page.set_viewport_size({"width": width, "height": 3200})
            page.wait_for_timeout(800)
            page.screenshot(path=str(SHOTS / f"config-en-{width}-long.png"))
            page.set_viewport_size({"width": width, "height": 900})

        # ---- the same pages in Chinese, the language the owner reads
        cn = browser.new_context(viewport={"width": 1040, "height": 900}, locale="zh-CN")
        # The page takes its language from localStorage, not from the browser's.
        # about:blank, which the run passes through, has no storage: the script must not fail there.
        cn.add_init_script("try { localStorage.setItem('lang', 'cn') } catch (e) {}")
        cpage = cn.new_page()
        cpage.on("pageerror", lambda e: errors.append(str(e)))
        login(cpage)
        for width in (360, 390, 1040):
            cpage.set_viewport_size({"width": width, "height": 900})
            cpage.goto("about:blank")
            cpage.goto(device_url(INSTANCE))
            peer_row(cpage).wait_for(state="visible", timeout=60000)
            open_paths(cpage)
            no_sideways_scroll(cpage, f"status page (Chinese), {width} px")
            effect_badges_fit(cpage, f"status page (Chinese), {width} px")
            nothing_cut(cpage, f"status page (Chinese), {width} px")
            shoot_status(cpage, "cn", width)
            cpage.goto("about:blank")
            cpage.goto(device_url(INSTANCE))
            cpage.locator('button:has(.pi-ellipsis-v)').first.click()
            cpage.get_by_text("编辑网络").first.click()
            open_panel(cpage, "高级设置", "#hostname")
            no_sideways_scroll(cpage, f"config page (Chinese), {width} px")
            effect_badges_fit(cpage, f"config page (Chinese), {width} px")
            cpage.set_viewport_size({"width": width, "height": 3200})
            cpage.wait_for_timeout(800)
            cpage.screenshot(path=str(SHOTS / f"config-cn-{width}-long.png"))
            cpage.set_viewport_size({"width": width, "height": 900})
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
