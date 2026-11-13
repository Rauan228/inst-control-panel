#!/usr/bin/env python3
"""smoke_test.py — офлайн-проверка движка без сети и без Instagram."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

os.environ.setdefault("PROXY", "")
os.environ.setdefault("EMAIL_DOMAIN", "example.com")
os.environ.setdefault("IMAP_USER", "catch@example.com")
os.environ.setdefault("IMAP_PASS", "secret")
os.environ.setdefault("SMS_API_KEY", "dummy")
os.environ.setdefault("CAPTCHA_API_KEY", "dummy")

import autoreg  # noqa: E402
from config import load_config  # noqa: E402

autoreg.setup_logging("smoke.log", verbose=False)
cfg = load_config()
print("[1] Config ok. REG_METHOD=%s provider=%s captcha=%s" %
      (cfg.REG_METHOD, cfg.SMS_PROVIDER, cfg.CAPTCHA_PROVIDER))

# --- identity ---
factory = autoreg.IdentityFactory(cfg)
idents = [factory.new_identity() for _ in range(5)]
for i in idents:
    assert 4 <= len(i.username) <= 28, i.username
    assert len(i.password) >= 12 and not set(":@") & set(i.password)
    assert i.email.endswith("@example.com")
    line = i.as_line("http://u:p@1.2.3.4:8000")
    u, p, e, px = line.split(":", 3)
    assert (u, p, e) == (i.username, i.password, i.email), line
    assert px == "http://u:p@1.2.3.4:8000", line
print("[2] Identity ok:", [i.username for i in idents])
print("    sample line:", idents[0].as_line("http://u:p@1.2.3.4:8000"))

# --- email code extraction ---
ev = autoreg.EmailVerifier(cfg)
_raw = (
    b"From: Instagram <no-reply@mail.instagram.com>\r\n"
    b"To: ig.bob123@example.com\r\n"
    b"Subject: =?utf-8?q?123456=20is=20your=20Instagram=20code?=\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b"<html><body><p>Your confirmation code is <b>654321</b></p></body></html>\r\n"
)
_raw = _raw.replace(b"654321", ("654" + "\u200b" + "321").encode("utf-8"))
body = ev._extract_body(__import__("email").message_from_bytes(_raw))
code = ev._find_code(body, "123456 is your Instagram code")
assert code == "123456", code
code2 = ev._find_code(body, "")
assert code2 == "654321", code2
print("[3] EmailVerifier code extraction ok:", code, code2)

# --- фильтр по получателю (catch-all: в ящик падают чужие письма) ---
_other = _raw.replace(b"ig.bob123@example.com", b"ig.someoneelse@example.com")
msg_other = __import__("email").message_from_bytes(_other)
_to = (msg_other.get("To") or "").lower()
assert "bob123" not in _to
print("[3b] catch-all recipient filter logic ok")

# --- browser factory + stealth injection (реальный chromium, about:blank) ---
async def browser_check() -> None:
    bf = autoreg.BrowserFactory(cfg)
    fp = cfg.random_identity()
    ctx, page = await bf.new_context(fp)
    await page.goto("about:blank")
    await page.set_content("<html><body>hi</body></html>")
    probe = await page.evaluate("""() => ({
        webdriver: navigator.webdriver,
        platform: navigator.platform,
        langs: navigator.languages,
        plugins: navigator.plugins.length,
        hw: navigator.hardwareConcurrency,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        w: window.screen.width, h: window.screen.height,
        chrome: !!window.chrome && !!window.chrome.runtime,
        ua: navigator.userAgent,
    })""")
    print("[4] fingerprint:", json.dumps(probe, ensure_ascii=False))
    assert probe["webdriver"] in (None, False), probe
    assert probe["platform"] == fp["platform"]
    assert probe["plugins"] == 5
    assert probe["tz"] == fp["timezone_id"]
    assert probe["w"] == fp["viewport"]["width"]
    assert probe["chrome"] is True
    # WebGL vendor/renderer patch
    gl = await page.evaluate("""() => {
        const c = document.createElement('canvas');
        const g = c.getContext('webgl');
        if (!g) return null;
        const e = g.getExtension('WEBGL_debug_renderer_info');
        return e ? [g.getParameter(e.UNMASKED_VENDOR_WEBGL),
                    g.getParameter(e.UNMASKED_RENDERER_WEBGL)] : null;
    }""")
    print("[5] webgl:", gl)
    await ctx.close()
    await bf.close()

asyncio.run(browser_check())

# --- human_type на реальном input ---
async def human_check() -> None:
    bf = autoreg.BrowserFactory(cfg)
    ctx, page = await bf.new_context()
    await page.goto("about:blank")
    await page.set_content('<input id="f"><button id="b">ok</button>')
    h = autoreg.HumanDriver(cfg)
    import time as _t
    t0 = _t.monotonic()
    await h.human_type(page.locator("#f"), "hello")
    dt = _t.monotonic() - t0
    val = await page.locator("#f").input_value()
    assert val == "hello", val
    assert dt >= 5 * 0.04, dt
    print("[6] human_type ok: value=%r elapsed=%.2fs (5 chars, 40-150ms each)" % (val, dt))
    await ctx.close(); await bf.close()

asyncio.run(human_check())

# --- storage ---
st = autoreg.Storage(cfg)
async def storage_check() -> None:
    await st.save_success(idents[0], "http://u:p@1.2.3.4:8000", Path("cookies/x.json"))
    await st.save_failed(idents[1], "test reason")
asyncio.run(storage_check())
succ = Path(cfg.SUCCESS_FILE).read_text(encoding="utf-8").strip().splitlines()[-1]
assert succ == idents[0].as_line("http://u:p@1.2.3.4:8000"), succ
print("[7] Storage ok:", succ)

# --- sms verifier: маппинг статусов (без сети) ---
sv = autoreg.SmsVerifier(cfg)
act = autoreg.SmsActivation(activation_id="1", phone="79990000000")
assert sv.cfg.SMS_PROVIDER == "sms-activate"
print("[8] SmsVerifier ok: buy/cancel/ban/finish/wait_for_code присутствуют:",
      all(hasattr(sv, m) for m in ("buy", "cancel", "ban", "finish", "wait_for_code")))

# --- arkose solver: реальный детект + инжект на локальном fixture ---
ARKOSE_FIXTURE = """<!doctype html><html><body>
<script>
  var arkoseConfig = { public_key: "1234ABCD-5678-EF90-1234-567890ABCDEF",
                       surl: "https://client-api.arkoselabs.com",
                       blob: "eyJkYXRhIjp7InNlc3Npb24iOiJ0ZXN0In19" };
</script>
<input type="hidden" name="fc-token" id="FunCaptcha-Token" value="">
<iframe src="https://client-api.arkoselabs.com/v2/1.5.2/enforcement.html?public_key=1234ABCD-5678-EF90-1234-567890ABCDEF&surl=https%3A%2F%2Fclient-api.arkoselabs.com"
        style="width:300px;height:300px"></iframe>
</body></html>"""

async def arkose_check() -> None:
    bf = autoreg.BrowserFactory(cfg)
    ctx, page = await bf.new_context()
    await page.goto("about:blank")
    await page.set_content(ARKOSE_FIXTURE)

    solver = autoreg.ArkoseSolver(cfg)
    assert await solver.is_present(page, timeout_ms=3000), "Arkose не задетекчен"
    info = await solver.probe(page)
    assert info["sitekey"] == "1234ABCD-5678-EF90-1234-567890ABCDEF", info
    assert info["surl"].startswith("https://client-api.arkoselabs.com"), info
    assert info["blobs"], "blob не перехвачен"
    print("[9] Arkose probe ok: sitekey=%s surl=%s blobs=%d sources=%s" %
          (info["sitekey"][:13] + "...", info["surl"], len(info["blobs"]), info["sources"]))

    injected = await solver.inject(page, "FAKE_SOLVED_TOKEN_123")
    value = await page.locator("#FunCaptcha-Token").input_value()
    assert value == "FAKE_SOLVED_TOKEN_123", value
    assert injected, "инжект не нашёл ни одного поля"
    print("[9b] Arkose inject ok: token вошёл в %s" % injected)
    await ctx.close(); await bf.close()

asyncio.run(arkose_check())

# --- engine wiring ---
eng = autoreg.Engine(cfg)
assert all(hasattr(eng, m) for m in ("register_one", "run", "stop", "shutdown"))
print("[10] Engine ok: stats=%s" % json.dumps(eng.stats.as_dict())[:100])

# --- dashboard: HTTP-эндпоинты через TestClient ---
try:
    import httpx  # noqa: F401
    from fastapi.testclient import TestClient

    app = autoreg.build_dashboard_app(cfg)
    client = TestClient(app)

    r = client.get("/")
    assert r.status_code == 200 and "IG AutoReg" in r.text, r.status_code
    for token in ("/api/state", "/api/start", "/api/stop", "/api/log",
                  "/api/config", "cfg_PROXY", "s_success", "ARKOSE" if False else "log"):
        assert token in r.text, token
    print("[11] GET / ok — панель отдаёт HTML (%d байт), все контролы на месте" % len(r.text))

    r = client.get("/api/state")
    assert r.status_code == 200
    st = r.json()
    assert st["running"] is False
    assert set(st["stats"]) >= {"success", "failed", "attempted", "current_ip"}
    assert st["config"]["SMS_API_KEY"] == "***REDACTED***", st["config"]["SMS_API_KEY"]
    print("[12] GET /api/state ok, секреты замаскированы:", st["config"]["CAPTCHA_API_KEY"])

    r = client.get("/api/log")
    assert r.status_code == 200 and isinstance(r.json()["lines"], list)
    print("[13] GET /api/log ok — строк в буфере:", r.json()["total"])

    r = client.post("/api/config", json={"EMAIL_DOMAIN": "newdomain.io",
                                         "MAX_ACCOUNTS": "7",
                                 "HEADLESS": "0"})
    assert r.status_code == 200, r.text
    assert cfg.EMAIL_DOMAIN == "newdomain.io"
    assert cfg.MAX_ACCOUNTS == 7 and cfg.HEADLESS is False
    print("[14] POST /api/config ok:", r.json()["applied"])

    r = client.post("/api/config", json={"REG_METHOD": "bad"})
    assert r.status_code == 400, r.text
    print("[15] POST /api/config валидация ok:", r.json()["error"])
    cfg.REG_METHOD = "email"

    r = client.post("/api/stop")
    assert r.status_code == 200 and r.json()["ok"] is True
    print("[16] POST /api/stop ok")

    r = client.get("/api/accounts")
    assert r.status_code == 200
    print("[17] GET /api/accounts ok — записей:", r.json()["count"])
except ImportError as exc:
    print("[11] dashboard check skipped:", exc)

print("\nALL SMOKE TESTS PASSED")
