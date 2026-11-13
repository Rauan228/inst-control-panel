#!/usr/bin/env python3
"""
test_services.py — интеграционные тесты сетевых подсистем на локальных mock-серверах.

Проверяются без реальных провайдеров:
  * ProxyRotator     — GET на rotation URL, сон, смена IP, ProxyDeadError
  * SmsVerifier      — sms-activate (getNumber/getStatus/setStatus) и 5sim
                       (buy/check/cancel/ban/finish), таймаут 180 с, BANNED
  * ArkoseSolver     — CapMonster и 2Captcha: createTask/getTaskResult, токен
  * полный цикл handle() на mock-странице с Arkose iframe
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("PROXY", "")
os.environ.setdefault("EMAIL_DOMAIN", "example.com")
os.environ.setdefault("SMS_API_KEY", "test-key")
os.environ.setdefault("CAPTCHA_API_KEY", "test-captcha-key")

from aiohttp import web  # noqa: E402

import autoreg  # noqa: E402
from config import load_config  # noqa: E402

autoreg.setup_logging("test_services.log", verbose=False)
log = autoreg.log

STATE: dict[str, object] = {
    "rotation_hits": 0,
    "ip": "10.0.0.1",
    "sms_status_calls": 0,
    "sms_set_status": [],
    "sms_mode": "ok",          # ok | banned | wait_forever
    "fivesim": {},
    "cap_tasks": {},
    "two_tasks": {},
    "cap_calls": 0,
}


# ----------------------------------------------------------------- mock API
async def rotate(request: web.Request) -> web.Response:
    STATE["rotation_hits"] += 1
    # каждый вызов меняет исходящий IP
    octet = int(str(STATE["ip"]).split(".")[-1]) + 1
    STATE["ip"] = f"10.0.0.{octet}"
    return web.Response(text=f"OK ip changed to {STATE['ip']}")


async def rotate_fail(request: web.Request) -> web.Response:
    return web.Response(status=503, text="proxy provider down")


async def ipify(request: web.Request) -> web.Response:
    return web.Response(text=json.dumps({"ip": STATE["ip"]}),
                        content_type="application/json")


async def ipify_dead(request: web.Request) -> web.Response:
    raise web.HTTPServiceUnavailable(text="no route")


async def sms_activate(request: web.Request) -> web.Response:
    """Эмуляция https://api.sms-activate.org/stubs/handler.php"""
    q = request.query
    action = q.get("action")
    assert q.get("api_key") == "test-key", "api_key не передан"

    if action == "getNumber":
        assert q.get("service") == "ig", q
        return web.Response(text="ACCESS_NUMBER:44412345:79991234567")

    if action == "getStatus":
        STATE["sms_status_calls"] += 1
        mode = STATE["sms_mode"]
        if mode == "banned":
            return web.Response(text="ERROR:BANNED")
        if mode == "wait_forever":
            return web.Response(text="STATUS_WAIT_CODE")
        if mode == "cancel":
            return web.Response(text="STATUS_CANCEL")
        # первые 2 опроса — ждём, потом код
        if STATE["sms_status_calls"] <= 2:
            return web.Response(text="STATUS_WAIT_CODE")
        return web.Response(text="STATUS_OK:246810")

    if action == "setStatus":
        STATE["sms_set_status"].append((q.get("id"), int(q.get("status", -1))))
        return web.Response(text="ACCESS_CANCEL" if q.get("status") == "8" else "ACCESS_BAN")

    return web.Response(text="ERROR:UNKNOWN_ACTION")


async def fivesim_buy(request: web.Request) -> web.Response:
    assert request.headers.get("Authorization") == "Bearer test-key"
    data = {"id": 99887766, "phone": "79998887766", "price": 5.0, "status": "WAIT_CODE"}
    STATE["fivesim"] = {"checks": 0, "actions": [], **data}
    return web.Response(text=json.dumps(data), content_type="application/json")


async def fivesim_check(request: web.Request) -> web.Response:
    STATE["fivesim"]["checks"] += 1
    n = STATE["fivesim"]["checks"]
    if STATE["sms_mode"] == "banned":
        payload = {"id": 99887766, "status": "BANNED", "sms": []}
    elif STATE["sms_mode"] == "wait_forever":
        payload = {"id": 99887766, "status": "WAIT_CODE", "sms": []}
    elif n < 3:
        payload = {"id": 99887766, "status": "WAIT_CODE", "sms": []}
    else:
        payload = {"id": 99887766, "status": "RECEIVED",
                   "sms": [{"code": "", "text": "Instagram code: 135790. Don't share it."}]}
    return web.Response(text=json.dumps(payload), content_type="application/json")


async def fivesim_action(request: web.Request) -> web.Response:
    act = request.match_info["action"]
    STATE["fivesim"]["actions"].append((request.match_info["id"], act))
    return web.Response(text=json.dumps({"id": 99887766, "status": act.upper()}),
                        content_type="application/json")


async def cap_create(request: web.Request) -> web.Response:
    body = await request.json()
    assert body["clientKey"] == "test-captcha-key", body
    task = body["task"]
    assert task["type"] == "FunCaptchaTaskProxyless", task
    assert task["websitePublicKey"], task
    STATE["cap_calls"] += 1
    STATE["cap_last_task"] = task
    tid = f"cap-{STATE['cap_calls']}"
    STATE["cap_tasks"][tid] = {"polls": 0, "public_key": task["websitePublicKey"]}
    return web.Response(text=json.dumps({"errorId": 0, "taskId": tid}),
                        content_type="application/json")


async def cap_result(request: web.Request) -> web.Response:
    body = await request.json()
    tid = body["taskId"]
    t = STATE["cap_tasks"][tid]
    t["polls"] += 1
    if t["polls"] < 2:
        payload = {"errorId": 0, "status": "processing"}
    else:
        payload = {"errorId": 0, "status": "ready",
                   "solution": {"token": f"ARKOSE_TOKEN_FOR_{t['public_key'][:8]}"}}
    return web.Response(text=json.dumps(payload), content_type="application/json")


async def two_create(request: web.Request) -> web.Response:
    body = await request.json()
    assert body["clientKey"] == "test-captcha-key"
    assert body["task"]["type"] == "FunCaptchaTaskProxyless"
    tid = f"two-{len(STATE['two_tasks']) + 1}"
    STATE["two_tasks"][tid] = {"polls": 0, "task": body["task"]}
    return web.Response(text=json.dumps({"errorId": 0, "taskId": tid}),
                       content_type="application/json")


async def two_result(request: web.Request) -> web.Response:
    body = await request.json()
    t = STATE["two_tasks"][body["taskId"]]
    t["polls"] += 1
    if t["polls"] < 2:
        payload = {"errorId": 0, "status": "processing"}
    else:
        payload = {"errorId": 0, "status": "ready",
                   "solution": {"token": "2CAPTCHA_SOLVED_TOKEN"}}
    return web.Response(text=json.dumps(payload), content_type="application/json")


async def mock_signup(request: web.Request) -> web.Response:
    """Страница с Arkose-челленджем: iframe + config в inline-скрипте + token-поле."""
    html = """<!doctype html><html><body>
    <script>
      window.arkoseEnforcement = {
        _config: { public_key: "AAAABBBB-1111-2222-3333-CCCCDDDDEEEE",
                   surl: "https://client-api.arkoselabs.com",
                   blob: "eyJkYXRhIjp7ImIiOjF9fQ==" },
        setConfig: function (c) { window.__injected = c; },
        run: function () { window.__ran = true; },
      };
    </script>
    <input type="hidden" name="fc-token" value="">
    <iframe id="arkose" src="https://client-api.arkoselabs.com/v2/1.5.2/enforcement.html?public_key=AAAABBBB-1111-2222-3333-CCCCDDDDEEEE&surl=https%3A%2F%2Fclient-api.arkoselabs.com"
            style="width:340px;height:400px"></iframe>
    <button type="submit">Next</button>
    <script>
      document.querySelector('button').onclick = () => {
        if (document.querySelector('[name="fc-token"]').value) {
          document.getElementById('arkose').remove();
          document.title = 'CHALLENGE_PASSED';
        }
      };
    </script></body></html>"""
    return web.Response(text=html, content_type="text/html")


async def ei_captcha(request: web.Request) -> web.Response:
    """EveryInfra EverySolve: синхронный POST /api/v1/captcha, type=funcaptcha."""
    assert request.headers.get("Authorization") == "Bearer test-captcha-key"
    body = await request.json()
    assert body["type"] == "funcaptcha", body
    assert body["website_key"], body
    STATE["ei_last_payload"] = body
    payload = {
        "type": "funcaptcha",
        "solution": {"token": "EVERYINFRA_SOLVED_TOKEN"},
        "token": "EVERYINFRA_SOLVED_TOKEN",
        "billing": {"charged": True, "charged_usd": 0.001667,
                    "balance_after_usd": 0.998333},
    }
    return web.Response(text=json.dumps(payload), content_type="application/json")


async def ei_account(request: web.Request) -> web.Response:
    assert request.headers.get("Authorization") == "Bearer test-captcha-key"
    return web.Response(text=json.dumps({"balance": {"total_usd": 1.0}}),
                        content_type="application/json")


async def ei_error(request: web.Request) -> web.Response:
    return web.Response(status=402,
                        text=json.dumps({"error": "insufficient_balance"}),
                        content_type="application/json")


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/rotate", rotate)
    app.router.add_get("/rotate-fail", rotate_fail)
    app.router.add_get("/ip", ipify)
    app.router.add_get("/ip-dead", ipify_dead)
    app.router.add_get("/sms-activate", sms_activate)
    app.router.add_get("/5sim/buy/activation/{country}/instagram", fivesim_buy)
    app.router.add_get("/5sim/check/{id}", fivesim_check)
    app.router.add_get("/5sim/{action}/{id}", fivesim_action)
    app.router.add_post("/capmonster/createTask", cap_create)
    app.router.add_post("/capmonster/getTaskResult", cap_result)
    app.router.add_post("/2captcha/createTask", two_create)
    app.router.add_post("/2captcha/getTaskResult", two_result)
    app.router.add_post("/everyinfra/api/v1/captcha", ei_captcha)
    app.router.add_post("/everyinfra-broke/api/v1/captcha", ei_error)
    app.router.add_get("/everyinfra/api/v1/account", ei_account)
    app.router.add_get("/signup", mock_signup)
    return app


# ------------------------------------------------------------------- tests
async def test_proxy(cfg: autoreg.Config, session) -> None:
    base = cfg.TEST_BASE
    rot = autoreg.ProxyRotator(cfg)
    cfg.PROXY_ROTATION_URL = f"{base}/rotate"
    cfg.PROXY_ROTATE_SLEEP = 1          # ТЗ требует 10; в тесте ускоряем
    cfg.PROXY_MAX_RETRIES = 2

    t0 = time.monotonic()
    ip1 = await rot.rotate(session)
    dt = time.monotonic() - t0
    assert ip1 == "10.0.0.2", ip1
    assert STATE["rotation_hits"] == 1, STATE
    assert dt >= cfg.PROXY_ROTATE_SLEEP, f"не выдержан сон {dt}"
    ip2 = await rot.rotate(session)
    assert ip2 == "10.0.0.3" and ip2 != ip1
    assert STATE["rotation_hits"] == 2
    print(f"[proxy] ok: ротаций={rot.rotations} IP {ip1} -> {ip2}, сон {dt:.1f}с выдержан")

    # мёртвый rotation URL -> ProxyDeadError
    cfg.PROXY_ROTATION_URL = f"{base}/rotate-fail"
    try:
        await rot.rotate(session)
        raise AssertionError("ожидался ProxyDeadError")
    except autoreg.ProxyDeadError as exc:
        assert "503" in str(exc), exc
        print("[proxy] ok: 503 от rotation URL ->", exc)

    # мёртвый прокси (IP-сервис не отвечает)
    cfg.PROXY_ROTATION_URL = ""
    autoreg.ProxyRotator.IP_SERVICES = (f"{base}/ip-dead",)
    try:
        await rot.check(session)
        raise AssertionError("ожидался ProxyDeadError")
    except autoreg.ProxyDeadError as exc:
        print("[proxy] ok: недоступный IP-сервис ->", str(exc)[:70])
    autoreg.ProxyRotator.IP_SERVICES = (f"{base}/ip",)


async def test_sms_activate(cfg: autoreg.Config, base: str, session) -> None:
    cfg.SMS_PROVIDER = "sms-activate"
    cfg.SMS_TIMEOUT = 20
    cfg.SMS_POLL_INTERVAL = 0.2
    autoreg.SmsVerifier.SMS_ACTIVATE_URL = f"{base}/sms-activate"
    sv = autoreg.SmsVerifier(cfg)

    STATE["sms_mode"] = "ok"
    STATE["sms_status_calls"] = 0
    STATE["sms_set_status"] = []

    act = await sv.buy(session)
    assert act.activation_id == "44412345" and act.phone == "79991234567", act
    code = await sv.wait_for_code(session, act)
    assert code == "246810", code
    print(f"[sms-activate] ok: номер {act.phone} id={act.activation_id} код={code} "
          f"(опросов={STATE['sms_status_calls']})")

    await sv.finish(session, act)
    assert ("44412345", 1) in STATE["sms_set_status"], STATE["sms_set_status"]

    # забаненный номер
    STATE["sms_mode"] = "banned"
    STATE["sms_status_calls"] = 0
    STATE["sms_set_status"] = []
    act2 = await sv.buy(session)
    try:
        await sv.wait_for_code(session, act2)
        raise AssertionError("ожидался BannedNumberError")
    except autoreg.BannedNumberError as exc:
        await sv.ban(session, act2)
        assert ("44412345", 6) in STATE["sms_set_status"], STATE["sms_set_status"]
        print("[sms-activate] ok: BANNED -> BannedNumberError + setStatus(6):", exc)

    # таймаут ожидания кода -> отмена активации
    STATE["sms_mode"] = "wait_forever"
    STATE["sms_status_calls"] = 0
    STATE["sms_set_status"] = []
    cfg.SMS_TIMEOUT = 2
    act3 = await sv.buy(session)
    try:
        await sv.wait_for_code(session, act3)
        raise AssertionError("ожидался VerificationTimeoutError")
    except autoreg.VerificationTimeoutError as exc:
        await sv.cancel(session, act3)
        assert ("44412345", 8) in STATE["sms_set_status"], STATE["sms_set_status"]
        print("[sms-activate] ok: таймаут -> VerificationTimeoutError + setStatus(8) (отмена)")
    cfg.SMS_TIMEOUT = 20


async def test_5sim(cfg: autoreg.Config, base: str, session) -> None:
    cfg.SMS_PROVIDER = "5sim"
    cfg.SMS_TIMEOUT = 20
    cfg.SMS_POLL_INTERVAL = 0.2
    sv = autoreg.SmsVerifier(cfg)
    sv.FIVESIM_URL = f"{base}/5sim"

    STATE["sms_mode"] = "ok"
    STATE["fivesim"] = {}
    act = await sv.buy(session)
    assert act.activation_id == "99887766" and act.phone == "79998887766", act
    code = await sv.wait_for_code(session, act)
    assert code == "135790", code      # вырезан из текста SMS регуляркой \b\d{6}\b
    await sv.finish(session, act)
    assert ("99887766", "finish") in STATE["fivesim"]["actions"]
    print(f"[5sim] ok: номер {act.phone} код={code} (из текста SMS), finish вызван")

    STATE["sms_mode"] = "banned"
    act2 = await sv.buy(session)
    try:
        await sv.wait_for_code(session, act2)
        raise AssertionError("ожидался BannedNumberError")
    except autoreg.BannedNumberError:
        await sv.ban(session, act2)
        assert any(a == "ban" for _, a in STATE["fivesim"]["actions"])
        print("[5sim] ok: статус BANNED -> BannedNumberError + /ban")

    STATE["sms_mode"] = "wait_forever"
    cfg.SMS_TIMEOUT = 2
    act3 = await sv.buy(session)
    try:
        await sv.wait_for_code(session, act3)
        raise AssertionError("ожидался VerificationTimeoutError")
    except autoreg.VerificationTimeoutError:
        await sv.cancel(session, act3)
        assert any(a == "cancel" for _, a in STATE["fivesim"]["actions"])
        print("[5sim] ok: таймаут -> cancel активации")
    cfg.SMS_TIMEOUT = 20


async def test_captcha(cfg: autoreg.Config, base: str) -> None:
    cfg.CAPMONSTER_HOST = f"{base}/capmonster"
    cfg.TWOCAPTCHA_HOST = f"{base}/2captcha"
    cfg.CAPTCHA_TIMEOUT = 30

    solver_cm = autoreg.ArkoseSolver(cfg)
    cfg.CAPTCHA_PROVIDER = "capmonster"
    async with aiohttp_session() as s:
        tok = await solver_cm._capmonster(
            s, "https://www.instagram.com/accounts/emailsignup/",
            "AAAABBBB-1111-2222-3333-CCCCDDDDEEEE",
            "https://client-api.arkoselabs.com", "eyJkYXRhIjp7ImIiOjF9fQ==")
    assert tok == "ARKOSE_TOKEN_FOR_AAAABBBB", tok
    assert STATE["cap_last_task"]["funcaptchaBlob"] == "eyJkYXRhIjp7ImIiOjF9fQ=="
    assert STATE["cap_last_task"]["funcaptchaApiJSSubdomain"] == "https://client-api.arkoselabs.com"
    print("[capmonster] ok: токен", tok, "| blob и surl переданы в задачу")

    solver_2c = autoreg.ArkoseSolver(cfg)
    cfg.CAPTCHA_PROVIDER = "2captcha"
    async with aiohttp_session() as s:
        tok2 = await solver_2c._twocaptcha(
            s, "https://www.instagram.com/accounts/emailsignup/",
            "AAAABBBB-1111-2222-3333-CCCCDDDDEEEE",
            "https://client-api.arkoselabs.com", None)
    assert tok2 == "2CAPTCHA_SOLVED_TOKEN", tok2
    print("[2captcha] ok: токен", tok2)

    # --- EveryInfra EverySolve (синхронный POST /api/v1/captcha) ---
    cfg.CAPTCHA_PROVIDER = "everyinfra"
    cfg.EVERYINFRA_HOST = f"{base}/everyinfra"
    solver_ei = autoreg.ArkoseSolver(cfg)
    async with aiohttp_session() as s:
        tok3 = await solver_ei._everyinfra(
            s, "https://www.instagram.com/accounts/emailsignup/",
            "AAAABBBB-1111-2222-3333-CCCCDDDDEEEE",
            "https://client-api.arkoselabs.com", "eyJkYXRhIjp7ImIiOjF9fQ==")
    assert tok3 == "EVERYINFRA_SOLVED_TOKEN", tok3
    sent = STATE["ei_last_payload"]
    assert sent["type"] == "funcaptcha" and sent["website_key"].startswith("AAAABBBB")
    assert sent["api_subdomain"] == "client-api.arkoselabs.com", sent
    assert sent["blob"] == "eyJkYXRhIjp7ImIiOjF9fQ==", sent
    print("[everyinfra] ok: токен %s | payload type=%s key=%s subdomain=%s blob=%s"
          % (tok3, sent["type"], sent["website_key"][:8] + "…",
             sent["api_subdomain"], sent["blob"][:10] + "…"))

    # --- ошибка провайдера (нет денег) -> CaptchaRequiredError ---
    cfg.EVERYINFRA_HOST = f"{base}/everyinfra-broke"
    async with aiohttp_session() as s:
        try:
            await solver_ei._everyinfra(s, "https://x/", "K", "", None)
            raise AssertionError("ожидался CaptchaRequiredError")
        except autoreg.CaptchaRequiredError as exc:
            assert "402" in str(exc), exc
            print("[everyinfra] ok: HTTP 402 ->", str(exc)[:60])
    cfg.EVERYINFRA_HOST = f"{base}/everyinfra"


def aiohttp_session():
    import aiohttp
    return aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))


async def test_arkose_full_cycle(cfg: autoreg.Config, base: str) -> None:
    """handle(): детект iframe -> probe sitekey -> CapMonster -> инжект -> submit."""
    cfg.CAPTCHA_PROVIDER = "capmonster"
    bf = autoreg.BrowserFactory(cfg)
    ctx, page = await bf.new_context()
    await page.goto(f"{base}/signup", wait_until="domcontentloaded")

    solver = autoreg.ArkoseSolver(cfg)
    assert await solver.is_present(page, timeout_ms=5000), "Arkose не задетекчен"

    info = await solver.probe(page)
    assert info["sitekey"] == "AAAABBBB-1111-2222-3333-CCCCDDDDEEEE", info
    assert info["surl"] == "https://client-api.arkoselabs.com", info
    assert info["blobs"] and info["blobs"][0] == "eyJkYXRhIjp7ImIiOjF9fQ==", info
    print("[arkose] probe ok: sitekey=%s sources=%s" % (info["sitekey"][:12] + "…", info["sources"]))

    ok = await solver.handle(page)
    assert ok is True
    token_value = await page.evaluate("document.querySelector('[name=\"fc-token\"]').value")
    injected_into = await page.evaluate("window.__injected && window.__injected.data.token")
    ran = await page.evaluate("window.__ran === true")
    title = await page.title()
    assert token_value == "ARKOSE_TOKEN_FOR_AAAABBBB", token_value
    assert injected_into == token_value, injected_into
    assert ran is True
    assert title == "CHALLENGE_PASSED", title
    print("[arkose] handle ok: токен в поле + setConfig + run(); челлендж закрыт (%s)" % title)

    await ctx.close()
    await bf.close()


async def run_all() -> int:
    runner = web.AppRunner(build_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    print(f"[mock] сервисы-заглушки на {base}")

    cfg = load_config()
    cfg.TEST_BASE = base  # type: ignore[attr-defined]
    cfg.PROXY = ""        # без прокси: mock'и локальные

    import aiohttp
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        autoreg.ProxyRotator.IP_SERVICES = (f"{base}/ip",)
        await test_proxy(cfg, session)
        await test_sms_activate(cfg, base, session)
        await test_5sim(cfg, base, session)
    await test_captcha(cfg, base)
    await test_arkose_full_cycle(cfg, base)

    await runner.cleanup()
    print("\nALL SERVICE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_all()))
