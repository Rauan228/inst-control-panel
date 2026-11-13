#!/usr/bin/env python3
"""
test_engine_e2e.py — сквозной прогон Engine.register_one() на локальных заглушках.

Цепочка, которая реально исполняется:
  ротация прокси (mock) -> Playwright-контекст со случайным фингерпринтом ->
  заполнение формы регистрации (mock Instagram) -> submit -> Arkose FunCaptcha ->
  CapMonster (mock) -> инжект токена -> экран ввода кода ->
  IMAP catch-all (mock-сервер, настоящий imaplib) -> ввод кода ->
  траст: аватар (file chooser) + Follow -> storage_state JSON + success.txt

Вне заглушек остаются только реальные instagram.com и боевые API провайдеров.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("PROXY", "")
os.environ.setdefault("SMS_API_KEY", "test-key")
os.environ.setdefault("CAPTCHA_API_KEY", "test-captcha-key")

from aiohttp import web  # noqa: E402

import autoreg  # noqa: E402
from config import load_config  # noqa: E402
from test_email_imap import MAILBOX, FakeIMAPServer, make_mail  # noqa: E402

autoreg.setup_logging("test_e2e.log", verbose=False)

E2E_EMAIL = "ig.e2e_account@example.com"
E2E_CODE = "739201"
STATE: dict[str, object] = {"rotations": 0, "ip": "172.16.0.1", "cap_tasks": {}}

ROOT = Path(__file__).parent
MOCK = ROOT / "_mock_ig"
MOCK.mkdir(exist_ok=True)

# --- заглушки страниц: реальная разметка Meta signup + Arkose + экран кода --
from mock_ig import write_all as _write_mock  # noqa: E402

_write_mock(MOCK, with_challenge=True)


# ---------------------------------------------------------------- mock HTTP
async def rotate(request: web.Request) -> web.Response:
    STATE["rotations"] += 1
    last = int(str(STATE["ip"]).split(".")[-1]) + 1
    STATE["ip"] = f"172.16.0.{last}"
    return web.Response(text=f"OK {STATE['ip']}")


async def ipify(request: web.Request) -> web.Response:
    return web.Response(text=json.dumps({"ip": STATE["ip"]}), content_type="application/json")


async def cap_create(request: web.Request) -> web.Response:
    body = await request.json()
    task = body["task"]
    assert body["clientKey"] == "test-captcha-key"
    assert task["type"] == "FunCaptchaTaskProxyless"
    assert task["websitePublicKey"] == "EEEE1111-2222-3333-4444-555566667777", task
    assert task["funcaptchaBlob"] == "eyJkYXRhIjp7ImUyZSI6dHJ1ZX19", task
    tid = f"t{len(STATE['cap_tasks']) + 1}"
    STATE["cap_tasks"][tid] = {"polls": 0}
    STATE["cap_last_task"] = task
    return web.Response(text=json.dumps({"errorId": 0, "taskId": tid}),
                        content_type="application/json")


async def cap_result(request: web.Request) -> web.Response:
    body = await request.json()
    t = STATE["cap_tasks"][body["taskId"]]
    t["polls"] += 1
    payload = ({"errorId": 0, "status": "processing"} if t["polls"] < 2 else
               {"errorId": 0, "status": "ready",
                "solution": {"token": "E2E_ARKOSE_TOKEN"}})
    return web.Response(text=json.dumps(payload), content_type="application/json")


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/rotate", rotate)
    app.router.add_get("/ip", ipify)
    app.router.add_post("/capmonster/createTask", cap_create)
    app.router.add_post("/capmonster/getTaskResult", cap_result)
    # статикой отдаём mock-страницы Instagram (signup.html / edit.html / profile.html)
    app.router.add_static("/", path=str(MOCK), show_index=True)
    return app


# ------------------------------------------------------- e2e-подготовка cfg
def prepare_cfg(base: str, imap_port: int) -> autoreg.Config:
    cfg = load_config()
    cfg.REG_METHOD = "email"
    cfg.HEADLESS = True
    cfg.PROXY = ""                                   # локальные mock'и без прокси
    cfg.PROXY_ROTATION_URL = f"{base}/rotate"
    cfg.PROXY_ROTATE_SLEEP = 1                       # в бою — 10 (по ТЗ)
    cfg.TARGET_URL = f"{base}/signup.html"
    cfg.CAPTCHA_PROVIDER = "capmonster"
    cfg.CAPMONSTER_HOST = f"{base}/capmonster"
    cfg.CAPTCHA_TIMEOUT = 30
    cfg.EMAIL_DOMAIN = "example.com"
    cfg.IMAP_HOST = "127.0.0.1"
    cfg.IMAP_PORT = imap_port
    cfg.IMAP_SSL = False
    cfg.IMAP_USER = "catchall@example.com"
    cfg.IMAP_PASS = "app-password"
    cfg.IMAP_POLL_INTERVAL = 0.3
    cfg.IMAP_TIMEOUT = 60
    cfg.PROFILE_EDIT_URL = f"{base}/edit.html"
    cfg.TRUST_TARGETS = [f"{base}/profile.html"]
    # .env может отключать траст — тест всегда проверяет полную ветку
    cfg.ENABLE_AVATAR = True
    cfg.ENABLE_TRUST = True
    cfg.AVATARS_DIR = str(ROOT / "avatars")
    cfg.COOKIES_DIR = str(ROOT / "cookies_e2e")
    cfg.SUCCESS_FILE = str(ROOT / "success_e2e.txt")
    cfg.FAILED_FILE = str(ROOT / "failed_e2e.txt")
    cfg.LOG_FILE = str(ROOT / "test_e2e.log")
    cfg.GLOBAL_TIMEOUT = 240
    # без реальных пауз: отлёжка проверяется отдельно в test_gate.py
    cfg.COOLDOWN_MIN = cfg.COOLDOWN_MAX = 0

    # известный адрес через пул — чтобы заранее положить письмо в catch-all ящик
    pool = ROOT / "email_pool_e2e.txt"
    pool.write_text(f"{E2E_EMAIL}\n", encoding="utf-8")
    cfg.EMAIL_POOL_FILE = str(pool)

    # аватар
    av = Path(cfg.AVATARS_DIR) / "e2e_avatar.png"
    Path(cfg.AVATARS_DIR).mkdir(parents=True, exist_ok=True)
    av.write_bytes(bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
        "1f15c4890000000a49444154789c6300010000050001"
        "0d0a2db40000000049454e44ae426082"))

    # birthday из доступных в mock-селектах
    cfg.MIN_BIRTHDAY_AGE = cfg.MAX_BIRTHDAY_AGE = datetime_now_year() - 1994
    return cfg


def datetime_now_year() -> int:
    return time.localtime().tm_year


async def main() -> int:
    # --- mock HTTP ---
    runner = web.AppRunner(build_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"

    # --- mock IMAP ---
    imap_server = FakeIMAPServer()
    imap_server.start()

    cfg = prepare_cfg(base, imap_server.port)
    autoreg.ProxyRotator.IP_SERVICES = (f"{base}/ip",)
    autoreg.TrustBuilder.FOLLOW_PATTERNS = ("Follow",)

    # письмо «приходит» от Instagram через 3 секунды после старта формы
    MAILBOX.clear()

    def deliver_mail() -> None:
        time.sleep(6)
        MAILBOX.append(make_mail(E2E_EMAIL, E2E_CODE))

    threading.Thread(target=deliver_mail, daemon=True).start()

    # confirm_logged_in ждёт cookie sessionid на instagram.com — на mock-домене
    # его быть не может, поэтому подменяем на проверку факта входа
    async def fake_confirm(self, page, timeout_ms: int = 60000,  # noqa: ANN001
                           mail=None, email=None, since_ts=0.0) -> None:
        await page.wait_for_function("document.title === 'LOGGED_IN'", timeout=30000)

    autoreg.InstagramRegistrar.confirm_logged_in = fake_confirm

    # прогрев ленты ходит на реальный instagram.com — в тесте отключаем
    async def no_warm(self, page, human, minutes: float = 0,  # noqa: ANN001
                      seconds: float = 0) -> None:
        return None

    autoreg.TrustBuilder.warm_feed = no_warm
    autoreg.TrustBuilder.warm_visit = no_warm

    print(f"[e2e] mock IG: {base}/signup.html | mock IMAP: 127.0.0.1:{imap_server.port}")
    print(f"[e2e] письмо с кодом {E2E_CODE} для {E2E_EMAIL} придёт через 6 сек")

    engine = autoreg.Engine(cfg)
    try:
        import aiohttp
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session:
            ident = await engine.register_one(session)
    finally:
        await engine.shutdown()
        imap_server.close()
        await runner.cleanup()

    # ------------------------------------------------------------- проверки
    assert ident is not None, "аккаунт не зарегистрирован"
    assert ident.email == E2E_EMAIL, ident.email
    st = engine.stats
    assert st.success == 1 and st.failed == 0, st.as_dict()
    assert st.current_ip and st.current_ip.startswith("172.16.0."), st.current_ip
    assert STATE["rotations"] >= 1, STATE
    assert engine.arkose.solved == 1, "Arkose не был решён"
    assert STATE["cap_last_task"]["websitePublicKey"] == "EEEE1111-2222-3333-4444-555566667777"
    print(f"[e2e] аккаунт: {ident.username} | pass={ident.password[:4]}… | email={ident.email}")
    print(f"[e2e] proxy ротаций={STATE['rotations']} ip={st.current_ip} captcha решено={engine.arkose.solved}")

    # success.txt
    succ = Path(cfg.SUCCESS_FILE).read_text(encoding="utf-8").strip().splitlines()[-1]
    u, p, e, px = succ.split(":", 3)
    assert (u, p, e) == (ident.username, ident.password, ident.email), succ
    print("[e2e] success.txt:", succ)

    # cookies JSON
    cookie_files = sorted(Path(cfg.COOKIES_DIR).glob(f"{ident.username}_*.json"))
    assert cookie_files, "cookies не сохранены"
    data = json.loads(cookie_files[-1].read_text(encoding="utf-8"))
    assert "cookies" in data and "origins" in data, list(data)[:5]
    print("[e2e] cookies:", cookie_files[-1].name, "| записей:", len(data["cookies"]))

    # accounts.json
    db = json.loads((ROOT / "accounts.json").read_text(encoding="utf-8"))
    rec = [r for r in db if r["username"] == ident.username]
    assert rec, "записи нет в accounts.json"
    assert rec[-1]["cookies"] and rec[-1]["created_at"]
    trust = rec[-1]["trust"]
    assert trust["avatar"] is True, trust
    assert trust["followed"] == f"{base}/profile.html", trust
    print("[e2e] accounts.json:", json.dumps(rec[-1], ensure_ascii=False)[:200])
    print("[e2e] траст-отчёт:", trust)

    print("\nE2E TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
