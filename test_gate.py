#!/usr/bin/env python3
"""
test_gate.py — человеческий гейт «Confirm you're human» (/accounts/suspended).

Что проверяем офлайн, без реального Instagram:
  1. детект гейта по URL и по тексту, отсутствие ложных срабатываний на ленте;
  2. прохождение гейта кнопкой Continue (аккаунт уезжает на профиль/ленту);
  3. проброс sitekey reCAPTCHA + инжект токена в скрытое поле;
  4. confirm_logged_in поднимает SuspendedError, если гейт не пройден
     (а не молча уходит, как раньше после появления sessionid);
  5. статус аккаунта сохраняется в accounts.json (alive/suspended) — метрика
     выживаемости, без которой нельзя оценить качество трафика.

Сеть нужна только локальная (aiohttp на 127.0.0.1).
"""
from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from aiohttp import web  # noqa: E402

import autoreg  # noqa: E402
from config import load_config  # noqa: E402
from mock_ig import write_all as write_mock  # noqa: E402

autoreg.setup_logging("test_gate.log", verbose=False)

MOCK = Path(tempfile.mkdtemp(prefix="gate_mock_"))
write_mock(MOCK, with_challenge=False, with_gate=True)


def build_cfg(tmp: Path) -> autoreg.Config:
    cfg = load_config()
    cfg.HEADLESS = True
    cfg.PROXY = ""
    cfg.BLOCK_MEDIA = False
    cfg.ENABLE_GATE = True
    cfg.GATE_TIMEOUT = 12
    cfg.GATE_MAX_ROUNDS = 1
    cfg.COOLDOWN_MIN = cfg.COOLDOWN_MAX = 0
    cfg.COOKIES_DIR = str(tmp / "cookies")
    cfg.SUCCESS_FILE = str(tmp / "success.txt")
    cfg.FAILED_FILE = str(tmp / "failed.txt")
    cfg.LOG_FILE = str(tmp / "gate.log")
    cfg.CAPTCHA_PROVIDER = "everyinfra"
    cfg.CAPTCHA_API_KEY = "test-key"
    return cfg


async def main() -> int:
    runner = web.AppRunner(web.Application())
    runner.app.router.add_static("/", path=str(MOCK), show_index=True)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"

    tmp = Path(tempfile.mkdtemp(prefix="gate_state_"))
    cfg = build_cfg(tmp)
    browser = autoreg.BrowserFactory(cfg)
    human = autoreg.HumanDriver(cfg)
    arkose = autoreg.ArkoseSolver(cfg)
    gate = autoreg.HumanGate(cfg)
    context, page = await browser.new_context(cfg.random_identity())

    try:
        # --- 1. детект -----------------------------------------------------
        await page.goto(f"{base}/feed.html")
        assert not await gate.is_gate(page), "ложное срабатывание на ленте"
        print("[1] лента гейтом не считается — ok")

        await page.goto(f"{base}/gate.html")
        assert await gate.is_gate(page), "гейт по тексту не распознан"
        print("[2] гейт распознан по тексту «Confirm you're human» — ok")

        # URL-детект (как у реального /accounts/suspended)
        assert autoreg.HumanGate.URL_RE.search("/accounts/suspended/?next=/x")
        print("[3] URL /accounts/suspended матчится — ok")

        # --- 2. прохождение Continue ---------------------------------------
        await page.goto(f"{base}/gate.html")
        ok = await gate.pass_gate(page, human, arkose)
        assert ok, "гейт не пройден по Continue"
        assert "feed.html" in page.url, page.url
        print(f"[4] гейт пройден Continue -> {page.url.rsplit('/', 1)[-1]} — ok")

        # --- 3. reCAPTCHA: probe + инжект ----------------------------------
        await page.goto(f"{base}/gate_recaptcha.html")
        info = await arkose.probe_recaptcha(page)
        assert info.get("sitekey") == "6Lc_TESTKEY_ENTERPRISE", info
        assert info.get("enterprise") is True, info
        print(f"[5] sitekey перехвачен: {info['sitekey']} (enterprise) — ok")

        async def fake_solve(_page):  # noqa: ANN001
            return "RECAPTCHA_TOKEN"

        arkose.solve_recaptcha = fake_solve  # type: ignore[assignment]
        assert await arkose.handle_recaptcha(page), "reCAPTCHA-ветка не отработала"
        assert "feed.html" in page.url, page.url
        print("[6] токен reCAPTCHA внедрён, гейт пропущен — ok")

        # --- 4. залипший гейт -> SuspendedError ----------------------------
        registrar = autoreg.InstagramRegistrar(cfg, human, arkose)
        await page.goto(f"{base}/gate_stuck.html")
        await context.add_cookies([{
            "name": "sessionid", "value": "fake-session",
            "domain": ".instagram.com", "path": "/",
        }])
        try:
            await registrar.confirm_logged_in(page, timeout_ms=5000)
            raise AssertionError("SuspendedError не поднят")
        except autoreg.SuspendedError as exc:
            print(f"[7] SuspendedError поднят: {str(exc)[:60]} — ok")

        # --- 5. статусы в accounts.json ------------------------------------
        storage = autoreg.Storage(cfg)
        storage.accounts_db = tmp / "accounts.json"
        ident = autoreg.Identity(
            full_name="Nathan Smith", username="nathan.smith123",
            password="Abc123456789", email="nathan.smith123@example.com",
            birthday=(1994, 7, 5))
        await storage.save_success(ident, "http://u:p@1.2.3.4:1", None,
                                   {"gate": False}, status="suspended")
        assert json.loads(storage.accounts_db.read_text())[0]["status"] == "suspended"
        assert storage.update_status(ident.username, "alive")
        assert json.loads(storage.accounts_db.read_text())[0]["status"] == "alive"
        print("[8] статус suspended/alive пишется в accounts.json — ok")

        # --- 6. отлёжка: контекст переоткрывается с теми же cookies --------
        state = tmp / "state.json"
        await context.storage_state(path=str(state))
        fp = cfg.random_identity()
        ctx2, page2 = await browser.new_context(fp, storage_state=state,
                                               proxy_url="")
        try:
            cookies = await ctx2.cookies("https://www.instagram.com")
            assert any(c["name"] == "sessionid" for c in cookies), cookies
            print("[9] переоткрытие контекста сохраняет сессию — ok")
        finally:
            await ctx2.close()

    finally:
        await context.close()
        await browser.close()
        await runner.cleanup()

    print("\nGATE TEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
