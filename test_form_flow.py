#!/usr/bin/env python3
"""
test_form_flow.py — интеграционная проверка InstagramRegistrar на локальном
mock-сайте, который повторяет реальную разметку формы регистрации Instagram
(те же name/aria-label/структура submit'а и экрана ввода кода).

Сети и настоящего Instagram не требуется: поднимается http.server на 127.0.0.1,
TARGET_URL временно подменяется на него.
"""
from __future__ import annotations

import asyncio
import os
import sys
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("PROXY", "")
os.environ.setdefault("EMAIL_DOMAIN", "example.com")
os.environ.setdefault("IMAP_USER", "catch@example.com")
os.environ.setdefault("IMAP_PASS", "secret")

import autoreg  # noqa: E402
from config import load_config  # noqa: E402

autoreg.setup_logging("test_form.log", verbose=False)

MOCK_ROOT = Path(__file__).parent / "_mock_ig"
MOCK_ROOT.mkdir(exist_ok=True)

# Заглушки повторяют реальную разметку Meta signup (без name-атрибутов,
# combobox-дата рождения, div[role=button] submit) — см. mock_ig.py
from mock_ig import write_all as _write_mock  # noqa: E402

_write_mock(MOCK_ROOT, with_challenge=False)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args, **kwargs) -> None:  # глушим access-лог
        pass


async def main() -> int:
    handler = partial(QuietHandler, directory=str(MOCK_ROOT))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print(f"[mock] Instagram-заглушка на http://127.0.0.1:{port}/index.html")

    cfg = load_config()
    cfg.TARGET_URL = f"http://127.0.0.1:{port}/index.html"
    cfg.HEADLESS = True
    # локальный mock не должен ходить через боевой прокси из .env
    cfg.PROXY = ""
    cfg.PROXY_LIST = ""

    bf = autoreg.BrowserFactory(cfg)
    human = autoreg.HumanDriver(cfg)
    arkose = autoreg.ArkoseSolver(cfg)
    ident = autoreg.IdentityFactory(cfg).new_identity()
    ident.birthday = (1996, 11, 14)   # есть в listbox'ах заглушки

    ctx, page = await bf.new_context()
    reg = autoreg.InstagramRegistrar(cfg, human, arkose)

    need_code = await reg.run_form(page, ident, "email")

    # заглушка складывает принятые значения в window.__form (как это сделал бы IG)
    filled = await page.evaluate("""() => Object.assign({}, window.__form, {title: document.title})""")
    print("[form] заполнено:", {k: (str(v)[:18] + '…' if len(str(v)) > 18 else v)
                                for k, v in filled.items()})
    assert filled["contact"] == ident.email, filled
    assert filled["fullname"] == ident.full_name, filled
    assert filled["username"] == ident.username, filled
    assert filled["password"] == ident.password, filled
    assert filled["day"] == "14", filled
    assert filled["month"] == "november", filled
    assert filled["year"] == "1996", filled
    assert filled["title"] == "CODE_PROMPT", filled
    assert need_code is True, "регистрация должна запросить код"
    print("[form] submit прошёл (div[role=button] «Отправить»), экран кода получен")

    await reg.enter_code(page, "654321")
    await asyncio.sleep(1)
    dbg = await page.evaluate("""() => ({ title: document.title,
        code: document.querySelector('#codeScreen input').value,
        codeVisible: document.getElementById('codeScreen').style.display,
        feedVisible: document.getElementById('feed').style.display })""")
    print("[debug] после enter_code:", dbg)
    assert dbg["code"] == "654321", dbg
    # mock мгновенно переходит CODE_SUBMITTED -> LOGGED_IN, поэтому ждём финал
    await page.wait_for_function("document.title === 'LOGGED_IN'", timeout=15000)
    print("[form] код отправлен ->", await page.title())
    print("[form] сессия получена (LOGGED_IN)")

    # --- траст-блок: страницы edit.html / profile.html уже созданы mock_ig ---

    av = Path(cfg.AVATARS_DIR) / "test_avatar.png"
    av.write_bytes(bytes.fromhex(
        "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
        "1f15c4890000000a49444154789c6300010000050001"
        "0d0a2db40000000049454e44ae426082"))

    trust = autoreg.TrustBuilder(cfg)
    cfg.PROFILE_EDIT_URL = f"http://127.0.0.1:{port}/edit.html"
    cfg.TRUST_TARGETS = [f"http://127.0.0.1:{port}/profile.html"]
    cfg.ENABLE_AVATAR = True      # .env может отключать — тест проверяет полную ветку
    cfg.ENABLE_TRUST = True

    ok = await trust.upload_avatar(page, human)
    title_after_avatar = await page.title()
    print("[trust] аватар загружен:", ok, "| title:", title_after_avatar)
    assert ok, "аватар не загрузился"
    assert title_after_avatar == "AVATAR_SET", title_after_avatar

    followed = await trust.follow_target(page, human)
    title_after_follow = await page.title()
    print("[trust] follow_target вернул:", followed, "| title:", title_after_follow)
    assert followed and title_after_follow == "FOLLOWED", title_after_follow
    btn_text = await page.locator('div[role="button"]').inner_text()
    assert btn_text == "Following", btn_text
    print("[trust] Follow нажат, кнопка сменилась на", btn_text)

    # --- cookies ---
    cookies = await ctx.cookies()
    print("[cookies] получено:", len(cookies), "штук")

    await ctx.close()
    await bf.close()
    httpd.shutdown()
    print("\nFORM FLOW TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
