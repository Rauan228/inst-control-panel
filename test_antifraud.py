#!/usr/bin/env python3
"""
test_antifraud.py — проверки «человечности» идентичности и экономии трафика.

  1. username и full_name строятся из ОДНОЙ пары имя+фамилия (нет «Nathan
     Smith» рядом с ником «laura8419.hernandez»);
  2. нет «красивых» дат рождения (25.12, 01.01, 14.02…), возраст в диапазоне;
  3. local-part почты — без узнаваемого префикса «ig.» по умолчанию;
  4. TrafficSaver режет картинки/шрифты, но пропускает HTML/JS/CSS,
     и снимает блокировку по allow() (нужно на время загрузки аватара).
"""
from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from aiohttp import web  # noqa: E402

import autoreg  # noqa: E402
from config import BIRTHDAY_BLACKLIST, load_config  # noqa: E402

autoreg.setup_logging("test_antifraud.log", verbose=False)

PAGE = """<!doctype html><html><head><link rel="stylesheet" href="/s.css">
<script src="/s.js"></script></head>
<body><img id="i" src="/s.png"><div id="out"></div>
<script>document.getElementById('out').textContent = window.__js_loaded || 'no';</script>
</body></html>"""


def build_app() -> web.Application:
    app = web.Application()

    async def page(_r):
        return web.Response(text=PAGE, content_type="text/html")

    async def css(_r):
        return web.Response(text="body{color:#000}", content_type="text/css")

    async def js(_r):
        return web.Response(text="window.__js_loaded='yes';",
                            content_type="application/javascript")

    async def png(_r):
        return web.Response(body=bytes.fromhex(
            "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
            "1f15c4890000000a49444154789c6300010000050001"
            "0d0a2db40000000049454e44ae426082"), content_type="image/png")

    app.router.add_get("/", page)
    app.router.add_get("/s.css", css)
    app.router.add_get("/s.js", js)
    app.router.add_get("/s.png", png)
    return app


def check_identity(cfg) -> None:
    factory = autoreg.IdentityFactory(cfg)
    checked = 0
    for _ in range(300):
        ident = factory.new_identity()
        first, last = (p.lower() for p in ident.full_name.split()[:2])
        uname = ident.username.lower()
        # каждый шаблон ника содержит либо имя целиком, либо фамилию целиком
        assert first in uname or last in uname, (uname, ident.full_name)
        year, month, day = ident.birthday
        assert (month, day) not in BIRTHDAY_BLACKLIST, ident.birthday
        age = autoreg.datetime.now().year - year
        assert cfg.MIN_BIRTHDAY_AGE <= age <= cfg.MAX_BIRTHDAY_AGE, (age, ident.birthday)
        assert 1 <= day <= 28 and 1 <= month <= 12, ident.birthday
        assert ident.email.endswith(f"@{cfg.EMAIL_DOMAIN}"), ident.email
        assert not ident.email.startswith("ig."), ident.email
        checked += 1
    print(f"[1] ok: {checked} идентичностей — ник из той же пары, что full_name")
    print("[2] ok: даты рождения без «красивых» MM-DD, возраст в диапазоне")
    print("[3] ok: почта без префикса «ig.» —", factory.new_identity().email)


async def check_traffic(cfg) -> None:
    cfg.BLOCK_MEDIA = True
    browser = autoreg.BrowserFactory(cfg)
    context, page = await browser.new_context(cfg.random_identity())
    try:
        await page.goto(PAGE_URL, wait_until="load")
        await asyncio.sleep(1.0)
        js_loaded = await page.locator("#out").inner_text()
        img_width = await page.evaluate("document.getElementById('i').naturalWidth")
        assert js_loaded == "yes", "JS не загрузился при блокировке медиа"
        assert img_width == 0, "картинка не заблокирована"
        assert browser.traffic.blocked >= 1, browser.traffic.blocked
        print(f"[4] ok: медиа заблокировано ({browser.traffic.blocked} запросов), JS работает")

        browser.traffic.allow()
        await page.reload(wait_until="load")
        await asyncio.sleep(1.0)
        img_width = await page.evaluate("document.getElementById('i').naturalWidth")
        assert img_width == 1, f"после allow картинка не загрузилась ({img_width})"
        print("[5] ok: allow() снимает блокировку (нужно для аватара)")
    finally:
        await context.close()
        await browser.close()


async def main() -> int:
    global PAGE_URL
    cfg = load_config()
    cfg.HEADLESS = True
    cfg.PROXY = ""
    check_identity(cfg)

    runner = web.AppRunner(build_app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    PAGE_URL = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/"
    try:
        await check_traffic(cfg)
    finally:
        await runner.cleanup()

    print("\nANTIFRAUD TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
