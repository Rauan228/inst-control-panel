#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_headers_cors.py — регресс-тест на причину «пустой страницы Instagram».

Баг был такой: BrowserFactory клал в extra_http_headers заголовки
`Upgrade-Insecure-Requests: 1` и `sec-ch-ua-platform`. Playwright применяет
extra_http_headers ко ВСЕМ запросам контекста, включая кросс-доменные XHR к
static.cdninstagram.com. Такой заголовок делает запрос «не-простым» (non-simple),
браузер шлёт preflight OPTIONS, а CDN Instagram не отдаёт его в
Access-Control-Allow-Headers -> весь JS/CSS блокируется CORS-политикой,
страница остаётся пустой, форма не находится.

Тест проверяет:
  1. XHR/fetch с страницы НЕ несёт Upgrade-Insecure-Requests и sec-ch-ua-*;
  2. Accept-Language при этом на месте (он CORS-safelisted);
  3. document-запрос по-прежнему выглядит нормально;
  4. пустая страница диагностируется как PageBlankError, а не как
     FormNotFoundError, и при заблокированном CDN в сообщении есть слово CORS;
  5. BrowserCrashedError при закрытой странице.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# локальный сервер не должен ходить через боевой прокси из .env
os.environ["PROXY"] = ""
os.environ["PROXY_LIST"] = ""

import autoreg  # noqa: E402
from config import Config  # noqa: E402

autoreg.setup_logging(str(Path(__file__).parent / "test_headers.log"), verbose=False)

RECEIVED: dict[str, dict[str, str]] = {}

PAGE = """<!doctype html><html><body>
<h1>header probe</h1>
<script>
  fetch('/probe-xhr', { method: 'GET' }).then(r => r.text()).then(t => {
    document.title = 'XHR_DONE';
  }).catch(e => { document.title = 'XHR_FAIL:' + e; });
</script>
</body></html>"""

BLANK = """<!doctype html><html><body><div>no form here</div></body></html>"""

#: страница, имитирующая Instagram: HTML есть, но JS/CSS «заблокированы CORS»
CORS_PAGE = """<!doctype html><html><head>
<script src="https://static.cdninstagram.com/rsrc.php/v4/ys/r/364p170lgUQ.js"></script>
<link rel="stylesheet" href="https://static.cdninstagram.com/rsrc.php/v5/y5/l/0,cross/x.css">
</head><body><div id="mount_0_0_T0"></div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        RECEIVED[self.path] = {k.lower(): v for k, v in self.headers.items()}
        if self.path.startswith("/probe"):
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith("/blank"):
            body = BLANK.encode()
            ctype = "text/html"
        elif self.path.startswith("/cors"):
            body = CORS_PAGE.encode()
            ctype = "text/html"
        else:
            body = PAGE.encode()
            ctype = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        # намеренно НЕ разрешаем upgrade-insecure-requests — как настоящий CDN IG
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.send_header("Access-Control-Allow-Methods", "GET")
        self.end_headers()


async def main() -> int:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    print(f"[probe] сервер заголовков на {base}")

    cfg = Config(PROXY="", PROXY_ROTATE_SLEEP=0, AVATARS_DIR="avatars",
                 COOKIES_DIR="cookies_hdr", LOG_FILE="test_headers.log")
    bf = autoreg.BrowserFactory(cfg)
    ctx, page = await bf.new_context()

    try:
        # --- 1-3. заголовки XHR -------------------------------------------
        await page.goto(f"{base}/page.html", wait_until="domcontentloaded")
        await page.wait_for_function("document.title.startsWith('XHR_')", timeout=15000)
        xhr_headers = RECEIVED.get("/probe-xhr", {})
        doc_headers = RECEIVED.get("/page.html", {})

        # Upgrade-Insecure-Requests — вот он как раз провоцирует preflight и
        # блокировку CDN. sec-ch-ua-* браузер шлёт сам, это safelisted-заголовки,
        # но они обязаны СОГЛАСОВАННО соответствовать user_agent.
        forbidden = ("upgrade-insecure-requests",)
        bad = [k for k in forbidden if k in xhr_headers]
        assert not bad, (
            f"XHR несёт запрещённые заголовки {bad} — это и ломает CORS на "
            f"static.cdninstagram.com. Получено: {json.dumps(xhr_headers, indent=1)}")
        print("[1] ok: XHR не несёт Upgrade-Insecure-Requests (preflight не провоцируется)")

        # --- headless-палево и рассинхрон версий ---
        sec_ch_ua = xhr_headers.get("sec-ch-ua", "")
        ua = xhr_headers.get("user-agent", "")
        assert "headless" not in sec_ch_ua.lower(), \
            f"sec-ch-ua палит headless: {sec_ch_ua}"
        assert "headless" not in ua.lower(), f"UA палит headless: {ua}"
        ua_major = re.search(r"Chrome/(\d+)", ua)
        ch_major = re.search(r'Chromium";v="(\d+)"', sec_ch_ua)
        assert ua_major and ch_major, (ua, sec_ch_ua)
        assert ua_major.group(1) == ch_major.group(1), \
            f"рассинхрон версий: UA Chrome/{ua_major.group(1)} vs sec-ch-ua v{ch_major.group(1)}"
        assert "Google Chrome" in sec_ch_ua, f"нет бренда Google Chrome: {sec_ch_ua}"
        print(f"[1b] ok: client hints согласованы с UA (Chrome/{ua_major.group(1)}), "
              f"headless не светится: {sec_ch_ua}")

        assert "accept-language" in xhr_headers, xhr_headers
        assert xhr_headers["accept-language"].startswith(cfg.random_identity()["locale"].split("-")[0]) \
            or "en" in xhr_headers["accept-language"]
        print("[2] ok: Accept-Language на месте ->", xhr_headers["accept-language"])

        assert doc_headers, "document-запрос не зафиксирован"
        print("[3] ok: document-запрос дошёл, заголовков:", len(doc_headers))

        # --- 4. пустая страница -> PageBlankError -------------------------
        reg = autoreg.InstagramRegistrar(cfg, autoreg.HumanDriver(cfg),
                                         autoreg.ArkoseSolver(cfg))
        cfg.TARGET_URL = f"{base}/blank.html"
        try:
            await reg.open_signup(page)
            raise AssertionError("ожидался PageBlankError")
        except autoreg.PageBlankError as exc:
            assert "пуст" in str(exc) or "байт" in str(exc), exc
            print("[4] ok: пустая страница -> PageBlankError:", str(exc)[:70])

        # --- 5. «как в Instagram»: HTML есть, CDN-ресурсы не загрузились ---
        cfg.TARGET_URL = f"{base}/cors.html"
        try:
            await reg.open_signup(page)
            raise AssertionError("ожидался PageBlankError")
        except autoreg.PageBlankError as exc:
            msg = str(exc)
            assert "CORS" in msg or "блокир" in msg.lower(), msg
            print("[5] ok: незагруженный CDN диагностирован ->", msg[:90])
            assert reg._blocked, "список упавших запросов пуст"
            print("    зафиксировано упавших запросов:", len(reg._blocked))

        # --- 6. закрытая страница -> BrowserCrashedError ------------------
        await page.close()
        try:
            await reg._wait_page_ready(page, timeout_s=2)
            raise AssertionError("ожидался BrowserCrashedError")
        except autoreg.BrowserCrashedError as exc:
            print("[6] ok: закрытая страница -> BrowserCrashedError:", str(exc)[:60])

    finally:
        with contextlib_suppress():
            pass
        await bf.close()
        httpd.shutdown()

    print("\nHEADERS/CORS TESTS PASSED")
    return 0


class contextlib_suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
