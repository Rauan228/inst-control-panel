#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_setup.py — preflight-диагностика перед боевым запуском.

Проверяет ВСЁ, что нужно движку, и печатает вердикт по каждому пункту:
  1. конфиг / .env                 — что подхватилось (секреты маскируются)
  2. Playwright + Chromium         — реальный запуск браузера и фингерпринт-проба
  3. прокси + rotation URL         — внешний IP через прокси, ответ ротации
  4. IMAP (catch-all почта)        — LOGIN / EXAMINE / SEARCH / FETCH, последние письма
  5. SMS-сервис                    — баланс и доступность сервиса Instagram
  6. капча-сервис                  — баланс CapMonster / 2Captcha
  7. аватарки                      — сколько изображений в AVATARS_DIR
  8. итог                          — что заблокирует запуск + точная команда

Никакого Instagram не трогает. Только твои сервисы из .env.

    python check_setup.py
    python check_setup.py --skip-browser --skip-sms
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import imaplib
import json
import re
import socket
import ssl
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

import aiohttp

from config import Config, load_config, load_dotenv

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"

RESULTS: list[tuple[str, bool | None, str]] = []   # (имя, ok/None=warn, деталь)


def ok(name: str, detail: str = "") -> None:
    RESULTS.append((name, True, detail))
    print(f"{GREEN}[ OK ]{RESET} {name}{(' — ' + detail) if detail else ''}")


def warn(name: str, detail: str = "") -> None:
    RESULTS.append((name, None, detail))
    print(f"{YELLOW}[WARN]{RESET} {name}{(' — ' + detail) if detail else ''}")


def fail(name: str, detail: str = "") -> None:
    RESULTS.append((name, False, detail))
    print(f"{RED}[FAIL]{RESET} {name}{(' — ' + detail) if detail else ''}")


def head(title: str) -> None:
    print(f"\n{CYAN}=== {title} ==={RESET}")


def mask(value: str, keep: int = 4) -> str:
    if not value:
        return "<пусто>"
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


# ---------------------------------------------------------------------------
# 1. Конфиг
# ---------------------------------------------------------------------------


def check_config(cfg: Config) -> None:
    head("1. КОНФИГ / .env")
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        ok(".env найден", str(env_path))
    else:
        warn(".env не найден", "используются переменные окружения и дефолты")

    print(f"{DIM}  REG_METHOD        = {cfg.REG_METHOD}")
    print(f"  HEADLESS          = {cfg.HEADLESS}")
    print(f"  MAX_ACCOUNTS      = {cfg.MAX_ACCOUNTS}")
    print(f"  TARGET_URL        = {cfg.TARGET_URL}")
    print(f"  EMAIL_DOMAIN      = {cfg.EMAIL_DOMAIN}")
    print(f"  PROXY             = {mask(cfg.PROXY, 6)}")
    print(f"  PROXY_ROTATION_URL= {cfg.PROXY_ROTATION_URL or '<не задан>'}")
    print(f"  SMS_PROVIDER      = {cfg.SMS_PROVIDER}  key={mask(cfg.SMS_API_KEY)}")
    print(f"  SMS_API_BASE      = {cfg.SMS_API_BASE}")
    print(f"  CAPTCHA_PROVIDER  = {cfg.CAPTCHA_PROVIDER}  key={mask(cfg.CAPTCHA_API_KEY)}")
    print(f"  IMAP              = {cfg.IMAP_USER}@{cfg.IMAP_HOST}:{cfg.IMAP_PORT}"
          f" ssl={cfg.IMAP_SSL} pass={mask(cfg.IMAP_PASS)}{RESET}")

    if cfg.REG_METHOD == "email":
        if not cfg.IMAP_USER or not cfg.IMAP_PASS:
            fail("REG_METHOD=email, но IMAP_USER/IMAP_PASS пустые",
                 "код подтверждения выкачать не получится")
        if "@" not in cfg.EMAIL_DOMAIN:
            ok("EMAIL_DOMAIN задан", cfg.EMAIL_DOMAIN)
    else:
        if not cfg.SMS_API_KEY:
            fail("REG_METHOD=sms, но SMS_API_KEY пустой")


# ---------------------------------------------------------------------------
# 2. Playwright + Chromium
# ---------------------------------------------------------------------------


async def check_browser(cfg: Config) -> None:
    head("2. PLAYWRIGHT + CHROMIUM")
    try:
        import autoreg
    except Exception as exc:  # noqa: BLE001
        fail("импорт autoreg.py", str(exc))
        return

    bf = autoreg.BrowserFactory(cfg)
    try:
        fp = cfg.random_identity()
        ctx, page = await bf.new_context(fp)
        await page.goto("about:blank")
        await page.set_content("<html><body>probe</body></html>")
        probe = await page.evaluate("""() => ({
            webdriver: navigator.webdriver,
            platform: navigator.platform,
            plugins: navigator.plugins.length,
            tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
            w: screen.width, h: screen.height,
            ua: navigator.userAgent })""")
        gl = await page.evaluate("""() => {
            const c = document.createElement('canvas');
            const g = c.getContext('webgl');
            if (!g) return null;
            const e = g.getExtension('WEBGL_debug_renderer_info');
            return e ? g.getParameter(e.UNMASKED_VENDOR_WEBGL) : null; }""")
        await ctx.close()

        if probe["webdriver"] in (None, False) and probe["plugins"] == 5:
            ok("Chromium запускается, stealth-инжект работает",
               f"webdriver={probe['webdriver']} plugins={probe['plugins']}")
        else:
            warn("Chromium работает, но stealth-проба подозрительная", json.dumps(probe))
        print(f"{DIM}  UA       = {probe['ua']}")
        print(f"  platform = {probe['platform']} | {probe['w']}x{probe['h']} | tz={probe['tz']}")
        print(f"  WebGL    = {gl}{RESET}")
    except Exception as exc:  # noqa: BLE001
        fail("Chromium не запустился", f"{type(exc).__name__}: {exc}")
        print(f"{DIM}  лечение: python -m playwright install chromium{RESET}")
    finally:
        with contextlib.suppress(Exception):
            await bf.close()


# ---------------------------------------------------------------------------
# 3. Прокси и ротация
# ---------------------------------------------------------------------------


async def check_proxy(cfg: Config, session: aiohttp.ClientSession) -> None:
    head("3. ПРОКСИ + ROTATION URL")
    placeholder = "http://user:pass@ip:port"
    if not cfg.PROXY or cfg.PROXY == placeholder:
        warn("PROXY не задан", "движок пойдёт напрямую — для Instagram это почти гарантированный бан")
    else:
        rot = autoreg_rotator(cfg)
        try:
            ip = await rot.check(session)
            ok("прокси живой", f"внешний IP = {ip}")
        except Exception as exc:  # noqa: BLE001
            fail("прокси не отвечает", f"{type(exc).__name__}: {exc}")
            return

    pool = cfg.proxies
    if not cfg.PROXY_ROTATION_URL:
        if len(pool) > 1:
            ok(f"ротация через пул из {len(pool)} эндпоинтов",
               "каждый цикл берёт следующий порт (sticky-сессия Decodo = свой IP)")
            hosts = [re.sub(r"^https?://", "", p).split("@")[-1] for p in pool]
            print(f"{DIM}  {', '.join(hosts)}{RESET}")
        else:
            warn("PROXY_ROTATION_URL не задан и пул из одного эндпоинта",
                 "IP не будет меняться между циклами — все аккаунты с одного адреса")
        return
    try:
        async with session.get(cfg.PROXY_ROTATION_URL,
                               timeout=aiohttp.ClientTimeout(total=30)) as r:
            body = (await r.text(errors="ignore"))[:200]
        if r.status < 400:
            ok("rotation URL отвечает", f"HTTP {r.status} | {body!r}")
        else:
            fail("rotation URL вернул ошибку", f"HTTP {r.status} | {body!r}")
    except Exception as exc:  # noqa: BLE001
        fail("rotation URL недоступен", f"{type(exc).__name__}: {exc}")


def autoreg_rotator(cfg: Config):
    import autoreg
    return autoreg.ProxyRotator(cfg)


# ---------------------------------------------------------------------------
# 4. IMAP / catch-all
# ---------------------------------------------------------------------------


def _imap_probe(cfg: Config) -> dict[str, Any]:
    """Синхронная проба IMAP: login -> examine -> search -> fetch последнего письма."""
    out: dict[str, Any] = {"stage": "connect"}
    try:
        if cfg.IMAP_SSL:
            ctx = ssl.create_default_context()
            conn = imaplib.IMAP4_SSL(cfg.IMAP_HOST, cfg.IMAP_PORT, ssl_context=ctx)
        else:
            conn = imaplib.IMAP4(cfg.IMAP_HOST, cfg.IMAP_PORT)
        out["stage"] = "login"
        conn.login(cfg.IMAP_USER, cfg.IMAP_PASS)
        out["stage"] = "select"
        typ, data = conn.select(cfg.IMAP_MAILBOX, readonly=True)
        out["exists"] = int(data[0]) if typ == "OK" and data and data[0] else 0
        out["stage"] = "search"
        typ, data = conn.search(None, "ALL")
        ids = data[0].split() if typ == "OK" and data and data[0] else []
        out["total"] = len(ids)
        out["subjects"] = []
        for mid in ids[-5:][::-1]:
            typ, msg = conn.fetch(mid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])")
            if typ == "OK" and msg and msg[0]:
                out["subjects"].append(msg[0][1].decode("utf-8", "ignore")
                                       .replace("\r\n", " | ")[:140])
        out["stage"] = "done"
        conn.logout()
        return out
    except imaplib.IMAP4.error as exc:
        out["error"] = f"IMAP4.error на этапе {out['stage']}: {exc}"
        return out
    except (socket.gaierror, ConnectionRefusedError, socket.timeout, TimeoutError,
            ssl.SSLError, OSError) as exc:
        out["error"] = f"сеть/TLS на этапе {out['stage']}: {type(exc).__name__}: {exc}"
        return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__} на этапе {out['stage']}: {exc}"
        return out


async def check_imap(cfg: Config) -> None:
    head("4. IMAP / CATCH-ALL ПОЧТА")
    if not cfg.IMAP_HOST or not cfg.IMAP_USER or not cfg.IMAP_PASS:
        fail("IMAP не настроен", "заполни IMAP_HOST / IMAP_USER / IMAP_PASS в .env")
        return

    t0 = time.monotonic()
    res = await asyncio.to_thread(_imap_probe, cfg)
    dt = time.monotonic() - t0

    if res.get("error"):
        fail(f"IMAP недоступен ({cfg.IMAP_HOST}:{cfg.IMAP_PORT})", res["error"])
        print(f"{DIM}  частые причины:")
        print("   • нужен app-пароль (пароль приложений), а не пароль от аккаунта")
        print("   • IMAP выключен в настройках почтового сервиса")
        print("   • порт 993 (SSL) / 143 (без SSL); проверь IMAP_SSL="
              f"{cfg.IMAP_SSL}")
        print(f"   • доменное имя неверное (у Zoho — imap.zoho.com, "
              f"у Яндекса — imap.yandex.ru){RESET}")
        return

    ok("IMAP: LOGIN + EXAMINE + SEARCH + FETCH прошли", f"{dt:.1f} с")
    print(f"{DIM}  писем в {cfg.IMAP_MAILBOX}: {res['total']}")
    for s in res["subjects"]:
        print(f"   · {s}")
    print(RESET, end="")

    if res["total"] == 0:
        warn("ящик пуст",
             "это нормально для свежего ящика; проверь catch-all отдельным письмом")
    print(f"{DIM}  ПРОВЕРКА CATCH-ALL: отправь письмо на "
          f"random-test-{int(time.time())}@{cfg.EMAIL_DOMAIN} с любого другого ящика,")
    print(f"  подожди минуту и запусти: python check_setup.py --only imap")
    print(f"  если письмо появится в списке выше — catch-all работает.{RESET}")


# ---------------------------------------------------------------------------
# 5. SMS-сервис
# ---------------------------------------------------------------------------


async def check_sms(cfg: Config, session: aiohttp.ClientSession) -> None:
    head("5. SMS-СЕРВИС")
    if cfg.REG_METHOD != "sms":
        warn("проверка SMS пропущена", f"REG_METHOD={cfg.REG_METHOD}")
        return
    if not cfg.SMS_API_KEY:
        fail("SMS_API_KEY пустой")
        return

    import autoreg
    sv = autoreg.SmsVerifier(cfg)
    try:
        if cfg.SMS_PROVIDER == "sms-activate":
            params = {"api_key": cfg.SMS_API_KEY, "action": "getBalance"}
            async with session.get(sv.SMS_ACTIVATE_URL, params=params,
                                   timeout=aiohttp.ClientTimeout(total=30)) as r:
                text = (await r.text(errors="ignore")).strip()
            if text.startswith("ACCESS_BALANCE"):
                ok("sms-activate: ключ рабочий", f"баланс {text.split(':', 1)[1]}")
            else:
                fail("sms-activate: ключ не принят", text[:200])
                return

            params = {"api_key": cfg.SMS_API_KEY, "action": "getPrices",
                      "service": cfg.SMS_SERVICE_CODE, "country": cfg.SMS_COUNTRY}
            async with session.get(sv.SMS_ACTIVATE_URL, params=params,
                                   timeout=aiohttp.ClientTimeout(total=30)) as r:
                text = (await r.text(errors="ignore")).strip()
            if text.startswith("ACCESS_PRICES"):
                ok(f"сервис '{cfg.SMS_SERVICE_CODE}' в стране {cfg.SMS_COUNTRY} доступен",
                   text[13:160])
            else:
                fail(f"сервис '{cfg.SMS_SERVICE_CODE}' / страна {cfg.SMS_COUNTRY} недоступны",
                     text[:200])
        else:
            headers = {"Authorization": f"Bearer {cfg.SMS_API_KEY}"}
            async with session.get(f"{sv.FIVESIM_URL}/profile", headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=30)) as r:
                data = await r.json(content_type=None)
            if r.status == 200 and "balance" in data:
                ok("5sim: ключ рабочий", f"баланс {data.get('balance')}")
            else:
                fail("5sim: ключ не принят", f"HTTP {r.status} {data}")
    except Exception as exc:  # noqa: BLE001
        fail("SMS API недоступен", f"{type(exc).__name__}: {exc}")
        print(f"{DIM}  для реселлеров (hero-sms и т.п.) пропиши SMS_API_BASE "
              f"в .env — сейчас: {cfg.SMS_API_BASE}{RESET}")


# ---------------------------------------------------------------------------
# 6. Капча-сервис
# ---------------------------------------------------------------------------


async def check_captcha(cfg: Config, session: aiohttp.ClientSession) -> None:
    head("6. КАПЧА-СЕРВИС")
    if not cfg.CAPTCHA_API_KEY:
        fail("CAPTCHA_API_KEY пустой", "Arkose FunCaptcha не решится")
        return
    try:
        if cfg.CAPTCHA_PROVIDER == "capmonster":
            async with session.post(
                f"{cfg.CAPMONSTER_HOST}/getBalance",
                json={"clientKey": cfg.CAPTCHA_API_KEY},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as r:
                data = await r.json(content_type=None)
            if data.get("errorId") == 0:
                ok("CapMonster: ключ рабочий", f"баланс ${data.get('balance')}")
            else:
                fail("CapMonster: ключ не принят",
                     f"{data.get('errorCode')} {data.get('errorDescription')}")
        elif cfg.CAPTCHA_PROVIDER == "everyinfra":
            # GET /api/v1/account -> баланс кошелька
            async with session.get(
                f"{cfg.EVERYINFRA_HOST}/api/v1/account",
                headers={"Authorization": f"Bearer {cfg.CAPTCHA_API_KEY}"},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as r:
                data = await r.json(content_type=None)
            if r.status == 200:
                bal = data.get("balance") or {}
                total = bal.get("total_usd", bal)
                ok("EveryInfra: ключ рабочий", f"баланс ${total}")
                # заодно проверим, что тип funcaptcha сейчас продаётся
                try:
                    async with session.get(
                        f"{cfg.EVERYINFRA_HOST}/api/v1/captcha/types",
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as tr:
                        types = await tr.json(content_type=None)
                    items = types if isinstance(types, list) else (
                        types.get("types") or types.get("data") or [])
                    fc = [t for t in items
                          if isinstance(t, dict) and t.get("type") == "funcaptcha"]
                    if fc:
                        t = fc[0]
                        if t.get("available"):
                            ok("EverySolve: funcaptcha доступен",
                               f"${t.get('price_usd')} за решение, shape="
                               f"{(t.get('solution') or {}).get('shape')}")
                        else:
                            fail("EverySolve: funcaptcha сейчас недоступен",
                                 "провайдер не продаёт этот тип — капчу не решить")
                    else:
                        warn("тип funcaptcha не найден в каталоге",
                             "проверь GET /api/v1/captcha/types")
                except Exception as exc:  # noqa: BLE001
                    warn("каталог капчи не прочитался", f"{type(exc).__name__}: {exc}")
            else:
                fail("EveryInfra: ключ не принят", f"HTTP {r.status} {str(data)[:200]}")
        else:
            async with session.post(
                f"{cfg.TWOCAPTCHA_HOST}/getBalance",
                json={"clientKey": cfg.CAPTCHA_API_KEY},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as r:
                data = await r.json(content_type=None)
            if data.get("errorId") == 0:
                ok("2Captcha: ключ рабочий", f"баланс ${data.get('balance')}")
            else:
                fail("2Captcha: ключ не принят",
                     f"{data.get('errorCode')} {data.get('errorDescription')}")
    except Exception as exc:  # noqa: BLE001
        fail("капча-API недоступен", f"{type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# 7. Аватарки
# ---------------------------------------------------------------------------


def check_avatars(cfg: Config) -> None:
    head("7. АВАТАРКИ")
    d = Path(cfg.AVATARS_DIR)
    if not d.exists():
        fail("папка не существует", str(d))
        return
    files = [p for p in d.rglob("*")
             if p.suffix.lower() in (".jpg", ".jpeg", ".png", ".webp")]
    if not files:
        warn("папка пустая", f"{d} — траст-блок пропустит загрузку аватара")
    elif len(files) < 10:
        warn(f"всего {len(files)} изображений",
             "при серии регистраций аватарки начнут повторяться — это палево")
    else:
        ok(f"{len(files)} изображений в {d}", f"пример: {files[0].name}")


# ---------------------------------------------------------------------------
# 8. Итог
# ---------------------------------------------------------------------------


def summary(cfg: Config) -> int:
    head("8. ИТОГ")
    failed = [r for r in RESULTS if r[1] is False]
    warns = [r for r in RESULTS if r[1] is None]
    oks = [r for r in RESULTS if r[1] is True]
    print(f"  {GREEN}OK: {len(oks)}{RESET}   "
          f"{YELLOW}WARN: {len(warns)}{RESET}   {RED}FAIL: {len(failed)}{RESET}")
    if warns:
        print(f"\n{YELLOW}Предупреждения:{RESET}")
        for name, _, detail in warns:
            print(f"  • {name}: {detail}")
    if failed:
        print(f"\n{RED}Блокирует запуск:{RESET}")
        for name, _, detail in failed:
            print(f"  • {name}: {detail}")
        return 1

    print(f"\n{GREEN}Всё готово. Команды запуска:{RESET}")
    print(f"{DIM}  # один аккаунт, видимый браузер — посмотреть глазами")
    print(f"  python autoreg.py --run --count 1 --headed")
    print(f"  # серия в фоне")
    print(f"  python autoreg.py --run --count {cfg.MAX_ACCOUNTS}")
    print(f"  # web-панель")
    print(f"  python autoreg.py --serve   ->  http://{cfg.DASHBOARD_HOST}:{cfg.DASHBOARD_PORT}{RESET}")
    return 0


# ---------------------------------------------------------------------------


async def amain(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="preflight-диагностика IG AutoReg")
    p.add_argument("--config", default=None)
    p.add_argument("--only", default="", help="запустить только проверки через запятую: "
                                              "config,browser,proxy,imap,sms,captcha,avatars")
    p.add_argument("--skip-browser", action="store_true")
    p.add_argument("--skip-sms", action="store_true")
    p.add_argument("--skip-captcha", action="store_true")
    args = p.parse_args(argv)

    only = {s.strip() for s in args.only.split(",") if s.strip()}

    def want(name: str) -> bool:
        return not only or name in only

    cfg = load_config(args.config)
    print(f"{CYAN}IG AutoReg — preflight{RESET}  ({time.strftime('%Y-%m-%d %H:%M:%S')})")

    if want("config"):
        check_config(cfg)

    connector = aiohttp.TCPConnector(limit=8, ssl=False)
    async with aiohttp.ClientSession(connector=connector,
                                     timeout=aiohttp.ClientTimeout(total=60)) as session:
        if want("proxy"):
            await check_proxy(cfg, session)
        if want("imap"):
            await check_imap(cfg)
        if want("sms") and not args.skip_sms:
            await check_sms(cfg, session)
        if want("captcha") and not args.skip_captcha:
            await check_captcha(cfg, session)

    if want("browser") and not args.skip_browser:
        await check_browser(cfg)
    if want("avatars"):
        check_avatars(cfg)

    return summary(cfg)


def main() -> int:
    try:
        return asyncio.run(amain())
    except KeyboardInterrupt:
        print("\nпрервано")
        return 130


if __name__ == "__main__":
    sys.exit(main())
