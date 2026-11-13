#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
open_account.py — открыть созданный аккаунт в браузере, используя сохранённую
сессию (cookies/*.json). Без повторного логина и без ввода кода.

Использование:
    python open_account.py                          # последний аккаунт из accounts.json
    python open_account.py laura8419.hernandez       # конкретный username
    python open_account.py --profile                 # сразу на /accounts/edit/
    python open_account.py --no-proxy                # открыть без прокси (риск checkpoint)

По умолчанию браузер идёт через тот же прокси, что указан в записи аккаунта —
иначе Instagram с нового IP может запросить повторную проверку.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from playwright.async_api import async_playwright

from config import Config, load_config


def find_record(username: str | None) -> dict | None:
    """Достаёт запись аккаунта из accounts.json (или последнюю)."""
    db = Path("accounts.json")
    if not db.exists():
        return None
    try:
        data = json.loads(db.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not data:
        return None
    if username:
        for rec in reversed(data):
            if rec.get("username") == username:
                return rec
        return None
    return data[-1]


def parse_proxy(proxy: str) -> dict | None:
    """http://user:pass@host:port -> словарь для Playwright."""
    if not proxy:
        return None
    m = re.match(r"(?P<scheme>https?)://(?:(?P<u>[^:]+):(?P<p>[^@]+)@)?(?P<host>.+)",
                 proxy.strip())
    if not m:
        return None
    out = {"server": f"{m.group('scheme')}://{m.group('host')}"}
    if m.group("u"):
        out["username"] = m.group("u")
        out["password"] = m.group("p") or ""
    return out


async def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="открыть аккаунт по сохранённым cookies")
    p.add_argument("username", nargs="?", default=None)
    p.add_argument("--profile", action="store_true", help="открыть /accounts/edit/")
    p.add_argument("--no-proxy", action="store_true", help="не использовать прокси")
    p.add_argument("--headed", action="store_true", default=True)
    args = p.parse_args(argv)

    rec = find_record(args.username)
    if not rec:
        print(f"аккаунт {args.username!r} не найден в accounts.json")
        return 1

    username = rec["username"]
    cookies_path = rec.get("cookies")
    print(f"аккаунт : {username}")
    print(f"email   : {rec.get('email')}")
    print(f"пароль  : {rec.get('password')}")
    print(f"cookies : {cookies_path}")

    if not cookies_path or not Path(cookies_path).exists():
        print(f"файл сессии не найден: {cookies_path}")
        print("-> открой вручную и войди по логину/паролю выше")
        return 1

    cfg = load_config()
    proxy = None if args.no_proxy else parse_proxy(rec.get("proxy", ""))
    url = (f"https://www.instagram.com/accounts/edit/" if args.profile
           else f"https://www.instagram.com/{username}/")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=False)
        context = await browser.new_context(
            storage_state=cookies_path,
            proxy=proxy,
            viewport={"width": 1400, "height": 900},
            locale=cfg.GEO_LOCALE or "en-US",
            timezone_id=cfg.GEO_TIMEZONE or "America/New_York",
        )
        page = await context.new_page()
        print(f"\nоткрываю {url} (proxy={'да' if proxy else 'нет'})…")
        await page.goto(url, wait_until="domcontentloaded", timeout=90000)
        await asyncio.sleep(3)

        # диагностика: залогинены ли мы
        state = await page.evaluate("""() => ({
            url: location.href,
            title: document.title,
            hasLogin: !!document.querySelector('input[name="username"]'),
        })""")
        if state["hasLogin"] or "/accounts/login" in state["url"]:
            print("\n[!] Instagram сбросил сессию и просит логин.")
            print("    Причины: вход с нового IP, истёк sessionid, или checkpoint.")
            print(f"    Войди вручную: {username} / {rec.get('password')}")
        else:
            print(f"\n[ok] сессия живая, ты внутри: {state['title']}")

        print("\nБраузер открыт. Смотри профиль; закрой окно или нажми Enter для выхода.")
        try:
            await asyncio.get_event_loop().run_in_executor(None, input)
        except (EOFError, KeyboardInterrupt):
            pass
        await context.close()
        await browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
