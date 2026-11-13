#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_account.py — диагностика состояния созданного аккаунта.

Отвечает на вопрос «почему профиль недоступен по ссылке»:
  1. жива ли сохранённая сессия (sessionid)
  2. существует ли username и в каком он состоянии
     (активен / приватный / заблокирован / удалён / checkpoint)
  3. подписан ли аккаунт на цель траста

Использует те же cookies и тот же прокси, что и при регистрации — иначе
Instagram отвечает с точки зрения другого IP и может показать checkpoint.

    python check_account.py                       # последний аккаунт
    python check_account.py laura8419.hernandez    # конкретный
    python check_account.py --no-proxy             # без прокси (может дать checkpoint)

Данные берёт из публичного web-API профиля (тот же запрос, что делает браузер
на странице профиля) и из загрузки /accounts/edit/.
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

from config import load_config

#: app-id веб-клиента Instagram — без него web_profile_info отдаёт 401
IG_APP_ID = "936619743392459"


def find_record(username: str | None) -> dict | None:
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
    p = argparse.ArgumentParser(description="диагностика состояния аккаунта")
    p.add_argument("username", nargs="?", default=None)
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--target", default=None,
                   help="проверить подписку на этот username")
    args = p.parse_args(argv)

    cfg = load_config()
    rec = find_record(args.username)
    if not rec:
        print(f"аккаунт {args.username!r} не найден в accounts.json")
        return 1

    username = rec["username"]
    cookies = rec.get("cookies")
    proxy = None if args.no_proxy else parse_proxy(rec.get("proxy", ""))

    print(f"аккаунт   : {username}")
    print(f"email     : {rec.get('email')}")
    print(f"пароль    : {rec.get('password')}")
    print(f"сессия    : {cookies}")
    print(f"прокси    : {'да (' + rec.get('proxy', '').split('@')[-1] + ')' if proxy else 'НЕТ'}")
    print(f"создан    : {rec.get('created_at')}")
    print("-" * 68)

    if not cookies or not Path(cookies).exists():
        print(f"[!] файл сессии не найден: {cookies}")
        return 1

    target = args.target
    if not target:
        tt = cfg.TRUST_TARGETS or []
        target = tt[0].rstrip("/").split("/")[-1] if tt else None

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            storage_state=cookies,
            proxy=proxy,
            viewport={"width": 1400, "height": 900},
            locale=cfg.GEO_LOCALE or "en-US",
            timezone_id=cfg.GEO_TIMEZONE or "America/New_York",
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        page = await context.new_page()

        # --- 1. жива ли сессия ------------------------------------------
        print("\n[1] ПРОВЕРКА СЕССИИ")
        session_alive = False
        try:
            await page.goto("https://www.instagram.com/accounts/edit/",
                            wait_until="domcontentloaded", timeout=60000)
            await asyncio.sleep(3)
            url = page.url
            ck = {c["name"] for c in await context.cookies("https://www.instagram.com")}
            if "/accounts/login" in url or "login" in url.split("/")[-2:][0]:
                print(f"    [НЕТ] Instagram редиректит на логин: {url}")
                print("    -> sessionid истёк / сброшен, либо checkpoint по IP")
            else:
                session_alive = True
                print(f"    [ДА] сессия живая, url={url}")
                print(f"    cookies: sessionid={'sessionid' in ck} "
                      f"ds_user_id={'ds_user_id' in ck}")
        except Exception as exc:  # noqa: BLE001
            print(f"    [ОШИБКА] {type(exc).__name__}: {exc}")

        # --- 2. состояние профиля через web-API --------------------------
        print("\n[2] СОСТОЯНИЕ ПРОФИЛЯ (web_profile_info)")
        api = ("https://www.instagram.com/api/v1/users/web_profile_info/"
               f"?username={username}")
        info = None
        try:
            resp = await page.evaluate(
                """async ([url, appId]) => {
                    const r = await fetch(url, {
                        headers: { 'x-ig-app-id': appId },
                        credentials: 'include',
                    });
                    const text = await r.text();
                    return { status: r.status, body: text.slice(0, 4000) };
                }""",
                [api, IG_APP_ID],
            )
            status = resp["status"]
            body = resp["body"]
            print(f"    HTTP {status}")
            if status == 200:
                try:
                    data = json.loads(body)
                    user = (data.get("data") or {}).get("user")
                    if user is None:
                        print("    [НЕТ] data.user = null — username не существует")
                        print("    -> аккаунт удалён/заблокирован Instagram, либо ник не занят")
                    else:
                        info = user
                        print(f"    [ЕСТЬ] id={user.get('id')}")
                        print(f"      username       : {user.get('username')}")
                        print(f"      full_name      : {user.get('full_name')}")
                        print(f"      is_private     : {user.get('is_private')}")
                        print(f"      is_verified    : {user.get('is_verified')}")
                        print(f"      followers      : "
                              f"{(user.get('edge_followed_by') or {}).get('count')}")
                        print(f"      following      : "
                              f"{(user.get('edge_follow') or {}).get('count')}")
                        print(f"      posts          : "
                              f"{(user.get('edge_owner_to_timeline_media') or {}).get('count')}")
                        for flag in ("is_disabled", "is_supervised",
                                     "has_anonymous_profile_picture"):
                            if flag in user:
                                print(f"      {flag:19}: {user[flag]}")
                        if user.get("is_disabled"):
                            print("    -> АККАУНТ ОТКЛЮЧЁН (is_disabled=true)")
                except json.JSONDecodeError:
                    print(f"    [?] ответ не JSON: {body[:200]!r}")
            elif status == 404:
                print("    [НЕТ] 404 — профиль не существует или удалён")
            elif status in (401, 403):
                print("    [БЛОК] 401/403 — запрос не авторизован (сессия мертва "
                      "или IP под фильтром)")
            else:
                print(f"    [?] {body[:300]}")
        except Exception as exc:  # noqa: BLE001
            print(f"    [ОШИБКА] {type(exc).__name__}: {exc}")

        # --- 3. страница профиля глазами браузера ------------------------
        print("\n[3] СТРАНИЦА ПРОФИЛЯ")
        try:
            r = await page.goto(f"https://www.instagram.com/{username}/",
                                wait_until="domcontentloaded", timeout=60000)
            await asyncio.sleep(3)
            title = await page.title()
            body_text = (await page.locator("body").inner_text(timeout=8000))[:300]
            print(f"    HTTP {r.status if r else '?'} | url={page.url}")
            print(f"    title: {title}")
            low = body_text.lower()
            if "недоступен" in low or "isn't available" in low or "page not found" in low:
                print("    -> СТРАНИЦА НЕДОСТУПНА: профиль удалён/забанен, "
                      "либо требуется вход")
                print(f"    текст: {body_text[:160]!r}")
            elif "checkpoint" in page.url or "challenge" in page.url:
                print(f"    -> CHECKPOINT: {page.url}")
            else:
                print(f"    -> страница отдаётся. текст: {body_text[:160]!r}")
            Path("debug").mkdir(exist_ok=True)
            stamp = f"account_{username}_{__import__('time').strftime('%H%M%S')}"
            Path(f"debug/{stamp}.html").write_text(await page.content(),
                                                   encoding="utf-8")
            await page.screenshot(path=f"debug/{stamp}.png")
            print(f"    дамп: debug/{stamp}.html + .png")
        except Exception as exc:  # noqa: BLE001
            print(f"    [ОШИБКА] {type(exc).__name__}: {exc}")

        # --- 4. подписка на цель ----------------------------------------
        if target:
            print(f"\n[4] ПОДПИСКА НА {target}")
            try:
                r = await page.goto(f"https://www.instagram.com/{target}/",
                                    wait_until="domcontentloaded", timeout=60000)
                await asyncio.sleep(3)
                txt = (await page.locator("body").inner_text(timeout=8000))
                low = txt.lower()
                if "недоступен" in low or "isn't available" in low:
                    print(f"    -> профиль {target} недоступен (ник занят? приватный? удалён?)")
                elif re.search(r"\bfollowing\b|\bподписки\b", low):
                    print(f"    -> уже подписан (в тексте есть «Following»)")
                elif re.search(r"\bfollow\b|\bподписаться\b", low):
                    print("    -> НЕ подписан: на странице есть кнопка Follow")
                else:
                    print("    -> состояние не определено, см. debug/-дамп")
                stamp = f"target_{target}"
                Path(f"debug/{stamp}.html").write_text(await page.content(),
                                                       encoding="utf-8")
                print(f"    дамп: debug/{stamp}.html")
            except Exception as exc:  # noqa: BLE001
                print(f"    [ОШИБКА] {type(exc).__name__}: {exc}")

        await context.close()
        await browser.close()

    print("\n" + "-" * 68)
    if info is None:
        print("ИТОГ: профиль не отдаётся — аккаунт скорее всего удалён/забанен "
              "или сессия мертва. Смотри вывод [1]-[3].")
        return 2
    print(f"ИТОГ: профиль существует, session_alive={session_alive}, "
          f"private={info.get('is_private')}, disabled={info.get('is_disabled')}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
