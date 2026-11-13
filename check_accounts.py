#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_accounts.py — проверка выживаемости созданных аккаунтов + дожим гейта.

Зачем: без метрики выживаемости нельзя понять, работает ли антифрод-обвязка
и окупается ли трафик/капча. Скрипт открывает каждый аккаунт по сохранённым
cookies с ТЕМ ЖЕ прокси, что был при регистрации, и ставит статус:

    alive      — профиль отдаётся, сессия живая
    suspended  — «Confirm you're human» (/accounts/suspended) — можно дожать
    banned     — профиль недоступен (isn't available / 404)
    dead       — сессия слетела (просит логин)

Использование:
    python check_accounts.py                 # проверить аккаунты, созданные за 48 ч
    python check_accounts.py --all           # вообще все
    python check_accounts.py --fix           # попытаться пройти гейт капчей
    python check_accounts.py --limit 5 --headed

--fix платный (капча), поэтому по умолчанию выключен.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import time
import random
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import autoreg  # noqa: E402
import api_reg  # noqa: E402
from config import load_config  # noqa: E402

DB = Path(os.getenv("ACCOUNTS_DB", "accounts.json"))
USE_PROXY: str | None = None
PROFILE = "https://www.instagram.com/{}/"

BANNED_MARKERS = ("isn't available", "недоступен", "page not found",
                  "sorry, this page", "we disabled your account",
                  "account disabled")
LOGIN_MARKERS = ('input[name="username"]', 'input[name="password"]')


def load_records(limit: int | None, age_hours: int | None,
                 username: str | None = None) -> list[dict]:
    if not DB.exists():
        return []
    try:
        data = json.loads(DB.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    horizon = (datetime.now().timestamp() - age_hours * 3600) if age_hours else 0
    out: list[dict] = []
    for rec in reversed([r for r in data if isinstance(r, dict)]):
        if username and rec.get("username") != username:
            continue
        if age_hours:
            try:
                if datetime.fromisoformat(rec.get("created_at", "")).timestamp() < horizon:
                    continue
            except ValueError:
                pass
        out.append(rec)
        if limit and len(out) >= limit:
            break
    return out


async def live_proxy(cfg: autoreg.Config) -> str | None:
    """Первый живой эндпоинт пула (407 «traffic limit» на Decodo — норма)."""
    import aiohttp
    async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=20)) as session:
        for proxy in cfg.proxies:
            try:
                async with session.get("https://api.ipify.org?format=json",
                                       proxy=proxy) as r:
                    if r.status == 200:
                        return proxy
                    hint = r.headers.get("x-error-message", "")
                    print(f"  прокси {proxy.split('@')[-1]}: HTTP {r.status} {hint[:60]}")
            except Exception as exc:  # noqa: BLE001
                print(f"  прокси {proxy.split('@')[-1]}: {type(exc).__name__}")
    return None


async def proxy_alive(proxy: str) -> bool:
    import aiohttp
    try:
        async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=15)) as session:
            async with session.get("https://api.ipify.org?format=json",
                                   proxy=proxy) as r:
                return r.status == 200
    except Exception:  # noqa: BLE001
        return False


async def classify(page, gate: autoreg.HumanGate) -> str:
    """Статус по содержимому страницы."""
    if page.url.startswith("chrome-error://"):
        return "suspended"          # страница не отдалась — точно не alive
    if await gate.is_appeal_submitted(page):
        return "appeal_pending"
    if await gate.is_gate(page, timeout_ms=1500):
        return "suspended"
    for sel in LOGIN_MARKERS:
        if await page.locator(sel).count():
            return "dead"
    with contextlib.suppress(Exception):
        body = (await page.locator("body").inner_text(timeout=6000)).lower()
        if any(m in body for m in BANNED_MARKERS):
            return "banned"
        # гостевая выдача: IG разлогинил сессию
        if ("log in to see their photos" in body
                or "see everyday moments from your close friends" in body
                or "already follow" in body
                or ('log in' in body and 'sign up' in body)):
            return "dead"
    return "alive"


async def _follow(page, cfg, human, username: str) -> None:
    """Подписка/запрос на TRUST_TARGETS и отметка в accounts.json."""
    trust = autoreg.TrustBuilder(cfg)
    try:
        target = await trust.follow_target(page, human)
    except Exception as exc:  # noqa: BLE001
        print(f"    follow: ошибка {type(exc).__name__}: {str(exc)[:80]}")
        return
    if target:
        print(f"    follow: отправлен запрос/подписка на {target}")
        autoreg.Storage(cfg).update_follow(username, target)
        # профиль уже открыт — ставим аватар, пока не выкинуло
        try:
            if await trust.upload_avatar(page, human):
                print("    avatar: загружен")
        except Exception as exc:  # noqa: BLE001
            print(f"    avatar: не удалось ({type(exc).__name__})")
    else:
        print("    follow: не удалось (кнопка не найдена или не подтвердилось)")


async def check_api(rec: dict, cfg: autoreg.Config, fix: bool,
                    sms=None, session=None, follow: bool = False) -> str:
    """
    Проверка аккаунта, созданного через приватный API: сессия и статус
    смотрятся тем же клиентом, что и регистрация, без браузера.
    """
    import api_reg

    username = rec.get("username", "?")
    path = Path(rec.get("cookies") or "")
    if not path.exists():
        print(f"  {username:32} dead (нет файла settings)")
        return "dead"

    client = api_reg.build_client(cfg)
    client.settings = json.loads(path.read_text(encoding="utf-8"))
    client.init()
    storage = autoreg.Storage(cfg)
    status = "dead"
    challenge_url = ""
    try:
        await client.login(username, rec.get("password") or "")
        info = await client.account_info()
        status = "alive" if info else "dead"
    except Exception as exc:  # noqa: BLE001 — тип решает статус
        challenge_url = str(getattr(exc, "challenge", {}).get("url", ""))
        if "disabled" in challenge_url:
            status = "banned"
        elif "suspended" in challenge_url or isinstance(
                exc, (api_reg.AccountSuspended, api_reg.ChallengeRequired)):
            status = "suspended"
        else:
            status = "dead"

    storage.audit(username, "probe", status=status, channel="api",
                  cookie_sessionid=bool(client.sessionid),
                  url=challenge_url[:120])

    if status == "suspended" and fix:
        try:
            await api_reg.ApiRegistrar(cfg).open_suspended(client, rec)
            ok = await api_reg.ApiRegistrar(cfg).pass_gate(client, rec, session)
            status = "alive" if ok else status
        except Exception as exc:  # noqa: BLE001
            print(f"    fix: {type(exc).__name__}: {str(exc)[:90]}")

    if status == "alive" and follow:
        for target in (cfg.TRUST_TARGETS or []):
            name = str(target).rstrip("/").split("/")[-1]
            try:
                uid = await client.user_id_from_username(name)
                if await client.user_follow(uid):
                    print(f"    follow: запрос/подписка на {name}")
                    storage.update_follow(username, name)
            except Exception as exc:  # noqa: BLE001
                print(f"    follow: {name} — {type(exc).__name__}: {str(exc)[:70]}")

    print(f"  {username:32} {status}  (api)")
    return status


async def check_one(rec: dict, cfg: autoreg.Config, browser: autoreg.BrowserFactory,
                    human: autoreg.HumanDriver, arkose: autoreg.ArkoseSolver,
                    mail: autoreg.EmailVerifier, gate: autoreg.HumanGate,
                    fix: bool, sms=None, session=None,
                    follow: bool = False, restorer=None) -> str:
    if rec.get("channel") == "api":
        return await check_api(rec, cfg, fix, sms, session, follow)

    username = rec.get("username", "?")
    cookies = rec.get("cookies")
    if not cookies or not Path(cookies).exists():
        print(f"  {username:32} dead (нет файла cookies)")
        return "dead"
    # свой эндпоинт аккаунта важнее «любого живого»: IG привязан к IP
    own = rec.get("proxy") or ""
    proxy_url = own if own and await proxy_alive(own) else USE_PROXY
    context, page = await browser.new_context(
        cfg.random_identity(), storage_state=cookies,
        proxy_url=proxy_url)
    net: list[int] = []
    page.on("response", lambda r: net.append(r.status)
            if r.request.resource_type == "document" else None)
    try:
        if page.url.startswith("chrome-error://"):
            return "error"
        url = PROFILE.format(username)
        for attempt in (1, 2):
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=60000)
                break
            except Exception as exc:  # noqa: BLE001 — 4xx/429, страница всё равно отрисована
                msg = str(exc).splitlines()[0][:70]
                if attempt == 2:
                    print(f"  {username:32} goto вернул ошибку ({msg}) — смотрю что отрисовалось")
                    break
                print(f"  {username:32} goto не удался ({msg}), повтор")
                await asyncio.sleep(12)
        await asyncio.sleep(random_pause())
        status = await classify(page, gate)
        jar = await context.cookies("https://www.instagram.com")
        storage_audit = autoreg.Storage(cfg)
        storage_audit.audit(username, "probe", status=status,
                            cookie_sessionid=any(c["name"] == "sessionid" for c in jar),
                            http=net[-6:], url=page.url[:120])

        if status == "dead" and restorer is not None and rec.get("password"):
            print(f"  {username:32} сессия слетела — вхожу по паролю")
            box: dict = {}
            ok = await restorer.run(page, rec.get("email") or username,
                                    rec["password"], mail, sms, session, box)
            if ok:
                storage = autoreg.Storage(cfg)
                path = Path(cfg.COOKIES_DIR) / f"{username}_relogin_{int(time.time())}.json"
                await page.context.storage_state(path=str(path))
                storage.update_cookies(username, str(path))
                status = await classify(page, gate)
                print(f"  {username:32} вход ок, статус {status}")
            else:
                return "dead"

        jar = await context.cookies("https://www.instagram.com")
        autoreg.Storage(cfg).audit(
            username, "probe", status=status,
            cookie_sessionid=any(c["name"] == "sessionid" for c in jar),
            http=net[-6:], url=page.url[:120])

        if status == "alive" and follow:
            await _follow(page, cfg, human, username)
        if status == "suspended" and fix:
            box: dict = {}
            ok = await gate.pass_gate(page, human, arkose, mail, rec.get("email"),
                                      datetime.now().timestamp(), sms, session, box)
            act = box.get("activation")
            if act is not None:
                if ok:
                    await sms.finish(session, act)
                else:
                    with contextlib.suppress(Exception):
                        await sms.cancel(session, act)
            status = "alive" if ok else await classify(page, gate)
            if ok and follow:
                await _follow(page, cfg, human, rec.get("username"))
        print(f"  {username:32} {status}  ({page.url[:60]})")
        return status
    finally:
        with contextlib.suppress(Exception):
            await context.close()


def random_pause() -> float:
    return random.uniform(2.0, 5.0)


async def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="проверка выживаемости аккаунтов")
    p.add_argument("--all", action="store_true", help="проверять все, без фильтра по возрасту")
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--fix", action="store_true", help="проходить гейт капчей (платно)")
    p.add_argument("--headed", action="store_true")
    p.add_argument("--age-hours", type=int, default=48)
    p.add_argument("--username", default=None, help="только этот аккаунт")
    p.add_argument("--follow", action="store_true",
                   help="подписаться на TRUST_TARGETS (запрос для закрытого)")
    args = p.parse_args(argv)

    autoreg.setup_logging("check_accounts.log", verbose=False)
    cfg = load_config()
    cfg.HEADLESS = not args.headed
    cfg.BLOCK_MEDIA = True
    if args.fix:
        cfg.ENABLE_GATE = True

    global USE_PROXY
    USE_PROXY = await live_proxy(cfg) or ""
    if USE_PROXY:
        print(f"использую живой прокси {USE_PROXY.split('@')[-1]}")
    else:
        print("живых прокси нет (лимит трафика?) — иду напрямую")

    records = load_records(args.limit, None if args.all else args.age_hours,
                           args.username)
    if not records:
        print("нечего проверять: подходящих аккаунтов в accounts.json нет")
        return 0

    storage = autoreg.Storage(cfg)
    browser = autoreg.BrowserFactory(cfg)
    human = autoreg.HumanDriver(cfg)
    arkose = autoreg.ArkoseSolver(cfg)
    mail = autoreg.EmailVerifier(cfg)
    gate = autoreg.HumanGate(cfg)
    sms = autoreg.SmsVerifier(cfg)
    restorer = autoreg.SessionRestorer(cfg, human, arkose, gate)

    counts = {"alive": 0, "suspended": 0, "appeal_pending": 0,
              "banned": 0, "dead": 0}
    print(f"проверяю {len(records)} аккаунт(ов)…")
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            for rec in records:
                try:
                    status = await check_one(rec, cfg, browser, human, arkose, mail,
                                             gate, args.fix, sms, session,
                                             args.follow, restorer)
                except Exception as exc:  # noqa: BLE001
                    print(f"  {rec.get('username', '?'):32} dead (ошибка: "
                          f"{type(exc).__name__}: {str(exc)[:80]})")
                    status = "dead"
                counts[status] = counts.get(status, 0) + 1
                if status == "banned":
                    autoreg.Storage(cfg).audit(rec.get("username", ""), "disabled")
                storage.update_status(rec.get("username", ""), status)
                await asyncio.sleep(3)
    finally:
        await browser.close()

    total = sum(counts.values())
    alive = counts["alive"]
    print("\n" + "-" * 60)
    print(f"всего {total}: живых {alive}, suspended {counts['suspended']}, "
          f"на апелляции {counts['appeal_pending']}, "
          f"забанено {counts['banned']}, сессия мертва {counts['dead']}")
    if total:
        print(f"выживаемость: {alive / total * 100:.0f}%")
    print("статусы записаны в accounts.json")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
