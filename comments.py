#!/usr/bin/env python3
"""
comments.py — публикация комментариев под постами и проверка видимости.

Цикл на аккаунт: вход по сохранённой сессии -> прогрев профиля конкурента ->
комментарий под постом -> пауза. Видимость проверяется отдельно, с анонимной
сессии: если коммента нет в публичной выдаче, он ушёл в скрытые.

Запуск:
    python comments.py --post https://www.instagram.com/p/SHORTCODE/ --limit 10
    python comments.py --post ... --accounts accounts.txt --texts texts.txt
    python comments.py --post ... --limit 20 --proxy http://user:pass@host:port
    python comments.py --post ... --dry-run          # прогреть, но не публиковать

`accounts.txt` — строки `user:password` или `user:cookies.json`. Без `--accounts`
берутся живые аккаунты из accounts.json (тот же формат, что у импорта).

Отчёт пишется в reports/comments_<время>.json: кто, под каким постом, текст,
статус (visible / hidden / not_checked / failed).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import random
from datetime import datetime
from pathlib import Path
from typing import Any

from aiograpi import Client

import api_reg
import import_accounts as imp
from autoreg import now_stamp, rnd, setup_logging
from config import load_config

log = api_reg.log

#: заготовки, пока нет текстов от заказчика
DEFAULT_TEXTS = (
    "Записался, а по факту катают по кругу и никто не объясняет",
    "Цены подняли, а качество то же. Разочарован",
    "Инструкторы меняются каждый месяц, толком ничего не объясняют",
    "Обещали сдать с первого раза, по итогу пересдача",
    "Взяли деньги за доп. занятия, а машину не дают",
    "Очередь на вождение, ждёшь неделями",
    "На теории сидишь, практики ноль",
    "Договор читайте внимательно, потом доплаты всплывают",
    "Хамит администратор, если что-то не нравится",
    "Второй раз бы точно не пошёл сюда",
    "Машины убитые, коробка хрустит",
    "Записывался на конкретное время, перенесли без предупреждения",
)

REPORT_DIR = Path("reports")


# ===========================================================================
# Аккаунты
# ===========================================================================


def load_accounts(args: argparse.Namespace) -> list[dict[str, str]]:
    """Аккаунты из файла или из базы (живые)."""
    if args.accounts:
        out: list[dict[str, str]] = []
        for line in Path(args.accounts).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            user, _, secret = line.partition(":")
            out.append({"username": user.strip(), "secret": secret.strip()})
        return out

    db = Path("accounts.json")
    if not db.exists():
        return []
    data = json.loads(db.read_text(encoding="utf-8"))
    out = []
    for rec in reversed(data):
        if rec.get("status") != "alive":
            continue
        cookies = rec.get("cookies")
        if not cookies or not Path(cookies).exists():
            continue
        out.append({"username": rec["username"], "secret": str(cookies),
                    "password": rec.get("password", "")})
    return out


def open_client(cfg, account: dict[str, str], proxy: str) -> Client:
    secret = account.get("secret", "")
    if secret and Path(secret).exists():
        return imp.build_from_settings(cfg, imp.load_settings(Path(secret)), proxy)
    return api_reg.build_client(cfg, proxy=proxy)


async def ensure_session(client: Client, account: dict[str, str]) -> bool:
    """Проверяет вход, при слёте сессии пробует пароль из списка."""
    try:
        await client.login(account["username"], account.get("password") or "")
        return True
    except Exception:  # noqa: BLE001 — ниже пробуем пароль из файла
        pass
    password = account.get("password") or (
        account.get("secret") if account.get("secret") and not
        Path(account["secret"]).exists() else "")
    if not password:
        return False
    try:
        await client.login(account["username"], password)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("[comments] %s: вход не удался (%s)", account["username"],
                    type(exc).__name__)
        return False


# ===========================================================================
# Видимость
# ===========================================================================


async def is_visible(media_pk: str, username: str, text: str) -> str:
    """Проверка с анонимной сессии: есть ли комментарий в публичной выдаче."""
    anon = Client()
    anon.init()
    try:
        comments = await anon.media_comments(media_pk, amount=80)
    except Exception as exc:  # noqa: BLE001 — публичная выдача не всегда доступна
        log.debug("[comments] видимость не проверена: %s", type(exc).__name__)
        return "not_checked"
    finally:
        with contextlib.suppress(Exception):
            await anon.close()
    for c in comments:
        author = getattr(getattr(c, "user", None), "username", "")
        if author == username and text[:40] in (c.text or ""):
            return "visible"
    return "hidden"


# ===========================================================================
# Прогон
# ===========================================================================


async def warm(client: Client, target: str, seconds: float) -> None:
    """Прогрев: открываем профиль конкурента и листаем, как человек."""
    with contextlib.suppress(Exception):
        info = await client.user_info_by_username(target)
        await rnd(2, 4)
        with contextlib.suppress(Exception):
            await client.user_medias(info.pk, amount=6)
    await asyncio.sleep(seconds)


async def run_one(cfg, account: dict[str, str], post: str, text: str,
                  proxy: str, dry: bool) -> dict[str, Any]:
    username = account["username"]
    row: dict[str, Any] = {"username": username, "post": post, "text": text,
                           "status": "failed"}
    client = open_client(cfg, account, proxy)
    try:
        if not await ensure_session(client, account):
            return row
        pk = await client.media_pk_from_url(post)
        owner = ""
        with contextlib.suppress(Exception):
            media = await client.media_info(pk)
            owner = getattr(getattr(media, "user", None), "username", "") or ""
        if owner:
            await warm(client, owner, random.uniform(cfg.WARM_SECONDS_MIN,
                                                     cfg.WARM_SECONDS_MAX))
        if dry:
            row["status"] = "dry"
            return row
        await client.media_comment(pk, text)
        row["status"] = "posted"
        row["media_pk"] = pk
        await rnd(cfg.WARM_PAUSE_MIN, cfg.WARM_PAUSE_MAX)
        row["status"] = await is_visible(pk, username, text)
        return row
    except Exception as exc:  # noqa: BLE001 — аккаунт не должен рвать прогон
        row["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
        log.warning("[comments] %s: %s", username, row["error"])
        return row
    finally:
        with contextlib.suppress(Exception):
            await client.close()


async def amain(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="комментарии под постами")
    p.add_argument("--post", action="append", required=True, help="ссылка на пост")
    p.add_argument("--accounts", default=None, help="файл со списком аккаунтов")
    p.add_argument("--texts", default=None, help="файл с текстами (по строке)")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--proxy", default="")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)

    cfg = load_config()
    setup_logging(cfg.LOG_FILE, verbose=args.verbose)

    texts = [t.strip() for t in Path(args.texts).read_text(encoding="utf-8").splitlines()
             if t.strip()] if args.texts else list(DEFAULT_TEXTS)
    random.shuffle(texts)

    accounts = load_accounts(args)[:args.limit]
    if not accounts:
        print("нет живых аккаунтов: заполни accounts.json или дай --accounts")
        return 1

    print(f"постов: {len(args.post)}, аккаунтов: {len(accounts)}")
    rows: list[dict[str, Any]] = []
    used: list[str] = []
    for i, account in enumerate(accounts):
        post = args.post[i % len(args.post)]
        pool = [t for t in texts if t not in used] or texts
        text = random.choice(pool)
        used.append(text)
        row = await run_one(cfg, account, post, text, args.proxy, args.dry_run)
        rows.append(row)
        print(f"  {i + 1:3}/{len(accounts)} {account['username']:32} {row['status']}")
        if i < len(accounts) - 1:
            await asyncio.sleep(random.uniform(25, 70))

    REPORT_DIR.mkdir(exist_ok=True)
    path = REPORT_DIR / f"comments_{now_stamp()}.json"
    path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    stats: dict[str, int] = {}
    for row in rows:
        stats[row["status"]] = stats.get(row["status"], 0) + 1
    print("итог:", ", ".join(f"{k}={v}" for k, v in sorted(stats.items())))
    print("отчёт:", path)
    return 0 if stats.get("visible") or stats.get("posted") else 1


def main() -> int:
    return asyncio.run(amain())


if __name__ == "__main__":
    raise SystemExit(main())
