#!/usr/bin/env python3
"""
import_accounts.py — приём готовых аккаунтов в ферму.

Ферма не обязана регистрировать аккаунты сама: источник может отдать готовые.
Импорт принимает список и раскладывает по базе, проверяя вход.

Форматы строк во входном файле (`--file`):

    user:password                  # вход по паролю, сессия сохраняется
    user:/path/to/cookies.json     # готовая сессия (settings aiograpi или storage_state Playwright)

Пустые строки и `#` игнорируются. Мёртвые аккаунты уходят в failed.txt,
живые — в accounts.json со статусом alive и путём к сохранённой сессии.

Запуск:
    python import_accounts.py --file accounts.txt
    python import_accounts.py --file accounts.txt --proxy http://user:pass@host:port
    python import_accounts.py --file accounts.txt --check-only
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import random
import string
from datetime import datetime
from pathlib import Path
from typing import Any

from aiograpi import Client

import api_reg
from autoreg import Identity, Storage, mask_secret, setup_logging
from config import load_config

log = api_reg.log


# ===========================================================================
# Сессии
# ===========================================================================


def _storage_state_to_settings(path: Path) -> dict[str, Any]:
    """Переводит storage_state Playwright в settings aiograpi."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    cookies = {c["name"]: c["value"] for c in raw.get("cookies", [])}
    sessionid = cookies.pop("sessionid", "")
    ds_user_id = cookies.pop("ds_user_id", "") or cookies.get("ds_user_id", "")
    authorization = {}
    if sessionid and ds_user_id:
        authorization = {"ds_user_id": ds_user_id, "sessionid": sessionid}
    settings: dict[str, Any] = {
        "cookies": cookies,
        "authorization_data": authorization,
        "mid": cookies.get("mid", ""),
    }
    for name, key in (("android_device_id", "ig_did"), ("csrftoken", "csrftoken")):
        if cookies.get(key):
            settings.setdefault("uuids", {})[name] = cookies[key]
    return settings


def load_settings(path: Path) -> dict[str, Any]:
    """settings aiograpi из файла (с конвертацией storage_state при надобности)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "uuids" in data:
        return data
    if isinstance(data, dict) and isinstance(data.get("cookies"), list):
        return _storage_state_to_settings(path)
    raise ValueError(f"{path.name}: неизвестный формат сессии")


def build_from_settings(cfg, settings: dict[str, Any],
                        proxy: str = "") -> Client:
    client = api_reg.build_client(cfg, proxy=proxy)
    client.settings = settings
    client.init()
    return client


# ===========================================================================
# Импорт
# ===========================================================================


class Importer:
    def __init__(self, cfg) -> None:
        self.cfg = cfg
        self.storage = Storage(cfg)

    async def _login(self, client: Client, username: str,
                     password: str) -> bool:
        try:
            await client.login(username, password)
            return True
        except Exception as exc:  # noqa: BLE001 — статус решает вызывающий
            log.warning("[import] %s: вход не удался (%s: %s)", username,
                        type(exc).__name__, str(exc)[:120])
            return False

    async def add(self, line: str, proxy: str = "",
                  check_only: bool = False) -> str:
        login, _, secret = line.partition(":")
        login, secret = login.strip(), secret.strip()
        if not login:
            return "skip"

        if secret and Path(secret).exists():
            cookie_path = Path(secret)
            try:
                settings = load_settings(cookie_path)
            except ValueError as exc:
                log.error("[import] %s: %s", login, exc)
                return "bad"
            client = build_from_settings(self.cfg, settings, proxy)
            password = ""
        else:
            password = secret
            client = api_reg.build_client(self.cfg, proxy=proxy)
            if not await self._login(client, login, password):
                await self.storage.save_failed(
                    Identity(full_name="", username=login, password=password,
                             email=""), "импорт: вход не удался")
                return "dead"

        status = "alive"
        with contextlib.suppress(Exception):
            if not await client.account_info():
                status = "dead"

        if check_only and status != "alive":
            return status
        if status != "alive":
            await self.storage.save_failed(
                Identity(full_name="", username=login, password=password,
                         email=""), "импорт: профиль недоступен")
            return status

        path = Path(self.cfg.COOKIES_DIR) / f"{login}_{datetime.now():%Y%m%d_%H%M%S}.json"
        path.write_text(json.dumps(client.get_settings(), ensure_ascii=False),
                        encoding="utf-8")
        await self.storage.save_success(
            Identity(full_name="", username=login, password=password, email=""),
            proxy, cookies_path=path, status="alive", channel="api")
        self.storage.audit(login, "imported", channel="api",
                           password=bool(password))
        await client.close()
        return "alive"


# ===========================================================================
# CLI
# ===========================================================================


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="импорт готовых аккаунтов")
    p.add_argument("--file", required=True, help="файл со списком аккаунтов")
    p.add_argument("--proxy", default="", help="прокси для проверки и работы")
    p.add_argument("--check-only", action="store_true",
                   help="только проверить вход, в базу не писать")
    p.add_argument("--sleep", type=float, default=0.0,
                   help="пауза между аккаунтами, сек")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args(argv)


async def amain(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = load_config()
    setup_logging(cfg.LOG_FILE, verbose=args.verbose)

    lines = [ln.strip() for ln in Path(args.file).read_text(encoding="utf-8").splitlines()
             if ln.strip() and not ln.startswith("#")]
    if not lines:
        print("пустой список")
        return 1

    importer = Importer(cfg)
    counts: dict[str, int] = {}
    for i, line in enumerate(lines, 1):
        status = await importer.add(line, proxy=args.proxy,
                                    check_only=args.check_only)
        counts[status] = counts.get(status, 0) + 1
        print(f"  {i:3}/{len(lines)} {line.split(':')[0]:32} {status}")
        if args.sleep and i < len(lines):
            await asyncio.sleep(args.sleep + random.uniform(0, 2))

    print("итого:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 0 if counts.get("alive") else 1


def main() -> int:
    return asyncio.run(amain())


if __name__ == "__main__":
    raise SystemExit(main())
