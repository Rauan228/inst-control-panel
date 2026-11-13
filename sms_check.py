#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sms_check.py — проверка SMS-провайдера перед прогоном: баланс, наличие и цена.

Скрипт умеет работать с любым sms-activate-совместимым API (bee-sms, hollysms,
eveses и т.п.) — достаточно прописать базу и ключ в .env.

Использование:
    python sms_check.py                     # баланс + цена Instagram в SMS_COUNTRY
    python sms_check.py --country 187       # конкретная страна
    python sms_check.py --find ig           # где вообще есть этот сервис и почём

Ничего не покупает — только читает getBalance/getPrices.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import aiohttp  # noqa: E402

from config import load_config  # noqa: E402

SERVICE_ALIASES = ("ig", "instagram", "insta", "instagram.com")


async def call(session: aiohttp.ClientSession, base: str, key: str, **params):
    query = {"api_key": key, **params}
    async with session.get(base, params=query,
                           timeout=aiohttp.ClientTimeout(total=30)) as r:
        return r.status, (await r.text(errors="ignore")).strip()


async def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="проверка SMS-провайдера")
    p.add_argument("--country", default=None)
    p.add_argument("--find", default=None, help="найти сервис по коду (напр. ig)")
    args = p.parse_args(argv)

    cfg = load_config()
    base = cfg.SMS_API_BASE
    key = cfg.SMS_API_KEY
    print(f"база: {base}")
    print(f"провайдер: {cfg.SMS_PROVIDER}")
    if not key:
        print("SMS_API_KEY пуст — сначала впиши ключ в .env")
        return 1

    async with aiohttp.ClientSession() as session:
        status, body = await call(session, base, key, action="getBalance")
        print(f"баланс: HTTP {status} {body[:120]}")
        if "BAD_KEY" in body:
            print("-> ключ не принят этим провайдером")
            return 1

        country = args.country or cfg.SMS_COUNTRY
        service = args.find or cfg.SMS_SERVICE_CODE
        print(f"\nцена {service} / страна {country}:")
        for candidate in ([service] if args.find else SERVICE_ALIASES):
            status, body = await call(session, base, key, action="getPrices",
                                      service=candidate, country=country)
            print(f"  service={candidate}: HTTP {status} {body[:160]}")
            if status == 200 and body and "BAD" not in body:
                break

        if args.find:
            status, body = await call(session, base, key, action="getPrices",
                                      service=args.find)
            print("\nвсе страны с этим сервисом (топ по цене):")
            try:
                import json as _json
                data = _json.loads(body)
                flat = []
                for country_id, services in (data or {}).items():
                    info = services.get(args.find) if isinstance(services, dict) else None
                    if info:
                        flat.append((float(info.get("cost", 0)), country_id,
                                     info.get("count")))
                for cost, country_id, count in sorted(flat)[:10]:
                    print(f"  страна {country_id}: ${cost:.3f} (доступно {count})")
            except Exception:  # noqa: BLE001
                print(f"  (не разобрал ответ: {body[:200]})")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
