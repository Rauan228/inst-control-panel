#!/usr/bin/env python3
"""
test_proxy_pool.py — ротация по пулу sticky-эндпоинтов (Decodo-сценарий).

Проверяется без реальных прокси:
  * Config.proxies парсит PROXY_LIST (запятые/пробелы/дубли)
  * __post_init__ ставит PROXY на первый эндпоинт пула
  * ProxyRotator.next_endpoint() — round-robin по кругу, cfg.PROXY переключается
  * rotate() меняет эндпоинт, если IP не сменился (sticky-сессия)
  * rotate() бьёт rotation URL, если он задан (URL имеет приоритет над пулом)
  * мёртвый пул -> ProxyDeadError
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import aiohttp

import autoreg
from config import Config, load_config

autoreg.setup_logging(str(Path(__file__).parent / "test_pool.log"), verbose=False)

P1 = "http://u:p@us.decodo.com:10001"
P2 = "http://u:p@us.decodo.com:10002"
P3 = "http://u:p@us.decodo.com:10003"


def make_cfg(**kw) -> Config:
    cfg = Config(PROXY=kw.pop("PROXY", P1),
                 PROXY_ROTATE_SLEEP=0,
                 PROXY_MAX_RETRIES=2,
                 # без привязки к реальной базе: иначе занятые эндпоинты из
                 # accounts.json ломают ожидаемый порядок round-robin
                 PROXY_STICKY_HOURS=kw.pop("PROXY_STICKY_HOURS", 0),
                 ACCOUNTS_DB=kw.pop("ACCOUNTS_DB", "accounts.json"),
                 **kw)
    return cfg


def test_parsing() -> None:
    cfg = make_cfg(PROXY_LIST=f"{P1}, {P2} ;{P3},{P1}")
    assert cfg.proxies == [P1, P2, P3], cfg.proxies       # дедуп + разделители
    assert cfg.PROXY == P1, cfg.PROXY                    # первый стал текущим
    print("[1] ok: PROXY_LIST парсится (запятые/пробелы/точки с запятой), дубли сняты")

    cfg2 = make_cfg(PROXY_LIST="")
    assert cfg2.proxies == [P1] and cfg2.PROXY == P1
    print("[2] ok: без PROXY_LIST используется одиночный PROXY")

    cfg3 = Config(PROXY="", PROXY_LIST="", PROXY_ROTATE_SLEEP=0)
    assert cfg3.proxies == [], cfg3.proxies
    print("[3] ok: пустой PROXY-плейсхолдер не попадает в пул")


async def test_round_robin() -> None:
    cfg = make_cfg(PROXY_LIST=f"{P1},{P2},{P3}")
    rot = autoreg.ProxyRotator(cfg)
    seen = []
    for _ in range(7):
        rot.next_endpoint()
        seen.append(cfg.PROXY)
    assert seen == [P1, P2, P3, P1, P2, P3, P1], seen
    print("[4] ok: round-robin по пулу ->", [s.rsplit(':', 1)[-1] for s in seen])


async def test_rotate_sticky() -> None:
    """IP залип -> ротатор обязан сменить эндпоинт, пока не получит новый IP."""
    cfg = make_cfg(PROXY_LIST=f"{P1},{P2},{P3}")
    rot = autoreg.ProxyRotator(cfg)

    ips = {"10001": "1.1.1.1", "10002": "1.1.1.1", "10003": "3.3.3.3"}
    calls: list[str] = []

    async def fake_check(session):
        port = cfg.PROXY.rsplit(":", 1)[-1]
        calls.append(port)
        return ips[port]

    rot.check = fake_check                      # type: ignore[method-assign]
    # имитируем прошлый цикл: внешний IP уже 1.1.1.1 (sticky-сессия залипла)
    rot.current_ip = "1.1.1.1"
    ip = await rot.rotate(None)
    assert ip == "3.3.3.3", ip
    assert cfg.PROXY == P3, cfg.PROXY           # залипшие 10001/10002 пропущены
    assert calls[0] == "10001" and "10003" in calls, calls
    print("[5] ok: sticky-IP отброшен, дошли до %s (проверок: %s)" % (ip, calls))


async def test_affinity() -> None:
    """Эндпоинт свежего аккаунта не переиспользуется (PROXY_STICKY_HOURS)."""
    import json as _json
    import tempfile
    from datetime import datetime as _dt

    db = Path(tempfile.mkdtemp()) / "acc.json"
    db.write_text(_json.dumps([{"username": "a", "proxy": P1,
                                "created_at": _dt.now().isoformat(timespec="seconds")}]),
                  encoding="utf-8")
    cfg = make_cfg(PROXY_LIST=f"{P1},{P2},{P3}", PROXY_STICKY_HOURS=24,
                   ACCOUNTS_DB=str(db))
    rot = autoreg.ProxyRotator(cfg)
    picks = []
    for _ in range(4):
        rot.next_endpoint()
        picks.append(cfg.PROXY)
    assert P1 not in picks[:2], picks          # занятый уходит в конец очереди
    assert picks[-1] == P1 or len(set(picks)) == 3, picks
    rot.bind_account("b")
    assert rot.affinity_for("b") == cfg.PROXY
    print("[4a] ok: занятый эндпоинт отодвинут, affinity пишется:", picks)


async def test_rotation_url_priority() -> None:
    """Если задан PROXY_ROTATION_URL — он важнее пула."""
    cfg = make_cfg(PROXY_LIST=f"{P1},{P2}", PROXY_ROTATION_URL="http://mock/rotate")
    rot = autoreg.ProxyRotator(cfg)
    hits: list[str] = []

    async def fake_hit(session):
        hits.append(cfg.PROXY_ROTATION_URL)

    async def fake_check(session):
        return "9.9.9.9"

    rot._hit_rotation_url = fake_hit            # type: ignore[method-assign]
    rot.check = fake_check                      # type: ignore[method-assign]
    ip = await rot.rotate(None)
    assert ip == "9.9.9.9" and hits == ["http://mock/rotate"], (ip, hits)
    assert cfg.PROXY == P1, "пул не должен переключаться при заданном rotation URL"
    print("[6] ok: rotation URL имеет приоритет, пул не трогается")


async def test_dead_proxy() -> None:
    cfg = make_cfg(PROXY_LIST=f"{P1},{P2}")
    rot = autoreg.ProxyRotator(cfg)
    autoreg.ProxyRotator.IP_SERVICES = ("http://127.0.0.1:1/ip",)   # заведомо мёртвый
    async with aiohttp.ClientSession() as session:
        try:
            await rot.rotate(session)
            raise AssertionError("ожидался ProxyDeadError")
        except autoreg.ProxyDeadError as exc:
            print("[7] ok: мёртвый пул -> ProxyDeadError:", str(exc)[:60])
    autoreg.ProxyRotator.IP_SERVICES = (
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json",
        "https://ifconfig.me/all.json",
    )


async def test_live_us_exit() -> None:
    """Живая проверка: каждый эндпоинт пула даёт свой US-IP (если .env заполнен)."""
    cfg = load_config()
    pool = cfg.proxies
    if not pool or "decodo" not in pool[0]:
        print("[8] skip: в .env нет пула Decodo")
        return
    rot = autoreg.ProxyRotator(cfg)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as s:
        ips = {}
        for p in pool[:3]:
            cfg.PROXY = p
            try:
                ips[p.rsplit(":", 1)[-1]] = await rot.check(s)
            except autoreg.ProxyDeadError as exc:
                ips[p.rsplit(":", 1)[-1]] = f"DEAD: {exc}"
    uniq = {v for v in ips.values() if not str(v).startswith("DEAD")}
    print("[8] живые выходы пула:", ips)
    assert len(uniq) == len([v for v in ips.values() if not str(v).startswith("DEAD")]), \
        "эндпоинты дают одинаковый IP — sticky-сессии не разведены"
    print("    ok: у каждого эндпоинта свой внешний IP")


async def main() -> int:
    test_parsing()
    await test_round_robin()
    await test_affinity()
    await test_rotate_sticky()
    await test_rotation_url_priority()
    await test_dead_proxy()
    await test_live_us_exit()
    print("\nPROXY POOL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
