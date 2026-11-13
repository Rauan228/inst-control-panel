#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
autoreg.py — асинхронный движок регистрации Instagram + web-панель управления.

Python 3.11+, Playwright (async), aiohttp, imaplib.

Компоненты:
  1. ProxyRotator    — ротация мобильного IP перед каждым циклом
  2. IdentityFactory — username / password / email / birthday
  3. HumanDriver     — human_type, human_click, рандомные задержки
  4. ArkoseSolver    — перехват sitekey + решение FunCaptcha (CapMonster / 2Captcha)
  5. EmailVerifier   — imaplib + re(r'\\b\\d{6}\\b') по catch-all ящику
  6. SmsVerifier     — sms-activate / 5sim: аренда, поллинг, бан/отмена
  7. TrustBuilder    — аватар + подписка на популярный аккаунт
  8. Storage         — cookies JSON + success.txt (login:password:email:proxy)
  9. Dashboard       — FastAPI web-страница: старт/стоп, конфиг, живой лог

CLI :  python autoreg.py --run
Web :  python autoreg.py --serve   ->  http://127.0.0.1:8088
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import email
import email.header
import email.utils
import imaplib
import json
import logging
import os
import random
import re
import secrets
import string
import sys
import time
import traceback
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp

from playwright.async_api import (
    Browser,
    BrowserContext,
    Error as PWError,
    Page,
    Route,
    TimeoutError as PWTimeout,
    async_playwright,
)

from config import (
    BIRTHDAY_BLACKLIST,
    BIRTHDAY_MONTH_WEIGHTS,
    Config,
    EMAIL_LOCAL_WORDS,
    FIRST_NAMES_BY_GENDER,
    FIRST_NAMES_FEMALE,
    FIRST_NAMES_MALE,
    LAST_NAMES,
    TRUST_TARGETS,
    USERNAME_SEPARATORS,
    load_config,
)

# ===========================================================================
# ЛОГИРОВАНИЕ
# ===========================================================================

LOG_FMT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FMT = "%Y-%m-%d %H:%M:%S"

#: кольцевой буфер последних строк лога — его читает web-панель
LOG_RING: deque[str] = deque(maxlen=500)


class _RingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            LOG_RING.append(self.format(record))
        except Exception:  # noqa: BLE001
            pass


def setup_logging(log_file: str, verbose: bool = True) -> logging.Logger:
    """Корневой логгер: консоль + файл + ring-буфер для web-панели."""
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(LOG_FMT, DATE_FMT))
    root.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh.setFormatter(logging.Formatter(LOG_FMT, DATE_FMT))
    root.addHandler(sh)

    rh = _RingHandler()
    rh.setLevel(logging.INFO)
    rh.setFormatter(logging.Formatter(LOG_FMT, DATE_FMT))
    root.addHandler(rh)

    for noisy in ("asyncio", "urllib3", "aiohttp.access", "filelock", "PIL"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return logging.getLogger("autoreg")


log = logging.getLogger("autoreg")

# ===========================================================================
# ИСКЛЮЧЕНИЯ
# ===========================================================================


class AutoRegError(Exception):
    """Базовая ошибка движка."""


class ProxyDeadError(AutoRegError):
    """Прокси не отвечает / IP не сменился — перезапускаем цикл."""


class CaptchaRequiredError(AutoRegError):
    """Появилась CAPTCHA, которую не удалось решить."""


class BannedNumberError(AutoRegError):
    """SMS-номер забанен — нужна отмена/бан активации через API."""


class VerificationTimeoutError(AutoRegError):
    """Код подтверждения не пришёл за отведённое время."""


class FormNotFoundError(AutoRegError):
    """Ожидаемое поле/кнопка не найдены (селекторы устарели)."""


class AccountRejectedError(AutoRegError):
    """Instagram отклонил регистрацию (email taken / suspended / checkpoint)."""


class SuspendedError(AutoRegError):
    """
    Аккаунт создан, но остался на гейте «Confirm you're human».
    Сессия и пароль валидны — его можно дожать позже, поэтому это не «фейл»
    регистрации, а отдельный статус suspended.
    """


class BrowserCrashedError(AutoRegError):
    """Страница/контекст/браузер закрылись или крашнулись — нужен перезапуск браузера."""


class PageBlankError(AutoRegError):
    """Страница загрузилась пустой (заблокированы JS/CSS, CORS, капча-стена)."""


# ===========================================================================
# ОБЩИЕ УТИЛИТЫ
# ===========================================================================


async def rnd(a: float = 1.0, b: float = 3.0) -> None:
    """Случайная пауза [a, b] сек — по ТЗ 1..3 сек между кликами/полями."""
    await asyncio.sleep(random.uniform(a, b))


async def long_rnd(a: float = 3.0, b: float = 8.0) -> None:
    """Длинная пауза — имитация чтения экрана."""
    await asyncio.sleep(random.uniform(a, b))


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def mask_secret(value: str, keep: int = 3) -> str:
    if not value:
        return ""
    return value[:keep] + "*" * max(len(value) - keep * 2, 0) + value[-keep:]


#: регуляровка для вырезания 6-значного кода из письма / SMS
CODE_RE = re.compile(r"\b\d{6}\b")


# ===========================================================================
# 1. КОНФИГУРАЦИЯ И СЕТЬ — ProxyRotator
# ===========================================================================


class ProxyRotator:
    """
    Мобильный прокси:
      * GET на PROXY_ROTATION_URL (API провайдера меняет исходящий IP);
      * сон PROXY_ROTATE_SLEEP секунд (по ТЗ — 10);
      * проверка живости прокси и фиксация нового внешнего IP.
    """

    IP_SERVICES = (
        "https://api.ipify.org?format=json",
        "https://ipinfo.io/json",
        "https://ifconfig.me/all.json",
    )

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.current_ip: str | None = None
        self.rotations = 0
        self._idx = -1                 # индекс текущего эндпоинта в пуле
        self.pool: list[str] = cfg.proxies
        self.current_endpoint: str | None = None
        self._affinity_path = Path(cfg.PROXY_AFFINITY_FILE)
        self._last_use: dict[str, float] = {}

    # -- «занятость» эндпоинтов --------------------------------------------
    def _busy_endpoints(self) -> set[str]:
        """
        Эндпоинты, с которых уже создавали аккаунт за последние
        PROXY_STICKY_HOURS часов. Два свежих аккаунта с одного IP — паттерн.
        """
        if self.cfg.PROXY_STICKY_HOURS <= 0:
            return set()
        horizon = datetime.now().timestamp() - self.cfg.PROXY_STICKY_HOURS * 3600
        busy: set[str] = set()
        try:
            db = Path(self.cfg.ACCOUNTS_DB)
            if db.exists():
                for rec in json.loads(db.read_text(encoding="utf-8")) or []:
                    if not isinstance(rec, dict):
                        continue
                    try:
                        ts = datetime.fromisoformat(
                            str(rec.get("created_at") or "")).timestamp()
                    except (TypeError, ValueError):
                        ts = 0.0
                    if ts >= horizon and rec.get("proxy"):
                        busy.add(str(rec["proxy"]).strip())
        except (OSError, json.JSONDecodeError):
            pass
        return busy

    def _ordered_pool(self) -> list[str]:
        """Пул, начиная со следующего индекса; свободные — вперёд занятых."""
        self.pool = self.cfg.proxies
        if not self.pool:
            return []
        n = len(self.pool)
        rotated = [self.pool[(self._idx + 1 + i) % n] for i in range(n)]
        busy = self._busy_endpoints() | set(self._last_use)
        free = [p for p in rotated if p not in busy]
        # занятые — в порядке давности использования (LRU), чтобы после
        # исчерпания свободных уходить к самому «отлежавшемуся» эндпоинту
        taken = sorted((p for p in rotated if p in busy),
                       key=lambda p: self._last_use.get(p, 0.0))
        if taken and free:
            log.info("[proxy] свободных эндпоинтов %s, занятых свежими аккаунтами %s "
                     "— беру свободный", len(free), len(taken))
        return free + taken

    def next_endpoint(self) -> str | None:
        """
        Выбирает следующий эндпоинт пула.

        Для sticky-сессий (Decodo: каждый порт = отдельная сессия/IP) смена
        порта и есть ротация. Предпочитаем эндпоинты, на которых ещё не
        создавали аккаунт за PROXY_STICKY_HOURS часов.
        """
        order = self._ordered_pool()
        if not order:
            self.current_endpoint = None
            return None
        chosen = order[0]
        self._idx = self.pool.index(chosen)
        if chosen != self.cfg.PROXY:
            self.cfg.PROXY = chosen
        self.current_endpoint = chosen
        self._last_use[chosen] = time.monotonic()
        host = re.sub(r"^https?://", "", chosen).split("@")[-1]
        log.info("[proxy] эндпоинт %s/%s -> %s", self._idx + 1, len(self.pool), host)
        return chosen

    def bind_account(self, username: str) -> None:
        """Запоминает, что этот эндпоинт занят аккаунтом (для переоткрытия)."""
        if not self.current_endpoint:
            return
        data: dict[str, Any] = {}
        try:
            if self._affinity_path.exists():
                data = json.loads(self._affinity_path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    data = {}
        except (OSError, json.JSONDecodeError):
            data = {}
        data[username] = {"proxy": self.current_endpoint,
                          "bound_at": datetime.now().isoformat(timespec="seconds")}
        with contextlib.suppress(OSError):
            self._affinity_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def affinity_for(self, username: str) -> str | None:
        try:
            data = json.loads(self._affinity_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        rec = data.get(username) if isinstance(data, dict) else None
        return (rec or {}).get("proxy") if isinstance(rec, dict) else None

    async def rotate(self, session: aiohttp.ClientSession) -> str:
        """
        Полный цикл ротации. Возвращает новый внешний IP.

        Порядок: смена эндпоинта (если пул) -> GET rotation URL (если есть) ->
        сон PROXY_ROTATE_SLEEP -> проверка IP. Если IP не сменился — берём
        следующий эндпоинт и проверяем снова (до конца пула).
        """
        if self.cfg.PROXY_ROTATION_URL:
            await self._hit_rotation_url(session)
        else:
            self.next_endpoint()

        log.info("[proxy] сон %s сек до стабилизации IP…", self.cfg.PROXY_ROTATE_SLEEP)
        await asyncio.sleep(self.cfg.PROXY_ROTATE_SLEEP)

        new_ip = await self.check(session)

        # sticky-сессия может вернуть тот же IP — пробуем другие эндпоинты пула
        tries = 0
        while new_ip == self.current_ip and len(self.pool) > 1 and tries < len(self.pool):
            tries += 1
            log.warning("[proxy] IP %s не сменился — беру следующий эндпоинт (%s/%s)",
                        new_ip, tries, len(self.pool))
            if self.cfg.PROXY_ROTATION_URL:
                await self._hit_rotation_url(session)
            else:
                self.next_endpoint()
            await asyncio.sleep(self.cfg.PROXY_ROTATE_SLEEP)
            new_ip = await self.check(session)

        self.current_ip = new_ip
        self.rotations += 1
        log.info("[proxy] ротация #%s ok, внешний IP = %s", self.rotations, new_ip)
        return new_ip

    async def _hit_rotation_url(self, session: aiohttp.ClientSession) -> None:
        url = self.cfg.PROXY_ROTATION_URL
        log.debug("[proxy] GET %s", url)
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=30)
            ) as resp:
                body = (await resp.text(errors="ignore"))[:300]
                log.info("[proxy] rotation url -> HTTP %s | %s", resp.status, body)
                if resp.status >= 400:
                    raise ProxyDeadError(f"rotation url HTTP {resp.status}: {body}")
        except ProxyDeadError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise ProxyDeadError(f"rotation url недоступен: {exc}") from exc

    async def check(self, session: aiohttp.ClientSession) -> str:
        """Внешний IP через прокси. ProxyDeadError при провале всех сервисов."""
        last: Any = None
        for service in self.IP_SERVICES:
            try:
                async with session.get(
                    service,
                    proxy=self.cfg.PROXY or None,
                    timeout=aiohttp.ClientTimeout(total=25),
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                ) as resp:
                    text = await resp.text(errors="ignore")
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
                    if resp.status == 200 and m:
                        return m.group(1)
                    hint = resp.headers.get("x-error-message", "")
                    last = ProxyDeadError(
                        f"{service} -> HTTP {resp.status}"
                        + (f" ({hint[:120]})" if hint else ""))
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                last = exc
        raise ProxyDeadError(f"прокси мёртв: {last}")


# ===========================================================================
# 2. ГЕНЕРАЦИЯ ИДЕНТИЧНОСТИ
# ===========================================================================


@dataclass
class Identity:
    full_name: str
    username: str
    password: str
    email: str
    phone: str = ""
    birthday: tuple[int, int, int] = (1997, 5, 14)  # (year, month, day)

    def as_line(self, proxy: str) -> str:
        """login:password:email:proxy — формат success.txt"""
        return f"{self.username}:{self.password}:{self.email}:{proxy}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "password": self.password,
            "email": self.email,
            "phone": self.phone,
            "full_name": self.full_name,
            "birthday": "-".join(map(str, self.birthday)),
        }


class IdentityFactory:
    """Генератор username / password / email / birthday."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._email_pool = self._load_email_pool()
        self._used: set[str] = set()

    def _load_email_pool(self) -> list[str]:
        p = Path(self.cfg.EMAIL_POOL_FILE)
        if p.exists():
            lines = [
                ln.strip()
                for ln in p.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.startswith("#")
            ]
            log.info("[identity] пул email загружен: %s адресов", len(lines))
            return lines
        return []

    def _pick_names(self) -> tuple[str, str, str]:
        """(gender, first, last) — одна связка на всю идентичность."""
        gender = random.choice(("m", "f"))
        first = random.choice(FIRST_NAMES_BY_GENDER[gender])
        return gender, first, random.choice(LAST_NAMES)

    def username(self, first: str | None = None, last: str | None = None) -> str:
        """
        Имя + фамилия + 3-4 случайных цифры (6 вариантов компоновки).

        Первый/последний передаются из new_identity: ник должен строиться из
        ТОЙ ЖЕ пары, что уходит в full_name, иначе «Nathan Smith» рядом с ником
        «laura8419.hernandez» — расхождение идентичности.
        """
        for _ in range(80):
            if not first or not last:
                _, first, last = self._pick_names()
            sep = random.choice(USERNAME_SEPARATORS)
            digits = "".join(random.choices(string.digits, k=random.choice([3, 3, 4, 4])))
            style = random.randint(0, 8)
            if style == 0:
                base = f"{first}{sep}{last}{digits}"
            elif style == 1:
                base = f"{first}{digits}{sep}{last}"
            elif style == 2:
                base = f"{first}{sep}{last}{sep}{digits}"
            elif style == 3:
                base = f"{first[0]}{sep}{last}{digits}"
            elif style == 4:
                base = f"{first}{last[0]}{digits}"
            elif style == 5:
                base = f"{random.choice(EMAIL_LOCAL_WORDS)}.{first}{digits}"
            elif style == 6:
                base = f"the{first}{digits}"
            elif style == 7:
                base = f"{first}{sep}{last}{random.randint(1988, 2005)}"
            else:
                base = f"{first[0]}{sep}{last}_{digits}"
            uname = base.lower().strip("._-")
            if 6 <= len(uname) <= 28 and uname not in self._used:
                self._used.add(uname)
                return uname
        uname = f"{first or random.choice(FIRST_NAMES_MALE)}{secrets.token_hex(3)}"
        self._used.add(uname)
        return uname

    def password(self) -> str:
        """
        12+ символов, смешанный регистр + цифры. Спецсимволы не используем —
        они ломают разделители формата login:password:email:proxy.
        """
        alphabet = string.ascii_letters + string.digits
        length = max(self.cfg.PASSWORD_LENGTH, 12)
        while True:
            pwd = "".join(secrets.choice(alphabet) for _ in range(length))
            if (
                any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
            ):
                return pwd

    def email_address(self, username: str) -> str:
        """
        Адрес из пула (email_pool.txt) ИЛИ catch-all на своём домене.

        Стиль local-part задаётся EMAIL_LOCAL_STYLE:
          name   — nathan.smith84@domain  (похоже на личную почту)
          prefix — ig.nathan.smith84@domain (текущий шаблон, самый узнаваемый)
          random — sky4417@domain
        Все local-part'ы падают в один IMAP-ящик, фильтр — в EmailVerifier.
        """
        if self._email_pool:
            return self._email_pool.pop(random.randrange(len(self._email_pool)))
        style = (self.cfg.EMAIL_LOCAL_STYLE or "name").strip().lower()
        if style == "mixed":                      # разные схемы вперемешку
            style = random.choice(["name", "prefix", "random"])
        prefix = self.cfg.EMAIL_LOCAL_PREFIX.strip().rstrip(".")
        if style == "random":
            local = (f"{random.choice(EMAIL_LOCAL_WORDS)}"
                     f"{random.randint(10, 9999)}")
        elif style == "prefix" and prefix:
            local = f"{prefix}.{username}"
        else:
            local = username
        return f"{local}@{self.cfg.EMAIL_DOMAIN}"

    def birthday(self) -> tuple[int, int, int]:
        """
        Реалистичная дата рождения: возраст по треугольному распределению
        (пик ~29–32), сезонность месяцев как у реальных US-пользователей,
        «красивые» MM-DD (25.12, 01.01, 14.02…) отбрасываются.
        """
        low, high = self.cfg.MIN_BIRTHDAY_AGE, self.cfg.MAX_BIRTHDAY_AGE
        age = int(random.triangular(low, high, min(low + 7, high)))
        month = day = 1
        for _ in range(30):
            month = random.choices(range(1, 13),
                                   weights=BIRTHDAY_MONTH_WEIGHTS, k=1)[0]
            day = random.randint(1, 28)
            if (month, day) not in BIRTHDAY_BLACKLIST:
                break
        return (datetime.now().year - age, month, day)

    def full_name(self, first: str | None = None,
                  last: str | None = None) -> str:
        if not first or not last:
            _, first, last = self._pick_names()
        return f"{first.capitalize()} {last.capitalize()}"

    def new_identity(self) -> Identity:
        _, first, last = self._pick_names()
        uname = self.username(first, last)
        ident = Identity(
            full_name=self.full_name(first, last),
            username=uname,
            password=self.password(),
            email=self.email_address(uname),
            birthday=self.birthday(),
        )
        log.info(
            "[identity] user=%s email=%s pass=%s bday=%s",
            ident.username,
            ident.email,
            mask_secret(ident.password),
            "-".join(map(str, ident.birthday)),
        )
        return ident


# ===========================================================================
# 2.1 ИМИТАЦИЯ ЖИВОГО ПОЛЬЗОВАТЕЛЯ — HumanDriver
# ===========================================================================


class HumanDriver:
    """
    Всё, что делает сессию «человеческой»:
      * human_type  — посимвольный ввод 40..150 мс (+ редкие длинные паузы);
      * human_click — движение мыши к цели, джиттер, пауза до/после;
      * random_delay — asyncio.sleep(1..3) между полями и кнопками.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.mouse_steps = 0

    # -- text ---------------------------------------------------------------
    async def human_type(self, element: Any, text: str, *, clear: bool = True) -> None:
        """
        Ввод строки посимвольно с рандомной задержкой 40..150 мс.
        ~3% символов — «задумаемся» на 0.3..0.9 сек; ~2% — опечатка + Backspace.
        """
        if element is None:
            raise FormNotFoundError("human_type: element is None")
        try:
            await element.scroll_into_view_if_needed(timeout=5000)
        except (PWTimeout, PWError):
            pass

        if clear:
            with contextlib.suppress(PWError, PWTimeout):
                await element.fill("")
        await element.click(timeout=10000)
        await asyncio.sleep(random.uniform(0.15, 0.45))

        log.debug("[human] печать %s символов", len(text))
        for i, ch in enumerate(text):
            # имитация опечатки
            if random.random() < 0.02 and i > 2:
                wrong = random.choice(string.ascii_lowercase)
                await element.type(wrong, delay=random.randint(40, 150))
                await asyncio.sleep(random.uniform(0.1, 0.35))
                await element.press("Backspace")
                await asyncio.sleep(random.uniform(0.08, 0.25))

            await element.type(ch, delay=random.randint(40, 150))

            if random.random() < 0.03:
                await asyncio.sleep(random.uniform(0.3, 0.9))
            elif random.random() < 0.06:
                await asyncio.sleep(random.uniform(0.16, 0.32))

        await asyncio.sleep(random.uniform(0.4, 1.1))

    # -- clicks -------------------------------------------------------------
    async def human_click(self, element: Any, *, label: str = "") -> None:
        """Клик с наведением мыши, джиттером и паузами 1..3 сек."""
        tag = label or "element"
        try:
            await element.scroll_into_view_if_needed(timeout=5000)
        except (PWTimeout, PWError):
            pass

        with contextlib.suppress(Exception):
            box = await element.bounding_box()
            if box:
                x = box["x"] + box["width"] * random.uniform(0.25, 0.75)
                y = box["y"] + box["height"] * random.uniform(0.25, 0.75)
                await self._move_mouse(x, y)

        await asyncio.sleep(random.uniform(0.35, 1.2))
        await element.click(timeout=15000)
        log.debug("[human] клик по %s", tag)
        await rnd(1.0, 3.0)  # по ТЗ: 1..3 сек между кликами

    async def _move_mouse(self, x: float, y: float, page: Page | None = None) -> None:
        """Плавное перемещение курсора по кривой Безье-ish."""
        if page is None:
            return
        try:
            await page.mouse.move(x, y, steps=random.randint(8, 24))
        except PWError:
            pass

    async def wander(self, page: Page, seconds: float | None = None) -> None:
        """Бесцельное движение мыши + микро-скролл — шум для антибот-эвристики."""
        total = seconds if seconds is not None else random.uniform(1.5, 5.0)
        end = time.monotonic() + total
        vp = page.viewport_size or {"width": 1366, "height": 768}
        while time.monotonic() < end:
            await page.mouse.move(
                random.uniform(20, vp["width"] - 20),
                random.uniform(20, vp["height"] - 20),
                steps=random.randint(5, 18),
            )
            if random.random() < 0.3:
                await page.mouse.wheel(0, random.randint(-120, 220))
            await asyncio.sleep(random.uniform(0.2, 0.8))
        self.mouse_steps += 1

    # -- helpers ------------------------------------------------------------
    @staticmethod
    async def random_delay(a: float = 1.0, b: float = 3.0) -> None:
        """Публичная обёртка: задержка 1..3 сек."""
        await rnd(a, b)

    async def press_tab(self, page: Page) -> None:
        """Переход к следующему полю по Tab с человеческой паузой."""
        await asyncio.sleep(random.uniform(0.3, 0.9))
        await page.keyboard.press("Tab")
        await rnd(0.8, 2.2)


# ===========================================================================
# 4. ОБХОД ЗАЩИТЫ — Arkose Labs FunCaptcha (CapMonster / 2Captcha)
# ===========================================================================

#: JS, который вытаскивает параметры Arkose из страницы
ARKOSE_PROBE_JS = """
() => {
  const out = { sitekey: null, surl: null, blobs: [], pageUrl: location.href,
                iframes: [], sources: [] };
  const UUID = /[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}/g;

  // 1. iframe'ы Arkose
  document.querySelectorAll('iframe').forEach(f => {
    const src = f.src || f.getAttribute('data-src') || '';
    if (!src) return;
    out.iframes.push(src.slice(0, 300));
    if (/arkoselabs|funcaptcha/i.test(src)) {
      try {
        const u = new URL(src, location.href);
        const pk = u.searchParams.get('public_key') ||
                   u.searchParams.get('publickey') ||
                   u.searchParams.get('surl_public_key');
        if (pk) { out.sitekey = pk; out.sources.push('iframe:' + u.host); }
        const su = u.searchParams.get('surl') || u.searchParams.get('service_url');
        if (su) out.surl = su;
      } catch (e) {}
    }
  });

  // 2. Глобальные объекты IG/Arkose
  const cand = [];
  try { if (window.arkoseEnforcement) cand.push(window.arkoseEnforcement); } catch(e){}
  try { if (window.__ARKOSE__) cand.push(window.__ARKOSE__); } catch(e){}
  try { if (window.ArkoseEnforcement) cand.push(window.ArkoseEnforcement); } catch(e){}
  cand.forEach(o => {
    try {
      const cfg = o._config || o.config || o.settings || o;
      const s = JSON.stringify(cfg);
      const m = s.match(UUID); if (m && !out.sitekey) { out.sitekey = m[0]; out.sources.push('global-object'); }
      const sm = s.match(/"surl"\\s*:\\s*"([^"]+)"/); if (sm && !out.surl) out.surl = sm[1];
      const bm = s.match(/"blob"\\s*:\\s*"([^"]+)"/g); if (bm) out.blobs.push(...bm.map(x => x.replace(/.*"blob"\\s*:\\s*"/,'').replace(/"$/,'')));
    } catch (e) {}
  });

  // 3. Скрипты и HTML страницы — ищем public key / surl / blob
  const html = document.documentElement.innerHTML;
  if (!out.sitekey) {
    const keys = html.match(/(?:public_key|publicKey|sitekey)["']?\\s*[:=]\\s*["']([0-9A-Fa-f-]{36})["']/i);
    if (keys) { out.sitekey = keys[1]; out.sources.push('html-attr'); }
  }
  if (!out.surl) {
    const su = html.match(/(https:\\/\\/[a-z0-9.-]*arkoselabs\\.com[^"'\\s\\\\]*)/i);
    if (su) out.surl = su[1];
  }
  document.querySelectorAll('script').forEach(s => {
    const t = s.textContent || '';
    if (!t) return;
    if (!out.sitekey) {
      const m = t.match(UUID);
      if (m && /arkose|funcaptcha|public_key/i.test(t)) {
        out.sitekey = m[0]; out.sources.push('inline-script');
      }
    }
    const bm = t.match(/blob["']?\\s*[:=]\\s*["']([^"']{10,})["']/);
    if (bm) out.blobs.push(bm[1]);
  });

  // 4. Скрытые поля с токеном
  out.tokenFields = Array.from(
    document.querySelectorAll('input[name*="token" i], input[id*="token" i], textarea[name*="token" i]')
  ).map(e => ({ name: e.name || '', id: e.id || '' }));

  return out;
}
"""

#: JS, который внедряет готовый токен решения обратно в форму
ARKOSE_INJECT_JS = """
(token) => {
  const done = [];
  // 1. Все известные поля, куда Arkose/IG складывает токен
  const sels = [
    'input[name="fc-token"]', '#FunCaptcha-Token', 'input[name="FunCaptcha-Token"]',
    'input[name="arkose_token"]', 'input[name="jazoest"]',
    'input[data-testid="challenge-token"]', 'textarea[name="fc-token"]',
    'input[id*="fun-captcha" i]', 'input[name*="captcha_token" i]',
  ];
  sels.forEach(sel => {
    document.querySelectorAll(sel).forEach(el => {
      el.value = token;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      done.push(sel);
    });
  });

  // 2. Любой скрытый input, созданный Arkose динамически
  document.querySelectorAll('input[type="hidden"]').forEach(el => {
    const k = (el.name || '') + ' ' + (el.id || '');
    if (/token|arkose|captcha|fc/i.test(k) && !el.value) {
      el.value = token;
      el.dispatchEvent(new Event('change', { bubbles: true }));
      done.push(el.name || el.id);
    }
  });

  // 3. Программный путь — через сам enforcement-объект
  try {
    if (window.arkoseEnforcement) {
      window.arkoseEnforcement.setConfig({ data: { token: token } });
      if (typeof window.arkoseEnforcement.run === 'function') window.arkoseEnforcement.run();
      done.push('arkoseEnforcement.setConfig');
    }
  } catch (e) {}
  try {
    if (window.__ARKOSE__ && window.__ARKOSE__.setToken) {
      window.__ARKOSE__.setToken(token); done.push('__ARKOSE__.setToken');
    }
  } catch (e) {}

  // 4. Колбэки, которые IG регистрирует глобально
  ['arkoseEnforcementLoadCallback', 'funCaptchaLoadCallback'].forEach(fn => {
    try { if (typeof window[fn] === 'function') { window[fn](token); done.push(fn); } } catch (e) {}
  });

  return done;
}
"""


class ArkoseSolver:
    """
    Детект iframe Arkose Labs -> перехват sitekey/public_key -> решение через
    CapMonster Cloud или 2Captcha -> инжект токена в форму.
    """

    FUNCAPTCHA_SELECTORS = (
        'iframe[src*="arkoselabs"]',
        'iframe[src*="funcaptcha"]',
        'iframe[src*="fc_assets"]',
        '[data-testid="challenge"]',
        'div[class*="FunCaptcha"]',
    )

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.solved = 0
        self.failed = 0

    # -- detection ----------------------------------------------------------
    async def is_present(self, page: Page, timeout_ms: int = 4000) -> bool:
        """Быстрая проверка: есть ли Arkose-iframe/челлендж на странице."""
        with contextlib.suppress(PWTimeout, PWError):
            await page.locator(", ".join(self.FUNCAPTCHA_SELECTORS)) \
                .first.wait_for(state="visible", timeout=timeout_ms)
            return True
        if "challenge" in page.url.lower() or "arkose" in page.url.lower():
            return True
        return False

    async def probe(self, page: Page) -> dict[str, Any]:
        """Собираем sitekey / surl / blob со страницы и из всех frame'ов."""
        info: dict[str, Any] = {}
        try:
            info = await page.evaluate(ARKOSE_PROBE_JS)
        except PWError as exc:
            log.warning("[arkose] probe в main frame упал: %s", exc)

        # добираем параметры из дочерних frame'ов Arkose
        for fr in page.frames:
            if not re.search(r"arkoselabs|funcaptcha|fc_assets", fr.url or ""):
                continue
            try:
                sub = await fr.evaluate(ARKOSE_PROBE_JS)
            except PWError:
                continue
            if not info.get("sitekey") and sub.get("sitekey"):
                info["sitekey"] = sub["sitekey"]
                info.setdefault("sources", []).append("frame:" + fr.url[:80])
            info.setdefault("surl", None)
            info["surl"] = info.get("surl") or sub.get("surl")
            info.setdefault("blobs", []).extend(sub.get("blobs", []))

        if info.get("sitekey"):
            log.info(
                "[arkose] sitekey=%s surl=%s sources=%s blobs=%s",
                info["sitekey"],
                info.get("surl"),
                info.get("sources"),
                len(info.get("blobs") or []),
            )
        else:
            log.warning("[arkose] sitekey не найден. iframes=%s", info.get("iframes"))
        return info

    # -- solving ------------------------------------------------------------
    async def solve(self, page: Page) -> str:
        """
        Полный цикл обхода FunCaptcha. Возвращает токен решения.
        Бросает CaptchaRequiredError, если решить не удалось.
        """
        if not self.cfg.CAPTCHA_API_KEY:
            raise CaptchaRequiredError("CAPTCHA_API_KEY не задан — Arkose не решить")

        info = await self.probe(page)
        sitekey = info.get("sitekey")
        if not sitekey:
            raise CaptchaRequiredError(
                "Arkose присутствует, но sitekey не перехвачен "
                f"(iframes={info.get('iframes')})"
            )

        blob = (info.get("blobs") or [None])[0]
        surl = info.get("surl") or "https://client-api.arkoselabs.com"

        log.info("[arkose] отправляю задачу в %s (sitekey=%s)",
                 self.cfg.CAPTCHA_PROVIDER, sitekey)

        async with aiohttp.ClientSession() as session:
            if self.cfg.CAPTCHA_PROVIDER == "capmonster":
                token = await self._capmonster(session, page.url, sitekey, surl, blob)
            elif self.cfg.CAPTCHA_PROVIDER == "everyinfra":
                token = await self._everyinfra(session, page.url, sitekey, surl, blob)
            elif self.cfg.CAPTCHA_PROVIDER == "voidcaptcha":
                token = await self._void_funcaptcha(session, page.url, sitekey,
                                                    surl, blob)
            else:
                token = await self._twocaptcha(session, page.url, sitekey, surl, blob)

        if not token:
            self.failed += 1
            raise CaptchaRequiredError(f"{self.cfg.CAPTCHA_PROVIDER} не вернул токен")

        self.solved += 1
        log.info("[arkose] токен получен (%s симв.) — внедряю в форму", len(token))
        return token

    async def inject(self, page: Page, token: str) -> list[str]:
        """Внедряем токен во все известные поля + в enforcement-объект."""
        injected: list[str] = []
        try:
            injected = await page.evaluate(ARKOSE_INJECT_JS, token) or []
        except PWError as exc:
            log.error("[arkose] инжект в main frame упал: %s", exc)
        for fr in page.frames:
            if re.search(r"arkoselabs|funcaptcha|fc_assets", fr.url or ""):
                with contextlib.suppress(PWError):
                    injected += await fr.evaluate(ARKOSE_INJECT_JS, token) or []
        log.info("[arkose] токен внедрён в: %s", injected or ["<ничего не найдено>"])
        return injected

    async def handle(self, page: Page) -> bool:
        """
        Высокоуровневый обработчик: детект -> решение -> инжект -> submit.
        Возвращает True, если челлендж был и успешно пройден.
        """
        if not await self.is_present(page, timeout_ms=3500):
            return False
        log.warning("[arkose] обнаружен FunCaptcha челлендж на %s", page.url)
        token = await self.solve(page)
        await self.inject(page, token)
        await rnd(1.5, 3.5)

        # Жмём submit внутри челленджа, если кнопка ещё видна.
        # В текущей вёрстке Meta это div[role="button"][tabindex="0"] с текстом,
        # а не <button type="submit"> — поэтому идём от роли/текста к CSS.
        texts = ("Далее", "Next", "Отправить", "Submit", "Confirm", "Подтвердить",
                 "Continue", "Продолжить")
        clicked = False
        for text in texts:
            with contextlib.suppress(Exception):
                btn = page.get_by_role(
                    "button", name=re.compile(rf"^\s*{re.escape(text)}\s*$", re.I)
                ).first
                await btn.wait_for(state="visible", timeout=1500)
                await btn.click(timeout=8000)
                log.info("[arkose] submit челленджа: role=button «%s»", text)
                clicked = True
                break

        if not clicked:
            for sel in ('div[role="button"][tabindex="0"]', 'button[type="submit"]',
                        'input[type="submit"]', '[data-testid="challenge-submit"]',
                        'div[role="button"]', 'button'):
                with contextlib.suppress(PWTimeout, PWError):
                    loc = page.locator(sel)
                    n = await loc.count()
                    for i in range(min(n, 10)):
                        el = loc.nth(i)
                        with contextlib.suppress(Exception):
                            if await el.is_visible():
                                await el.click(timeout=5000)
                                log.info("[arkose] submit челленджа: %s #%s", sel, i)
                                clicked = True
                                break
                if clicked:
                    break

        if not clicked:
            log.warning("[arkose] кнопку submit челленджа не нашёл — жду авто-отправку")

        # Ждём, пока челлендж уйдёт
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if not await self.is_present(page, timeout_ms=1500):
                log.info("[arkose] челлендж пройден")
                return True
            await asyncio.sleep(2)
        raise CaptchaRequiredError("токен внедрён, но челлендж не исчез за 45 сек")

    # -- VoidCaptcha --------------------------------------------------------
    def _proxy_line(self) -> str:
        """cfg.PROXY -> host:port:user:pass (формат прокси VoidCaptcha)."""
        raw = (self.cfg.PROXY or "").strip()
        m = re.match(r"https?://(?:(?P<u>[^:]+):(?P<p>[^@]+)@)?(?P<host>[^/]+)", raw)
        if not m:
            return ""
        if m.group("u"):
            return f"{m.group('host')}:{m.group('u')}:{m.group('p')}"
        return m.group("host")

    async def _void_call(self, session: aiohttp.ClientSession,
                         task: dict[str, Any]) -> dict[str, Any]:
        """Синхронный POST /v1/getResult: держим соединение до решения."""
        payload = {"clientKey": self.cfg.CAPTCHA_API_KEY, "task": task}
        async with session.post(
            f"{self.cfg.VOIDCAPTCHA_HOST}/v1/getResult",
            json=payload,
            timeout=aiohttp.ClientTimeout(total=self.cfg.CAPTCHA_TIMEOUT),
        ) as r:
            text = await r.text(errors="ignore")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise CaptchaRequiredError(
                f"voidcaptcha не-JSON (HTTP {r.status}): {text[:200]}") from None
        if data.get("errorId"):
            raise CaptchaRequiredError(
                f"voidcaptcha {data.get('errorCode')}: {data.get('errorDescription')}"
                f" (retry={data.get('retry')})")
        log.info("[void] решено за %sms, cost=%s, баланс=%s",
                 data.get("elapsedMs"), data.get("cost"), data.get("balance"))
        return data.get("solution") or {}

    async def _void_funcaptcha(self, session: aiohttp.ClientSession,
                               page_url: str, sitekey: str, surl: str,
                               blob: str | None) -> str:
        host = re.sub(r"^https?://", "", surl or "").split("/")[0] \
            or "client-api.arkoselabs.com"
        task: dict[str, Any] = {
            "type": "FunCaptcha_Image",
            "url": page_url,
            "site_key": sitekey,
            "JSdomain": host,
        }
        if blob:
            task["blob"] = blob
        proxy = self._proxy_line()
        if proxy:
            task["proxy"] = proxy
        sol = await self._void_call(session, task)
        return sol.get("token", "")

    async def _void_recaptcha(self, session: aiohttp.ClientSession,
                              page_url: str, sitekey: str,
                              enterprise: bool) -> str:
        task: dict[str, Any] = {
            "type": ("ReCaptchaV2EnterpriseProxyless" if enterprise
                     else "ReCaptchaV2Proxyless"),
            "url": page_url,
            "site_key": sitekey,
        }
        proxy = self._proxy_line()
        if proxy:
            task["proxy"] = proxy
        sol = await self._void_call(session, task)
        return sol.get("token", "")

    # -- CapMonster ---------------------------------------------------------
    async def _capmonster(
        self,
        session: aiohttp.ClientSession,
        page_url: str,
        sitekey: str,
        surl: str,
        blob: str | None,
    ) -> str:
        task: dict[str, Any] = {
            "type": "FunCaptchaTaskProxyless",
            "websiteURL": page_url,
            "websitePublicKey": sitekey,
            "funcaptchaApiJSSubdomain": surl,
        }
        if blob:
            task["funcaptchaBlob"] = blob

        async with session.post(
            f"{self.cfg.CAPMONSTER_HOST}/createTask",
            json={"clientKey": self.cfg.CAPTCHA_API_KEY, "task": task},
            timeout=aiohttp.ClientTimeout(total=60),
        ) as r:
            data = await r.json(content_type=None)
        if data.get("errorId"):
            raise CaptchaRequiredError(
                f"CapMonster createTask: {data.get('errorCode')} {data.get('errorDescription')}"
            )
        task_id = data["taskId"]
        log.debug("[capmonster] taskId=%s", task_id)

        deadline = time.monotonic() + self.cfg.CAPTCHA_TIMEOUT
        while time.monotonic() < deadline:
            await asyncio.sleep(5)
            async with session.post(
                f"{self.cfg.CAPMONSTER_HOST}/getTaskResult",
                json={"clientKey": self.cfg.CAPTCHA_API_KEY, "taskId": task_id},
                timeout=aiohttp.ClientTimeout(total=60),
            ) as r:
                res = await r.json(content_type=None)
            st = res.get("status")
            log.debug("[capmonster] status=%s", st)
            if st == "ready":
                return res["solution"].get("token", "")
            if res.get("errorId"):
                raise CaptchaRequiredError(
                    f"CapMonster getTaskResult: {res.get('errorDescription')}"
                )
        raise CaptchaRequiredError(f"CapMonster не решил задачу за {self.cfg.CAPTCHA_TIMEOUT} сек")

    # -- 2Captcha -----------------------------------------------------------
    async def _twocaptcha(
        self,
        session: aiohttp.ClientSession,
        page_url: str,
        sitekey: str,
        surl: str,
        blob: str | None,
    ) -> str:
        task: dict[str, Any] = {
            "type": "FunCaptchaTaskProxyless",
            "websiteURL": page_url,
            "websitePublicKey": sitekey,
            "funcaptchaApiJSSubdomain": surl,
        }
        if blob:
            task["funcaptchaBlob"] = blob

        async with session.post(
            f"{self.cfg.TWOCAPTCHA_HOST}/createTask",
            json={"clientKey": self.cfg.CAPTCHA_API_KEY, "task": task},
            timeout=aiohttp.ClientTimeout(total=60),
        ) as r:
            data = await r.json(content_type=None)
        if data.get("errorId"):
            raise CaptchaRequiredError(
                f"2Captcha createTask: {data.get('errorCode')} {data.get('errorDescription')}"
            )
        task_id = data["taskId"]
        log.debug("[2captcha] taskId=%s", task_id)

        deadline = time.monotonic() + self.cfg.CAPTCHA_TIMEOUT
        while time.monotonic() < deadline:
            await asyncio.sleep(6)
            async with session.post(
                f"{self.cfg.TWOCAPTCHA_HOST}/getTaskResult",
                json={"clientKey": self.cfg.CAPTCHA_API_KEY, "taskId": task_id},
                timeout=aiohttp.ClientTimeout(total=60),
            ) as r:
                res = await r.json(content_type=None)
            st = res.get("status")
            log.debug("[2captcha] status=%s", st)
            if st == "ready":
                return res["solution"].get("token", "")
            if res.get("errorId"):
                raise CaptchaRequiredError(
                    f"2Captcha getTaskResult: {res.get('errorDescription')}"
                )
        raise CaptchaRequiredError(f"2Captcha не решил задачу за {self.cfg.CAPTCHA_TIMEOUT} сек")

    # -- EveryInfra (EverySolve) --------------------------------------------
    async def _everyinfra(
        self,
        session: aiohttp.ClientSession,
        page_url: str,
        sitekey: str,
        surl: str,
        blob: str | None,
    ) -> str:
        """
        EveryInfra EverySolve: синхронный POST /api/v1/captcha, type=funcaptcha.

        Тело запроса по их каталогу (/api/v1/captcha/types):
          website_url  — полный URL страницы с капчой        (обязательно)
          website_key  — sitekey / data-pkey                  (обязательно)
          api_subdomain— хост api.js Arkose (surl), если не дефолтный
          blob         — data[blob] из запроса /fc/gt2/public_key/<key>
        Ответ: {"type":"funcaptcha","solution":{"token":...},"token":...,"billing":{...}}
        Тарификация только за успешное решение.
        """
        payload: dict[str, Any] = {
            "type": "funcaptcha",
            "website_url": page_url,
            "website_key": sitekey,
        }
        # surl передаём как хост или полный URL — Their API ждёт имя хоста
        if surl:
            host = re.sub(r"^https?://", "", surl).split("/")[0]
            if host and host != "client-api.arkoselabs.com":
                payload["api_subdomain"] = host
            elif host:
                payload["api_subdomain"] = host
        if blob:
            payload["blob"] = blob

        headers = {
            "Authorization": f"Bearer {self.cfg.CAPTCHA_API_KEY}",
            "Content-Type": "application/json",
        }
        url = f"{self.cfg.EVERYINFRA_HOST}/api/v1/captcha"
        log.debug("[everyinfra] POST %s payload=%s", url,
                  {k: (v[:40] + "…" if isinstance(v, str) and len(v) > 40 else v)
                   for k, v in payload.items()})

        try:
            async with session.post(
                url, json=payload, headers=headers,
                timeout=aiohttp.ClientTimeout(total=self.cfg.CAPTCHA_TIMEOUT),
            ) as r:
                text = await r.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            raise CaptchaRequiredError(f"EveryInfra недоступен: {exc}") from exc

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise CaptchaRequiredError(
                f"EveryInfra вернул не-JSON (HTTP {r.status}): {text[:200]}"
            ) from None

        billing = data.get("billing") or {}
        if billing:
            log.info("[everyinfra] billing: charged=%s $%s, остаток $%s",
                     billing.get("charged"), billing.get("charged_usd"),
                     billing.get("balance_after_usd"))

        token = data.get("token") or (data.get("solution") or {}).get("token")
        if r.status >= 400 or not token:
            raise CaptchaRequiredError(
                f"EveryInfra не решил задачу: HTTP {r.status} {text[:300]}"
            )
        return token

    # -- reCAPTCHA (гейт «Confirm you're human») ----------------------------
    RECAPTCHA_SELECTORS = (
        'iframe[src*="recaptcha/api2/anchor"]',
        'iframe[src*="recaptcha/enterprise/anchor"]',
        'iframe[title*="reCAPTCHA" i]',
        'div.g-recaptcha',
        'div[data-sitekey]',
        'textarea[name="g-recaptcha-response"]',
    )

    async def is_recaptcha_present(self, page: Page, timeout_ms: int = 1500) -> bool:
        with contextlib.suppress(PWTimeout, PWError):
            await page.locator(", ".join(self.RECAPTCHA_SELECTORS)) \
                .first.wait_for(state="attached", timeout=timeout_ms)
            return True
        return False

    async def probe_recaptcha(self, page: Page) -> dict[str, Any]:
        """Достаём sitekey (data-sitekey или параметр k= у iframe) + признак enterprise."""
        info: dict[str, Any] = {}
        try:
            info = await page.evaluate(RECAPTCHA_PROBE_JS) or {}
        except PWError as exc:
            log.warning("[recaptcha] probe упал: %s", exc)
        for fr in page.frames:
            if "recaptcha" not in (fr.url or ""):
                continue
            if info.get("sitekey"):
                break
            with contextlib.suppress(PWError):
                sub = await fr.evaluate(RECAPTCHA_PROBE_JS) or {}
            if sub.get("sitekey"):
                info["sitekey"] = sub["sitekey"]
                info["enterprise"] = info.get("enterprise") or sub.get("enterprise")
        return info

    async def solve_recaptcha(self, page: Page) -> str:
        """Решение reCAPTCHA v2 (в т.ч. enterprise) через выбранный провайдер."""
        if not self.cfg.CAPTCHA_API_KEY:
            raise CaptchaRequiredError("CAPTCHA_API_KEY не задан — reCAPTCHA не решить")
        info = await self.probe_recaptcha(page)
        sitekey = info.get("sitekey")
        if not sitekey:
            raise CaptchaRequiredError("reCAPTCHA есть, но sitekey не найден")
        enterprise = bool(info.get("enterprise"))
        log.warning("[recaptcha] челлендж на %s (sitekey=%s enterprise=%s) -> %s",
                    page.url[:70], sitekey, enterprise, self.cfg.CAPTCHA_PROVIDER)

        async with aiohttp.ClientSession() as session:
            if self.cfg.CAPTCHA_PROVIDER == "everyinfra":
                token = await self._everyinfra_recaptcha(session, page.url, sitekey,
                                                         enterprise)
            elif self.cfg.CAPTCHA_PROVIDER == "voidcaptcha":
                token = await self._void_recaptcha(session, page.url, sitekey,
                                                   enterprise)
            else:
                token = await self._task_recaptcha(session, page.url, sitekey, enterprise)
        if not token:
            self.failed += 1
            raise CaptchaRequiredError("провайдер не вернул токен reCAPTCHA")
        self.solved += 1
        return token

    async def _task_recaptcha(self, session: aiohttp.ClientSession, page_url: str,
                              sitekey: str, enterprise: bool) -> str:
        """createTask/getTaskResult у CapMonster или 2Captcha."""
        host = (self.cfg.CAPMONSTER_HOST if self.cfg.CAPTCHA_PROVIDER == "capmonster"
                else self.cfg.TWOCAPTCHA_HOST)
        task_type = ("RecaptchaV2EnterpriseTaskProxyless" if enterprise
                     else "RecaptchaV2TaskProxyless")
        async with session.post(
            f"{host}/createTask",
            json={"clientKey": self.cfg.CAPTCHA_API_KEY,
                  "task": {"type": task_type, "websiteURL": page_url,
                           "websiteKey": sitekey}},
            timeout=aiohttp.ClientTimeout(total=60),
        ) as r:
            data = await r.json(content_type=None)
        if data.get("errorId"):
            raise CaptchaRequiredError(
                f"{self.cfg.CAPTCHA_PROVIDER} createTask: {data.get('errorDescription')}")
        task_id = data["taskId"]
        deadline = time.monotonic() + self.cfg.CAPTCHA_TIMEOUT
        while time.monotonic() < deadline:
            await asyncio.sleep(5)
            async with session.post(
                f"{host}/getTaskResult",
                json={"clientKey": self.cfg.CAPTCHA_API_KEY, "taskId": task_id},
                timeout=aiohttp.ClientTimeout(total=60),
            ) as r:
                res = await r.json(content_type=None)
            if res.get("status") == "ready":
                return res.get("solution", {}).get("gRecaptchaResponse", "")
            if res.get("errorId"):
                raise CaptchaRequiredError(
                    f"{self.cfg.CAPTCHA_PROVIDER} getTaskResult: {res.get('errorDescription')}")
        raise CaptchaRequiredError("reCAPTCHA не решена за отведённое время")

    async def _everyinfra_recaptcha(self, session: aiohttp.ClientSession,
                                    page_url: str, sitekey: str,
                                    enterprise: bool) -> str:
        payload = {
            "type": "recaptcha_v2_enterprise" if enterprise else "recaptcha_v2",
            "website_url": page_url,
            "website_key": sitekey,
        }
        async with session.post(
            f"{self.cfg.EVERYINFRA_HOST}/api/v1/captcha",
            json=payload,
            headers={"Authorization": f"Bearer {self.cfg.CAPTCHA_API_KEY}",
                     "Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=self.cfg.CAPTCHA_TIMEOUT),
        ) as r:
            text = await r.text(errors="ignore")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            raise CaptchaRequiredError(
                f"EveryInfra вернул не-JSON (HTTP {r.status}): {text[:200]}") from None
        billing = data.get("billing") or {}
        if billing:
            log.info("[everyinfra] billing: charged=$%s, остаток $%s",
                     billing.get("charged_usd"), billing.get("balance_after_usd"))
        token = data.get("token") or (data.get("solution") or {}).get("token")
        if r.status >= 400 or not token:
            raise CaptchaRequiredError(
                f"EveryInfra не решил reCAPTCHA: HTTP {r.status} {text[:300]}")
        return token

    async def inject_recaptcha(self, page: Page, token: str) -> list[str]:
        done: list[str] = []
        for frame in [page, *page.frames]:
            with contextlib.suppress(PWError):
                done += await frame.evaluate(RECAPTCHA_INJECT_JS, token) or []
        log.info("[recaptcha] токен внедрён: %s", done or ["<поля не найдены>"])
        return done

    async def handle_recaptcha(self, page: Page) -> bool:
        """Полный цикл reCAPTCHA: детект -> решение -> инжект -> submit -> ожидание."""
        if not await self.is_recaptcha_present(page, timeout_ms=2500):
            return False
        token = await self.solve_recaptcha(page)
        await self.inject_recaptcha(page, token)
        await rnd(1.0, 2.5)
        for text in ("Continue", "Продолжить", "Submit", "Next", "Далее",
                     "Verify", "Подтвердить"):
            with contextlib.suppress(Exception):
                btn = page.get_by_role(
                    "button", name=re.compile(rf"^\s*{re.escape(text)}\s*$", re.I)
                ).first
                if await btn.count() and await btn.is_visible():
                    await btn.click(timeout=8000)
                    break
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if not await self.is_recaptcha_present(page, timeout_ms=1200):
                return True
            await asyncio.sleep(2)
        return False


#: поиск sitekey reCAPTCHA (data-sitekey, k= во frame, grecaptcha.enterprise)
RECAPTCHA_PROBE_JS = """
() => {
  const out = {};
  const el = document.querySelector('[data-sitekey]');
  if (el) out.sitekey = el.getAttribute('data-sitekey');
  if (!out.sitekey) {
    for (const f of document.querySelectorAll('iframe[src]')) {
      const m = /[?&]k=([^&#]+)/.exec(f.src);
      if (m && /recaptcha/.test(f.src)) { out.sitekey = decodeURIComponent(m[1]); break; }
    }
  }
  out.enterprise = Array.from(document.scripts).some(s =>
    (s.src || '').includes('recaptcha/enterprise'));
  return out;
}
"""

#: проставляем токен в скрытые поля и во все зарегистрированные колбэки
RECAPTCHA_INJECT_JS = """
(token) => {
  const done = [];
  document.querySelectorAll(
    'textarea[name="g-recaptcha-response"], input[name="g-recaptcha-response"], '
    + '#g-recaptcha-response'
  ).forEach(el => { el.value = token; el.innerHTML = token; done.push(el.name || el.id); });
  try {
    const cfg = window.___grecaptcha_cfg;
    if (cfg && cfg.clients) {
      for (const key in cfg.clients) {
        const c = cfg.clients[key];
        if (c && typeof c.callback === 'function') { c.callback(token); done.push('callback'); }
      }
    }
  } catch (e) {}
  return done;
}
"""


async def human_click_force(page: Page, el: Any) -> bool:
    """Клик по элементу web-blocks: DOM-клик, затем force, затем координаты."""
    for how in ("dom", "force", "mouse"):
        with contextlib.suppress(Exception):
            if how == "dom":
                await el.evaluate("e => e.click()")
            elif how == "force":
                await el.click(force=True, timeout=5000)
            else:
                box = await el.bounding_box()
                if not box:
                    continue
                await page.mouse.click(box["x"] + box["width"] / 2,
                                       box["y"] + box["height"] / 2)
            return True
    return False


# ===========================================================================
# 3a. ЧЕЛОВЕЧЕСКИЙ ГЕЙТ — HumanGate
# ===========================================================================


class HumanGate:
    """
    Гейт «Confirm you're human to use your profile» (/accounts/suspended).

    Свежий аккаунт после выдачи sessionid почти всегда попадает сюда. Если
    гейт не пройти, профиль остаётся недоступным (web_profile_info -> 404),
    а аккаунт уходит в suspended навсегда. Поэтому гейт — обязательный шаг
    сразу после регистрации, ДО любой активности.

    Порядок: Continue -> (cookie-баннер) -> Arkose / reCAPTCHA / код на почту
    -> ожидание выхода с /accounts/suspended. До GATE_MAX_ROUNDS попыток.
    """

    URL_RE = re.compile(r"/accounts/suspended|/challenge|/checkpoint", re.I)

    TEXT_MARKERS = (
        "confirm you're human", "confirm you’re human",
        "confirm you`re human", "подтвердите, что вы человек",
        "takes about 30 seconds", "займёт около 30 секунд",
        "help us confirm you're human", "проверка, что вы человек",
    )

    CONTINUE_TEXTS = ("Continue", "Продолжить", "Confirm", "Подтвердить",
                      "Next", "Далее", "Verify", "Пройти проверку", "Начать")

    COOKIE_TEXTS = ("Allow all cookies", "Allow essential and optional cookies",
                    "Разрешить все cookie", "Только необходимые cookie",
                    "Accept", "Принять", "Accept all")

    CODE_LABEL_RE = re.compile(r"(code|код|confirmation|подтвержд)", re.I)

    #: терминальное состояние: апелляция отправлена, решение придёт позже
    APPEAL_MARKERS = ("you submitted an appeal", "we'll take another look",
                      "апелляц", "рассмотр")

    #: финальный шаг гейта — загрузка селфи
    SELFIE_MARKERS = ("verification selfie",
                      "upload a photo that clearly shows your face",
                      "селфи", "upload a photo")

    #: шаг «Enter your mobile number» (после капчи гейт просит номер)
    PHONE_FIELD = 'input#phone, input[type="tel"][placeholder*="phone" i], ' \
                  'input[type="tel"]'

    #: текстовая капча Meta: картинка /captcha/tfbimage + textarea под неё
    IMAGE_CAPTCHA_IMG = 'img[src*="/captcha/tfbimage"]'
    IMAGE_CAPTCHA_FIELD = 'textarea[placeholder*="code from the image" i], ' \
                          'textarea[placeholder*="код с картинки" i]'

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        #: до какого момента не дёргать платную капчу (402 «нет баланса»)
        self._captcha_broken_until = 0.0
        self._ocr_engine: Any = None
        self._ocr_engine_v1: Any = None

    def captcha_available(self) -> bool:
        return time.monotonic() >= self._captcha_broken_until

    # -- детект -------------------------------------------------------------
    async def is_gate(self, page: Page, timeout_ms: int = 0) -> bool:
        if self.URL_RE.search(page.url or "") and "emailsignup" not in page.url:
            return True
        if timeout_ms:
            await asyncio.sleep(min(timeout_ms, 5000) / 1000)
        with contextlib.suppress(PWError):
            body = (await page.locator("body").inner_text(timeout=6000)).lower()
            if any(m in body for m in self.TEXT_MARKERS):
                return True
        return False

    # -- вспомогательное ----------------------------------------------------
    async def _dump(self, page: Page, tag: str) -> None:
        try:
            d = Path("debug")
            d.mkdir(parents=True, exist_ok=True)
            stamp = f"{tag}_{now_stamp()}"
            with contextlib.suppress(Exception):
                (d / f"{stamp}.html").write_text(await page.content(), encoding="utf-8")
            with contextlib.suppress(Exception):
                await page.screenshot(path=str(d / f"{stamp}.png"))
            log.error("[gate] дамп: debug/%s.html (url=%s)", stamp, page.url)
        except Exception as exc:  # noqa: BLE001
            log.debug("[gate] дамп не сохранён: %s", exc)

    async def _safe_click(self, page: Page, el: Any, human: HumanDriver,
                          label: str) -> bool:
        """
        Клик по элементу гейта с деградацией способов.

        Гейт Meta — web-blocks: у кнопки pointer-events:auto, но у её родителя
        pointer-events:none, поэтому обычный Playwright-клик ругается на
        перехват и падает по таймауту. force/dispatch — рабочие фолбэки.
        """
        try:
            await human.human_click(el, label=label)
            return True
        except Exception as exc:  # noqa: BLE001
            log.info("[gate] обычный клик не прошёл (%s): %s",
                     type(exc).__name__, str(exc).splitlines()[0][:140])

        # клик мышью по координатам: Playwright не проверяет перекрытие
        with contextlib.suppress(Exception):
            box = await el.bounding_box()
            if box and box["width"] and box["height"]:
                await page.mouse.click(box["x"] + box["width"] / 2,
                                       box["y"] + box["height"] / 2)
                log.info("[gate] клик по координатам: %s", label)
                return True

        # JS-клик: срабатывает даже когда координаты/перекрытие мешают
        with contextlib.suppress(Exception):
            await el.evaluate("e => e.click()")
            log.info("[gate] клик через DOM .click(): %s", label)
            return True
        # поиск узла по тексту напрямую в DOM (локатор мог отвалиться)
        with contextlib.suppress(Exception):
            if await self._dom_click_text(page, label.rsplit(":", 1)[-1]):
                log.info("[gate] клик по тексту через DOM: %s", label)
                return True
        for kwargs in ({"force": True, "timeout": 5000}, {"timeout": 5000}):
            with contextlib.suppress(Exception):
                await el.click(**kwargs)
                log.info("[gate] клик с обходом (%s): %s", kwargs, label)
                return True
        with contextlib.suppress(Exception):
            await el.dispatch_event("click")
            log.info("[gate] dispatch_event: %s", label)
            return True
        log.warning("[gate] элемент не кликается никак: %s", label)
        return False

    async def _dom_click_text(self, page: Page, text: str) -> bool:
        """Клик по кнопке по её тексту целиком внутри страницы (без локатора)."""
        if not text or len(text) > 30:
            return False
        return bool(await page.evaluate("""(t) => {
            const want = t.trim().toLowerCase();
            const nodes = [...document.querySelectorAll(
                'div[role="button"], button, [role="button"], [role="link"]')];
            const el = nodes.find(n => (n.innerText || '').trim().toLowerCase() === want);
            if (!el) return false;
            el.click();
            return true;
        }""", text))

    async def _click_any(self, page: Page, human: HumanDriver,
                         texts: tuple[str, ...], label: str) -> bool:
        for text in texts:
            # a11y-имя может быть длиннее подписи («Confirm you're human …»),
            # поэтому сначала подстрочный regex, а не точное равенство
            with contextlib.suppress(Exception):
                btn = page.get_by_role(
                    "button", name=re.compile(re.escape(text), re.I)).first
                if await btn.count() and await btn.is_visible():
                    if await self._safe_click(page, btn, human, f"{label}:{text}"):
                        return True

        for text in texts:
            with contextlib.suppress(PWError, PWTimeout):
                loc = page.locator(f'div[role="button"]:has-text("{text}"), '
                                   f'[role="link"]:has-text("{text}"), '
                                   f'button:has-text("{text}")')
                for i in range(min(await loc.count(), 8)):
                    el = loc.nth(i)
                    with contextlib.suppress(Exception):
                        if await el.is_visible():
                            if await self._safe_click(page, el, human, f"{label}:css"):
                                return True

        # точное совпадение inner_text (старая вёрстка div[role=button])
        with contextlib.suppress(PWError, PWTimeout):
            loc = page.locator('div[role="button"][tabindex="0"], div[role="button"]')
            for i in range(min(await loc.count(), 25)):
                el = loc.nth(i)
                with contextlib.suppress(Exception):
                    txt = (await el.inner_text(timeout=800)).strip().lower()
                    if txt and any(txt == t.lower() for t in texts):
                        if await self._safe_click(page, el, human, f"{label}:exact"):
                            return True
        return False

    async def _stuck_state(self, page: Page) -> bool:
        """Ни Continue, ни капчи, ни полей — шаг «висит», поможет перезагрузка."""
        if await self._code_input(page) is not None:
            return False
        if await self.is_phone_prompt(page):
            return False
        if await self.is_selfie_prompt(page):
            return False
        if await self._gate_ready(page):
            return False
        return True

    async def _gate_ready(self, page: Page) -> bool:
        """Гейт отрисован: есть Continue-кнопка или вложенная капча."""
        with contextlib.suppress(Exception):
            btn = page.get_by_role(
                "button", name=re.compile("continue|продолжить|confirm", re.I)).first
            if await btn.count() and await btn.is_visible():
                return True
        with contextlib.suppress(Exception):
            if await page.locator('textarea[name="g-recaptcha-response"], '
                                  '[data-sitekey]').count():
                return True
        with contextlib.suppress(Exception):
            if await page.locator(self.IMAGE_CAPTCHA_FIELD).count():
                return True
        return False

    async def is_image_captcha(self, page: Page) -> bool:
        with contextlib.suppress(Exception):
            if await page.locator(self.IMAGE_CAPTCHA_FIELD).count():
                return True
        return False

    def _ocr_local(self, data: bytes) -> str:
        """
        Бесплатный офлайн-фолбэк: ddddocr.

        Капча Meta — ровно 6 цифр, поэтому гоняем beta-модель (она точнее на
        искажениях), чистим не-цифры и при недоборе сверяемся с обычной
        моделью — вариант из 6 цифр выигрывает.
        """
        try:
            import ddddocr  # noqa: PLC0415 — тяжёлый импорт только по факту
        except ImportError:
            raise CaptchaRequiredError("ddddocr не установлен — локальный OCR недоступен")

        # предобработка: серая шкала + апскейл x3 + автоконтраст заметно
        # поднимают читаемость искажённых цифр
        with contextlib.suppress(Exception):
            import io  # noqa: PLC0415
            from PIL import Image, ImageOps  # noqa: PLC0415
            img = Image.open(io.BytesIO(data)).convert("L")
            img = img.resize((img.width * 3, img.height * 3), Image.LANCZOS)
            img = ImageOps.autocontrast(img)
            buf = io.BytesIO()
            img.save(buf, "PNG")
            data = buf.getvalue()

        def digits(raw: str) -> str:
            return re.sub(r"\D", "", raw or "")

        if not self._ocr_engine:
            self._ocr_engine = ddddocr.DdddOcr(show_ad=False, beta=True)
        beta = digits(self._ocr_engine.classification(data))
        if len(beta) == 6:
            return beta
        if not getattr(self, "_ocr_engine_v1", None):
            self._ocr_engine_v1 = ddddocr.DdddOcr(show_ad=False)
        plain = digits(self._ocr_engine_v1.classification(data))
        log.debug("[captcha] ocr beta=%r plain=%r", beta, plain)
        if len(plain) == 6:
            return plain
        return beta or plain

    async def _recognize_image(self, page: Page, img: Any) -> str:
        """
        Байты капчи берём скриншотом элемента: прямой GET к
        facebook.com/captcha/tfbimage отдаёт 302/400 без нужных кук, а движок
        уже нарисовал картинку — снимок локальный и CORS не мешает.
        """
        # ждём фактической загрузки (иначе screenshot = пустая рамка 1x1)
        with contextlib.suppress(Exception):
            await img.scroll_into_view_if_needed(timeout=5000)
        data = b""
        for _ in range(20):
            with contextlib.suppress(Exception):
                if await img.evaluate("e => e.complete && e.naturalWidth > 60"):
                    data = await img.screenshot(type="png")
                    if len(data) > 2000:
                        break
            await asyncio.sleep(0.7)
        if not data:
            data = await img.screenshot(type="png")
        log.info("[captcha] снимок капчи: %s байт", len(data))
        if len(data) < 500:
            raise CaptchaRequiredError(f"снимок капчи пустой ({len(data)} байт)")

        if self.captcha_available() and self.cfg.CAPTCHA_API_KEY:
            provider = self.cfg.CAPTCHA_PROVIDER
            try:
                if provider == "everyinfra":
                    return await self._service_image(data)
                return await self._service_image(data)
            except CaptchaRequiredError as exc:
                log.warning("[captcha] сервис не дал ответ (%s) — пробую ddddocr",
                            str(exc)[:80])

        answer = await asyncio.to_thread(self._ocr_local, data)
        log.info("[captcha] ddddocr: %r", answer)
        if not answer:
            raise CaptchaRequiredError("капча-картинка не распознана локально")
        return answer

    async def _service_image(self, data: bytes) -> str:
        b64 = base64.b64encode(data).decode()
        provider = self.cfg.CAPTCHA_PROVIDER
        log.info("[captcha] распознаю капчу через %s (%s байт b64)", provider, len(b64))
        async with aiohttp.ClientSession() as session:
            if provider == "voidcaptcha":
                async with session.post(
                    f"{self.cfg.VOIDCAPTCHA_HOST}/v1/getResult",
                    json={"clientKey": self.cfg.CAPTCHA_API_KEY,
                          "task": {"type": "ImageToTextTask", "body": b64,
                                   "numeric": 1, "minLength": 6, "maxLength": 6,
                                   "score": 0.3}},
                    timeout=aiohttp.ClientTimeout(total=90),
                ) as r:
                    text = await r.text(errors="ignore")
                try:
                    resp = json.loads(text)
                except json.JSONDecodeError:
                    raise CaptchaRequiredError(f"void не-JSON: {text[:200]}") from None
                if resp.get("errorId"):
                    raise CaptchaRequiredError(
                        f"void {resp.get('errorCode')}: "
                        f"{resp.get('errorDescription')}")
                sol = resp.get("solution") or {}
                log.info("[captcha] void: %r (уверенность %s, cost %s)",
                         sol.get("text"), sol.get("confidence"), resp.get("cost"))
                answer = sol.get("text")
                if not answer:
                    raise CaptchaRequiredError("void не вернул текст")
                return str(answer).strip()

            if provider == "everyinfra":
                async with session.post(
                    f"{self.cfg.EVERYINFRA_HOST}/api/v1/captcha",
                    json={"type": "image", "body": b64, "charset": "any"},
                    headers={"Authorization": f"Bearer {self.cfg.CAPTCHA_API_KEY}",
                             "Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=90),
                ) as r:
                    text = await r.text(errors="ignore")
                try:
                    data_json = json.loads(text)
                except json.JSONDecodeError:
                    raise CaptchaRequiredError(f"image -> не-JSON: {text[:200]}")
                answer = (data_json.get("token") or data_json.get("text")
                          or (data_json.get("solution") or {}).get("text"))
                if not answer:
                    if r.status == 402:
                        self._captcha_broken_until = time.monotonic() + 900
                        log.error("[captcha] баланса нет — 15 мин не пробую сервис")
                    raise CaptchaRequiredError(f"HTTP {r.status} {text[:120]}")
                return str(answer).strip()

            host = (self.cfg.CAPMONSTER_HOST if provider == "capmonster"
                    else self.cfg.TWOCAPTCHA_HOST)
            async with session.post(
                f"{host}/createTask",
                json={"clientKey": self.cfg.CAPTCHA_API_KEY,
                      "task": {"type": "ImageToTextTask", "body": b64}},
                timeout=aiohttp.ClientTimeout(total=60),
            ) as r:
                task = await r.json(content_type=None)
            if task.get("errorId"):
                raise CaptchaRequiredError(str(task.get("errorDescription")))
            deadline = time.monotonic() + 60
            answer = ""
            while time.monotonic() < deadline and not answer:
                await asyncio.sleep(4)
                async with session.post(
                    f"{host}/getTaskResult",
                    json={"clientKey": self.cfg.CAPTCHA_API_KEY,
                          "taskId": task["taskId"]},
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as r2:
                    res = await r2.json(content_type=None)
                answer = (res.get("solution") or {}).get("text", "")
            if not answer:
                raise CaptchaRequiredError("сервис не распознал картинку")
            return str(answer).strip()

    async def solve_image_captcha(self, page: Page, human: HumanDriver) -> bool:
        """
        Текстовая капча Meta «Enter the code from the image».

        До 3 попыток: вводим ответ, ждём ухода капчи; не ушла — берём новую
        картинку («Get a new code») и пробуем снова.
        """
        for attempt in range(1, 4):
            field_loc = page.locator(self.IMAGE_CAPTCHA_FIELD).first
            img = page.locator(self.IMAGE_CAPTCHA_IMG).first
            if await field_loc.count() == 0 or await img.count() == 0:
                return False
            try:
                answer = await self._recognize_image(page, img)
            except CaptchaRequiredError as exc:
                log.error("[captcha] попытка %s: %s", attempt, str(exc)[:120])
                await self._click_any(page, human, ("Get a new code", "Новый код"),
                                      "captcha-refresh")
                await asyncio.sleep(3.0)
                continue

            Path("debug").mkdir(exist_ok=True)
            with contextlib.suppress(Exception):
                (Path("debug") / f"captcha_{now_stamp()}.png").write_bytes(
                    await img.screenshot(type="png"))

            with contextlib.suppress(Exception):
                await field_loc.focus()
            with contextlib.suppress(Exception):
                await field_loc.click(force=True, timeout=5000)
            with contextlib.suppress(Exception):
                await field_loc.fill("")
            await asyncio.sleep(random.uniform(0.3, 0.7))
            with contextlib.suppress(Exception):
                await page.keyboard.type(answer, delay=random.randint(45, 120))
            value = ""
            with contextlib.suppress(Exception):
                value = await field_loc.input_value()
            if value != answer:
                with contextlib.suppress(Exception):
                    await field_loc.fill(answer)
                    value = await field_loc.input_value()
            if value != answer:
                log.warning("[captcha] в поле %r, ожидалось %r — ввожу заново",
                            value, answer)
                with contextlib.suppress(Exception):
                    await field_loc.focus()
                    await page.keyboard.type(answer, delay=60)
            await asyncio.sleep(random.uniform(0.6, 1.2))
            await self._click_any(page, human,
                                  ("Next", "Далее", "Continue", "Продолжить"),
                                  "captcha-next")

            # капча осталась? -> ответ не принят, обновляем картинку
            for _ in range(8):
                await asyncio.sleep(1.0)
                with contextlib.suppress(Exception):
                    if await page.locator(self.IMAGE_CAPTCHA_FIELD).count() == 0:
                        log.info("[captcha] капча принята (попытка %s)", attempt)
                        return True
                with contextlib.suppress(Exception):
                    if not await self.is_gate(page):
                        return True
            log.warning("[captcha] ответ %r не принят (попытка %s/3)", answer, attempt)
            with contextlib.suppress(Exception):
                await self._click_any(page, human, ("Get a new code", "Новый код"),
                                      "captcha-refresh")
            await asyncio.sleep(2.5)
        log.error("[captcha] 3 попытки не прошли")
        return False

    async def pass_code_step(self, page: Page, human: HumanDriver, field: Any,
                             sms: Any, mail: Any, session: Any,
                             box: dict[str, Any] | None, email: str | None,
                             since_ts: float) -> bool:
        """
        Ввод кода подтверждения на гейте: SMS, если номер уже арендован и
        страница говорит про SMS, иначе — код из письма.
        """
        body = ""
        with contextlib.suppress(PWError):
            body = (await page.locator("body").inner_text(timeout=4000)).lower()
        via_sms = "sms" in body or "whatsapp" in body
        act = (box or {}).get("activation")

        code = None
        if via_sms and act is not None and sms is not None:
            log.info("[gate] экран SMS-кода — жду SMS")
            try:
                code = await sms.wait_for_code(session, act)
            except Exception as exc:  # noqa: BLE001
                log.error("[gate] SMS-код не пришёл: %s", exc)
                with contextlib.suppress(Exception):
                    await sms.cancel(session, act)
                if box is not None:
                    box.pop("activation", None)
                return False
        elif via_sms and act is None:
            log.warning("[gate] экран SMS-кода без аренды — перезагружаю страницу")
            await self._click_any(page, human,
                                  ("Update mobile number", "Request new code",
                                   "Изменить номер", "Новый код"), "gate-back")
            with contextlib.suppress(PWError, PWTimeout):
                await page.reload(wait_until="domcontentloaded", timeout=60000)
            await asyncio.sleep(4.0)
            return False
        elif mail is not None and email:
            log.info("[gate] экран кода на почте — жду письмо на %s", email)
            code = await mail.wait_for_code(email, since_ts)
        if not code:
            return False

        # поле тоже в web-blocks: human_type может не пробить клик,
        # поэтому фокус + печать с клавиатуры + сверка значения
        with contextlib.suppress(Exception):
            await field.focus()
        with contextlib.suppress(Exception):
            await field.click(force=True, timeout=5000)
        await asyncio.sleep(random.uniform(0.3, 0.7))
        with contextlib.suppress(Exception):
            await page.keyboard.type(code, delay=random.randint(50, 120))
        got = ""
        with contextlib.suppress(Exception):
            got = await field.input_value()
        if got != code:
            with contextlib.suppress(Exception):
                await field.fill(code)
                got = await field.input_value()
        if got != code:
            log.error("[gate] код не лёг в поле (%r != %r)", got, code)
            return False
        await rnd(0.8, 1.8)
        await self._click_any(page, human,
                              ("Continue", "Next", "Далее", "Submit"), "gate-code")
        return True

    async def is_appeal_submitted(self, page: Page) -> bool:
        with contextlib.suppress(PWError):
            body = (await page.locator("body").inner_text(timeout=4000)).lower()
            return any(m in body for m in self.APPEAL_MARKERS)
        return False

    async def is_selfie_prompt(self, page: Page) -> bool:
        with contextlib.suppress(Exception):
            if not await page.locator('input[type="file"][accept*="image"]').count():
                return False
            body = (await page.locator("body").inner_text(timeout=4000)).lower()
        return any(m in body for m in self.SELFIE_MARKERS)

    async def pass_selfie_step(self, page: Page, human: HumanDriver) -> bool:
        """Загрузка селфи: file-input -> Submit. Без фото шаг не пройти."""
        photo = self.pick_selfie()
        if photo is None:
            log.error("[gate] гейт просит селфи, а в %s нет файлов — "
                      "положи 5-10 фото лиц", self.cfg.SELFIES_DIR)
            return False
        log.info("[gate] загружаю селфи %s", photo.name)
        with contextlib.suppress(PWError, PWTimeout):
            await page.locator('input[type="file"]').first.set_input_files(
                str(photo), timeout=20000)
        await asyncio.sleep(random.uniform(3.0, 6.0))
        if await self._click_any(page, human,
                                 ("Submit", "Next", "Continue", "Далее"),
                                 "selfie-submit"):
            log.info("[gate] селфи отправлено")
            return True
        return False

    def pick_selfie(self) -> Any:
        d = Path(self.cfg.SELFIES_DIR)
        if not d.exists():
            return None
        files = [p for p in d.rglob("*")
                 if p.suffix.lower() in (".jpg", ".jpeg", ".png", ".webp")]
        if not files:
            return None
        used_file = Path("selfies_used.txt")
        try:
            used = set(used_file.read_text(encoding="utf-8").split())
        except OSError:
            used = set()
        fresh = [p for p in files if str(p) not in used]
        # реальные фото важнее AI-лиц, мелкие (<15 КБ) — в последнюю очередь
        pool = fresh or files
        big = [p for p in pool if p.stat().st_size >= 15000]
        real = [p for p in big if "image" in p.name.lower()]
        photo = random.choice(real or big or pool)
        with contextlib.suppress(OSError):
            with open(used_file, "a", encoding="utf-8") as fh:
                fh.write(str(photo) + "\n")
        return photo

    async def is_phone_prompt(self, page: Page) -> bool:
        found = 0
        with contextlib.suppress(Exception):
            found = await page.locator(self.PHONE_FIELD).count()
        text_hit = False
        with contextlib.suppress(Exception):
            body = (await page.locator("body").inner_text(timeout=4000)).lower()
            text_hit = "enter your mobile number" in body
        log.debug("[gate] phone-prompt: поля=%s текст=%s url=%s",
                  found, text_hit, page.url[:60])
        return bool(found) or text_hit

    async def pass_phone_step(self, page: Page, human: HumanDriver,
                              sms: Any, session: Any,
                              box: dict[str, Any] | None) -> bool:
        """
        Шаг номера после капчи: арендуем номер, вводим, ждём SMS-код.

        Номер нужен именно здесь — без него гейт не закрывается, и аккаунт
        остаётся suspended даже с пройденной капчей.
        """
        if sms is None or session is None or not self.cfg.SMS_API_KEY:
            log.error("[gate] нужен номер телефона, а SMS-провайдер не настроен "
                      "(SMS_API_KEY пуст) — гейт не закрыть")
            return False

        field = page.locator(self.PHONE_FIELD).first
        if await field.count() == 0:
            return False

        act = (box or {}).get("activation")
        if act is None:
            try:
                act = await sms.buy(session)
            except Exception as exc:  # noqa: BLE001
                log.error("[gate] номер не арендован: %s", exc)
                return False
            if box is not None:
                box["activation"] = act
            log.info("[gate] арендован номер %s", act.phone)

        # на форме уже выбран код страны (+1), поэтому в поле идёт номер БЕЗ
        # него: 11-значный «19083425160» IG читает как «+1 190…» и отбивает
        number = str(act.phone).lstrip("+")
        if self.cfg.MANUAL_COUNTRY:
            with contextlib.suppress(Exception):
                await self.select_phone_country(page, human, self.cfg.MANUAL_COUNTRY)
            number = number[1:] if number.startswith("7") else number
        elif len(number) == 11 and number.startswith("1"):
            number = number[1:]
        with contextlib.suppress(Exception):
            await field.click(force=True, timeout=5000)
        with contextlib.suppress(Exception):
            await field.fill("")
        await asyncio.sleep(random.uniform(0.4, 1.0))
        # форма перерисовывается: ввод только с фокусом и обязательной сверкой
        got = ""
        for attempt in range(3):
            with contextlib.suppress(Exception):
                await field.focus()
            with contextlib.suppress(Exception):
                await field.fill("")
            await asyncio.sleep(random.uniform(0.3, 0.6))
            with contextlib.suppress(Exception):
                await page.keyboard.type(number, delay=random.randint(50, 120))
            with contextlib.suppress(Exception):
                got = await field.input_value()
            if got == number:
                break
            with contextlib.suppress(Exception):
                await field.fill(number)
                got = await field.input_value()
            if got == number:
                break
            log.warning("[gate] номер не лёг (попытка %s: %r)", attempt + 1, got)
            await asyncio.sleep(0.8)
        if got != number:
            log.error("[gate] не удалось ввести номер (%r != %r)", got, number)
            with contextlib.suppress(Exception):
                await sms.cancel(session, act)
            if box is not None:
                box.pop("activation", None)
            return False
        await asyncio.sleep(random.uniform(0.8, 1.6))
        await self._click_any(page, human,
                              ("Send code", "Send SMS", "Next", "Далее",
                               "Продолжить", "Continue"), "phone-send")

        # принимает ли IG номер: экран кода / текст «sent via SMS», либо ошибка
        accepted = False
        body = ""
        sent_markers = ("confirmation code", "we sent", "sent via sms",
                        "request new code", "код подтверждения", "мы отправили")
        # IG иногда отвечает на отправку номера почти минуту — не отменяем раньше
        for _ in range(60):
            await asyncio.sleep(1.0)
            if await self._code_input(page) is not None:
                accepted = True
                break
            with contextlib.suppress(PWError):
                body = (await page.locator("body").inner_text(timeout=4000)).lower()
            if any(m in body for m in sent_markers):
                accepted = True
                break
            if any(m in body for m in ("try again", "invalid", "can't send",
                                       "cannot send", "недействителен",
                                       "попробуйте")):
                break
        if not accepted:
            log.warning("[gate] IG не принял номер %s (текст: %r)",
                        number, body[:160])
            await self._dump(page, "phone_rejected")
            with contextlib.suppress(Exception):
                await sms.cancel(session, act)
            if box is not None:
                box.pop("activation", None)
            return False

        log.info("[gate] номер %s принят, жду SMS-код", number)
        try:
            code = await sms.wait_for_code(session, act)
        except Exception as exc:  # noqa: BLE001
            # IG часто не отправляет SMS с первого раза — пробуем повторную отправку
            log.warning("[gate] код не пришёл (%s) — жму повторную отправку", exc)
            await self._click_any(page, human,
                                  ("Send code", "Resend", "Get a new code",
                                   "Отправить код", "Отправить ещё"), "phone-resend")
            await asyncio.sleep(3.0)
            old_timeout = getattr(sms.cfg, "SMS_TIMEOUT", 180)
            try:
                setattr(sms.cfg, "SMS_TIMEOUT", 120)
                code = await sms.wait_for_code(session, act)
            except Exception as exc2:  # noqa: BLE001
                log.error("[gate] код не пришёл и после повтора: %s", exc2)
                with contextlib.suppress(Exception):
                    await sms.cancel(session, act)
                if box is not None:
                    box.pop("activation", None)
                return False
            finally:
                with contextlib.suppress(Exception):
                    setattr(sms.cfg, "SMS_TIMEOUT", old_timeout)
        if box is not None:
            box["code"] = code

        code_field = None
        for _ in range(15):
            code_field = await self._code_input(page)
            if code_field is not None:
                break
            await asyncio.sleep(1.0)
        if code_field is None:
            log.warning("[gate] поля для SMS-кода нет — возможно, шаг уже закрыт")
            return True
        await human.human_type(code_field, code)
        await asyncio.sleep(random.uniform(0.6, 1.2))
        await self._click_any(page, human,
                              ("Next", "Continue", "Далее", "Продолжить"),
                              "phone-code")
        return True

    async def select_phone_country(self, page: Page, human: HumanDriver,
                                   country: str) -> bool:
        """Меняет страну в телефонном селекторе (по умолчанию стоит US +1)."""
        if not country:
            return False
        trigger = page.locator('div:has-text("US +1"), div:has-text("+1")').last
        if await trigger.count() == 0:
            log.warning("[gate] селектор страны не найден")
            return False
        if not await human_click_force(page, trigger):
            return False
        await asyncio.sleep(random.uniform(1.5, 2.5))

        # в появившемся списке может быть поиск
        search = page.locator('input[placeholder*="search" i], input[type="search"]').first
        with contextlib.suppress(Exception):
            if await search.count() and await search.is_visible():
                await search.fill("")
                await search.type(country[:6], delay=80)
                await asyncio.sleep(1.2)

        option = page.locator(f'div[role="option"]:has-text("{country}"), '
                              f'[role="option"]:has-text("{country}"), '
                              f'div:has-text("{country}")').last
        if await option.count() == 0:
            log.warning("[gate] страна %s не найдена в списке", country)
            await page.keyboard.press("Escape")
            return False
        if not await human_click_force(page, option):
            return False
        await asyncio.sleep(random.uniform(1.0, 2.0))
        log.info("[gate] страна переключена на %s", country)
        return True

    async def _code_input(self, page: Page) -> Any | None:
        """Поле кода. Meta отдаёт его как textarea, а не input."""
        with contextlib.suppress(PWError, PWTimeout):
            loc = page.locator(
                'textarea[autocomplete="one-time-code"], textarea[maxlength="6"], '
                'input[autocomplete="one-time-code"], input[maxlength="6"], '
                'textarea[inputmode="numeric"], input[inputmode="numeric"], '
                'textarea[placeholder*="code" i], input[placeholder*="code" i]'
            ).first
            if await loc.count() and await loc.is_visible():
                return loc
        return None

    # -- прохождение --------------------------------------------------------
    async def pass_gate(self, page: Page, human: HumanDriver, arkose: ArkoseSolver,
                        mail: Any = None, email: str | None = None,
                        since_ts: float = 0.0, sms: Any = None,
                        session: Any = None,
                        box: dict[str, Any] | None = None) -> bool:
        """True — гейт пройден. Ничего не бросает: результат в логе и возврате."""
        deadline = time.monotonic() + self.cfg.GATE_TIMEOUT
        log.warning("[gate] аккаунт на человеческом гейте: %s", page.url)

        # URL /accounts/suspended совпадает раньше, чем React отрисует текст,
        # поэтому сначала ждём кнопку/капчу, и только потом дампим и кликаем
        ready_until = time.monotonic() + 30
        while time.monotonic() < ready_until:
            if await self._gate_ready(page):
                break
            await asyncio.sleep(1.5)
        await self._dump(page, "gate_detected")

        for rnd_no in range(1, self.cfg.GATE_MAX_ROUNDS + 1):
            if time.monotonic() > deadline:
                log.error("[gate] таймаут %s сек — гейт не пройден", self.cfg.GATE_TIMEOUT)
                await self._dump(page, "gate_timeout")
                return False
            if await self.is_appeal_submitted(page):
                log.info("[gate] апелляция отправлена — решение IG обычно за час")
                return True
            if not await self.is_gate(page):
                if page.url.startswith("chrome-error"):
                    # навигация упала: страница не отрисована, это не «пройдено»
                    log.warning("[gate] страница ошибки — перезагружаю")
                    with contextlib.suppress(PWError):
                        await page.reload(wait_until="domcontentloaded",
                                          timeout=60000)
                    await asyncio.sleep(3.0)
                    continue
                log.info("[gate] гейт пройден (раунд %s, url=%s)", rnd_no, page.url)
                return True

            log.info("[gate] раунд %s/%s", rnd_no, self.cfg.GATE_MAX_ROUNDS)

            # 1. cookie-баннер (каждый второй раз — «принять всё», как живой)
            if random.random() < 0.6:
                await self._click_any(page, human, self.COOKIE_TEXTS, "cookies")
                await rnd(1.0, 2.0)

            # шаг «завис» и ничего не распознаётся — перезагружаем
            if await self._stuck_state(page):
                log.info("[gate] состояние не распознано — перезагружаю страницу")
                with contextlib.suppress(PWError):
                    await page.reload(wait_until="domcontentloaded", timeout=60000)
                await asyncio.sleep(4.0)

            # 2. Continue — первая кнопка гейта
            clicked = await self._click_any(page, human, self.CONTINUE_TEXTS, "gate")
            if not clicked:
                log.warning("[gate] кнопки Continue нет — пробую captcha напрямую")
            await asyncio.sleep(random.uniform(2.0, 5.0))

            # 3. вложенный челлендж: Arkose -> reCAPTCHA -> код на почту
            try:
                if await arkose.is_present(page, timeout_ms=2500):
                    log.warning("[gate] внутри гейта Arkose")
                    await arkose.handle(page)
                elif await arkose.is_recaptcha_present(page, timeout_ms=2500):
                    log.warning("[gate] внутри гейта reCAPTCHA")
                    await arkose.handle_recaptcha(page)
                elif await self.is_selfie_prompt(page):
                    log.warning("[gate] гейт просит селфи")
                    if await self.pass_selfie_step(page, human):
                        for _ in range(30):
                            await asyncio.sleep(2.0)
                            if await self.is_appeal_submitted(page):
                                log.info("[gate] апелляция отправлена")
                                return True
                            if not await self.is_gate(page):
                                log.info("[gate] гейт закрыт после селфи")
                                return True
                elif await self.is_phone_prompt(page):
                    log.warning("[gate] гейт просит номер телефона")
                    await self.pass_phone_step(page, human, sms, session, box)
                elif await self.is_image_captcha(page):
                    if self.captcha_available():
                        log.warning("[gate] внутри гейта текстовая капча с картинки")
                        await self.solve_image_captcha(page, human)
                    else:
                        log.warning("[gate] капча на экране, но баланса сервиса нет")
                else:
                    field = await self._code_input(page)
                    if field is not None:
                        await self.pass_code_step(page, human, field, sms, mail,
                                                  session, box, email, since_ts)
            except (CaptchaRequiredError, VerificationTimeoutError) as exc:
                log.error("[gate] шаг челленджа не удался: %s", exc)

            # 4. ждём, пока страница уедет с гейта
            settle = time.monotonic() + 25
            while time.monotonic() < settle:
                await asyncio.sleep(2.0)
                if await self.is_appeal_submitted(page):
                    log.info("[gate] апелляция отправлена")
                    return True
                if not await self.is_gate(page):
                    log.info("[gate] гейт пройден после раунда %s", rnd_no)
                    return True
                # появился новый челлендж — выходим из ожидания, идём на след. раунд
                if (await arkose.is_present(page, timeout_ms=300)
                        or await arkose.is_recaptcha_present(page, timeout_ms=300)):
                    break

        log.error("[gate] исчерпаны %s раундов — гейт не пройден", self.cfg.GATE_MAX_ROUNDS)
        await self._dump(page, "gate_failed")
        return False

    async def wait_clear(self, page: Page, timeout: int = 90) -> bool:
        """Ждём выхода с гейта без действий (например, после инжекта токена)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not await self.is_gate(page):
                return True
            await asyncio.sleep(2.0)
        return False


# ===========================================================================
# 3a. ПОДТВЕРЖДЕНИЕ ПО EMAIL — EmailVerifier (imaplib)
# ===========================================================================


class EmailVerifier:
    """
    Catch-all IMAP: выкачиваем последние письма, ищем отправителя Instagram и
    вырезаем код регуляркой r'\\b\\d{6}\\b'. imaplib блокирующий — гоняем его
    через asyncio.to_thread.
    """

    FROM_MARKERS = ("instagram", "mail.instagram.com", "security@mail.instagram.com",
                    "no-reply@mail.instagram.com", "instagram.com")

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    # -- sync core ----------------------------------------------------------
    def _connect(self) -> imaplib.IMAP4 | imaplib.IMAP4_SSL:
        if self.cfg.IMAP_SSL:
            return imaplib.IMAP4_SSL(self.cfg.IMAP_HOST, self.cfg.IMAP_PORT)
        return imaplib.IMAP4(self.cfg.IMAP_HOST, self.cfg.IMAP_PORT)

    def _fetch_sync(self, recipient: str, since_ts: float) -> str | None:
        """
        Один проход по ящику. Возвращает 6-значный код или None.
        Фильтр: письмо пришло ПОСЛЕ since_ts и адресовано нашему recipient
        (для catch-all это критично — в ящик валятся все домены сразу).
        """
        conn = self._connect()
        try:
            conn.login(self.cfg.IMAP_USER, self.cfg.IMAP_PASS)
            conn.select(self.cfg.IMAP_MAILBOX, readonly=True)
            status, data = conn.search(None, "ALL")
            if status != "OK" or not data or not data[0]:
                log.debug("[imap] ящик пуст")
                return None

            ids = data[0].split()[-40:]          # последние 40 писем
            ids.reverse()                        # от новых к старым
            local_part = recipient.split("@")[0].lower()

            for mid in ids:
                status, msg_data = conn.fetch(mid, "(BODY.PEEK[])")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                msg = email.message_from_bytes(raw)

                # --- время письма ---
                ts = self._parse_date(msg.get("Date", ""))
                if ts and ts < since_ts - 30:
                    continue

                # --- отправитель ---
                frm = (msg.get("From") or "").lower()
                if not any(m in frm for m in self.FROM_MARKERS):
                    continue

                # --- для catch-all проверяем, что письмо именно наше ---
                to = ((msg.get("To") or "") + " " + (msg.get("Delivered-To") or "")
                      + " " + (msg.get("X-Original-To") or "")).lower()
                if local_part and to and local_part not in to:
                    log.debug("[imap] письмо от IG, но не для %s — пропускаем", local_part)
                    continue

                body = self._extract_body(msg)
                code = self._find_code(body, msg.get("Subject") or "")
                if code:
                    log.info(
                        "[imap] код %s найден в письме «%s» от %s",
                        code, (msg.get("Subject") or "")[:60], frm[:40],
                    )
                    return code
            return None
        finally:
            with contextlib.suppress(Exception):
                conn.logout()

    @staticmethod
    def _parse_date(value: str) -> float | None:
        if not value:
            return None
        try:
            return email.utils.mktime_tz(email.utils.parsedate_tz(value))  # type: ignore[arg-type]
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _extract_body(msg: email.message.Message) -> str:
        """Текст письма: prefer text/plain, fallback text/html (теги срезаем)."""
        parts: list[str] = []
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        parts.append(payload.decode(charset, errors="ignore"))
                    except LookupError:
                        parts.append(payload.decode("utf-8", errors="ignore"))
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                parts.append(payload.decode(charset, errors="ignore"))

        text = "\n".join(parts)
        # декодируем HTML-entities и убираем разметку — код часто внутри <b>/<span>
        text = re.sub(r"<[^>]+>", " ", text)
        text = text.replace("&#8203;", "").replace("&zwnj;", "").replace("\u200b", "")
        text = re.sub(r"\s+", " ", text)
        return text

    @staticmethod
    def _find_code(body: str, subject: str) -> str | None:
        """Ищем \\b\\d{6}\\b. Сначала в теме, потом в теле (по убыванию «похожести»)."""
        for source in (subject, body):
            if not source:
                continue
            # приоритет — цифры рядом со словами confirmation / code / Instagram
            for m in re.finditer(
                r"(?:confirmation|confirm|code|код)[^\d]{0,40}(\d{6})", source, re.I
            ):
                return m.group(1)
            m = CODE_RE.search(source)
            if m:
                return m.group(0)
        return None

    # -- async api ----------------------------------------------------------
    async def wait_for_code(self, recipient: str, since_ts: float) -> str:
        """
        Опрос IMAP до получения кода (таймаут cfg.IMAP_TIMEOUT, шаг POLL_INTERVAL).
        Бросает VerificationTimeoutError.
        """
        if not (self.cfg.IMAP_USER and self.cfg.IMAP_PASS):
            raise AccountRejectedError(
                "IMAP_USER/IMAP_PASS не заданы — email-верификация невозможна"
            )
        deadline = time.monotonic() + self.cfg.IMAP_TIMEOUT
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            log.info(
                "[imap] попытка #%s: жду письмо для %s (осталось %d сек)",
                attempt, recipient, int(deadline - time.monotonic()),
            )
            try:
                code = await asyncio.to_thread(self._fetch_sync, recipient, since_ts)
            except (imaplib.IMAP4.error, OSError, TimeoutError) as exc:
                log.warning("[imap] ошибка подключения: %s — ретрай", exc)
                code = None
            if code:
                return code
            await asyncio.sleep(self.cfg.IMAP_POLL_INTERVAL)
        raise VerificationTimeoutError(
            f"email-код для {recipient} не пришёл за {self.cfg.IMAP_TIMEOUT} сек"
        )


# ===========================================================================
# 3b. ПОДТВЕРЖДЕНИЕ ПО SMS — SmsVerifier (sms-activate / 5sim)
# ===========================================================================


@dataclass
class SmsActivation:
    activation_id: str
    phone: str          # международный формат, без '+'
    raw: dict[str, Any] = field(default_factory=dict)


class SmsVerifier:
    """
    Аренда виртуального номера и приём кода Instagram.
    Поддерживает sms-activate.org и 5sim.net.
    Жизненный цикл: buy -> poll(180 сек) -> finish | cancel | ban.
    """

    DEFAULT_SA = "https://api.sms-activate.org/stubs/handler.php"
    DEFAULT_5S = "https://5sim.net/v1/user"

    #: переопределяются из cfg (SMS_API_BASE / FIVESIM_API_BASE) в __init__;
    #: классовые атрибуты оставлены как хук для тестов
    SMS_ACTIVATE_URL = DEFAULT_SA
    FIVESIM_URL = DEFAULT_5S

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.spent = 0.0
        if cfg.SMS_API_BASE and cfg.SMS_API_BASE != self.DEFAULT_SA:
            self.SMS_ACTIVATE_URL = cfg.SMS_API_BASE
        if cfg.FIVESIM_API_BASE and cfg.FIVESIM_API_BASE != self.DEFAULT_5S:
            self.FIVESIM_URL = cfg.FIVESIM_API_BASE
        log.info(
            "[sms] provider=%s api=%s service=%s",
            cfg.SMS_PROVIDER,
            self.SMS_ACTIVATE_URL if cfg.SMS_PROVIDER == "sms-activate" else self.FIVESIM_URL,
            cfg.SMS_SERVICE_CODE,
        )

    @property
    def _5sim_product(self) -> str:
        """Код сервиса для 5sim: 'ig'/'insta' -> 'instagram', иначе как задано."""
        code = (self.cfg.SMS_SERVICE_CODE or "ig").strip()
        return "instagram" if code.lower() in ("ig", "insta", "instagram") else code

    # ---------------- sms-activate ----------------
    async def _sa_buy(self, session: aiohttp.ClientSession) -> SmsActivation:
        params = {
            "api_key": self.cfg.SMS_API_KEY,
            "action": "getNumber",
            "service": self.cfg.SMS_SERVICE_CODE,
            "country": self.cfg.SMS_COUNTRY,
        }
        async with session.get(self.SMS_ACTIVATE_URL, params=params,
                               timeout=aiohttp.ClientTimeout(total=45)) as r:
            text = await r.text(errors="ignore")
        log.info("[sms-activate] getNumber -> %s", text[:200])
        if not text.startswith("ACCESS_NUMBER"):
            raise AutoRegError(f"sms-activate не выдал номер: {text[:200]}")
        _, act_id, phone = text.split(":", 2)
        return SmsActivation(activation_id=act_id.strip(), phone=phone.strip(),
                             raw={"raw": text})

    async def _sa_set_status(self, session: aiohttp.ClientSession,
                             act_id: str, status: int) -> str:
        """status: 1=готов, 3=запросить ещё, 6=бан, 8=отмена."""
        params = {
            "api_key": self.cfg.SMS_API_KEY,
            "action": "setStatus",
            "status": status,
            "id": act_id,
        }
        try:
            async with session.get(self.SMS_ACTIVATE_URL, params=params,
                                   timeout=aiohttp.ClientTimeout(total=30)) as r:
                out = (await r.text(errors="ignore")).strip()
            log.info("[sms-activate] setStatus(%s) id=%s -> %s", status, act_id, out)
            return out
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            log.error("[sms-activate] setStatus(%s) упал: %s", status, exc)
            return "ERROR"

    async def _sa_poll(self, session: aiohttp.ClientSession,
                       act_id: str) -> tuple[str | None, str]:
        """Возвращает (code, last_status)."""
        params = {"api_key": self.cfg.SMS_API_KEY, "action": "getStatus", "id": act_id}
        async with session.get(self.SMS_ACTIVATE_URL, params=params,
                               timeout=aiohttp.ClientTimeout(total=30)) as r:
            text = (await r.text(errors="ignore")).strip()
        log.debug("[sms-activate] getStatus -> %s", text[:150])

        if text.startswith("STATUS_OK:"):
            return text.split(":", 1)[1].strip(), "OK"
        if text.startswith("STATUS_WAIT_CODE") or text.startswith("STATUS_WAIT_RESEND"):
            return None, "WAIT"
        if text.startswith("STATUS_CANCEL"):
            return None, "CANCEL"
        if "BANNED" in text.upper() or text.startswith("ERROR"):
            return None, "BANNED"
        return None, text

    # ---------------- ручной номер ----------------
    def _manual_code(self) -> str | None:
        f = Path(self.cfg.MANUAL_SMS_FILE)
        if not f.exists():
            return None
        with contextlib.suppress(OSError):
            raw = f.read_text(encoding="utf-8")
            m = re.search(r"\b(\d{4,8})\b", raw)
            if m:
                return m.group(1)
        return None

    # ---------------- smspool ----------------
    async def _sp_buy(self, session: aiohttp.ClientSession) -> SmsActivation:
        data = {
            "key": self.cfg.SMS_API_KEY,
            "service": self.cfg.SMSPOOL_SERVICE,
            "country": self.cfg.SMSPOOL_COUNTRY,
        }
        async with session.post(f"{self.cfg.SMSPOOL_HOST}/purchase/sms", data=data,
                                timeout=aiohttp.ClientTimeout(total=60)) as r:
            text = await r.text(errors="ignore")
        log.info("[smspool] purchase -> %s", text[:200])
        try:
            res = json.loads(text)
        except json.JSONDecodeError:
            raise AutoRegError(f"smspool: не-JSON ответ: {text[:200]}") from None
        if not res.get("success"):
            raise AutoRegError(f"smspool не выдал номер: {res.get('message') or text[:150]}")
        phone = str(res.get("phonenumber") or res.get("number") or "")
        order = str(res.get("order_id") or res.get("orderid") or "")
        return SmsActivation(activation_id=order, phone=phone, raw=res)

    async def _sp_check(self, session: aiohttp.ClientSession,
                        order_id: str) -> tuple[str | None, str]:
        params = {"key": self.cfg.SMS_API_KEY, "orderid": order_id}
        async with session.get(f"{self.cfg.SMSPOOL_HOST}/sms/check", params=params,
                               timeout=aiohttp.ClientTimeout(total=30)) as r:
            text = (await r.text(errors="ignore")).strip()
        log.debug("[smspool] check -> %s", text[:150])
        try:
            res = json.loads(text)
        except json.JSONDecodeError:
            return None, "WAIT"
        sms = res.get("sms")
        if sms:
            return str(sms).strip(), "OK"
        status = res.get("status")
        if status == 3 or res.get("status") == "3":
            return None, "WAIT"
        if res.get("cancelled") or status in (6, "6"):
            return None, "CANCEL"
        return None, "WAIT"

    async def _sp_cancel(self, session: aiohttp.ClientSession, order_id: str) -> None:
        params = {"key": self.cfg.SMS_API_KEY, "orderid": order_id}
        # smspool не даёт отменить сразу после покупки (~2 мин) — ретраим
        for attempt in range(1, 4):
            try:
                async with session.post(f"{self.cfg.SMSPOOL_HOST}/sms/cancel",
                                        params=params,
                                        timeout=aiohttp.ClientTimeout(total=30)) as r:
                    out = (await r.text(errors="ignore")).strip()
                log.info("[smspool] cancel %s -> %s", order_id, out[:120])
                if '"success":1' in out:
                    return
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                log.error("[smspool] cancel упал: %s", exc)
                return
            await asyncio.sleep(4)

    # ---------------- 5sim ----------------
    async def _5s_buy(self, session: aiohttp.ClientSession) -> SmsActivation:
        url = (f"{self.FIVESIM_URL}/buy/activation/"
               f"{self.cfg.SMS_5SIM_COUNTRY}/{self._5sim_product}")
        headers = {"Authorization": f"Bearer {self.cfg.SMS_API_KEY}"}
        params: dict[str, str] = {}
        if self.cfg.SMS_5SIM_OPERATOR and self.cfg.SMS_5SIM_OPERATOR != "any":
            params["operator"] = self.cfg.SMS_5SIM_OPERATOR
        async with session.get(url, headers=headers, params=params,
                               timeout=aiohttp.ClientTimeout(total=45)) as r:
            data = await r.json(content_type=None)
        log.info("[5sim] buy -> %s", data)
        if r.status >= 400 or "id" not in data:
            raise AutoRegError(f"5sim не выдал номер: HTTP {r.status} {data}")
        return SmsActivation(
            activation_id=str(data["id"]),
            phone=str(data["phone"]),
            raw=data,
        )

    async def _5s_action(self, session: aiohttp.ClientSession,
                         act_id: str, action: str) -> dict[str, Any]:
        """action: finish | cancel | ban"""
        url = f"{self.FIVESIM_URL}/{action}/{act_id}"
        headers = {"Authorization": f"Bearer {self.cfg.SMS_API_KEY}"}
        try:
            async with session.get(url, headers=headers,
                                   timeout=aiohttp.ClientTimeout(total=30)) as r:
                data = await r.json(content_type=None) if r.content_length else {}
                log.info("[5sim] %s id=%s -> HTTP %s %s", action, act_id, r.status, data)
                return data if isinstance(data, dict) else {}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            log.error("[5sim] %s id=%s упал: %s", action, act_id, exc)
            return {}

    async def _5s_check(self, session: aiohttp.ClientSession,
                        act_id: str) -> tuple[str | None, str]:
        url = f"{self.FIVESIM_URL}/check/{act_id}"
        headers = {"Authorization": f"Bearer {self.cfg.SMS_API_KEY}"}
        async with session.get(url, headers=headers,
                               timeout=aiohttp.ClientTimeout(total=30)) as r:
            data = await r.json(content_type=None)
        status = str(data.get("status", "")).upper()
        log.debug("[5sim] check id=%s -> %s", act_id, status)
        if status in ("RECEIVED", "FINISHED"):
            for sms in reversed(data.get("sms") or []):
                code = str(sms.get("code") or "").strip()
                if code:
                    return code, "OK"
                text = str(sms.get("text") or "")
                m = CODE_RE.search(text)
                if m:
                    return m.group(0), "OK"
            return None, "OK_NO_CODE"
        if status in ("BANNED", "CANCELED", "TIMEOUT", "USED"):
            return None, status
        return None, status or "WAIT"

    # ---------------- общий интерфейс ----------------
    async def buy(self, session: aiohttp.ClientSession) -> SmsActivation:
        if not self.cfg.SMS_API_KEY:
            raise AutoRegError("SMS_API_KEY не задан")
        if self.cfg.SMS_PROVIDER == "sms-activate":
            return await self._sa_buy(session)
        if self.cfg.SMS_PROVIDER == "manual":
            num = self.cfg.MANUAL_PHONE.strip().lstrip("+")
            if not num:
                raise AutoRegError("MANUAL_PHONE пуст — нечего вводить")
            log.info("[sms] ручной номер %s, код ждём в %s", num, self.cfg.MANUAL_SMS_FILE)
            with contextlib.suppress(OSError):
                Path(self.cfg.MANUAL_SMS_FILE).unlink()
            return SmsActivation(activation_id="manual", phone=num)
        return await self._5s_buy(session)

    async def cancel(self, session: aiohttp.ClientSession, act: SmsActivation) -> None:
        """Отмена активации (деньги возвращаются на баланс)."""
        if self.cfg.SMS_PROVIDER == "manual":
            log.info("[sms] ручной номер — отменять нечего")
        elif self.cfg.SMS_PROVIDER == "sms-activate":
            await self._sa_set_status(session, act.activation_id, 8)
        elif self.cfg.SMS_PROVIDER == "smspool":
            await self._sp_cancel(session, act.activation_id)
        else:
            await self._5s_action(session, act.activation_id, "cancel")
        log.warning("[sms] активация %s отменена", act.activation_id)

    async def ban(self, session: aiohttp.ClientSession, act: SmsActivation) -> None:
        """Помечаем номер забаненным — больше не предлагать."""
        if self.cfg.SMS_PROVIDER == "sms-activate":
            await self._sa_set_status(session, act.activation_id, 6)
        elif self.cfg.SMS_PROVIDER == "smspool":
            await self._sp_cancel(session, act.activation_id)
        else:
            await self._5s_action(session, act.activation_id, "ban")
        log.warning("[sms] номер %s помечен как BANNED", act.phone)

    async def finish(self, session: aiohttp.ClientSession, act: SmsActivation) -> None:
        """Подтверждаем успешное завершение активации (только 5sim)."""
        if self.cfg.SMS_PROVIDER == "5sim":
            await self._5s_action(session, act.activation_id, "finish")
        elif self.cfg.SMS_PROVIDER == "smspool":
            log.debug("[sms] smspool закрывает заказ сам, finish не нужен")
        else:
            await self._sa_set_status(session, act.activation_id, 1)

    async def wait_for_code(self, session: aiohttp.ClientSession,
                            act: SmsActivation) -> str:
        """
        while-цикл с таймаутом 180 сек: опрашиваем API на предмет кода.
        При банe номера -> BannedNumberError (вызывающий обязан сделать ban/cancel).
        """
        deadline = time.monotonic() + self.cfg.SMS_TIMEOUT
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            left = int(deadline - time.monotonic())
            log.info("[sms] опрос #%s (номер %s, осталось %d сек)",
                     attempt, act.phone, left)
            try:
                if self.cfg.SMS_PROVIDER == "manual":
                    code = self._manual_code()
                    status = "OK" if code else "WAIT"
                    if not code:
                        await asyncio.sleep(self.cfg.SMS_POLL_INTERVAL)
                        continue
                elif self.cfg.SMS_PROVIDER == "sms-activate":
                    code, status = await self._sa_poll(session, act.activation_id)
                elif self.cfg.SMS_PROVIDER == "smspool":
                    code, status = await self._sp_check(session, act.activation_id)
                else:
                    code, status = await self._5s_check(session, act.activation_id)
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                log.warning("[sms] ошибка API: %s — продолжаем опрос", exc)
                await asyncio.sleep(self.cfg.SMS_POLL_INTERVAL)
                continue

            if code:
                log.info("[sms] получен код %s для %s", code, act.phone)
                return code

            if status in ("BANNED",):
                raise BannedNumberError(f"номер {act.phone} забанен")
            if status in ("CANCEL", "CANCELED", "TIMEOUT", "USED"):
                raise VerificationTimeoutError(f"активация закрыта сервисом: {status}")
            if status == "OK_NO_CODE":
                await asyncio.sleep(self.cfg.SMS_POLL_INTERVAL)
                continue

            await asyncio.sleep(self.cfg.SMS_POLL_INTERVAL)

        raise VerificationTimeoutError(
            f"SMS-код на {act.phone} не пришёл за {self.cfg.SMS_TIMEOUT} сек"
        )


# ===========================================================================
# 6. СОХРАНЕНИЕ — Storage
# ===========================================================================


class Storage:
    """
    * cookies/storage_state -> cookies/<username>_<ts>.json
    * success.txt           -> login:password:email:proxy
    * failed.txt            -> login|reason|timestamp
    * accounts.json         — машинально-читаемая база для web-панели
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        Path(cfg.COOKIES_DIR).mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self.accounts_db = Path(cfg.ACCOUNTS_DB)

    async def save_cookies(self, context: BrowserContext, ident: Identity) -> Path:
        path = Path(self.cfg.COOKIES_DIR) / f"{ident.username}_{now_stamp()}.json"
        await context.storage_state(path=str(path))
        log.info("[storage] cookies сохранены -> %s", path)
        return path

    async def save_success(self, ident: Identity, proxy: str,
                           cookies_path: Path | None = None,
                           trust: dict[str, Any] | None = None,
                           status: str = "alive",
                           channel: str = "web") -> None:
        """status: alive | suspended — suspended значит «создан, но на гейте»."""
        line = ident.as_line(proxy)
        async with self._lock:
            with open(self.cfg.SUCCESS_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            log.info("[storage] аккаунт записан в %s: %s (status=%s)",
                     self.cfg.SUCCESS_FILE, ident.username, status)

            record = ident.to_dict()
            record.update({
                "proxy": proxy,
                "cookies": str(cookies_path) if cookies_path else None,
                "cookies_kind": "settings" if channel == "api" else "storage_state",
                "channel": channel,
                "trust": trust or {},
                "status": status,
                "status_checked_at": datetime.now().isoformat(timespec="seconds"),
                "created_at": datetime.now().isoformat(timespec="seconds"),
            })
            self._append_json(record)

    def audit(self, username: str, event: str, **fields: Any) -> None:
        """
        Журнал событий жизненного цикла аккаунта (audit.jsonl).

        Нужен, чтобы установить порядок: сначала слетает сессия или сначала
        приходит disable, и отклоняется ли апелляция раньше отключения.
        """
        record = {"ts": datetime.now().isoformat(timespec="seconds"),
                  "username": username, "event": event, **fields}
        with contextlib.suppress(OSError):
            with open("audit.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def update_cookies(self, username: str, path: str) -> bool:
        """Обновляет путь к свежим cookies после повторного входа."""
        if not self.accounts_db.exists():
            return False
        try:
            data = json.loads(self.accounts_db.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        for rec in data if isinstance(data, list) else []:
            if isinstance(rec, dict) and rec.get("username") == username:
                rec["cookies"] = path
                self.accounts_db.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                return True
        return False

    def update_follow(self, username: str, target: str) -> bool:
        """Пишет факт подписки/запроса в accounts.json (критерий приёмки)."""
        if not self.accounts_db.exists():
            return False
        try:
            data = json.loads(self.accounts_db.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        for rec in data if isinstance(data, list) else []:
            if isinstance(rec, dict) and rec.get("username") == username:
                trust = rec.get("trust") or {}
                trust["followed"] = target
                trust["requested"] = True
                rec["trust"] = trust
                rec["followed_at"] = datetime.now().isoformat(timespec="seconds")
                self.accounts_db.write_text(
                    json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                return True
        return False

    def update_status(self, username: str, status: str,
                      note: str | None = None) -> bool:
        """Меняет статус аккаунта в accounts.json (alive/suspended/banned/dead)."""
        if not self.accounts_db.exists():
            return False
        try:
            data = json.loads(self.accounts_db.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        if not isinstance(data, list):
            return False
        changed = False
        for rec in data:
            if isinstance(rec, dict) and rec.get("username") == username:
                rec["status"] = status
                rec["status_checked_at"] = datetime.now().isoformat(timespec="seconds")
                if note:
                    rec["status_note"] = note[:200]
                changed = True
        if changed:
            self.accounts_db.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return changed

    def _append_json(self, record: dict[str, Any]) -> None:
        data: list[dict[str, Any]] = []
        if self.accounts_db.exists():
            try:
                data = json.loads(self.accounts_db.read_text(encoding="utf-8"))
                if not isinstance(data, list):
                    data = []
            except json.JSONDecodeError:
                log.error("[storage] accounts.json повреждён — пересоздаю")
                data = []
        data.append(record)
        self.accounts_db.write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    async def save_failed(self, ident: Identity | None, reason: str) -> None:
        who = ident.username if ident else "unknown"
        line = f"{who}|{reason.replace(chr(10), ' ')[:200]}|{datetime.now().isoformat(timespec='seconds')}"
        async with self._lock:
            with open(self.cfg.FAILED_FILE, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            log.warning("[storage] FAILED: %s", line)


# ===========================================================================
# 5. ИНИЦИАЛИЗАЦИЯ И ТРАСТ ПРОФИЛЯ — TrustBuilder
# ===========================================================================


class TrustBuilder:
    """
    Первичная «индексация» свежего аккаунта:
      а) загрузка случайного аватара из локальной папки;
      б) подписка на популярный аккаунт (Follow);
      в) лёгкий прогрев ленты (скролл, ховеры) — аккаунт выглядит живым.
    Сессию после этого НЕ закрываем: cookies уходят в Storage.
    """

    AVATAR_EXTS = (".jpg", ".jpeg", ".png", ".webp")

    #: страница редактирования профиля (переопределяется cfg.PROFILE_EDIT_URL)
    EDIT_URL = "https://www.instagram.com/accounts/edit/"

    FOLLOW_PATTERNS = (
        "Follow", "Подписаться", "Follow Back", "Follow back",
    )

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.traffic: Any = None
        self.gate = HumanGate(cfg)

    # -- avatar -------------------------------------------------------------
    def pick_avatar(self) -> Path | None:
        d = Path(self.cfg.AVATARS_DIR)
        if not d.exists():
            log.warning("[trust] папка аватарок %s не существует", d)
            return None
        files = [p for p in d.rglob("*") if p.suffix.lower() in self.AVATAR_EXTS]
        if not files:
            log.warning("[trust] в %s нет изображений (%s)", d, self.AVATAR_EXTS)
            return None
        return random.choice(files)

    async def upload_avatar(self, page: Page, human: HumanDriver) -> bool:
        """Загрузка аватарки через page file-chooser / скрытый input[type=file]."""
        avatar = self.pick_avatar()
        if avatar is None:
            return False
        log.info("[trust] загружаю аватар %s", avatar)

        try:
            edit_url = self.cfg.PROFILE_EDIT_URL or self.EDIT_URL
            await page.goto(edit_url, wait_until="domcontentloaded", timeout=60000)
        except (PWTimeout, PWError) as exc:
            log.error("[trust] не открылась страница редактирования: %s", exc)
            return False

        await long_rnd(2.0, 5.0)
        await human.wander(page, random.uniform(1.0, 3.0))

        # Путь 0: скрытый input[type=file] обычно уже в DOM — грузим напрямую
        fi = page.locator('input[type="file"]').first
        if await fi.count():
            with contextlib.suppress(PWError, PWTimeout):
                await fi.set_input_files(str(avatar), timeout=20000)
                log.info("[trust] аватар отправлен напрямую в input[type=file]")
                return await self._confirm_avatar(page, human)

        # Путь 1: явный file chooser по кнопке «Change profile photo»
        change_selectors = (
            'button:has-text("Change profile photo")',
            'div[role="button"]:has-text("Change profile photo")',
            'button:has-text("Сменить фото профиля")',
            '[aria-label="Change profile photo"]',
            'button:has-text("Upload Photo")',
        )
        for sel in change_selectors:
            with contextlib.suppress(PWError, PWTimeout):
                btn = page.locator(sel).first
                if await btn.count() and await btn.is_visible():
                    async with page.expect_file_chooser(timeout=15000) as fc_info:
                        await human.human_click(btn, label="change-photo")
                    fc = await fc_info.value
                    await fc.set_files(str(avatar))
                    log.info("[trust] аватар выбран через file chooser (%s)", sel)
                    return await self._confirm_avatar(page, human)

        # Путь 2: скрытый input[type=file] — грузим напрямую
        with contextlib.suppress(PWError, PWTimeout):
            file_input = page.locator('input[type="file"]').first
            await file_input.set_input_files(str(avatar), timeout=10000)
            log.info("[trust] аватар загружен напрямую в input[type=file]")
            return await self._confirm_avatar(page, human)

        log.warning("[trust] не найден элемент загрузки аватара")
        return False

    async def _confirm_avatar(self, page: Page, human: HumanDriver) -> bool:
        """Кнопка «Done / Next / Готово» после выбора файла + проверка результата."""
        await rnd(1.5, 3.5)
        for sel in ('button:has-text("Done")', 'button:has-text("Next")',
                    'div[role="button"]:has-text("Done")',
                    'button:has-text("Готово")', 'button[type="submit"]'):
            with contextlib.suppress(PWError, PWTimeout):
                btn = page.locator(sel).first
                if await btn.count() and await btn.is_visible():
                    await human.human_click(btn, label=f"confirm:{sel}")
                    break
        await long_rnd(3.0, 7.0)

        # файл реально лёг в input?
        file_set = False
        with contextlib.suppress(PWError):
            fi = page.locator('input[type="file"]').first
            if await fi.count():
                file_set = bool(await fi.evaluate("(el) => el.files && el.files.length"))

        url_ok = "accounts/edit" in page.url or (self.cfg.PROFILE_EDIT_URL or "") in page.url
        img_ok = False
        with contextlib.suppress(PWError):
            img_ok = await page.locator('img[alt*="profile" i], img[alt*="аватар" i]').count() > 0
        ok = file_set or url_ok or img_ok
        log.info(
            "[trust] аватар %s (input=%s url=%s img=%s, url=%s)",
            "загружен" if ok else "не подтверждён", file_set, url_ok, img_ok, page.url[:70],
        )
        return ok

    # -- follow -------------------------------------------------------------
    async def follow_target(self, page: Page, human: HumanDriver) -> str | None:
        """
        Заходим на популярный аккаунт и жмём Follow — триггер первичной
        индексации профиля в поиске.
        """
        targets = self.cfg.TRUST_TARGETS or TRUST_TARGETS
        target = random.choice(targets)
        log.info("[trust] перехожу на %s для подписки", target)
        try:
            await page.goto(target, wait_until="domcontentloaded", timeout=60000)
        except (PWTimeout, PWError) as exc:
            log.error("[trust] не открылся профиль: %s", exc)
            return None

        await long_rnd(2.5, 6.0)
        if await self.gate.is_gate(page) or page.url.startswith("chrome-error"):
            log.warning("[trust] на %s гейт/ошибка — follow отложен", target)
            await self._dump(page, "target_gate")
            return None
        await human.wander(page, random.uniform(2.0, 5.0))

        # Кнопка Follow: кнопки Meta — web-blocks, обычный клик по ним падает
        clicked = False
        for pat in self.FOLLOW_PATTERNS:
            with contextlib.suppress(Exception):
                btn = page.get_by_role(
                    "button", name=re.compile(re.escape(pat), re.I)).first
                if await btn.count() and await btn.is_visible():
                    clicked = await self.gate._safe_click(page, btn, human,
                                                          f"follow:{pat}")
                    if clicked:
                        log.info("[trust] Follow нажат (%s) на %s", pat, target)
                        break

        if not clicked:
            log.warning("[trust] кнопка Follow не найдена на %s", target)
            await self._dump(page, "nofollow")
            return None

        # закрытый профиль -> «Requested»/«Запрошено», открытый -> «Following»
        for _ in range(10):
            await asyncio.sleep(2.0)
            with contextlib.suppress(PWError):
                body = (await page.locator("body").inner_text(timeout=4000)).lower()
                if any(w in body for w in ("requested", "запрошено", "following",
                                           "подписки")):
                    log.info("[trust] подписка подтверждена на %s", target)
                    await self._dismiss_dialogs(page, human)
                    return target
        log.warning("[trust] клик был, но подтверждения подписки нет")
        await self._dump(page, "follow_unconfirmed")
        return None

        log.warning("[trust] кнопка Follow не найдена на %s", target)
        await self._dump(page, "nofollow")
        return None

    async def _dump(self, page: Page, tag: str) -> None:
        """Сохраняет HTML+скриншот страницы профиля в debug/ для правки селекторов."""
        try:
            d = Path("debug")
            d.mkdir(parents=True, exist_ok=True)
            stamp = f"{tag}_{now_stamp()}"
            with contextlib.suppress(Exception):
                (d / f"{stamp}.html").write_text(await page.content(), encoding="utf-8")
            with contextlib.suppress(Exception):
                await page.screenshot(path=str(d / f"{stamp}.png"), full_page=False)
            log.error("[trust] дамп страницы сохранён: debug/%s.html + .png (url=%s)",
                      stamp, page.url)
        except Exception as exc:  # noqa: BLE001
            log.error("[trust] не удалось сохранить дамп: %s", exc)

    async def _dismiss_dialogs(self, page: Page, human: HumanDriver) -> None:
        """Закрываем попапы «Turn on notifications» / «Suggested for you»."""
        await rnd(1.5, 3.0)
        for sel in ('button:has-text("Not Now")', 'button:has-text("Not now")',
                    'div[role="button"]:has-text("Not now")',
                    'button:has-text("Не сейчас")', 'button:has-text("Cancel")',
                    '[aria-label="Close"]'):
            with contextlib.suppress(PWError, PWTimeout):
                btn = page.locator(sel).first
                if await btn.count() and await btn.is_visible():
                    await human.human_click(btn, label=f"dismiss:{sel}")
                    break

    # -- warmup -------------------------------------------------------------
    async def warm_visit(self, page: Page, human: HumanDriver,
                         seconds: float) -> None:
        """Один короткий визит: лента, скроллы, изредка лайк, уход."""
        log.info("[trust] визит в ленту ~%.0f сек", seconds)
        with contextlib.suppress(PWError, PWTimeout):
            await page.goto("https://www.instagram.com/", wait_until="domcontentloaded",
                            timeout=60000)
        await rnd(3.0, 6.0)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            with contextlib.suppress(PWError):
                await page.mouse.wheel(0, random.randint(250, 700))
            await asyncio.sleep(random.uniform(2.5, 7.0))

            if random.random() < 0.2:
                with contextlib.suppress(PWError, PWTimeout):
                    like = page.locator('section span button svg[aria-label="Like"]').first
                    if await like.count() and await like.is_visible():
                        await human.human_click(like, label="like")
                        log.debug("[trust] лайк поставлен")

            if random.random() < 0.1:
                await human.wander(page, random.uniform(1.0, 2.5))
        log.info("[trust] визит закончен")

    async def warm_feed(self, page: Page, human: HumanDriver,
                        minutes: float = 1.5) -> None:
        """Совместимость: прогрев ленты «в минутах» одним визитом."""
        await self.warm_visit(page, human, seconds=minutes * 60)

    async def run(self, page: Page, human: HumanDriver, ident: Identity,
                  do_follow: bool = True) -> dict[str, Any]:
        """Полный траст-блок. Возвращает отчёт, ничего не бросает наружу."""
        report: dict[str, Any] = {"avatar": False, "followed": None,
                                  "warm": False, "visits": 0}
        if self.cfg.ENABLE_AVATAR:
            if self.traffic:
                self.traffic.allow()      # превью аватара грузится с CDN
            with contextlib.suppress(Exception):
                report["avatar"] = await self.upload_avatar(page, human)
            if self.traffic:
                self.traffic.block()

        # follow сразу: это критерий приёмки, и IP ещё «свежий» после гейта
        if self.cfg.ENABLE_TRUST and do_follow:
            with contextlib.suppress(Exception):
                report["followed"] = await self.follow_target(page, human)

        visits = max(1, self.cfg.WARM_VISITS)
        follow_after = 1 if visits > 1 else 0
        for i in range(visits):
            seconds = random.uniform(max(self.cfg.WARM_SECONDS_MIN, 10),
                                     max(self.cfg.WARM_SECONDS_MAX, 15))
            with contextlib.suppress(Exception):
                await self.warm_visit(page, human, seconds)
                report["visits"] = i + 1
                report["warm"] = True
            # если сразу не вышло — вторая попытка после визита
            if self.cfg.ENABLE_TRUST and report["followed"] is None and i >= follow_after:
                with contextlib.suppress(Exception):
                    report["followed"] = await self.follow_target(page, human)
            if i < visits - 1:
                await asyncio.sleep(random.uniform(max(self.cfg.WARM_PAUSE_MIN, 5),
                                                   max(self.cfg.WARM_PAUSE_MAX, 10)))
        log.info("[trust] отчёт: %s", report)
        return report


# ===========================================================================
# БРАУЗЕР: контекст со случайным UA и подменой фингерпринтов
# ===========================================================================


class TrafficSaver:
    """
    Режет тяжёлые ресурсы (фото ленты, сторис, видео, шрифты CDN).

    Зачем: на мобильном прокси трафик лимитирован, а лента Instagram на
    первом экране тянет 5–15 МБ. Селекторы от этого не страдают: кнопки
    находятся по роли/aria-label, аватар грузится с диска.

    ВАЖНО: нельзя рубить `static.cdninstagram.com` — на нём JS/CSS бандлы,
    без них React-приложение вообще не монтируется (проверено: гейт
    /accounts/suspended остаётся пустым). Поэтому блокировка идёт по хостам
    медиа-CDN и по типу `media`, а документы/скрипты/стили/запросы пропускаются.
    """

    HEAVY_HOSTS = ("scontent", "fbcdn.net", "instagram.f", "cdninstagram")
    PASS_TYPES = ("document", "script", "stylesheet", "xhr", "fetch", "other")

    def __init__(self, hosts: str | None = None) -> None:
        self.hosts = tuple(
            h.strip() for h in (hosts or "").split(",") if h.strip()
        ) or self.HEAVY_HOSTS
        self.blocked = 0
        self._enabled = False

    def _is_heavy(self, url: str, resource_type: str) -> bool:
        if resource_type in self.PASS_TYPES:
            return False
        if resource_type == "media":
            return True
        host = url.split("/")[2] if "//" in url else ""
        return any(h in host for h in self.hosts)

    async def install(self, context: BrowserContext, enabled: bool) -> None:
        self._enabled = enabled
        if not enabled:
            return

        async def handler(route: Route) -> None:
            req = route.request
            if self._enabled and self._is_heavy(req.url, req.resource_type):
                self.blocked += 1
                with contextlib.suppress(Exception):
                    await route.abort()
                return
            with contextlib.suppress(Exception):
                await route.continue_()

        with contextlib.suppress(Exception):
            await context.route("**/*", handler)
        log.info("[browser] блокировка медиа включена (экономия трафика)")

    def allow(self) -> None:
        self._enabled = False

    def block(self) -> None:
        self._enabled = True


class BrowserFactory:
    """
    Создание асинхронного Playwright-контекста:
      * случайный свежий Chrome/Windows User-Agent;
      * подмена screen resolution, locale, timezone, WebGL, plugins, webdriver;
      * мобильный прокси cfg.PROXY.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._pw: Any = None
        self._browser: Browser | None = None
        self.traffic = TrafficSaver(self.cfg.BLOCK_MEDIA_HOSTS)

    async def start(self) -> Browser:
        if self._browser is not None:
            return self._browser
        self._pw = await async_playwright().start()
        channel = (self.cfg.BROWSER_CHANNEL or "").strip()
        launch_kwargs: dict[str, Any] = {
            "headless": self.cfg.HEADLESS,
            "slow_mo": self.cfg.SLOW_MO,
            "args": self.cfg.EXTRA_ARGS,
        }
        if channel:
            try:
                self._browser = await self._pw.chromium.launch(
                    channel=channel, **launch_kwargs)
                log.info("[browser] запущен Chromium через канал %r "
                         "(new headless, не headless_shell)", channel)
                return self._browser
            except Exception as exc:  # noqa: BLE001
                log.warning("[browser] канал %r недоступен (%s) — откат на "
                            "встроенный билд", channel, str(exc).splitlines()[0][:160])
        self._browser = await self._pw.chromium.launch(**launch_kwargs)
        log.info("[browser] chromium запущен (headless=%s)", self.cfg.HEADLESS)
        return self._browser

    async def _apply_client_hints(self, page: Page, fp: dict[str, Any]) -> None:
        """
        Синхронизирует Client Hints с User-Agent через CDP.

        Без этого headless-Chromium шлёт в sec-ch-ua «HeadlessChrome» и версию
        своего бранча (v158), пока в user_agent стоит «Chrome/130» — прямое
        противоречие, по которому детект отсекает сессию без всякой капчи.
        """
        ua = fp["user_agent"]
        m = re.search(r"Chrome/(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?", ua)
        if m:
            major = m.group(1)
            full = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4) or '0'}"
        else:
            major, full = "131", "131.0.0.0"

        # порядок брендов в реальном Chrome рандомизирован — делаем так же
        brands = [
            {"brand": "Not.A/Brand", "version": random.choice(["8", "24", "99"])},
            {"brand": "Chromium", "version": major},
            {"brand": "Google Chrome", "version": major},
        ]
        random.shuffle(brands)
        full_list = [
            {"brand": b["brand"],
             "version": full if b["brand"] in ("Chromium", "Google Chrome") else f"{b['version']}.0.0.0"}
            for b in brands
        ]
        mobile = bool(fp.get("is_mobile"))
        metadata = {
            "brands": brands,
            "fullVersionList": full_list,
            "fullVersion": full,
            "platform": "iPhone" if mobile else "Windows",
            "platformVersion": ("17.5.0" if mobile
                                else random.choice(["10.0.0", "13.0.0", "15.0.0"])),
            "architecture": "" if mobile else "x86",
            "bitness": "" if mobile else "64",
            "model": "iPhone" if mobile else "",
            "mobile": bool(fp.get("is_mobile")),
            "wow64": False,
        }

        try:
            cdp = await page.context.new_cdp_session(page)
            await cdp.send("Emulation.setUserAgentOverride", {
                "userAgent": ua,
                "acceptLanguage": fp["locale"],
                "platform": "iPhone" if mobile else "Win32",
                "userAgentMetadata": metadata,
            })
            log.debug("[browser] client hints синхронизированы: Chrome/%s (%s)",
                      major, ", ".join(b["brand"] for b in brands))
        except PWError as exc:
            log.warning("[browser] не удалось выставить client hints через CDP: %s", exc)

    async def new_context(
        self,
        identity: dict[str, Any] | None = None,
        *,
        storage_state: str | Path | None = None,
        proxy_url: str | None = None,
        extra_cookies: list[dict[str, Any]] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[BrowserContext, Page]:
        browser = await self.start()
        fp = identity or self.cfg.random_identity()
        vp = fp["viewport"]
        languages = [fp["locale"], fp["locale"].split("-")[0]]

        proxy = None
        # пустая строка = «явно без прокси», None = взять из конфига
        raw_proxy = (self.cfg.PROXY if proxy_url is None else proxy_url) or ""
        raw_proxy = raw_proxy.strip()
        if raw_proxy:
            m = re.match(r"(?P<scheme>https?)://(?:(?P<u>[^:]+):(?P<p>[^@]+)@)?(?P<host>.+)",
                         raw_proxy)
            if m:
                proxy = {"server": f"{m.group('scheme')}://{m.group('host')}"}
                if m.group("u"):
                    proxy["username"] = m.group("u")
                    proxy["password"] = m.group("p") or ""
            else:
                log.warning("[browser] PROXY не распознан: %s", raw_proxy)

        context = await browser.new_context(
            user_agent=fp["user_agent"],
            viewport=vp,
            screen={"width": vp["width"], "height": vp["height"]},
            locale=fp["locale"],
            timezone_id=fp["timezone_id"],
            device_scale_factor=fp["device_scale_factor"],
            is_mobile=bool(fp.get("is_mobile")),
            has_touch=bool(fp.get("has_touch")),
            geolocation=None,
            permissions=[],
            proxy=proxy,
            storage_state=str(storage_state) if storage_state else None,
            extra_http_headers={
                # ВНИМАНИЕ: сюда нельзя добавлять Upgrade-Insecure-Requests и
                # sec-ch-ua-* — Playwright шлёт extra_http_headers на ВСЕ запросы,
                # включая кросс-доменные XHR к static.cdninstagram.com. Такой
                # заголовок делает запрос «не-простым», браузер шлёт preflight
                # OPTIONS, CDN Instagram его не разрешает — и весь JS/CSS
                # блокируется CORS-политикой, страница остаётся пустой.
                # Accept-Language безопасен (входит в список CORS-safelisted),
                # client hints и Upgrade-Insecure-Requests Chromium добавит сам.
                "Accept-Language": (
                    f"{fp['locale']},{fp['locale'].split('-')[0]};q=0.9,en;q=0.8"
                ),
                **(extra_headers or {}),
            },
            java_script_enabled=True,
        )

        await self.traffic.install(context, self.cfg.BLOCK_MEDIA)

        # cookie API-клиента (mid/csrftoken/ig_did) — чтобы webview знал, о
        # каком аккаунте речь, когда sessionid ещё не выдан
        if extra_cookies:
            with contextlib.suppress(PWError):
                await context.add_cookies(extra_cookies)

        # значения фингерпринта кладём в window ДО скриптов страницы
        await context.add_init_script(
            "window.__FP_ARGS__ = " + json.dumps({
                "platform": fp["platform"],
                "hardwareConcurrency": fp["hardware_concurrency"],
                "deviceMemory": fp["device_memory"],
                "webglVendor": fp["webgl_vendor"],
                "webglRenderer": fp["webgl_renderer"],
                "locale": fp["locale"],
                "timezone": fp["timezone_id"],
                "languages": languages,
                "screen": {
                    "width": vp["width"], "height": vp["height"],
                    "availWidth": vp["width"], "availHeight": vp["height"] - 40,
                    "colorDepth": 24, "pixelDepth": 24,
                },
            }) + ";"
        )
        # подмена фингерпринта: инжектим реализацию и сразу её вызываем
        await context.add_init_script(STEALTH_BOOT_SRC + "\nSTEALTH_BOOT();")

        context.set_default_timeout(30000)
        context.set_default_navigation_timeout(60000)

        page = await context.new_page()
        await self._apply_client_hints(page, fp)

        # попапы/новые вкладки наследуют те же client hints
        def _on_new_page(new_page: Page) -> None:
            asyncio.get_event_loop().create_task(self._apply_client_hints(new_page, fp))

        with contextlib.suppress(Exception):
            context.on("page", _on_new_page)

        log.info(
            "[browser] контекст: UA=%s | %sx%s | %s | %s",
            fp["user_agent"].split("Chrome/")[-1][:12], vp["width"], vp["height"],
            fp["locale"], fp["timezone_id"],
        )
        return context, page

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            if self._browser:
                await self._browser.close()
        with contextlib.suppress(Exception):
            if self._pw:
                await self._pw.stop()
        self._browser = None
        self._pw = None
        log.info("[browser] закрыт")


#: глобальная функция подмены — вызывается из add_init_script до скриптов сайта
STEALTH_BOOT_SRC = """
function STEALTH_BOOT() {
  const args = window.__FP_ARGS__ || {};
  const { platform='Win32', hardwareConcurrency=8, deviceMemory=8,
          webglVendor='', webglRenderer='', locale='en-US',
          timezone='America/New_York', languages=['en-US','en'],
          screen={} } = args;

  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  try { delete Object.getPrototypeOf(navigator).webdriver; } catch (e) {}

  Object.defineProperty(navigator, 'platform', { get: () => platform });
  Object.defineProperty(navigator, 'language', { get: () => locale });
  Object.defineProperty(navigator, 'languages', { get: () => languages });
  Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => hardwareConcurrency });
  Object.defineProperty(navigator, 'deviceMemory', { get: () => deviceMemory });

  const mk = (n, d, f) => ({ name: n, description: d, filename: f, length: 1,
                            item: () => null, namedItem: () => null });
  Object.defineProperty(navigator, 'plugins', { get: () => [
    mk('PDF Viewer','Portable Document Format','internal-pdf-viewer'),
    mk('Chrome PDF Viewer','Portable Document Format','internal-pdf-viewer'),
    mk('Chromium PDF Viewer','Portable Document Format','internal-pdf-viewer'),
    mk('Microsoft Edge PDF Viewer','Portable Document Format','internal-pdf-viewer'),
    mk('WebKit built-in PDF','Portable Document Format','internal-pdf-viewer'),
  ]});
  Object.defineProperty(navigator, 'mimeTypes', { get: () => [
    { type:'application/pdf', suffixes:'pdf', description:'Portable Document Format' },
    { type:'text/pdf', suffixes:'pdf', description:'Portable Document Format' },
  ]});

  for (const [k, v] of Object.entries(screen)) {
    try { Object.defineProperty(window.screen, k, { get: () => v }); } catch (e) {}
  }
  try {
    Object.defineProperty(window, 'outerWidth', { get: () => screen.width || window.outerWidth });
    Object.defineProperty(window, 'outerHeight', { get: () => (screen.height || 800) + 40 });
  } catch (e) {}

  const patch = (proto) => {
    if (!proto) return;
    const gp = proto.getParameter;
    proto.getParameter = function (p) {
      if (p === 37445) return webglVendor;
      if (p === 37446) return webglRenderer;
      return gp.apply(this, arguments);
    };
  };
  try { patch(window.WebGLRenderingContext && WebGLRenderingContext.prototype); } catch (e) {}
  try { patch(window.WebGL2RenderingContext && WebGL2RenderingContext.prototype); } catch (e) {}

  try {
    const q = Permissions.prototype.query;
    Permissions.prototype.query = (p) =>
      (p && p.name === 'notifications')
        ? Promise.resolve({ state: Notification.permission })
        : q(p);
  } catch (e) {}

  window.chrome = window.chrome || {};
  window.chrome.runtime = window.chrome.runtime || { connect(){}, sendMessage(){} };
  window.chrome.loadTimes = () => ({});
  window.chrome.csi = () => ({});

  try {
    const dtf = Intl.DateTimeFormat.prototype.resolvedOptions;
    Intl.DateTimeFormat.prototype.resolvedOptions = function () {
      const r = dtf.call(this); r.timeZone = timezone; return r;
    };
  } catch (e) {}
}
"""


# ===========================================================================
# 3. ЛОГИКА РЕГИСТРАЦИИ — InstagramRegistrar
# ===========================================================================


class InstagramRegistrar:
    """
    Проходит веб-форму регистрации Instagram:
      email/phone -> fullName -> username -> password -> birthday -> Next
      -> Arkose (если есть) -> код подтверждения -> готовый аккаунт.
    Селекторы собраны списками с fallback'ами — IG часто их меняет.
    """

    SIGNUP_URL = "https://www.instagram.com/accounts/emailsignup/"
    HOME_URL = "https://www.instagram.com/"

    #: Реальная разметка Meta signup (ноябрь 2025+, проверено по дампу страницы):
    #: у input'ов НЕТ атрибута name — только автогенерируемые id (_r_1f_) и type.
    #: Поэтому первичная идентификация структурная (тип + порядок в DOM),
    #: а name-селекторы оставлены как fallback на случай старой вёрстки.
    #:
    #: Порядок полей в DOM:
    #:   1. input[type=text]      — телефон или email
    #:   2. input[type=password]  — пароль
    #:   3. input[type=text]      — имя и фамилия
    #:   4. input[type=search][role=combobox][aria-label*="Имя пользователя"] — username
    #:   5. три div[role=combobox][aria-haspopup=listbox] — день / месяц / год
    #:   6. div[role=button] с текстом «Отправить» / «Sign up»
    SEL = {
        "email": ('input[name="emailOrPhone"]', 'input[name="email"]',
                  'input[placeholder*="Email" i]', 'input[placeholder*="электрон" i]',
                  'input[aria-label*="Email" i]', 'input[aria-label*="телефон" i]',
                  'input[aria-label*="электрон" i]', 'input[type="email"]'),
        "phone": ('input[name="emailOrPhone"]', 'input[name="phoneNumber"]',
                  'input[placeholder*="Phone" i]', 'input[type="tel"]',
                  'input[aria-label*="Phone" i]', 'input[aria-label*="телефон" i]'),
        "fullname": ('input[name="fullName"]', 'input[placeholder*="Full name" i]',
                     'input[aria-label*="Full name" i]', 'input[aria-label*="полное имя" i]',
                     'input[aria-label*="Имя и фамилия" i]'),
        "username": ('input[name="username"]', 'input[placeholder*="Username" i]',
                     'input[aria-label*="Username" i]', 'input[aria-label*="имя пользователя" i]',
                     'input[type="search"][role="combobox"]', 'input[type="search"]'),
        "password": ('input[name="password"]', 'input[type="password"]',
                     'input[placeholder*="Password" i]', 'input[aria-label*="Password" i]',
                     'input[aria-label*="Пароль" i]'),
        "submit": ('button[type="submit"]', 'div[role="button"][type="submit"]',
                   'button:has-text("Sign up")', 'button:has-text("Next")',
                   'button:has-text("Continue")', 'button:has-text("Далее")',
                   'button:has-text("Регистрация")', '[data-testid="signup-submit"]'),
        "code": ('textarea[autocomplete="one-time-code"]', 'textarea[maxlength="6"]',
                 'textarea[placeholder*="code" i]',
                 'input[name="verificationCode"]', 'input[name="security_code"]',
                 'input[name="securityCode"]', 'input[placeholder*="code" i]',
                 'input[aria-label*="code" i]', 'input[aria-label*="код" i]',
                 'input[type="text"][maxlength="6"]', 'input[type="tel"][maxlength="6"]',
                 'input[maxlength="6"]', 'input[inputmode="numeric"]'),
        "birthday_year": ('select[name="_aaiYear"]', 'select[aria-label*="Year" i]',
                          'select[aria-label*="год" i]', 'select#year'),
        "birthday_month": ('select[name="_aaiMonth"]', 'select[aria-label*="Month" i]',
                           'select[aria-label*="месяц" i]', 'select#month'),
        "birthday_day": ('select[name="_aaiDay"]', 'select[aria-label*="Day" i]',
                         'select[aria-label*="день" i]', 'select#day'),
    }

    #: Текст submit-кнопки в текущей вёрстке (div[role=button], не <button>)
    SUBMIT_TEXTS = ("Submit", "Отправить", "Sign up", "Sign Up",
                    "Next", "Далее", "Continue", "Продолжить",
                    "Зарегистрироваться", "Create account", "Create Account")

    #: Кнопки, которые НЕ являются submit — исключаем из fallback-поиска
    NON_SUBMIT_TEXTS = ("back", "назад", "hide password", "show password",
                        "скрыть пароль", "показать пароль", "more information",
                        "подробнее", "i already have an account",
                        "у меня уже есть аккаунт", "log in", "войти")


    #: Виджеты даты рождения: div[role=combobox] с aria-haspopup=listbox
    BIRTHDAY_LABELS = {
        "day":   re.compile(r"(день|day)", re.I),
        "month": re.compile(r"(месяц|month)", re.I),
        "year":  re.compile(r"(год|year)", re.I),
    }

    #: маркеры отказа, которые IG показывает прямо в форме (EN + RU)
    REJECT_MARKERS = (
        "another account is using", "isn't available", "already taken",
        "try a different", "wasn't valid", "too many attempts",
        "your account has been disabled", "couldn't create",
        "this email is already", "enter a valid",
        "уже используется", "недоступно", "занято", "недействителен",
        "попробуйте другой", "попробуйте снова", "слишком много попыток",
        "аккаунт отключен", "не удалось создать", "введите действительный",
        "это имя пользователя уже", "неверный формат",
    )

    def __init__(self, cfg: Config, human: HumanDriver, arkose: ArkoseSolver,
                 factory: IdentityFactory | None = None) -> None:
        self.cfg = cfg
        self.human = human
        self.arkose = arkose
        self.factory = factory or IdentityFactory(cfg)
        self.gate = HumanGate(cfg)
        self._blocked: list[str] = []
        self._console_errors: list[str] = []

    # -- поиск элементов ----------------------------------------------------
    DEBUG_DIR = "debug"

    async def dump_page(self, page: Page, tag: str) -> str:
        """Сохраняет HTML + скриншот при ошибке, чтобы править селекторы по факту."""
        try:
            d = Path(self.DEBUG_DIR)
            d.mkdir(parents=True, exist_ok=True)
            stamp = f"{tag}_{now_stamp()}"
            html_path = d / f"{stamp}.html"
            png_path = d / f"{stamp}.png"
            with contextlib.suppress(Exception):
                html_path.write_text(await page.content(), encoding="utf-8")
            with contextlib.suppress(Exception):
                await page.screenshot(path=str(png_path), full_page=False)
            log.error("[reg] дамп страницы сохранён: %s + %s (url=%s)",
                      html_path, png_path, page.url)
            return str(html_path)
        except Exception as exc:  # noqa: BLE001
            log.error("[reg] не удалось сохранить дамп: %s", exc)
            return ""

    async def _text_inputs(self, page: Page) -> list[Any]:
        """
        Все видимые текстовые input'ы в DOM-порядке.

        В текущей вёрстке Meta это единственный надёжный способ: name нет,
        id генерируются случайно (_r_1f_), остаются только type и порядок.

        ВАЖНО: password-поле у Meta тоже имеет inputmode="text", поэтому
        фильтруем строго по type и явно исключаем password/search — иначе
        порядок полей съезжает и ФИО печатается в пароль.
        """
        loc = page.locator(
            'input[type="text"], input[type="tel"], input[type="email"], '
            'input:not([type])'
        )
        out = []
        n = await loc.count()
        for i in range(min(n, 12)):
            el = loc.nth(i)
            with contextlib.suppress(Exception):
                if not await el.is_visible() or not await el.is_enabled():
                    continue
                t = (await el.get_attribute("type") or "").lower()
                if t in ("password", "search", "hidden", "submit", "file"):
                    continue
                role = (await el.get_attribute("role") or "").lower()
                if role == "combobox" and t == "search":
                    continue
                out.append(el)
        return out

    async def locate(self, page: Page, key: str, timeout_ms: int = 8000) -> Any:
        """
        Первый видимый элемент из списка селекторов. FormNotFoundError, если нет.

        Для email/fullname дополнительно работает структурный fallback по
        порядку текстовых полей (0 = контакт, 1 = имя и фамилия).
        """
        for sel in self.SEL[key]:
            with contextlib.suppress(PWError, PWTimeout):
                loc = page.locator(sel).first
                await loc.wait_for(state="visible", timeout=min(timeout_ms, 6000))
                log.debug("[reg] найден %s -> %s", key, sel)
                return loc

        # структурный fallback: у Meta signup нет name-атрибутов
        if key in ("email", "phone", "fullname", "code"):
            inputs = await self._text_inputs(page)
            if key == "code":
                # на экране кода текстовое поле одно; плюс фильтруем по maxlength
                if len(inputs) == 1:
                    log.info("[reg] код найден структурно: единственный текстовый input")
                    return inputs[0]
                for el in inputs:
                    with contextlib.suppress(Exception):
                        ml = await el.get_attribute("maxlength")
                        im = await el.get_attribute("inputmode")
                        if ml in ("6", "8") or im in ("numeric", "one-time-code"):
                            log.info("[reg] код найден структурно: maxlength=%s inputmode=%s", ml, im)
                            return el
            else:
                idx = 1 if key == "fullname" else 0
                if len(inputs) > idx:
                    log.info("[reg] %s найден структурно: текстовый input #%s из %s "
                             "(name-атрибутов на странице нет)", key, idx, len(inputs))
                    return inputs[idx]

        await self.dump_page(page, f"nofield_{key}")
        raise FormNotFoundError(f"поле '{key}' не найдено (пробовал {self.SEL[key]})")

    async def locate_optional(self, page: Page, key: str,
                              timeout_ms: int = 3000) -> Any | None:
        with contextlib.suppress(FormNotFoundError):
            return await self.locate(page, key, timeout_ms)
        return None

    # -- диагностика загрузки страницы --------------------------------------
    def _attach_diagnostics(self, page: Page) -> None:
        """
        Ловит ошибки консоли и упавшие запросы. Без этого «пустая страница»
        выглядит как FormNotFoundError, а на деле это CORS/блокировка ресурсов.
        """
        def on_console(msg: Any) -> None:
            try:
                if msg.type in ("error", "warning"):
                    text = msg.text[:300]
                    if len(self._console_errors) < 20:
                        self._console_errors.append(f"{msg.type}: {text}")
            except Exception:  # noqa: BLE001
                pass

        def on_request_failed(request: Any) -> None:
            try:
                if len(self._blocked) < 40:
                    self._blocked.append(
                        f"{request.resource_type} {request.url[:110]} "
                        f"-> {getattr(request, 'failure', '') or ''}")
            except Exception:  # noqa: BLE001
                pass

        with contextlib.suppress(Exception):
            page.on("console", on_console)
            page.on("requestfailed", on_request_failed)

    async def _wait_page_ready(self, page: Page, timeout_s: float = 45.0) -> None:
        """
        Ждём, пока на странице появятся текстовые поля формы. Если не появились —
        диагностируем причину (заблокированные ресурсы / CORS / пустой HTML)
        и бросаем PageBlankError вместо безликого FormNotFoundError.
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with contextlib.suppress(Exception):
                if page.is_closed():
                    raise BrowserCrashedError("страница закрылась во время загрузки")
            try:
                if await self._text_inputs(page):
                    log.info("[reg] страница загружена, поля формы на месте")
                    return
            except PWError as exc:
                if "Target page, context or browser has been closed" in str(exc):
                    raise BrowserCrashedError(f"браузер закрылся: {exc}") from exc
            await asyncio.sleep(1.0)

        # поля так и не появились — разбираемся почему
        await self.dump_page(page, "blank_page")
        html_len = 0
        with contextlib.suppress(Exception):
            html_len = len(await page.content())
        cors = [b for b in self._blocked if "cdninstagram" in b or "fbcdn" in b]
        log.error(
            "[reg] страница пустая: html=%s байт, упавших запросов=%s (из них CDN=%s)",
            html_len, len(self._blocked), len(cors),
        )
        for line in self._blocked[:8]:
            log.error("[reg]   заблокирован: %s", line)
        for line in self._console_errors[:8]:
            log.error("[reg]   console: %s", line)

        if cors or any("CORS" in c for c in self._console_errors):
            raise PageBlankError(
                f"JS/CSS с CDN заблокированы CORS-политикой ({len(cors)} запросов). "
                "Обычно это значит, что в extra_http_headers попал «не-простой» "
                "заголовок (Upgrade-Insecure-Requests / sec-ch-ua-*) — он "
                "провоцирует preflight, который CDN Instagram не разрешает."
            )
        if html_len < 2000:
            raise PageBlankError(
                f"Instagram отдал почти пустой HTML ({html_len} байт) — "
                "похоже на блокировку по IP/фингерпринту или на страницу-заглушку"
            )
        raise PageBlankError(
            f"форма не появилась за {timeout_s:.0f} с (html={html_len} байт, "
            f"ошибок консоли={len(self._console_errors)})"
        )

    # -- шаги ---------------------------------------------------------------
    #: тексты промежуточных экранов Meta («Начните использовать Instagram с
    #: помощью аккаунта Meta») — их надо прокликать до появления полей
    INTERSTITIAL_TEXTS = ("Sign up with email", "Зарегистрироваться с помощью "
                          "электронной почты", "Create account", "Создать аккаунт",
                          "Create new account", "Продолжить", "Continue",
                          "Get started", "Начать")

    async def _skip_interstitial(self, page: Page, attempts: int = 3) -> None:
        """
        На /accounts/emailsignup/ Meta может показать промежуточный экран
        «Начните использовать Instagram с помощью аккаунта Meta» — тогда
        текстовых полей ещё нет, и их надо сначала открыть кликом.
        """
        for _ in range(attempts):
            if await self._text_inputs(page):
                return
            clicked = False
            for text in self.INTERSTITIAL_TEXTS:
                with contextlib.suppress(Exception):
                    btn = page.get_by_role(
                        "button", name=re.compile(re.escape(text), re.I)
                    ).first
                    await btn.wait_for(state="visible", timeout=1500)
                    log.info("[reg] промежуточный экран: жму «%s»", text)
                    await self.human.human_click(btn, label=f"interstitial:{text}")
                    clicked = True
                    break
            if not clicked:
                return
            await rnd(1.5, 3.5)

    async def open_signup(self, page: Page) -> None:
        log.info("[reg] открываю %s", self.cfg.TARGET_URL)
        self._blocked: list[str] = []
        self._console_errors: list[str] = []
        self._attach_diagnostics(page)

        try:
            await page.goto(self.cfg.TARGET_URL, wait_until="domcontentloaded",
                            timeout=60000)
        except (PWTimeout, PWError) as exc:
            msg = str(exc)
            if "Target page, context or browser has been closed" in msg:
                raise BrowserCrashedError(f"страница/браузер закрылись на goto: {exc}") from exc
            raise ProxyDeadError(f"instagram.com недоступен через прокси: {exc}") from exc

        await self._wait_page_ready(page)
        await long_rnd(2.0, 5.0)
        await self.human.wander(page, random.uniform(1.0, 3.0))

        # закрываем cookie-баннер
        for sel in ('button:has-text("Allow all cookies")', 'button:has-text("Allow essential and optional cookies")',
                    'button:has-text("Разрешить")', 'button:has-text("Decline optional cookies")',
                    '[data-testid="cookie-policy-manage-dialog-accept-button"]'):
            with contextlib.suppress(PWError, PWTimeout):
                btn = page.locator(sel).first
                if await btn.count() and await btn.is_visible():
                    await btn.click(timeout=5000)
                    log.info("[reg] cookie-баннер закрыт (%s)", sel)
                    await rnd(0.8, 2.0)
                    break

        # промежуточный экран Meta-аккаунта (если он есть) прокликиваем
        await self._skip_interstitial(page)

    async def fill_contact(self, page: Page, ident: Identity,
                           method: str) -> None:
        """Шаг 1: email ИЛИ номер телефона."""
        key = "email" if method == "email" else "phone"
        field = await self.locate(page, key, timeout_ms=15000)
        value = ident.email if method == "email" else f"+{ident.phone}"
        log.info("[reg] заполняю contact-поле (%s) = %s", method, value)
        await self.human.human_type(field, value)
        await self._verify_typed(field, value, "contact")

    async def fill_fullname(self, page: Page, ident: Identity) -> None:
        field = await self.locate_optional(page, "fullname", timeout_ms=6000)
        if field is None:
            log.debug("[reg] поле fullName отсутствует — пропускаю")
            return
        await self.human.press_tab(page)
        await self.human.human_type(field, ident.full_name)
        await self._verify_typed(field, ident.full_name, "fullname")

    async def fill_username(self, page: Page, ident: Identity) -> None:
        """
        Username — это input[type=search][role=combobox] с aria-autocomplete=list.

        ВНИМАНИЕ: нажимать Escape на input[type=search] нельзя — Chromium
        трактует это как «отмена поиска» и ПОЛНОСТЬЮ ОЧИЩАЕТ поле.
        Автокомплит закрываем через blur + клик в пустое место.
        """
        field = await self.locate_optional(page, "username", timeout_ms=6000)
        if field is None:
            log.debug("[reg] поле username отсутствует — пропускаю")
            return
        await self.human.press_tab(page)
        await self.human.human_type(field, ident.username)
        await self._dismiss_autocomplete(page, field)
        await self._verify_typed(field, ident.username, "username")
        await self.ensure_username_free(page, ident, field)

    async def _username_feedback(self, page: Page) -> str:
        """
        Что IG ответил про ник: 'valid' | 'taken' | 'unknown'.

        Ответ висит в aria-describedby у поля текстом «The username X is not
        available.» плюс иконка с title «Input Username is valid./is invalid.».
        """
        with contextlib.suppress(PWError, PWTimeout):
            field = page.locator('input[type="search"][role="combobox"]').first
            if await field.count():
                described = await field.get_attribute("aria-describedby")
                if described:
                    with contextlib.suppress(Exception):
                        text = (await page.locator(f"#{described}").inner_text(
                            timeout=1500)).lower()
                        if "not available" in text or "unavailable" in text:
                            return "taken"
                        if "invalid" in text:
                            return "invalid"
                if (await field.get_attribute("aria-invalid")) == "true":
                    return "taken"
        with contextlib.suppress(Exception):
            # у части svg/title inner text = None, join на таком падает
            hints = [h for h in await page.locator("title").all_inner_texts() if h]
            joined = " ".join(hints).lower()
            if "username is valid" in joined:
                return "valid"
            if "username is invalid" in joined:
                return "taken"
        return "unknown"

    async def ensure_username_free(self, page: Page, ident: Identity,
                                   field: Any | None = None) -> None:
        """
        Ждём проверку ника (дебаунс 500 мс + сеть) и меняем ник, если занят.

        Без этого занятый ник всплывал только после submit: форма оставалась
        на месте с aria-invalid=true, экран кода не появлялся, а повторные
        клики по Submit жали одно и то же «not available».
        """
        if field is None:
            field = await self.locate_optional(page, "username", timeout_ms=4000)
        if field is None:
            return
        for round_no in range(1, 5):
            await asyncio.sleep(random.uniform(1.2, 2.2))
            verdict = await self._username_feedback(page)
            if verdict == "valid":
                log.info("[reg] username %s свободен", ident.username)
                return
            if verdict == "unknown":
                if round_no >= 2:
                    log.debug("[reg] валидация ника не ответила — продолжаю")
                    return
                continue
            new_uname = self.factory.username(*ident.full_name.split()[:2])
            if field is not None:
                field = page.locator('input[type="search"][role="combobox"]').first
            if await field.count() == 0:
                return
            log.warning("[reg] username %s занят/невалиден (%s) — беру %s",
                        ident.username, verdict, new_uname)
            await field.click(timeout=8000)
            await field.fill("")
            await self.human.human_type(field, new_uname)
            old_email = ident.email
            ident.username = new_uname
            ident.email = self.factory.email_address(new_uname)
            # форма отправит ТО, что в поле контакта, а письмо придёт на новую
            # почту — поэтому перепечатываем и contact-поле
            if old_email != ident.email:
                contacts = await self._text_inputs(page)
                if contacts:
                    await contacts[0].click(timeout=8000)
                    await contacts[0].fill("")
                    await self.human.human_type(contacts[0], ident.email)
                    await self._verify_typed(contacts[0], ident.email, "contact")
            log.info("[reg] новый ник %s, почта %s", new_uname, ident.email)
            await self._dismiss_autocomplete(page, field)
            await self._verify_typed(field, new_uname, "username")
        log.warning("[reg] не удалось подобрать свободный ник за 4 попытки")

    async def _dismiss_autocomplete(self, page: Page, field: Any) -> None:
        """Закрываем listbox подсказок, НЕ трогая значение поля."""
        with contextlib.suppress(PWError):
            await field.evaluate("(el) => el.blur()")
        await asyncio.sleep(random.uniform(0.2, 0.6))
        with contextlib.suppress(PWError):
            # клик в пустой угол страницы — снимает фокус и прячет подсказки
            await page.mouse.click(4, 4)
        await asyncio.sleep(random.uniform(0.3, 0.8))

    async def _verify_typed(self, field: Any, expected: str, label: str) -> bool:
        """
        Контроль: значение реально легло в поле. Если нет — допечатываем
        клавиатурой. Защищает от нативных «очисток» (search/Escape), автозамены
        и дропающих событий у React-форм.
        """
        with contextlib.suppress(PWError):
            actual = await field.input_value()
            if actual == expected:
                return True
            log.warning("[reg] поле %s: ожидалось %r, получили %r — повторяю ввод",
                        label, expected[:24], actual[:24])
            await field.click(timeout=8000)
            if actual:
                await field.fill("")
            await field.type(expected, delay=random.randint(40, 120))
            actual = await field.input_value()
            if actual != expected:
                log.error("[reg] поле %s так и не заполнено (%r != %r)",
                          label, actual[:24], expected[:24])
                return False
            log.info("[reg] поле %s заполнено со второй попытки", label)
            return True
        return False

    async def fill_password(self, page: Page, ident: Identity) -> None:
        field = await self.locate_optional(page, "password", timeout_ms=6000)
        if field is None:
            return
        await self.human.press_tab(page)
        await self.human.human_type(field, ident.password)
        await self._verify_typed(field, ident.password, "password")
        # IG показывает чекбокс «Save password» — иногда жмём
        with contextlib.suppress(PWError, PWTimeout):
            cb = page.locator('input[name="persistLogin"]').first
            if await cb.count() and random.random() < 0.5:
                await cb.check(timeout=5000)
                await rnd(0.6, 1.8)

    #: названия месяцев для выбора в listbox (EN + RU, полные и короткие)
    MONTH_NAMES = {
        1: ("january", "jan", "январь", "янв"),
        2: ("february", "feb", "февраль", "фев"),
        3: ("march", "mar", "март", "мар"),
        4: ("april", "apr", "апрель", "апр"),
        5: ("may", "май"),
        6: ("june", "jun", "июнь", "июн"),
        7: ("july", "jul", "июль", "июл"),
        8: ("august", "aug", "август", "авг"),
        9: ("september", "sep", "сентябрь", "сен"),
        10: ("october", "oct", "октябрь", "окт"),
        11: ("november", "nov", "ноябрь", "ноя"),
        12: ("december", "dec", "декабрь", "дек"),
    }

    async def _birthday_widgets(self, page: Page) -> dict[str, Any]:
        """
        Виджеты дня/месяца/года в текущей вёрстке Meta: это НЕ <select>,
        а div[role="combobox"][aria-haspopup="listbox"] с aria-label
        «Выберите день» / «Выберите месяц» / «Выберите год».
        """
        loc = page.locator('[role="combobox"][aria-haspopup="listbox"]')
        ordered: list[tuple[Any, str]] = []
        with contextlib.suppress(PWError):
            n = await loc.count()
            for i in range(min(n, 8)):
                el = loc.nth(i)
                with contextlib.suppress(Exception):
                    if not await el.is_visible():
                        continue
                    label = (await el.get_attribute("aria-label")) or ""
                    if not label:
                        label = (await el.inner_text(timeout=2000)).strip()
                    ordered.append((el, label))

        out: dict[str, Any] = {}
        for el, label in ordered:
            for key, rx in self.BIRTHDAY_LABELS.items():
                if key not in out and rx.search(label or ""):
                    out[key] = (el, label)
        # fallback: порядок в DOM — день, месяц, год (по дампу страницы)
        for i, key in enumerate(("day", "month", "year")):
            if key not in out and i < len(ordered):
                out[key] = ordered[i]
        if out:
            log.info("[reg] birthday-виджеты: %s",
                     {k: (v[1] or "<без подписи>") for k, v in out.items()})
        return out

    async def _pick_listbox_option(self, page: Page, widget: Any, key: str,
                                   value: int, label: str) -> bool:
        """Открывает виджет и кликает нужный option в listbox."""
        await self.human.human_click(widget, label=f"birthday-{key}")

        lb = page.locator('[role="listbox"]:visible').last
        with contextlib.suppress(PWTimeout, PWError):
            await lb.wait_for(state="visible", timeout=6000)

        opts = page.locator('[role="option"]')
        count = 0
        with contextlib.suppress(PWError):
            count = await opts.count()
        if not count:
            log.warning("[reg] listbox для '%s' пуст", key)
            return False

        wanted = {str(value), f"{value:02d}"}
        if key == "month":
            wanted |= set(self.MONTH_NAMES.get(value, ()))

        # 1) точное совпадение текста опции
        for i in range(min(count, 200)):
            opt = opts.nth(i)
            with contextlib.suppress(Exception):
                if not await opt.is_visible():
                    continue
                text = (await opt.inner_text(timeout=1500)).strip().lower()
                if text in {w.lower() for w in wanted}:
                    await self.human.human_click(opt, label=f"option-{key}={text}")
                    log.info("[reg] %s = %s (по тексту)", key, text)
                    return True

        # 2) по индексу (listbox может быть виртуализован)
        idx = value - 1
        if 0 <= idx < count:
            with contextlib.suppress(Exception):
                opt = opts.nth(idx)
                await opt.scroll_into_view_if_needed(timeout=3000)
                await self.human.human_click(opt, label=f"option-{key}#index{idx}")
                log.warning("[reg] %s выбран по индексу %s (текст не совпал)", key, idx)
                return True

        log.warning("[reg] опция %s=%s не найдена среди %s вариантов", key, value, count)
        with contextlib.suppress(PWError):
            await page.keyboard.press("Escape")
        return False

    async def fill_birthday(self, page: Page, ident: Identity) -> None:
        """
        Дата рождения. Сначала пробуем новые combobox-виджеты Meta,
        затем классические <select> (старая вёрстка / A/B-варианты).
        """
        year, month, day = ident.birthday
        await rnd(1.0, 2.5)

        widgets = await self._birthday_widgets(page)
        if widgets:
            done = []
            for key, value in (("month", month), ("day", day), ("year", year)):
                if key not in widgets:
                    continue
                el, label = widgets[key]
                if await self._pick_listbox_option(page, el, key, value, label):
                    done.append(key)
                await rnd(0.8, 2.0)
            if len(done) == 3:
                return
            log.warning("[reg] через combobox заполнено %s из 3 — пробую <select>", done)

        # fallback: обычные селекты
        selects = []
        for key in ("birthday_month", "birthday_day", "birthday_year"):
            loc = await self.locate_optional(page, key, timeout_ms=2000)
            if loc is not None:
                selects.append((key, loc))
        if not selects:
            await self.dump_page(page, "no_birthday")
            log.debug("[reg] birthday-контролы не найдены")
            return

        values = {"birthday_month": month, "birthday_day": day, "birthday_year": year}
        for key, loc in selects:
            value = str(values[key])
            with contextlib.suppress(Exception):
                await loc.select_option(value=value, timeout=5000)
                log.debug("[reg] %s = %s", key, value)
                await rnd(0.7, 2.0)
                continue
            with contextlib.suppress(Exception):
                await loc.click(timeout=5000)
                await page.keyboard.type(value, delay=random.randint(50, 120))
                await page.keyboard.press("Enter")
                await rnd(0.7, 2.0)

    async def _check_inline_error(self, page: Page, field: str) -> None:
        """Инлайн-ошибка под полем (username занят / неверный формат)."""
        with contextlib.suppress(Exception):
            el = page.locator(f'input[aria-invalid="true"]')
            if await el.count():
                text = (await page.locator("body").inner_text(timeout=3000)).lower()
                for marker in self.REJECT_MARKERS:
                    if marker in text:
                        raise AccountRejectedError(
                            f"инлайн-ошибка у поля '{field}': «{marker}»")

    #: тексты кнопок подтверждения кода (div[role=button] в текущей вёрстке)
    CODE_SUBMIT_TEXTS = ("Далее", "Next", "Подтвердить", "Confirm", "Отправить",
                         "Submit", "Continue", "Продолжить")

    async def _click_button_by_text(self, page: Page, texts: tuple[str, ...],
                                    label: str) -> bool:
        """
        Кликает видимую кнопку по тексту. В текущей вёрстке Meta кнопки — это
        div[role="button"][tabindex="0"], а не <button>, поэтому сначала идём
        через get_by_role, затем через структурные CSS-селекторы.
        """
        for text in texts:
            rx = re.compile(rf"^\s*{re.escape(text)}\s*$", re.I)
            with contextlib.suppress(Exception):
                btn = page.get_by_role("button", name=rx).first
                await btn.wait_for(state="visible", timeout=2000)
                log.info("[reg] %s: кнопка «%s» (role=button)", label, text)
                if await self.gate._safe_click(page, btn, self.human, f"{label}:{text}"):
                    return True

        for sel in ('div[role="button"][tabindex="0"]', 'button[type="submit"]',
                    'div[role="button"]', 'button'):
            with contextlib.suppress(PWError, PWTimeout):
                loc = page.locator(sel)
                n = await loc.count()
                for i in range(min(n, 12)):
                    el = loc.nth(i)
                    with contextlib.suppress(Exception):
                        if not await el.is_visible():
                            continue
                        txt = (await el.inner_text(timeout=1500)).strip().lower()
                        if txt and any(t.lower() == txt for t in texts):
                            log.info("[reg] %s: кнопка «%s» (%s)", label, txt, sel)
                            if await self.gate._safe_click(page, el, self.human,
                                                      f"{label}:{sel}"):
                                return True

        # --- запасной поиск: primary-CTA по структуре, если текст не совпал ---
        # Meta часто меняет подпись кнопки (Submit/Sign up/Next/…), но она почти
        # всегда последняя видимая div[role=button][tabindex=0] с коротким текстом,
        # не иконка и не одна из служебных (Back / Hide password / I already have…).
        cands: list[tuple[Any, str]] = []
        with contextlib.suppress(PWError, PWTimeout):
            loc = page.locator('div[role="button"][tabindex="0"]')
            n = await loc.count()
            for i in range(min(n, 20)):
                el = loc.nth(i)
                with contextlib.suppress(Exception):
                    if not await el.is_visible():
                        continue
                    if (await el.get_attribute("aria-disabled")) == "true":
                        continue
                    txt = (await el.inner_text(timeout=1200)).strip()
                    low = txt.lower()
                    if not txt or len(txt) > 40:
                        continue                        # иконка или длинный блок
                    if any(bad in low for bad in self.NON_SUBMIT_TEXTS):
                        continue                        # служебная кнопка
                    if await el.locator("svg").count() and not txt:
                        continue                        # чисто иконочная
                    cands.append((el, txt))

        if cands:
            el, txt = cands[-1]                         # primary CTA — последняя
            log.warning("[reg] %s: текст не совпал, беру primary-CTA «%s» "
                        "(кандидатов: %s)", label, txt, [c[1] for c in cands])
            await self.gate._safe_click(page, el, self.human, f"{label}:primary-cta")
            return True

        await self.dump_page(page, f"nosubmit_{label}")
        return False

    async def submit(self, page: Page, ident: Identity | None = None) -> None:
        """
        Submit в текущей вёрстке Meta — это div[role="button"][tabindex="0"]
        с текстом «Отправить»/«Sign up», а не <button type=submit>.

        IG (Meta Account flow) иногда молча глотает первый клик: форма остаётся
        на месте, экран кода не появляется. Поэтому после клика проверяем, что
        шаг реально сменился, и повторяем отправку (Enter в пароле + повторный
        клик) — до трёх раз. Все XHR регистрации пишутся в лог.
        """
        self._net_log: list[str] = []

        def on_response(resp: Any) -> None:
            url = resp.url
            if not re.search(r"create|signup|sign_up|graphql|accounts", url):
                return
            if resp.request.resource_type not in ("xhr", "fetch"):
                return
            if len(self._net_log) >= 40:
                return
            self._net_log.append(f"HTTP {resp.status} {url.split('?')[0][-70:]}")

            async def read_body() -> None:
                with contextlib.suppress(Exception):
                    body = (await resp.text())[:500]
                    if body:
                        self._net_log.append("  BODY " + body.replace("\n", " "))

            with contextlib.suppress(Exception):
                asyncio.get_event_loop().create_task(read_body())

        with contextlib.suppress(Exception):
            page.on("response", on_response)

        async def step_changed() -> bool:
            with contextlib.suppress(PWError, PWTimeout):
                pwd = page.locator('input[type="password"]')
                if await pwd.count() == 0 or not await pwd.first.is_visible():
                    return True
            if await self.arkose.is_present(page, timeout_ms=200):
                return True
            if await self.arkose.is_recaptcha_present(page, timeout_ms=200):
                return True
            if await self.gate.is_image_captcha(page):
                return True
            with contextlib.suppress(PWError, PWTimeout):
                code_field = page.locator(
                    'input[maxlength="6"], input[inputmode="numeric"], '
                    'input[autocomplete="one-time-code"]').first
                if await code_field.count() and await code_field.is_visible():
                    return True
            return False

        for attempt in range(1, 4):
            clicked = await self._click_button_by_text(page, self.SUBMIT_TEXTS, "submit")
            if not clicked:
                log.info("[reg] кнопки отправки нет — пробую Enter")
                with contextlib.suppress(PWError):
                    await page.keyboard.press("Enter")

            for _ in range(12):
                await asyncio.sleep(1.0)
                if await step_changed():
                    log.info("[reg] шаг сменился после отправки (попытка %s)", attempt)
                    return

            log.warning("[reg] после submit шаг не сменился (попытка %s/3), "
                        "url=%s", attempt, page.url[:70])
            # IG мог ответить «username is not available» уже после клика
            if ident is not None and await self._username_feedback(page) == "taken":
                await self.ensure_username_free(page, ident)
            # снимаем фокус с полей (валидация по blur) и повторяем иначе
            with contextlib.suppress(Exception):
                await page.locator('input[type="password"]').first.click(timeout=3000)
                await page.keyboard.press("Enter")
            await rnd(2.0, 4.0)

        await self.dump_page(page, "submit_stuck")
        log.error("[reg] сетевые ответы сабмита: %s", self._net_log or "XHR не было")

    async def check_rejection(self, page: Page) -> None:
        """Проверяем текст страницы на маркеры отказа."""
        with contextlib.suppress(PWError):
            body = (await page.locator("body").inner_text(timeout=5000)).lower()
        for marker in self.REJECT_MARKERS:
            if marker in body:
                raise AccountRejectedError(f"IG отклонил регистрацию: «{marker}»")

    async def wait_for_code_prompt(self, page: Page, timeout_ms: int = 90000) -> bool:
        """
        Ждём появления поля ввода кода. Попутно решаем Arkose, если он
        выскочил раньше. Возвращает True, если поле кода найдено.
        """
        deadline = time.monotonic() + timeout_ms / 1000
        while time.monotonic() < deadline:
            # 1) челлендж?
            if await self.arkose.is_present(page, timeout_ms=1500):
                await self.arkose.handle(page)
                continue
            if await self.arkose.is_recaptcha_present(page, timeout_ms=1000):
                await self.arkose.handle_recaptcha(page)
                continue
            if await self.gate.is_image_captcha(page):
                await self.gate.solve_image_captcha(page, self.human)
                await asyncio.sleep(3.0)
                continue
            # 2) поле кода?
            loc = await self.locate_optional(page, "code", timeout_ms=2500)
            if loc is not None:
                return True
            # 3) нас уже кинуло в ленту — верификация не требуется
            if re.search(r"instagram\.com/?$|/accounts/onetap|/\?next=", page.url):
                if await page.locator('img[alt*="profile" i], [aria-label*="Profile" i]').count():
                    log.info("[reg] попали в ленту без запроса кода")
                    return False
            await asyncio.sleep(2.0)
            await self.check_rejection_silent(page)
        await self.dump_page(page, "no_code_prompt")
        log.error("[reg] сетевые ответы сабмита: %s",
                  getattr(self, "_net_log", None) or "XHR не было")
        raise VerificationTimeoutError("поле ввода кода так и не появилось за 90 сек")

    async def check_rejection_silent(self, page: Page) -> None:
        with contextlib.suppress(Exception):
            await self.check_rejection(page)

    async def enter_code(self, page: Page, code: str) -> None:
        # быстрый путь: поле кода ищем одним проходом, без перебора SEL
        # (перебор по 6 с съедал до минуты, и код успевал протухнуть)
        loc = None
        for _ in range(15):
            loc = await self.gate._code_input(page)
            if loc is not None:
                break
            await asyncio.sleep(1.0)
        if loc is None:
            loc = await self.locate(page, "code", timeout_ms=8000)
        log.info("[reg] ввожу код подтверждения %s", code)
        with contextlib.suppress(Exception):
            await loc.focus()
        with contextlib.suppress(Exception):
            await loc.click(force=True, timeout=5000)
        with contextlib.suppress(Exception):
            await loc.fill("")
        await asyncio.sleep(random.uniform(0.3, 0.7))
        with contextlib.suppress(Exception):
            await page.keyboard.type(code, delay=random.randint(50, 120))
        got = ""
        with contextlib.suppress(Exception):
            got = await loc.input_value()
        if got != code:
            with contextlib.suppress(Exception):
                await loc.fill(code)
                got = await loc.input_value()
        log.info("[reg] в поле кода %r", got)
        if got != code:
            log.error("[reg] код не введён (%r != %r)", got, code)
        await rnd(1.0, 2.0)

        # Enter сработает не везде — параллельно ищем ВИДИМУЮ кнопку.
        # В текущей вёрстке Meta это div[role=button] «Далее», поэтому
        # обычный locator('button[type=submit]') её не находит.
        clicked = await self._click_button_by_text(page, self.CODE_SUBMIT_TEXTS,
                                                   "submit-code")
        if not clicked:
            for sel in self.SEL["submit"]:
                with contextlib.suppress(PWError, PWTimeout):
                    btns = page.locator(sel)
                    for i in range(min(await btns.count(), 6)):
                        btn = btns.nth(i)
                        if await btn.is_visible():
                            clicked = await self.gate._safe_click(
                                page, btn, self.human, f"submit-code:{sel}")
                            break
                if clicked:
                    break

        # Подстраховка нужна, но осторожно: повторный сабмит, пока IG ещё
        # обрабатывает первый, даёт «code is invalid or has expired».
        # Ждём до 20 с и дожимаем только если поле на месте и ошибки нет.
        field_sel = ('textarea[autocomplete="one-time-code"], '
                     'textarea[maxlength="6"], input[maxlength="6"], '
                     'input[autocomplete="one-time-code"]')
        still = None
        for _ in range(20):
            await asyncio.sleep(1.0)
            with contextlib.suppress(PWError):
                body = (await page.locator("body").inner_text(timeout=3000)).lower()
                if "invalid" in body or "expired" in body:
                    log.warning("[reg] IG отверг код (invalid/expired)")
                    still = None
                    break
            loc2 = page.locator(field_sel).first
            with contextlib.suppress(PWError, PWTimeout):
                if await loc2.count() and await loc2.is_visible():
                    still = loc2
                    continue
            still = None
            break
        if still is not None:
            with contextlib.suppress(Exception):
                await still.press("Enter")
            with contextlib.suppress(PWError):
                await page.keyboard.press("Enter")
            log.info("[reg] код всё ещё на экране без ошибки — дожал Enter'ом")
        await self._verify_typed(loc, code, "code")

    async def confirm_logged_in(self, page: Page, timeout_ms: int = 60000,
                                mail: Any = None, email: str | None = None,
                                since_ts: float = 0.0, sms: Any = None,
                                session: Any = None,
                                box: dict[str, Any] | None = None) -> None:
        """
        Ждём появления авторизованной сессии и ПРОХОДИМ человеческий гейт.

        Важно: sessionid появляется ещё до гейта, поэтому старый вариант
        «увидел cookie -> уходим» оставлял аккаунт в suspended, а траст потом
        молча работал по странице-заглушке.
        """
        deadline = time.monotonic() + timeout_ms / 1000
        retries = 0
        while time.monotonic() < deadline:
            if await self.arkose.is_present(page, timeout_ms=1500):
                await self.arkose.handle(page)
            # код отвергнут — запрашиваем новый и вводим (до 2 раз)
            if retries < 2 and mail is not None and email:
                with contextlib.suppress(PWError):
                    body = (await page.locator("body").inner_text(timeout=3000)).lower()
                    if ("invalid" in body and "expired" in body) or "недействителен" in body:
                        retries += 1
                        log.warning("[reg] код отвергнут — запрашиваю новый (%s/2)",
                                    retries)
                        await self.gate._click_any(
                            page, self.human,
                            ("Request new code", "Get a new code", "Новый код",
                             "Отправить новый код"), "code-retry")
                        since = time.time()
                        await asyncio.sleep(3.0)
                        try:
                            code = await mail.wait_for_code(email, since)
                        except Exception:  # noqa: BLE001
                            code = ""
                        if code:
                            field = await self.locate_optional(page, "code",
                                                               timeout_ms=6000)
                            if field is not None:
                                with contextlib.suppress(Exception):
                                    await field.focus()
                                    await field.fill("")
                                with contextlib.suppress(Exception):
                                    await page.keyboard.type(code, delay=110)
                                await asyncio.sleep(1.0)
                                await self.gate._click_any(
                                    page, self.human,
                                    ("Continue", "Next", "Далее"), "code-retry-submit")
            with contextlib.suppress(PWError):
                cookies = await page.context.cookies("https://www.instagram.com")
            names = {c["name"] for c in cookies}
            if "sessionid" in names or "ds_user_id" in names:
                log.info("[reg] сессия получена (sessionid в cookies)")
                if self.cfg.ENABLE_GATE and await self.gate.is_gate(page):
                    ok = await self.gate.pass_gate(page, self.human, self.arkose,
                                                   mail, email, since_ts,
                                                   sms, session, box)
                    if not ok:
                        raise SuspendedError(
                            f"аккаунт остался на гейте проверки (url={page.url})")
                    log.info("[reg] гейт проверки пройден")
                return
            if "checkpoint" in page.url:
                await self.dump_page(page, "checkpoint")
                raise AccountRejectedError(f"IG выдал checkpoint: {page.url}")
            await asyncio.sleep(3.0)
        await self.dump_page(page, "no_session")
        body = ""
        with contextlib.suppress(PWError):
            body = (await page.locator("body").inner_text(timeout=5000)).strip()[:200]
        log.error("[reg] страница без сессии: %r", body)
        raise AccountRejectedError(
            f"после ввода кода сессия не появилась (url={page.url})"
        )

    # -- полный сценарий формы ---------------------------------------------
    async def run_form(self, page: Page, ident: Identity, method: str) -> bool:
        """
        Заполнение формы. Возвращает True, если нужно подтверждение кодом.
        Arkose решается на каждом шаге, где может выскочить.
        """
        await self.open_signup(page)

        await self.fill_contact(page, ident, method)
        await self.fill_fullname(page, ident)
        await self.fill_username(page, ident)
        await self.fill_password(page, ident)
        await self.fill_birthday(page, ident)

        if await self.arkose.is_present(page, timeout_ms=2000):
            await self.arkose.handle(page)

        await self.submit(page, ident)
        await self.check_rejection(page)
        return await self.wait_for_code_prompt(page)


# ===========================================================================
# ВХОД В СУЩЕСТВУЮЩИЙ АККАУНТ — SessionRestorer
# ===========================================================================


class SessionRestorer:
    """
    Логин по паролю, когда сохранённая сессия слетела (IG разлогинивает при
    смене IP). Нужен, чтобы дожать гейт и подписаться, не пересоздавая аккаунт.
    """

    LOGIN_URL = "https://www.instagram.com/accounts/login/"

    def __init__(self, cfg: Config, human: HumanDriver, arkose: ArkoseSolver,
                 gate: HumanGate) -> None:
        self.cfg = cfg
        self.human = human
        self.arkose = arkose
        self.gate = gate

    async def run(self, page: Page, login: str, password: str,
                  mail: Any = None, sms: Any = None, session: Any = None,
                  box: dict[str, Any] | None = None) -> bool:
        try:
            await page.goto(self.LOGIN_URL, wait_until="domcontentloaded",
                            timeout=60000)
        except (PWError, PWTimeout) as exc:
            log.error("[login] не открылась страница входа: %s", exc)
            return False
        await asyncio.sleep(random.uniform(2.0, 4.0))

        user = page.locator('input[name="email"], input[name="username"]').first
        pwd = page.locator('input[name="pass"], input[name="password"]').first
        if await user.count() == 0 or await pwd.count() == 0:
            # гостевую страницу IG часто отдаёт с кнопкой Log In вместо формы
            for text in ("Log In", "Log in", "Войти"):
                with contextlib.suppress(Exception):
                    btn = page.get_by_role(
                        "button", name=re.compile(rf"^\s*{re.escape(text)}\s*$",
                                                  re.I)).first
                    if await btn.count() and await btn.is_visible():
                        await self.gate._safe_click(page, btn, self.human,
                                                    f"login-open:{text}")
                        await asyncio.sleep(random.uniform(2.0, 4.0))
                        break
        src = page.locator(
            'input[name="email"], input[name="username"], input[name="pass"]').first
        for _ in range(20):
            with contextlib.suppress(PWError, PWTimeout):
                if await src.count() and await src.is_visible():
                    break
            await asyncio.sleep(1.0)
        user = page.locator('input[name="email"], input[name="username"]').first
        pwd = page.locator('input[name="pass"], input[name="password"]').first
        if await user.count() == 0 or await pwd.count() == 0:
            log.warning("[login] формы входа нет (url=%s)", page.url[:70])
            return await self._session_alive(page)

        for field, value in ((user, login), (pwd, password)):
            with contextlib.suppress(Exception):
                await field.click(force=True, timeout=5000)
            with contextlib.suppress(Exception):
                await field.fill("")
            await self.human.human_type(field, value)
            await rnd(0.5, 1.2)

        # форма отправляется скрытым input[type=submit] — Enter в пароле надёжнее
        with contextlib.suppress(Exception):
            await pwd.press("Enter")
        with contextlib.suppress(PWError):
            await page.keyboard.press("Enter")
        await asyncio.sleep(random.uniform(1.5, 3.0))

        clicked = False
        for text in ("Log in", "Log in ", "Войти", "Вход"):
            with contextlib.suppress(Exception):
                btn = page.get_by_role(
                    "button", name=re.compile(rf"^\s*{re.escape(text)}\s*$", re.I)).first
                if await btn.count() and await btn.is_visible():
                    clicked = await self.gate._safe_click(page, btn, self.human,
                                                          f"login:{text}")
                    if clicked:
                        break
        if not clicked:
            with contextlib.suppress(PWError):
                await page.keyboard.press("Enter")

        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            await asyncio.sleep(2.0)
            if await self._session_alive(page):
                log.info("[login] вход выполнен")
                await self._dismiss_after_login(page)
                return True
            if await self.gate.is_gate(page):
                log.warning("[login] после входа гейт — прохожу")
                if await self.gate.pass_gate(page, self.human, self.arkose, mail,
                                             login, time.time(), sms, session, box):
                    return True
            with contextlib.suppress(PWError):
                body = (await page.locator("body").inner_text(timeout=3000)).lower()
                if "password was incorrect" in body or "неверн" in body:
                    log.error("[login] пароль не подошёл")
                    return False
        with contextlib.suppress(Exception):
            await self.gate._dump(page, "login_failed")
            body = (await page.locator("body").inner_text(timeout=4000))[:300]
            log.error("[login] страница: %r", body)
        log.error("[login] вход не подтвердился (url=%s)", page.url)
        return False

    async def _session_alive(self, page: Page) -> bool:
        """Сессия реально работает: есть cookie и нет гостевых признаков."""
        if "/accounts/login" in page.url:
            return False
        with contextlib.suppress(PWError):
            cookies = await page.context.cookies("https://www.instagram.com")
            if not any(c["name"] == "sessionid" for c in cookies):
                return False
        with contextlib.suppress(PWError):
            body = (await page.locator("body").inner_text(timeout=4000)).lower()
            if ("see everyday moments" in body
                    or "log in to see their photos" in body
                    or "already follow" in body):
                return False
            return True
        return False

    async def _dismiss_after_login(self, page: Page) -> None:
        for text in ("Not Now", "Not now", "Не сейчас", "Save info", "Save Info"):
            with contextlib.suppress(Exception):
                btn = page.get_by_role("button", name=text).first
                if await btn.count() and await btn.is_visible():
                    await self.gate._safe_click(page, btn, self.human, "post-login")
                    await asyncio.sleep(1.5)


# ===========================================================================
# ДВИЖОК: один цикл регистрации + главный loop
# ===========================================================================


@dataclass
class Stats:
    attempted: int = 0
    success: int = 0
    suspended: int = 0
    failed: int = 0
    captcha_solved: int = 0
    proxy_rotations: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    current_ip: str | None = None
    last_error: str = ""
    accounts: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "success": self.success,
            "suspended": self.suspended,
            "failed": self.failed,
            "captcha_solved": self.captcha_solved,
            "proxy_rotations": self.proxy_rotations,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "current_ip": self.current_ip,
            "last_error": self.last_error,
            "accounts": self.accounts[-50:][::-1],
        }


class Engine:
    """
    Оркестратор. Один `register_one()` = один полный цикл:
      ротация IP -> браузер-контекст -> форма -> Arkose -> верификация
      -> траст (аватар + Follow) -> cookies JSON + success.txt
    Главный `run()` крутит цикл до MAX_ACCOUNTS с рестартами при мёртвом прокси.
    """

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.rotator = ProxyRotator(cfg)
        self.identity_factory = IdentityFactory(cfg)
        self.human = HumanDriver(cfg)
        self.arkose = ArkoseSolver(cfg)
        self.sms = SmsVerifier(cfg)
        self.mail = EmailVerifier(cfg)
        self.trust = TrustBuilder(cfg)
        self.gate = HumanGate(cfg)
        self.storage = Storage(cfg)
        self.browser = BrowserFactory(cfg)
        self.restorer: SessionRestorer | None = None
        self.stats = Stats()
        self._stop = asyncio.Event()

    # ------------------------------------------------------------------ stop
    def stop(self) -> None:
        log.warning("[engine] получен сигнал STOP")
        self._stop.set()

    async def shutdown(self) -> None:
        await self.browser.close()

    # ------------------------------------------------------- один аккаунт
    async def register_one(self, session: aiohttp.ClientSession) -> Identity | None:
        """Один цикл регистрации. Возвращает Identity при успехе, иначе None."""
        self.stats.attempted += 1
        log.info("=" * 78)
        log.info("[engine] ЦИКЛ #%s — метод %s", self.stats.attempted, self.cfg.REG_METHOD)
        log.info("=" * 78)

        # --- 1. ротация IP перед каждым циклом (GET rotation url + sleep 10) ---
        for attempt in range(1, self.cfg.PROXY_MAX_RETRIES + 1):
            try:
                ip = await self.rotator.rotate(session)
                self.stats.current_ip = ip
                self.stats.proxy_rotations = self.rotator.rotations
                break
            except ProxyDeadError as exc:
                log.error("[engine] прокси мёртв (попытка %s/%s): %s",
                          attempt, self.cfg.PROXY_MAX_RETRIES, exc)
                self.stats.last_error = f"proxy: {exc}"
                # лимит трафика у провайдера — остальные попытки бессмысленны
                if "traffic limit" in str(exc):
                    log.error("[engine] у прокси-провайдера кончился трафик — "
                              "пополни лимит, прогон остановлен")
                    await self.storage.save_failed(None, "proxy traffic limit")
                    self.stats.failed += 1
                    return None
                if attempt == self.cfg.PROXY_MAX_RETRIES:
                    await self.storage.save_failed(None, f"proxy dead: {exc}")
                    self.stats.failed += 1
                    return None
                await asyncio.sleep(random.uniform(5, 15))
        else:
            self.stats.failed += 1
            return None

        ident = self.identity_factory.new_identity()
        self.storage.audit(ident.username, "register_started",
                           email=ident.email, ip=self.stats.current_ip)
        activation: SmsActivation | None = None
        context: BrowserContext | None = None
        since_ts = time.time()
        proxy_url = self.rotator.current_endpoint or self.cfg.PROXY
        self.rotator.bind_account(ident.username)
        #: сюда гейт кладёт арендованный номер/код, чтобы движок их закрыл
        gate_box: dict[str, Any] = {}

        try:
            # --- 2. для SMS арендуем номер ДО заполнения формы ---
            if self.cfg.REG_METHOD == "sms":
                log.info("[engine] арендую SMS-номер (%s)", self.cfg.SMS_PROVIDER)
                activation = await self.sms.buy(session)
                ident.phone = activation.phone.lstrip("+")
                log.info("[engine] номер %s (id=%s)", activation.phone, activation.activation_id)

            # --- 3. браузер-контекст со случайным фингерпринтом ---
            fp = self.cfg.random_identity()
            context, page = await self.browser.new_context(fp, proxy_url=proxy_url)
            registrar = InstagramRegistrar(self.cfg, self.human, self.arkose,
                                          self.identity_factory)

            # --- 4. форма ---
            since_ts = time.time()
            need_code = await asyncio.wait_for(
                registrar.run_form(page, ident, self.cfg.REG_METHOD),
                timeout=self.cfg.GLOBAL_TIMEOUT,
            )

            # --- 5. верификация + человеческий гейт ---
            if need_code:
                if self.cfg.REG_METHOD == "email":
                    log.info("[engine] жду email-код на %s", ident.email)
                    code = await self.mail.wait_for_code(ident.email, since_ts)
                else:
                    assert activation is not None
                    log.info("[engine] жду SMS-код на %s", activation.phone)
                    code = await self.sms.wait_for_code(session, activation)
                await registrar.enter_code(page, code)
                await registrar.confirm_logged_in(
                    page, mail=self.mail, email=ident.email, since_ts=since_ts,
                    sms=self.sms, session=session, box=gate_box)
            else:
                with contextlib.suppress(Exception):
                    await registrar.confirm_logged_in(
                        page, timeout_ms=30000, mail=self.mail,
                        email=ident.email, since_ts=since_ts,
                        sms=self.sms, session=session, box=gate_box)

            gate_act = gate_box.get("activation")
            if gate_act is not None and not ident.phone:
                ident.phone = str(gate_act.phone).lstrip("+")
                log.info("[engine] номер из гейта закреплён за аккаунтом: %s",
                         ident.phone)
                with contextlib.suppress(Exception):
                    await self.sms.finish(session, gate_act)
            if await registrar.gate.is_appeal_submitted(page):
                self.storage.audit(ident.username, "appeal_sent")
            log.info("[engine] аккаунт %s зарегистрирован (гейт пройден)", ident.username)

            # --- 6. сохранение сессии и СРАЗУ подписка ---
            # пока сессия и IP «горячие»: у свежих аккаунтов окно доверия
            # короткое, после отлёжки с новым IP IG успевает их снести
            cookies_path = await self.storage.save_cookies(context, ident)
            # сохраняем учётку СРАЗУ: дальше идут долгие ожидания, и при сбое
            # пароль/почта должны остаться в базе
            await self.storage.save_success(ident, proxy_url or self.cfg.proxy_display(),
                                            cookies_path, {}, status="pending")
            self.storage.audit(ident.username, "created",
                               email=ident.email, phone=ident.phone,
                               ip=self.stats.current_ip)
            early_follow = None
            if self.cfg.ENABLE_TRUST:
                if self.restorer is None:
                    self.restorer = SessionRestorer(self.cfg, self.human, self.arkose,
                                                    registrar.gate)
                # на профиле снова может встать гейт — проходим и пробуем снова
                for attempt in range(1, 4):
                    with contextlib.suppress(Exception):
                        if await registrar.gate.is_gate(page):
                            log.warning("[engine] гейт на профиле цели (попытка %s) — "
                                        "прохожу", attempt)
                            await registrar.gate.pass_gate(
                                page, self.human, self.arkose, self.mail,
                                ident.email, since_ts, self.sms, session, gate_box)
                    # сессия могла слететь за время ожидания — входим по паролю
                    with contextlib.suppress(Exception):
                        if not await self.restorer._session_alive(page):
                            log.warning("[engine] сессия слетела на профиле — "
                                        "вхожу по паролю")
                            if await self.restorer.run(page, ident.email,
                                                       ident.password, self.mail,
                                                       self.sms, session, gate_box):
                                target_url = ((self.cfg.TRUST_TARGETS or TRUST_TARGETS)[0])
                                with contextlib.suppress(PWError):
                                    await page.goto(target_url,
                                                    wait_until="domcontentloaded",
                                                    timeout=60000)
                                await asyncio.sleep(random.uniform(2.0, 4.0))
                    with contextlib.suppress(Exception):
                        early_follow = await self.trust.follow_target(
                            page, self.human)
                    if early_follow:
                        log.info("[engine] запрос на подписку отправлен "
                                 "сразу после гейта")
                        break
                    await asyncio.sleep(random.uniform(3.0, 6.0))

            # --- 7. отлёжка: аккаунт «отвисает», как у живого человека.
            #     Без неё Follow через 3 секунды после создания — сильный
            #     сигнал синтетики. Переоткрываем с ТЕМ ЖЕ фингерпринтом и IP.
            pause = random.uniform(min(self.cfg.COOLDOWN_MIN, self.cfg.COOLDOWN_MAX),
                                   max(self.cfg.COOLDOWN_MIN, self.cfg.COOLDOWN_MAX))
            if pause >= 5:
                if self.cfg.CLOSE_BEFORE_COOLDOWN:
                    log.info("[engine] отлёжка %.0f сек (контекст закрыт, "
                             "фингерпринт и прокси сохранены)", pause)
                    await context.close()
                    context = None
                    await asyncio.sleep(pause)
                    context, page = await self.browser.new_context(
                        fp, storage_state=cookies_path, proxy_url=proxy_url)
                else:
                    # держим тот же контекст: IP и сессия не рвутся, а решение
                    # по апелляции приходит именно в это окно. Проверяем
                    # периодически и выходим, как только гейт сняли
                    log.info("[engine] жду решение по апелляции до %.0f сек "
                             "(IP держится 60 мин)", pause)
                    deadline_wait = time.monotonic() + pause
                    while time.monotonic() < deadline_wait:
                        await asyncio.sleep(min(300.0, deadline_wait - time.monotonic()))
                        with contextlib.suppress(PWError):
                            if not await registrar.gate.is_gate(page):
                                log.info("[engine] гейт снят — иду подписываться")
                                break
                        log.info("[engine] гейт ещё висит, ждём дальше")
                with contextlib.suppress(PWError, PWTimeout):
                    await page.goto("https://www.instagram.com/",
                                    wait_until="domcontentloaded", timeout=60000)
                if await registrar.gate.is_gate(page, timeout_ms=3000):
                    log.warning("[engine] после отлёжки снова гейт — прохожу повторно")
                    if not await registrar.gate.pass_gate(
                            page, self.human, self.arkose, self.mail,
                            ident.email, since_ts):
                        raise SuspendedError("гейт повторился после отлёжки")

            # --- 8. траст: аватар + Follow + короткие визиты ---
            self.trust.traffic = self.browser.traffic
            trust_report = await self.trust.run(page, self.human, ident,
                                                do_follow=not early_follow)
            if early_follow and not trust_report.get("followed"):
                trust_report["followed"] = early_follow

            # --- 9. финальное сохранение ---
            cookies_path = await self.storage.save_cookies(context, ident)
            await self.storage.save_success(ident, proxy_url or self.cfg.proxy_display(),
                                            cookies_path, trust_report, status="alive")

            if activation is not None:
                await self.sms.finish(session, activation)

            self.stats.success += 1
            self.stats.captcha_solved = self.arkose.solved
            self.stats.accounts.append({
                **ident.to_dict(),
                "proxy_ip": self.stats.current_ip,
                "status": "alive",
                "trust": trust_report,
                "created_at": datetime.now().isoformat(timespec="seconds"),
            })
            log.info("[engine] SUCCESS #%s — %s", self.stats.success, ident.username)
            return ident

        except SuspendedError as exc:
            # Аккаунт создан, пароль/сессия валидны — он сохранён и его можно
            # дожать отдельно (check_accounts.py --fix). В failed.txt не пишем.
            log.warning("[engine] аккаунт создан, но остался в suspended: %s", exc)
            self.stats.last_error = f"suspended: {exc}"
            self.stats.suspended += 1
            cookies_path = None
            if context is not None:
                with contextlib.suppress(Exception):
                    cookies_path = await self.storage.save_cookies(context, ident)
            with contextlib.suppress(Exception):
                await self.storage.save_success(
                    ident, proxy_url or self.cfg.proxy_display(), cookies_path,
                    {"avatar": False, "warm": False, "gate": False},
                    status="suspended")
            if activation is not None:
                with contextlib.suppress(Exception):
                    await self.sms.finish(session, activation)
            gate_act = gate_box.get("activation")
            if gate_act is not None:
                with contextlib.suppress(Exception):
                    await self.sms.cancel(session, gate_act)
                log.info("[gate] номер %s отменён (аккаунт не закрыт)",
                         gate_act.phone)
            self.stats.accounts.append({
                **ident.to_dict(),
                "proxy_ip": self.stats.current_ip,
                "status": "suspended",
                "created_at": datetime.now().isoformat(timespec="seconds"),
            })
            return ident

        except BannedNumberError as exc:
            log.error("[engine] номер забанен: %s", exc)
            self.stats.last_error = f"banned number: {exc}"
            if activation is not None:
                await self.sms.ban(session, activation)   # отменяем/баним активацию
            await self.storage.save_failed(ident, str(exc))
            self.stats.failed += 1
            return None

        except VerificationTimeoutError as exc:
            log.error("[engine] верификация не прошла: %s", exc)
            self.stats.last_error = f"verification: {exc}"
            if activation is not None:
                await self.sms.cancel(session, activation)   # возврат средств
            await self.storage.save_failed(ident, str(exc))
            self.stats.failed += 1
            return None

        except BrowserCrashedError as exc:
            log.error("[engine] браузер/страница закрылись: %s — перезапускаю браузер", exc)
            self.stats.last_error = f"browser crashed: {exc}"
            with contextlib.suppress(Exception):
                await self.browser.close()          # следующий цикл поднимет новый
            await self.storage.save_failed(ident, str(exc))
            self.stats.failed += 1
            return None

        except PageBlankError as exc:
            log.error("[engine] страница не прогрузилась: %s", exc)
            self.stats.last_error = f"blank page: {exc}"
            if activation is not None:
                await self.sms.cancel(session, activation)
            await self.storage.save_failed(ident, str(exc))
            self.stats.failed += 1
            return None

        except (ProxyDeadError, PWTimeout) as exc:
            log.error("[engine] сеть/прокси легли: %s — цикл будет перезапущен", exc)
            self.stats.last_error = f"proxy/network: {exc}"
            if activation is not None:
                await self.sms.cancel(session, activation)
            await self.storage.save_failed(ident, f"proxy: {exc}")
            self.stats.failed += 1
            return None

        except CaptchaRequiredError as exc:
            log.error("[engine] CAPTCHA не пройдена: %s", exc)
            self.stats.last_error = f"captcha: {exc}"
            if activation is not None:
                await self.sms.cancel(session, activation)
            await self.storage.save_failed(ident, str(exc))
            self.stats.failed += 1
            return None

        except (AccountRejectedError, FormNotFoundError) as exc:
            log.error("[engine] IG отклонил/форма изменилась: %s", exc)
            self.stats.last_error = str(exc)
            if activation is not None:
                await self.sms.cancel(session, activation)
            await self.storage.save_failed(ident, str(exc))
            self.stats.failed += 1
            return None

        except asyncio.TimeoutError as exc:
            log.error("[engine] GLOBAL_TIMEOUT превышен: %s", exc)
            self.stats.last_error = "global timeout"
            if activation is not None:
                await self.sms.cancel(session, activation)
            await self.storage.save_failed(ident, "global timeout")
            self.stats.failed += 1
            return None

        except (AutoRegError, PWError, aiohttp.ClientError, OSError) as exc:
            log.error("[engine] ошибка: %s\n%s", exc, traceback.format_exc())
            self.stats.last_error = f"{type(exc).__name__}: {exc}"
            # «Target page, context or browser has been closed» — браузер умер,
            # иначе следующий цикл упадёт на том же мёртвом контексте
            if "has been closed" in str(exc) or "Target closed" in str(exc):
                log.warning("[engine] браузер мёртв — перезапускаю перед следующим циклом")
                with contextlib.suppress(Exception):
                    await self.browser.close()
            if activation is not None:
                await self.sms.cancel(session, activation)
            await self.storage.save_failed(ident, f"{type(exc).__name__}: {exc}")
            self.stats.failed += 1
            return None

        finally:
            if context is not None:
                with contextlib.suppress(Exception):
                    await context.close()

    # ------------------------------------------------------- главный цикл
    async def run(self, target: int | None = None) -> Stats:
        """Крутит register_one() до target успешных аккаунтов или до STOP."""
        target = target or self.cfg.MAX_ACCOUNTS
        # suspended не засчитывается в target (его надо дожимать), поэтому
        # ограничиваем прогон, чтобы пачка гейтов не крутила цикл бесконечно
        max_attempts = max(target * 3, target + 2)
        self.stats.started_at = datetime.now().isoformat(timespec="seconds")
        self._stop.clear()

        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=120)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            consecutive_failures = 0
            while (self.stats.success < target
                   and self.stats.attempted < max_attempts
                   and not self._stop.is_set()):
                try:
                    ident = await self.register_one(session)
                except Exception as exc:  # noqa: BLE001 — движок не должен падать
                    log.critical("[engine] необработанная ошибка: %s\n%s",
                                 exc, traceback.format_exc())
                    self.stats.last_error = str(exc)
                    ident = None

                if ident is not None:
                    consecutive_failures = 0
                else:
                    consecutive_failures += 1
                    if consecutive_failures >= 5:
                        log.error("[engine] %s фейлов подряд — перезапускаю браузер",
                                  consecutive_failures)
                        await self.browser.close()
                        consecutive_failures = 0
                        await asyncio.sleep(random.uniform(20, 45))

                if self._stop.is_set():
                    break
                # пауза между циклами — не долбим IG
                await asyncio.sleep(random.uniform(15, 45))

        self.stats.finished_at = datetime.now().isoformat(timespec="seconds")
        log.info("[engine] ГОТОВО: success=%s suspended=%s failed=%s attempted=%s "
                 "captcha=%s rotations=%s",
                 self.stats.success, self.stats.suspended, self.stats.failed,
                 self.stats.attempted, self.arkose.solved, self.rotator.rotations)
        return self.stats


# ===========================================================================
# 9. WEB-ПАНЕЛЬ УПРАВЛЕНИЯ — Dashboard (FastAPI)
# ===========================================================================

#: HTML страницы управления. Все данные тянет из /api/*, лог — поллингом.
DASHBOARD_HTML = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IG AutoReg — панель управления</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --line:#21262d; --txt:#e6edf3;
          --mut:#8b949e; --acc:#58a6ff; --ok:#3fb950; --err:#f85149; --warn:#d29922; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--txt);
         font:14px/1.5 ui-sans-serif,system-ui,"Segoe UI",Roboto,sans-serif; }
  header { padding:18px 24px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
  header h1 { font-size:18px; margin:0; letter-spacing:.3px; }
  .pill { padding:3px 10px; border-radius:999px; font-size:12px;
          border:1px solid var(--line); color:var(--mut); }
  .pill.on { color:var(--ok); border-color:#1f6f3c; background:#0f2417; }
  main { padding:20px 24px; display:grid; gap:18px;
         grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); }
  section { background:var(--panel); border:1px solid var(--line);
            border-radius:10px; padding:16px; }
  section h2 { font-size:13px; text-transform:uppercase; letter-spacing:1px;
               color:var(--mut); margin:0 0 12px; }
  .stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); gap:10px; }
  .stat { background:#0d1117; border:1px solid var(--line); border-radius:8px; padding:10px; }
  .stat b { display:block; font-size:22px; }
  .stat span { color:var(--mut); font-size:12px; }
  label { display:block; color:var(--mut); font-size:12px; margin:10px 0 4px; }
  input, select { width:100%; padding:8px 10px; background:#0d1117; color:var(--txt);
                  border:1px solid var(--line); border-radius:6px; font-size:13px; }
  .row { display:flex; gap:10px; }
  .row > div { flex:1; }
  button { padding:9px 16px; border-radius:7px; border:1px solid var(--line);
           background:#21262d; color:var(--txt); cursor:pointer; font-size:13px; }
  button:hover { border-color:var(--acc); }
  button.primary { background:#1f6feb; border-color:#1f6feb; }
  button.danger { background:#7d1d1d; border-color:#a02c2c; }
  button:disabled { opacity:.45; cursor:not-allowed; }
  .actions { display:flex; gap:10px; margin-top:16px; flex-wrap:wrap; }
  pre#log { background:#010409; border:1px solid var(--line); border-radius:8px;
            padding:12px; height:340px; overflow:auto; font-size:12px;
            white-space:pre-wrap; word-break:break-all; margin:0; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--mut); font-weight:500; }
  .full { grid-column:1/-1; }
  .err { color:var(--err); font-size:12px; margin-top:8px; word-break:break-all; }
</style>
</head>
<body>
<header>
  <h1>IG AutoReg — панель управления</h1>
  <span class="pill" id="state">IDLE</span>
  <span class="pill" id="ip">IP: —</span>
  <span class="pill" id="method">method: —</span>
</header>

<main>
  <section>
    <h2>Управление прогоном</h2>
    <div class="row">
      <div>
        <label>Сколько аккаунтов</label>
        <input id="count" type="number" min="1" value="1">
      </div>
      <div>
        <label>Метод верификации</label>
        <select id="reg_method">
          <option value="email">email (IMAP catch-all)</option>
          <option value="sms">sms (sms-activate / 5sim)</option>
        </select>
      </div>
    </div>
    <label>Режим браузера</label>
    <select id="headless">
      <option value="1">headless</option>
      <option value="0">headed (видимый)</option>
    </select>
    <div class="actions">
      <button class="primary" id="start">▶ Запустить</button>
      <button class="danger" id="stop">■ Стоп</button>
      <button id="one">1 аккаунт (тест)</button>
    </div>
    <div class="err" id="lasterr"></div>
  </section>

  <section>
    <h2>Статистика</h2>
    <div class="stats">
      <div class="stat"><b id="s_success">0</b><span>успешно</span></div>
      <div class="stat"><b id="s_suspended">0</b><span>suspended</span></div>
      <div class="stat"><b id="s_failed">0</b><span>провалено</span></div>
      <div class="stat"><b id="s_attempted">0</b><span>попыток</span></div>
      <div class="stat"><b id="s_captcha">0</b><span>captcha решено</span></div>
      <div class="stat"><b id="s_rot">0</b><span>ротаций IP</span></div>
    </div>
  </section>

  <section>
    <h2>Конфигурация (runtime)</h2>
    <label>PROXY (http://user:pass@ip:port)</label>
    <input id="cfg_PROXY" placeholder="http://user:pass@ip:port">
    <label>PROXY_ROTATION_URL</label>
    <input id="cfg_PROXY_ROTATION_URL" placeholder="https://provider/change-ip?key=...">
    <div class="row">
      <div>
        <label>SMS_PROVIDER</label>
        <select id="cfg_SMS_PROVIDER">
          <option value="sms-activate">sms-activate</option>
          <option value="5sim">5sim</option>
        </select>
      </div>
      <div>
        <label>SMS_API_KEY</label>
        <input id="cfg_SMS_API_KEY" type="password">
      </div>
    </div>
    <div class="row">
      <div>
        <label>CAPTCHA_PROVIDER</label>
        <select id="cfg_CAPTCHA_PROVIDER">
          <option value="capmonster">CapMonster</option>
          <option value="2captcha">2Captcha</option>
        </select>
      </div>
      <div>
        <label>CAPTCHA_API_KEY</label>
        <input id="cfg_CAPTCHA_API_KEY" type="password">
      </div>
    </div>
    <div class="row">
      <div>
        <label>EMAIL_DOMAIN (catch-all)</label>
        <input id="cfg_EMAIL_DOMAIN">
      </div>
      <div>
        <label>IMAP_HOST</label>
        <input id="cfg_IMAP_HOST">
      </div>
    </div>
    <div class="row">
      <div><label>IMAP_USER</label><input id="cfg_IMAP_USER"></div>
      <div><label>IMAP_PASS</label><input id="cfg_IMAP_PASS" type="password"></div>
    </div>
    <div class="row">
      <div><label>AVATARS_DIR</label><input id="cfg_AVATARS_DIR"></div>
      <div><label>MAX_ACCOUNTS</label><input id="cfg_MAX_ACCOUNTS" type="number"></div>
    </div>
    <div class="actions"><button id="savecfg">Сохранить конфиг</button></div>
    <div class="err" id="cfgmsg"></div>
  </section>

  <section class="full">
    <h2>Живой лог</h2>
    <pre id="log"></pre>
  </section>

  <section class="full">
    <h2>Последние аккаунты (success.txt)</h2>
    <table>
      <thead><tr><th>username</th><th>email / phone</th><th>password</th>
      <th>proxy ip</th><th>cookies</th><th>создан</th></tr></thead>
      <tbody id="acc"></tbody>
    </table>
  </section>
</main>

<script>
const $ = (id) => document.getElementById(id);
const CFG_FIELDS = ['cfg_PROXY','cfg_PROXY_ROTATION_URL','cfg_SMS_PROVIDER','cfg_SMS_API_KEY',
  'cfg_CAPTCHA_PROVIDER','cfg_CAPTCHA_API_KEY','cfg_EMAIL_DOMAIN','cfg_IMAP_HOST',
  'cfg_IMAP_USER','cfg_IMAP_PASS','cfg_AVATARS_DIR','cfg_MAX_ACCOUNTS'];
let logOffset = 0;

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(path + ' -> HTTP ' + r.status);
  return r.json();
}

async function loadState() {
  try {
    const s = await api('/api/state');
    $('state').textContent = s.running ? 'RUNNING' : 'IDLE';
    $('state').className = 'pill' + (s.running ? ' on' : '');
    $('ip').textContent = 'IP: ' + (s.stats.current_ip || '—');
    $('method').textContent = 'method: ' + (s.config.REG_METHOD || '—');
    $('s_success').textContent = s.stats.success;
    $('s_suspended').textContent = s.stats.suspended;
    $('s_failed').textContent = s.stats.failed;
    $('s_attempted').textContent = s.stats.attempted;
    $('s_captcha').textContent = s.stats.captcha_solved;
    $('s_rot').textContent = s.stats.proxy_rotations;
    $('lasterr').textContent = s.stats.last_error ? 'last error: ' + s.stats.last_error : '';
    $('start').disabled = s.running;
    $('stop').disabled = !s.running;
    if (!CFG_LOADED) {
      for (const f of CFG_FIELDS) {
        const k = f.replace('cfg_','');
        const el = $(f);
        if (el && s.config[k] !== undefined) el.value = s.config[k];
      }
      $('reg_method').value = s.config.REG_METHOD || 'email';
      $('headless').value = s.config.HEADLESS ? '1' : '0';
      $('count').value = s.config.MAX_ACCOUNTS || 1;
      CFG_LOADED = true;
    }
    const rows = s.stats.accounts.map(a => `<tr>
      <td>${a.username||''}</td><td>${a.email||a.phone||''}</td>
      <td>${a.password||''}</td><td>${a.proxy_ip||''}</td>
      <td>${a.cookies||'—'}</td><td>${a.created_at||''}</td></tr>`).join('');
    $('acc').innerHTML = rows || '<tr><td colspan="6" style="color:var(--mut)">пока пусто</td></tr>';
  } catch (e) { console.error(e); }
}
let CFG_LOADED = false;

async function loadLog() {
  try {
    const l = await api('/api/log?since=' + logOffset);
    if (l.lines.length) {
      const el = $('log');
      el.textContent += l.lines.join('\\n') + '\\n';
      el.scrollTop = el.scrollHeight;
      logOffset = l.offset;
    }
  } catch (e) {}
}

$('start').onclick = async () => {
  await api('/api/start', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({count: +$('count').value, method: $('reg_method').value,
                          headless: $('headless').value === '1'})});
  loadState();
};
$('one').onclick = async () => { $('count').value = 1; $('start').click(); };
$('stop').onclick = async () => { await api('/api/stop', {method:'POST'}); loadState(); };
$('savecfg').onclick = async () => {
  const body = {};
  for (const f of CFG_FIELDS) {
    const k = f.replace('cfg_','');
    let v = $(f).value;
    if (!v) continue;
    if (k === 'MAX_ACCOUNTS') v = +v;
    if (k === 'SMS_API_KEY' || k === 'CAPTCHA_API_KEY' || k === 'IMAP_PASS')
      if (v === '***REDACTED***') continue;
    body[k] = v;
  }
  try {
    await api('/api/config', {method:'POST', headers:{'Content-Type':'application/json'},
                              body: JSON.stringify(body)});
    CFG_LOADED = false; $('cfgmsg').textContent = 'сохранено'; loadState();
  } catch (e) { $('cfgmsg').textContent = 'ошибка: ' + e.message; }
};

loadState(); loadLog();
setInterval(loadState, 3000);
setInterval(loadLog, 2000);
</script>
</body>
</html>
"""


def build_dashboard_app(cfg: Config) -> Any:
    """
    Собирает FastAPI-приложение web-панели (без запуска сервера).
    Выделено отдельно, чтобы его можно было протестировать через TestClient.
    """
    from fastapi import Body, FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse

    app = FastAPI(title="IG AutoReg Dashboard", version="1.0")
    holder: dict[str, Any] = {"engine": None, "task": None}

    def _engine() -> Engine:
        if holder["engine"] is None:
            holder["engine"] = Engine(cfg)
        return holder["engine"]

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return DASHBOARD_HTML

    @app.get("/api/state")
    async def state() -> JSONResponse:
        eng = _engine()
        running = holder["task"] is not None and not holder["task"].done()
        return JSONResponse({
            "running": running,
            "stats": eng.stats.as_dict(),
            "config": cfg.to_dict(redact=True),
        })

    @app.get("/api/log")
    async def get_log(since: int = 0) -> dict[str, Any]:
        lines = list(LOG_RING)
        return {"lines": lines[since:], "offset": len(lines), "total": len(lines)}

    @app.post("/api/start")
    async def start(payload: dict[str, Any] = Body(default={})) -> JSONResponse:
        if holder["task"] is not None and not holder["task"].done():
            return JSONResponse({"ok": False, "error": "прогон уже запущен"}, status_code=409)

        count = int(payload.get("count") or cfg.MAX_ACCOUNTS or 1)
        if payload.get("method") in ("email", "sms"):
            cfg.REG_METHOD = payload["method"]
        if "headless" in payload:
            cfg.HEADLESS = bool(payload["headless"])

        holder["engine"] = Engine(cfg)
        holder["engine"].stats.accounts = []
        holder["task"] = asyncio.create_task(_run_engine(holder, count))
        log.info("[dashboard] прогон запущен: count=%s method=%s headless=%s",
                 count, cfg.REG_METHOD, cfg.HEADLESS)
        return JSONResponse({"ok": True, "count": count, "method": cfg.REG_METHOD})

    @app.post("/api/stop")
    async def stop() -> JSONResponse:
        if holder["engine"] is not None:
            holder["engine"].stop()
        return JSONResponse({"ok": True})

    @app.post("/api/config")
    async def update_config(payload: dict[str, Any] = Body(default={})) -> JSONResponse:
        known = set(Config.__dataclass_fields__)
        applied: dict[str, Any] = {}
        for k, v in payload.items():
            if k not in known:
                continue
            cur = getattr(cfg, k)
            try:
                if isinstance(cur, bool):
                    v = str(v).lower() in ("1", "true", "yes", "on")
                elif isinstance(cur, int):
                    v = int(v)
                elif isinstance(cur, float):
                    v = float(v)
            except (TypeError, ValueError):
                continue
            setattr(cfg, k, v)
            applied[k] = "***" if k in ("SMS_API_KEY", "CAPTCHA_API_KEY",
                                        "IMAP_PASS", "PROXY") else v
        try:
            cfg.__post_init__()
        except ValueError as exc:
            return JSONResponse({"ok": False, "error": str(exc)}, status_code=400)
        holder["engine"] = None          # новый движок подхватит свежий конфиг
        log.info("[dashboard] конфиг обновлён: %s", applied)
        return JSONResponse({"ok": True, "applied": applied})

    @app.get("/api/accounts")
    async def accounts() -> JSONResponse:
        p = Path(cfg.ACCOUNTS_DB)
        data: list[Any] = []
        if p.exists():
            with contextlib.suppress(json.JSONDecodeError):
                data = json.loads(p.read_text(encoding="utf-8"))
        return JSONResponse({"count": len(data), "accounts": data[-100:][::-1]})

    async def _run_engine(holder: dict[str, Any], count: int) -> None:
        eng = holder["engine"]
        try:
            await eng.run(count)
        except Exception as exc:  # noqa: BLE001
            log.critical("[dashboard] прогон упал: %s\n%s", exc, traceback.format_exc())
        finally:
            await eng.shutdown()

    return app


async def serve_dashboard(cfg: Config) -> int:
    """Поднимает web-панель на uvicorn (импорт отложенный — для CLI не нужен)."""
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        log.error("для web-панели нужны fastapi и uvicorn: %s "
                  "(pip install fastapi uvicorn)", exc)
        return 1

    app = build_dashboard_app(cfg)
    config = uvicorn.Config(app, host=cfg.DASHBOARD_HOST, port=cfg.DASHBOARD_PORT,
                            log_level="warning")
    server = uvicorn.Server(config)
    log.info("[dashboard] панель доступна на http://%s:%s",
             cfg.DASHBOARD_HOST, cfg.DASHBOARD_PORT)
    await server.serve()
    return 0


# ===========================================================================
# CLI
# ===========================================================================


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="IG AutoReg — движок + web-панель")
    p.add_argument("--config", default=None, help="путь к config.json")
    p.add_argument("--run", action="store_true", help="запустить регистрацию из CLI")
    p.add_argument("--serve", action="store_true", help="поднять web-панель")
    p.add_argument("--count", type=int, default=None, help="сколько аккаунтов сделать")
    p.add_argument("--method", choices=["email", "sms"], default=None)
    p.add_argument("--headed", action="store_true", help="показывать браузер")
    p.add_argument("--quiet", action="store_true", help="меньше логов в консоль")
    return p.parse_args(argv)


async def amain(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = load_config(
        args.config,
        REG_METHOD=args.method,
        HEADLESS=False if args.headed else None,
    )
    setup_logging(cfg.LOG_FILE, verbose=not args.quiet)
    log.info("[main] конфиг загружен: %s", json.dumps(cfg.to_dict(redact=True),
                                                      ensure_ascii=False, indent=2))

    if args.serve:
        return await serve_dashboard(cfg)

    if args.run:
        engine = Engine(cfg)
        try:
            stats = await engine.run(args.count)
            return 0 if stats.success > 0 else 1
        finally:
            await engine.shutdown()

    parse_args(["--help"])
    return 2


def main() -> int:
    try:
        return asyncio.run(amain())
    except KeyboardInterrupt:
        log.warning("[main] прервано пользователем")
        return 130


if __name__ == "__main__":
    sys.exit(main())
