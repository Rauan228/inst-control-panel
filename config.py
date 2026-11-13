#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
config.py — единая точка конфигурации IG AutoReg.

Все секреты читаются из переменных окружения с fallback на значения по умолчанию,
чтобы файл можно было коммитить в репозиторий, а ключи держать в .env.
"""

from __future__ import annotations

import json
import os
import random
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Пулы данных для генерации идентичностей
# ---------------------------------------------------------------------------

FIRST_NAMES_MALE: list[str] = [
    "james", "michael", "robert", "david", "richard", "thomas", "daniel",
    "matthew", "anthony", "joshua", "andrew", "joseph", "christopher",
    "ryan", "brandon", "justin", "tyler", "kevin", "brian", "nathan",
    "oliver", "lucas", "mason", "ethan", "logan", "caleb", "isaac",
]

FIRST_NAMES_FEMALE: list[str] = [
    "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "jessica",
    "susan", "sarah", "karen", "nancy", "lisa", "betty", "margaret", "sandra",
    "ashley", "emily", "donna", "michelle", "dorothy", "carol", "amanda",
    "melissa", "deborah", "stephanie", "rebecca", "sharon", "laura", "olivia",
    "sophia", "isabella", "charlotte", "amelia", "harper", "evelyn", "abigail",
]

LAST_NAMES: list[str] = [
    "smith", "johnson", "williams", "brown", "jones", "garcia", "miller",
    "davis", "rodriguez", "martinez", "hernandez", "lopez", "gonzalez",
    "wilson", "anderson", "thomas", "taylor", "moore", "jackson", "martin",
    "lee", "perez", "thompson", "white", "harris", "sanchez", "clark",
    "ramirez", "lewis", "robinson", "walker", "young", "allen", "king",
    "wright", "scott", "torres", "nguyen", "hill", "flores", "green",
    "adams", "nelson", "baker", "hall", "rivera", "campbell", "mitchell",
    "carter", "roberts", "gomez", "phillips", "evans", "turner", "parker",
]

#: половые пары «имя -> пул фамилий-«своих»»: username строится из ТОГО ЖЕ
#: имени и фамилии, что уходят в full_name, иначе получается «Nathan Smith»
#: при нике «laura8419.hernandez» — для антифрода это расхождение идентичности.
FIRST_NAMES_BY_GENDER: dict[str, list[str]] = {
    "m": [
        "james", "michael", "robert", "david", "richard", "thomas", "daniel",
        "matthew", "anthony", "joshua", "andrew", "joseph", "christopher",
        "ryan", "brandon", "justin", "tyler", "kevin", "brian", "nathan",
        "oliver", "lucas", "mason", "ethan", "logan", "caleb", "isaac",
    ],
    "f": [
        "mary", "patricia", "jennifer", "linda", "elizabeth", "barbara", "jessica",
        "susan", "sarah", "karen", "nancy", "lisa", "betty", "margaret", "sandra",
        "ashley", "emily", "donna", "michelle", "dorothy", "carol", "amanda",
        "melissa", "deborah", "stephanie", "rebecca", "sharon", "laura", "olivia",
        "sophia", "isabella", "charlotte", "amelia", "harper", "evelyn", "abigail",
    ],
}

USERNAME_SEPARATORS: list[str] = ["", ".", "_", "-", ""]

#: «красивые» MM-DD, которые у ботов встречаются аномально часто — исключаем
BIRTHDAY_BLACKLIST: set[tuple[int, int]] = {
    (12, 25), (1, 1), (2, 14), (10, 31), (7, 4), (11, 11), (7, 7), (12, 12),
    (3, 8), (5, 5), (1, 15), (1, 20), (9, 1), (6, 1), (4, 1), (2, 1),
}

#: сезонность дней рождения (US): сентябрь — пик, февраль/март — минимум
BIRTHDAY_MONTH_WEIGHTS: list[float] = [8.1, 7.6, 8.3, 8.1, 8.6, 8.5,
                                       9.0, 9.1, 9.4, 8.8, 8.2, 8.3]

EMAIL_LOCAL_WORDS: list[str] = [
    "sky", "nova", "pixel", "ember", "frost", "raven", "solar", "lunar",
    "echo", "drift", "pulse", "vertex", "onyx", "quartz", "zephyr", "cobalt",
    "nimbus", "atlas", "vortex", "cipher", "helix", "prism", "orbit", "flux",
]

# Свежие стабильные Chrome/Windows UA (2024-2025 диапазон)
USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.87 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.92 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.101 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
]

LOCALES: list[str] = ["en-US", "en-GB", "en-CA", "en-AU", "es-ES", "de-DE", "fr-FR"]

TIMEZONE_POOL: list[tuple[str, str]] = [
    ("America/New_York", "en-US"),
    ("America/Chicago", "en-US"),
    ("America/Denver", "en-US"),
    ("America/Los_Angeles", "en-US"),
    ("America/Phoenix", "en-US"),
    ("Europe/London", "en-GB"),
    ("Europe/Berlin", "de-DE"),
    ("Europe/Madrid", "es-ES"),
    ("Europe/Paris", "fr-FR"),
]

VIEWPORTS: list[dict[str, int]] = [
    {"width": 1920, "height": 1080},
    {"width": 1600, "height": 900},
    {"width": 1536, "height": 864},
    {"width": 1440, "height": 900},
    {"width": 1366, "height": 768},
    {"width": 1280, "height": 720},
    {"width": 1680, "height": 1050},
    {"width": 2560, "height": 1440},
]

WEBGL_VENDORS: list[tuple[str, str]] = [
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"),
]

# Цели для первичной подписки (траст-индексация)
_DEFAULT_TRUST_TARGETS: list[str] = [
    "https://www.instagram.com/instagram/",
    "https://www.instagram.com/natgeo/",
    "https://www.instagram.com/nasa/",
    "https://www.instagram.com/nike/",
    "https://www.instagram.com/apple/",
    "https://www.instagram.com/google/",
    "https://www.instagram.com/spotify/",
    "https://www.instagram.com/netflix/",
    "https://www.instagram.com/cristiano/",
    "https://www.instagram.com/therock/",
]

#: публичный алиас (его импортирует autoreg.py как fallback)
TRUST_TARGETS = _DEFAULT_TRUST_TARGETS


def _env_list(name: str, default: list[str]) -> list[str]:
    """Список из env-переменной через запятую; пусто/отсутствует -> default."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return list(default)
    items = [x.strip() for x in re.split(r"[,\n;]+", raw) if x.strip()]
    return items or list(default)


def load_dotenv(path: str | None = None) -> Path | None:
    """
    Мини-.env загрузчик (без python-dotenv).

    ВАЖНО: вызывается ДО определения Config, потому что default-значения
    датакласса вычисляются один раз — в момент импорта модуля.
    Реальное окружение имеет приоритет над файлом (os.environ.setdefault).
    """
    candidates = [Path(path)] if path else [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent / ".env",
    ]
    for p in candidates:
        if not p or not p.exists():
            continue
        loaded = 0
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key.startswith("export "):
                key = key[len("export "):].strip()
            if key:
                os.environ.setdefault(key, value)
                loaded += 1
        print(f"[config] .env загружен: {p} ({loaded} переменных)")
        return p
    return None


load_dotenv()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """Центральный объект конфигурации движка регистрации."""

    # --- SMS / verification -------------------------------------------------
    SMS_PROVIDER: str = os.getenv("SMS_PROVIDER", "sms-activate")   # sms-activate | 5sim | smspool
    SMS_API_KEY: str = os.getenv("SMS_API_KEY", "")
    # Базовые URL API. Меняй, если работаешь через реселлера с sms-activate-совместимым
    # API (hero-sms, sms-man, online-sim и т.п.) — формат ответов у них тот же.
    SMS_API_BASE: str = os.getenv(
        "SMS_API_BASE", "https://api.bee-sms.com/stubs/handler_api.php"
    )
    FIVESIM_API_BASE: str = os.getenv("FIVESIM_API_BASE", "https://5sim.net/v1/user")
    #: SMSPool — собственный REST (POST /purchase\/sms, GET /sms\/check, POST /sms\/cancel)
    SMSPOOL_HOST: str = os.getenv("SMSPOOL_HOST", "https://api.smspool.net")
    SMSPOOL_SERVICE: str = os.getenv("SMSPOOL_SERVICE", "457")   # 457 = Instagram/Threads
    SMSPOOL_COUNTRY: str = os.getenv("SMSPOOL_COUNTRY", "US")
    #: ручной номер для теста: код ждём в файле (см. MANUAL_SMS_FILE)
    MANUAL_PHONE: str = os.getenv("MANUAL_PHONE", "")
    MANUAL_SMS_FILE: str = os.getenv("MANUAL_SMS_FILE", "manual_sms.txt")
    MANUAL_SMS_TIMEOUT: int = int(os.getenv("MANUAL_SMS_TIMEOUT", "600"))
    #: страна для ручного номера, как её показывать в селекторе (напр. Kazakhstan)
    MANUAL_COUNTRY: str = os.getenv("MANUAL_COUNTRY", "")
    #: ретраи создания аккаунта в API-канале (сервер часто отвечает сбоем)
    API_MAX_ATTEMPTS: int = int(os.getenv("API_MAX_ATTEMPTS", "3"))
    SMS_SERVICE_CODE: str = os.getenv("SMS_SERVICE_CODE", "ig")     # код сервиса (ig/insta)
    SMS_COUNTRY: str = os.getenv("SMS_COUNTRY", "187")              # sms-activate country id
    SMS_5SIM_COUNTRY: str = os.getenv("SMS_5SIM_COUNTRY", "any")
    SMS_5SIM_OPERATOR: str = os.getenv("SMS_5SIM_OPERATOR", "any")
    SMS_TIMEOUT: int = int(os.getenv("SMS_TIMEOUT", "180"))
    SMS_POLL_INTERVAL: float = float(os.getenv("SMS_POLL_INTERVAL", "5"))

    # --- Captcha -------------------------------------------------------------
    # capmonster | 2captcha | everyinfra
    CAPTCHA_PROVIDER: str = os.getenv("CAPTCHA_PROVIDER", "capmonster")
    CAPTCHA_API_KEY: str = os.getenv("CAPTCHA_API_KEY", "")
    CAPMONSTER_HOST: str = os.getenv("CAPMONSTER_HOST", "https://api.capmonster.cloud")
    TWOCAPTCHA_HOST: str = os.getenv("TWOCAPTCHA_HOST", "https://api.2captcha.com")
    EVERYINFRA_HOST: str = os.getenv("EVERYINFRA_HOST", "https://api.everyinfra.com")
    #: VoidCaptcha — один эндпоинт /v1/getResult, конверт как у CapMonster
    VOIDCAPTCHA_HOST: str = os.getenv("VOIDCAPTCHA_HOST", "https://api.voidcaptcha.com")
    CAPTCHA_TIMEOUT: int = int(os.getenv("CAPTCHA_TIMEOUT", "240"))

    # --- Email / IMAP (catch-all) -------------------------------------------
    EMAIL_DOMAIN: str = os.getenv("EMAIL_DOMAIN", "yourdomain.com")
    EMAIL_LOCAL_PREFIX: str = os.getenv("EMAIL_LOCAL_PREFIX", "")   # '' = random
    EMAIL_POOL_FILE: str = os.getenv("EMAIL_POOL_FILE", "email_pool.txt")
    #: как строить local-part у catch-all: name (nathan.smith84) | prefix
    #: (ig.nathan.smith84) | random (sky4417). «ig.» — самый узнаваемый паттерн.
    EMAIL_LOCAL_STYLE: str = os.getenv("EMAIL_LOCAL_STYLE", "name")
    IMAP_HOST: str = os.getenv("IMAP_HOST", "imap.yourdomain.com")
    IMAP_PORT: int = int(os.getenv("IMAP_PORT", "993"))
    IMAP_USER: str = os.getenv("IMAP_USER", "")
    IMAP_PASS: str = os.getenv("IMAP_PASS", "")
    IMAP_MAILBOX: str = os.getenv("IMAP_MAILBOX", "INBOX")
    IMAP_SSL: bool = os.getenv("IMAP_SSL", "1") == "1"
    IMAP_POLL_INTERVAL: float = float(os.getenv("IMAP_POLL_INTERVAL", "4"))
    IMAP_TIMEOUT: int = int(os.getenv("IMAP_TIMEOUT", "180"))

    # --- Network / proxy -----------------------------------------------------
    PROXY: str = os.getenv("PROXY", "http://user:pass@ip:port")
    #: Пул прокси-эндпоинтов через запятую. Для sticky-сессий (Decodo/Smartproxy:
    #: каждый порт = отдельная залипающая сессия на 10 мин) это и есть механизм
    #: ротации: движок берёт следующий эндпоинт на каждый цикл регистрации.
    #: Если задан — имеет приоритет над PROXY.
    PROXY_LIST: str = os.getenv("PROXY_LIST", "")
    PROXY_ROTATION_URL: str = os.getenv("PROXY_ROTATION_URL", "")
    PROXY_ROTATE_SLEEP: int = int(os.getenv("PROXY_ROTATE_SLEEP", "10"))
    PROXY_MAX_RETRIES: int = int(os.getenv("PROXY_MAX_RETRIES", "5"))
    #: сколько часов эндпоинт считается «занятым» аккаунтом, который на нём
    #: создавали: два свежих аккаунта с одного IP — заметный паттерн.
    PROXY_STICKY_HOURS: int = int(os.getenv("PROXY_STICKY_HOURS", "24"))
    #: файл соответствия аккаунт -> эндпоинт (чтобы переоткрывать с того же IP)
    PROXY_AFFINITY_FILE: str = os.getenv("PROXY_AFFINITY_FILE", "proxy_affinity.json")
    #: база аккаунтов (её читает и ротатор для проверки «занятых» IP)
    ACCOUNTS_DB: str = os.getenv("ACCOUNTS_DB", "accounts.json")

    # --- Антифрод: человеческий гейт после регистрации ----------------------
    #: IG сразу после выдачи сессии ставит /accounts/suspended «Confirm you're
    #: human». Если гейт не пройти, аккаунт остаётся в suspended и профиль 404.
    ENABLE_GATE: bool = os.getenv("ENABLE_GATE", "1") == "1"
    GATE_TIMEOUT: int = int(os.getenv("GATE_TIMEOUT", "600"))
    GATE_MAX_ROUNDS: int = int(os.getenv("GATE_MAX_ROUNDS", "8"))
    #: если гейт не пройден — аккаунт всё равно сохраняем со статусом suspended
    #: (его можно дожать позже), а не выбрасываем в failed.
    #: закрывать контекст перед отлёжкой (новый IP на новом коннекте)
    CLOSE_BEFORE_COOLDOWN: bool = os.getenv("CLOSE_BEFORE_COOLDOWN", "1") == "1"

    # --- Отлёжка перед трастом ----------------------------------------------
    #: Секунды «простоя» между регистрацией и первым Follow/аватаром.
    #: Живой человек не подписывается через 3 секунды после создания — это
    #: один из самых сильных сигналов синтетики.
    COOLDOWN_MIN: int = int(os.getenv("COOLDOWN_MIN", "240"))
    COOLDOWN_MAX: int = int(os.getenv("COOLDOWN_MAX", "900"))
    #: прогрев разбит на несколько коротких визитов вместо одного длинного
    WARM_VISITS: int = int(os.getenv("WARM_VISITS", "2"))
    WARM_SECONDS_MIN: int = int(os.getenv("WARM_SECONDS_MIN", "35"))
    WARM_SECONDS_MAX: int = int(os.getenv("WARM_SECONDS_MAX", "95"))
    #: между визитами прогрева
    WARM_PAUSE_MIN: int = int(os.getenv("WARM_PAUSE_MIN", "20"))
    WARM_PAUSE_MAX: int = int(os.getenv("WARM_PAUSE_MAX", "70"))

    # --- Трафик --------------------------------------------------------------
    #: режем картинки/шрифты/медиа от CDN: на 3 MB уходит визит вместо 5-15 MB.
    #: На время загрузки аватара блокировка снимается автоматически.
    BLOCK_MEDIA: bool = os.getenv("BLOCK_MEDIA", "1") == "1"
    #: хосты, чьи картинки/шрифты режем (JS/CSS на static.cdninstagram.com
    #: пропускаются всегда — без них страница не монтируется)
    BLOCK_MEDIA_HOSTS: str = os.getenv(
        "BLOCK_MEDIA_HOSTS", "scontent,fbcdn.net,instagram.f,cdninstagram")

    # --- Assets --------------------------------------------------------------
    AVATARS_DIR: str = os.getenv("AVATARS_DIR", "avatars")
    #: папка с селфи для шага «Upload a verification selfie» (лицо, без людей)
    SELFIES_DIR: str = os.getenv("SELFIES_DIR", "selfies")
    PROFILE_EDIT_URL: str = os.getenv(
        "PROFILE_EDIT_URL", "https://www.instagram.com/accounts/edit/"
    )
    COOKIES_DIR: str = os.getenv("COOKIES_DIR", "cookies")
    SUCCESS_FILE: str = os.getenv("SUCCESS_FILE", "success.txt")
    FAILED_FILE: str = os.getenv("FAILED_FILE", "failed.txt")
    LOG_FILE: str = os.getenv("LOG_FILE", "autoreg.log")

    # --- Engine --------------------------------------------------------------
    REG_METHOD: str = os.getenv("REG_METHOD", "email")              # email | sms
    TARGET_URL: str = os.getenv(
        "TARGET_URL", "https://www.instagram.com/accounts/emailsignup/"
    )
    HEADLESS: bool = os.getenv("HEADLESS", "1") == "1"
    MAX_ACCOUNTS: int = int(os.getenv("MAX_ACCOUNTS", "10"))
    CONCURRENT: int = int(os.getenv("CONCURRENT", "1"))
    GLOBAL_TIMEOUT: int = int(os.getenv("GLOBAL_TIMEOUT", "600"))
    PASSWORD_LENGTH: int = int(os.getenv("PASSWORD_LENGTH", "16"))
    ENABLE_TRUST: bool = os.getenv("ENABLE_TRUST", "1") == "1"
    ENABLE_AVATAR: bool = os.getenv("ENABLE_AVATAR", "1") == "1"
    SLOW_MO: int = int(os.getenv("SLOW_MO", "0"))
    #: канал браузера. По умолчанию "chromium" — это полноценный Chromium в
    #: new-headless, а не chromium_headless_shell (у shell другой набор
    #: JS-фич и он сильнее палится). Пусто = встроенный headless shell.
    BROWSER_CHANNEL: str = os.getenv("BROWSER_CHANNEL", "chromium")
    #: мобильный web-флоу (iPhone UA + touch): у Meta он мягче к регистрации
    MOBILE_MODE: bool = os.getenv("MOBILE_MODE", "0") == "1"
    # Гео-привязка: если заданы, фингерпринт берёт их вместо случайной пары
    # (нужно, когда прокси выходит из одной страны — иначе timezone/locale
    #  не совпадёт с IP, и это заметный сигнал для антифрода).
    GEO_TIMEZONE: str = os.getenv("GEO_TIMEZONE", "")   # напр. Asia/Ho_Chi_Minh
    GEO_LOCALE: str = os.getenv("GEO_LOCALE", "")       # напр. vi-VN
    #: пул TZ внутри страны выхода (US): IP в случайном городе США и TZ
    #: America/New_York на каждом аккаунте — тоже паттерн.
    GEO_TIMEZONE_POOL: str = os.getenv(
        "GEO_TIMEZONE_POOL",
        "America/New_York,America/Chicago,America/Denver,America/Los_Angeles,"
        "America/Phoenix,America/Detroit,America/Indiana/Indianapolis",
    )
    MIN_BIRTHDAY_AGE: int = int(os.getenv("MIN_BIRTHDAY_AGE", "24"))
    MAX_BIRTHDAY_AGE: int = int(os.getenv("MAX_BIRTHDAY_AGE", "38"))
    EXTRA_ARGS: list[str] = field(default_factory=lambda: [
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-dev-shm-usage",
    ])

    TRUST_TARGETS: list[str] = field(
        default_factory=lambda: _env_list("TRUST_TARGETS", _DEFAULT_TRUST_TARGETS)
    )

    # --- Dashboard -----------------------------------------------------------
    DASHBOARD_HOST: str = os.getenv("DASHBOARD_HOST", "127.0.0.1")
    DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "8088"))

    # ------------------------------------------------------------------ helpers
    def __post_init__(self) -> None:
        Path(self.AVATARS_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.COOKIES_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
        if self.REG_METHOD not in ("email", "sms"):
            raise ValueError(f"REG_METHOD must be 'email' or 'sms', got {self.REG_METHOD!r}")
        if self.CAPTCHA_PROVIDER not in ("capmonster", "2captcha", "everyinfra",
                                         "voidcaptcha"):
            raise ValueError("CAPTCHA_PROVIDER must be 'capmonster', '2captcha', "
                             "'everyinfra' or 'voidcaptcha'")
        if self.SMS_PROVIDER not in ("sms-activate", "5sim", "smspool", "manual"):
            raise ValueError("SMS_PROVIDER must be 'sms-activate', '5sim', "
                             "'smspool' or 'manual'")
        if self.MIN_BIRTHDAY_AGE < 18:
            self.MIN_BIRTHDAY_AGE = 18
        if not self.TRUST_TARGETS:
            self.TRUST_TARGETS = list(_DEFAULT_TRUST_TARGETS)
        # если задан пул — PROXY становится первым эндпоинтом (дальше его
        # переключает ProxyRotator на каждом цикле)
        pool = self.proxies
        if pool and self.PROXY not in pool:
            self.PROXY = pool[0]

    @property
    def proxies(self) -> list[str]:
        """
        Список прокси-эндпоинтов для ротации.

        PROXY_LIST (через запятую) имеет приоритет; если он пуст — один PROXY.
        Пустой список означает «без прокси» (только для локальных тестов).
        """
        items = [p.strip() for p in re.split(r"[,\s;]+", self.PROXY_LIST) if p.strip()]
        if not items and self.PROXY and self.PROXY != "http://user:pass@ip:port":
            items = [self.PROXY.strip()]
        # дедуп с сохранением порядка
        seen: set[str] = set()
        out: list[str] = []
        for p in items:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    @property
    def proxy_server(self) -> str:
        """Строка прокси для Playwright (http://user:pass@ip:port)."""
        return self.PROXY

    def proxy_display(self) -> str:
        """Прокси текущего цикла — уходит в success.txt и логи."""
        return self.PROXY

    MOBILE_UA: str = (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 "
        "Safari/604.1"
    )

    def random_identity(self) -> dict[str, Any]:
        """Случайная связка: UA + viewport + locale + timezone + WebGL."""
        if self.MOBILE_MODE:
            tz = random.choice([z.strip() for z in self.GEO_TIMEZONE_POOL.split(",")
                                if z.strip()] or ["America/New_York"])
            return {
                "user_agent": self.MOBILE_UA,
                "viewport": {"width": 390, "height": 844},
                "locale": self.GEO_LOCALE or "en-US",
                "timezone_id": tz,
                "device_scale_factor": 3,
                "webgl_vendor": "Apple Inc.",
                "webgl_renderer": "Apple GPU",
                "platform": "iPhone",
                "hardware_concurrency": 4,
                "device_memory": 4,
                "is_mobile": True,
                "has_touch": True,
            }
        tz, loc = random.choice(TIMEZONE_POOL)
        if self.GEO_TIMEZONE:
            tz = self.GEO_TIMEZONE
        zones = [z.strip() for z in self.GEO_TIMEZONE_POOL.split(",") if z.strip()]
        if zones:
            tz = random.choice(zones)
        if self.GEO_LOCALE:
            loc = self.GEO_LOCALE
        ua = random.choice(USER_AGENTS)
        vp = random.choice(VIEWPORTS)
        webgl = random.choice(WEBGL_VENDORS)
        # Chrome major version должен совпадать между UA и платформой
        return {
            "user_agent": ua,
            "viewport": vp,
            "locale": loc if loc in LOCALES else "en-US",
            "timezone_id": tz,
            "device_scale_factor": random.choice([1, 1, 1, 1, 1, 1.25, 1.5]),
            "webgl_vendor": webgl[0],
            "webgl_renderer": webgl[1],
            "platform": "Win32",
            "hardware_concurrency": random.choice([4, 8, 12, 16, 24]),
            "device_memory": random.choice([4, 8, 8, 16]),
        }

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        d = asdict(self)
        if redact:
            for k in ("SMS_API_KEY", "CAPTCHA_API_KEY", "IMAP_PASS", "PROXY"):
                if d.get(k):
                    d[k] = "***REDACTED***"
        return d


def load_config(path: str | None = None, **overrides: Any) -> Config:
    """
    Загрузка конфига.

    Приоритет: overrides > config.json > ENV > defaults.
    """
    data: dict[str, Any] = {}

    cfg_path = Path(path or os.getenv("IG_CONFIG", "config.json"))
    if cfg_path.exists():
        try:
            data.update(json.loads(cfg_path.read_text(encoding="utf-8")))
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"Не удалось разобрать {cfg_path}: {exc}") from exc

    data.update({k: v for k, v in overrides.items() if v is not None})
    known = {f for f in Config.__dataclass_fields__}
    filtered = {k: v for k, v in data.items() if k in known}
    return Config(**filtered)


if __name__ == "__main__":
    cfg = load_config()
    print(json.dumps(cfg.to_dict(redact=True), indent=2, ensure_ascii=False))
    print("identity sample:", json.dumps(cfg.random_identity(), indent=2))
