#!/usr/bin/env python3
"""
Регистрация через приватный мобильный API Instagram (aiograpi).

Отличие от web-канала (autoreg.py): нет браузера на шагах формы. Запросы
идут с device-профилем Android-приложения, подписью и app-заголовками, то
есть тем же каналом, которым регистрируется само приложение.

Почему так: веб-канал режет все аккаунты через 30–50 минут, а инфраструктура
(номер, IP, домен почты, сессия) уже исключена как причина.

Схема:
  1. identity (имя/ник/почта/дата рождения) — из autoreg.IdentityFactory;
  2. CAA-флоу aiograpi: почта -> код из IMAP -> пароль -> ДР -> имя -> ник -> create;
  3. сразу после создания IG отдаёт suspended-челлендж (это и есть гейт);
  4. челлендж уходит в webview: браузер с cookie клиента открывает
     /accounts/suspended/, дальше работает уже написанный HumanGate
     (капча -> номер -> SMS -> селфи -> апелляция);
  5. settings клиента (device + cookies) сохраняются как сессия аккаунта.

Управление аккаунтом потом идёт через тот же aiograpi-клиент, без браузера.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import random
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import aiohttp
from aiograpi import Client
from aiograpi.exceptions import (
    AccountSuspended,
    ChallengeRequired,
    ClientError,
    ClientLoginRequired,
)
from aiograpi.mixins.challenge import ChallengeChoice
from aiograpi.utils.serialization import dumps
from playwright.async_api import BrowserContext, Page

import autoreg
from autoreg import (
    AccountRejectedError,
    AutoRegError,
    Identity,
    IdentityFactory,
    ProxyRotator,
    Storage,
    VerificationTimeoutError,
    long_rnd,
    mask_secret,
    rnd,
    setup_logging,
)
from config import Config, load_config

log = autoreg.log

#: челлендж-страница, которую открывает webview приложения
SUSPENDED_URL = "https://www.instagram.com/accounts/suspended/"

#: экран проверки в bloks-слое; в актуальной сборке шаг называется без .async
UFAC_ACTION = "com.bloks.www.checkpoint.ufac"

#: aiograpi шлёт шаг имени как name_vtwo.async, сервер отвечает 404
NAME_ACTION_FIX = ("name_vtwo.async", "name.async")


class ApiError(AutoRegError):
    """Ошибка API-канала."""


class RegistrationRejected(ApiError):
    """IG отклонил создание аккаунта."""


# ===========================================================================
# Клиент
# ===========================================================================


def build_client(cfg: Config, proxy: str = "") -> Client:
    """Клиент с device-профилем и (опционально) прокси."""
    client = Client(proxy=proxy or None, delay_range=[1, 3])
    client.init()
    if cfg.MOBILE_MODE:
        client.set_device({**client.device_settings, "manufacturer": "samsung",
                           "model": "SM-G991B", "device": "o1s"})
        client.set_user_agent()
    # timezone_offset нужен CAA-шагу birthday
    client.timezone_offset = -7 * 3600
    return client


def patch_name_action(client: Client) -> None:
    """Подменяет устаревшее имя шага имени на актуальное."""
    old, new = NAME_ACTION_FIX
    original = client.caa_reg_async_action

    async def patched(action: str, *args: Any, **kwargs: Any) -> dict:
        return await original(action.replace(old, new), *args, **kwargs)

    client.caa_reg_async_action = patched  # type: ignore[method-assign]


# ===========================================================================
# Регистрация
# ===========================================================================


class ApiRegistrar:
    """Один аккаунт за проход: создание через API + проход гейта в webview."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.storage = Storage(cfg)
        self.identities = IdentityFactory(cfg)
        self.mail = autoreg.EmailVerifier(cfg)
        self.proxy = ProxyRotator(cfg)

    # -- код из почты -------------------------------------------------------
    async def _email_code(self, email: str, since_ts: float) -> str:
        return await self.mail.wait_for_code(email, since_ts)

    def _code_handler(self, email: str, since_ts: float):
        async def handler(username: str, choice: ChallengeChoice, **_: Any) -> str:
            if choice is not ChallengeChoice.EMAIL:
                return ""
            return await self._email_code(email, since_ts)

        return handler

    # -- создание -----------------------------------------------------------
    async def create(self, ident: Identity,
                     client: Client, since_ts: float) -> None:
        """Доводит CAA-флоу до created_user. Гейт здесь ещё не пройден."""
        check = await client.check_email(ident.email)
        if not check.get("valid"):
            raise RegistrationRejected(f"email невалиден: {check}")
        if not check.get("available"):
            raise RegistrationRejected(
                f"email занят: {check.get('feedback_message', check)}")

        year, month, day = ident.birthday
        try:
            await client.signup_caa_email(
                ident.username, ident.password, ident.email,
                full_name=ident.full_name,
                year=year, month=month, day=day,
            )
        except ClientError as exc:
            raise RegistrationRejected(str(exc)[:200]) from exc

        self.storage.audit(ident.username, "created",
                           email=ident.email, channel="api")

    # -- сессия -------------------------------------------------------------
    @staticmethod
    async def login(client: Client, ident: Identity) -> bool:
        """
        Пытается войти. Свежий аккаунт почти всегда отдаёт AccountSuspended —
        это ожидаемый гейт, а не сбой. True — сессия получена.
        """
        try:
            await client.login(ident.username, ident.password)
            return True
        except (AccountSuspended, ChallengeRequired):
            return False
        except ClientLoginRequired as exc:
            raise ApiError(f"логин отклонён: {exc}") from exc

    async def open_suspended(self, client: Client, ident: Identity) -> bool:
        """
        Проходит вход до suspended-челленджа и жмёт «начать» в bloks-слое.

        Именно этот шаг выдаёт sessionid: до него клиент анонимный, и webview
        выкидывает на форму логина. True — сессия есть.
        """
        try:
            await client.login(ident.username, ident.password)
            return True
        except (AccountSuspended, ChallengeRequired) as exc:
            challenge = getattr(exc, "challenge", None) or {}
        if not challenge.get("challenge_context") and not challenge.get("api_path"):
            raise ApiError(f"челлендж без данных: {challenge}")

        step = await client.challenge_api(challenge)
        context = step.get("challenge_context") or challenge.get("challenge_context", "")
        await client.bloks_challenge_take_challenge(challenge_context=context,
                                                    choice=0)
        if not client.sessionid:
            raise ApiError("sessionid не выдан после take_challenge")
        log.info("[api] sessionid получен, аккаунт аутентифицирован")
        return True

    # -- гейт через webview -------------------------------------------------
    def _client_cookies(self, client: Client) -> list[dict[str, Any]]:
        """Cookie клиента для проброса в браузер: сессия + метки устройства."""
        cookies: dict[str, str] = {}
        with contextlib.suppress(Exception):
            cookies.update(client.private.cookies_dict())
        pairs = (("sessionid", client.sessionid), ("ds_user_id", client.user_id),
                 ("mid", client.mid), ("csrftoken", client.token),
                 ("ig_did", client.android_device_id))
        for name, value in pairs:
            if value and name not in cookies:
                cookies[name] = str(value)
        return [{"name": k, "value": v, "domain": ".instagram.com", "path": "/"}
                for k, v in cookies.items()]

    async def pass_gate(self, client: Client, ident: Identity,
                        session: aiohttp.ClientSession, probe: bool = False) -> bool:
        """
        Открывает suspended-страницу в webview-браузере с cookie клиента и
        прогоняет существующий HumanGate. Возвращает True при отправленной
        апелляции/снятом гейте.
        """
        gate = autoreg.HumanGate(self.cfg)
        human = autoreg.HumanDriver(self.cfg)
        arkose = autoreg.ArkoseSolver(self.cfg)
        sms = autoreg.SmsVerifier(self.cfg)
        factory = autoreg.BrowserFactory(self.cfg)
        fp = self.cfg.random_identity()
        # webview приложения: UA и viewport берём у API-клиента, чтобы страница
        # не видела расхождения «мобильное приложение / десктопный браузер»
        fp.update({"user_agent": client.user_agent,
                   "viewport": {"width": 412, "height": 915},
                   "is_mobile": True, "has_touch": True,
                   "device_scale_factor": 2.6, "platform": "Linux armv8l"})

        # заголовки приложения: без X-IG-Attest-Params webview — просто браузер
        headers: dict[str, str] = {}
        with contextlib.suppress(Exception):
            await client.attestation_create_android_keystore(domain="b.i.instagram.com")
            params = client.attestation_params()
            if params:
                headers["X-IG-Attest-Params"] = params
                headers["X-IG-App-ID"] = str(client.app_id)

        context, page = await factory.new_context(
            fp, storage_state=None, extra_cookies=self._client_cookies(client),
            extra_headers=headers)
        try:
            await page.goto(SUSPENDED_URL, wait_until="domcontentloaded",
                            timeout=90000)
            await rnd(2, 4)
            if probe:
                text = (await page.locator("body").inner_text())[:1200]
                Path("debug/api_probe.txt").write_text(
                    f"URL: {page.url}\n\n{text}", encoding="utf-8")
                isgate = await gate.is_gate(page)
                print(f"PROBE url={page.url} gate={isgate}", flush=True)
                print("PROBE text=", text.replace("\n", " | ")[:500], flush=True)
                await page.screenshot(path="debug/api_probe.png", full_page=True)
                return False
            if not await gate.is_gate(page):
                log.info("[gate] гейт не показан, url=%s", page.url)
            ok = await gate.pass_gate(page, human, arkose, mail=self.mail,
                                      email=ident.email,
                                      since_ts=time.time() - 300,
                                      sms=sms, session=session)
            return ok
        finally:
            with contextlib.suppress(Exception):
                await context.close()
            with contextlib.suppress(Exception):
                await factory.close()

    # -- весь проход --------------------------------------------------------
    async def run_one(self, session: aiohttp.ClientSession,
                      probe: bool = False) -> dict[str, Any]:
        """
        Проход с ретраями: сервер отвечает «something went wrong» примерно в
        половине случаев. Аккаунт при отказе не создаётся, поэтому повтор
        берёт новую идентичность.
        """
        last: Exception | None = None
        for attempt in range(1, self.cfg.API_MAX_ATTEMPTS + 1):
            try:
                return await self._attempt(session, probe=probe)
            except (RegistrationRejected, VerificationTimeoutError) as exc:
                last = exc
                log.warning("[api] попытка %s/%s: %s", attempt,
                            self.cfg.API_MAX_ATTEMPTS, exc)
                if attempt < self.cfg.API_MAX_ATTEMPTS:
                    await asyncio.sleep(random.uniform(20, 40))
        assert last is not None
        raise last

    async def _attempt(self, session: aiohttp.ClientSession,
                       probe: bool = False) -> dict[str, Any]:
        ident = self.identities.new_identity()
        self.storage.audit(ident.username, "register_started",
                           email=ident.email, channel="api", proxy="")
        client: Client | None = None
        path: Path | None = None
        try:
            client = build_client(self.cfg)
            patch_name_action(client)
            since = time.time()
            client.challenge_code_handler = self._code_handler(ident.email, since)

            await self.create(ident, client, since)

            if await self.login(client, ident):
                log.info("[api] сессия получена сразу после создания")
            else:
                log.warning("[api] аккаунт на suspended-челлендже — прохожу челлендж")
                await self.open_suspended(client, ident)
                path = self._save_settings(ident, client)   # сессию не теряем
                passed = await self.pass_gate(client, ident, session, probe=probe)
                if probe:
                    await self.storage.save_success(ident, "", cookies_path=path,
                                                    status="suspended", channel="api")
                    return {"ident": ident, "cookies": path}
                if not passed:
                    await self.storage.save_success(ident, "", cookies_path=path,
                                                    status="suspended", channel="api")
                    raise AutoRegError("гейт не пройден")
                self.storage.audit(ident.username, "appeal_sent", channel="api")

            status = "suspended"
            with contextlib.suppress(Exception):
                if await client.account_info():
                    status = "alive"
            path = self._save_settings(ident, client)
            await self.storage.save_success(ident, "", cookies_path=path,
                                            status=status, channel="api")
            return {"ident": ident, "cookies": path}
        except Exception as exc:
            await self.storage.save_failed(ident, str(exc))
            if path is not None and client is not None and client.sessionid:
                self._save_settings(ident, client)
            raise
        finally:
            if client is not None:
                with contextlib.suppress(Exception):
                    await client.close()

    def _save_settings(self, ident: Identity, client: Client) -> Path:
        path = Path(self.cfg.COOKIES_DIR) / f"{ident.username}_{autoreg.now_stamp()}.json"
        path.write_text(json.dumps(client.get_settings(), ensure_ascii=False),
                        encoding="utf-8")
        log.info("[api] settings сохранены -> %s", path)
        return path


# ===========================================================================
# CLI
# ===========================================================================


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Регистрация через приватный API")
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--probe", action="store_true",
                   help="только создать и показать страницу гейта")
    return p.parse_args(argv)


async def amain(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = load_config()
    setup_logging(cfg.LOG_FILE, verbose=args.verbose)
    log.info("[api] старт: %s аккаунт(ов)", args.count)

    registrar = ApiRegistrar(cfg)
    async with aiohttp.ClientSession() as session:
        done = 0
        for i in range(1, args.count + 1):
            log.info("[api] проход %s/%s", i, args.count)
            try:
                res = await registrar.run_one(session, probe=args.probe)
                done += 1
                log.info("[api] готово: %s", res["ident"].username)
            except Exception as exc:  # noqa: BLE001 — проход не должен рвать серию
                log.error("[api] проход упал: %s: %s", type(exc).__name__, exc)
            if i < args.count:
                delay = random.randint(cfg.COOLDOWN_MIN, cfg.COOLDOWN_MAX)
                log.info("[api] пауза %s сек", delay)
                await asyncio.sleep(delay)
        log.info("[api] итог: %s/%s", done, args.count)
    return 0 if done else 1


def main() -> int:
    return asyncio.run(amain())


if __name__ == "__main__":
    raise SystemExit(main())
