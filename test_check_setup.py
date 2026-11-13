#!/usr/bin/env python3
"""
test_check_setup.py — проверка preflight-диагностики check_setup.py.

Поднимает mock IMAP-сервер (из test_email_imap), создаёт временный каталог с
`.env` и папкой аватарок, затем запускает check_setup.py отдельным процессом и
assert'ит его вердикты:
  * живой IMAP  -> [ OK ] IMAP: LOGIN + EXAMINE + SEARCH + FETCH
  * мёртвый порт-> [FAIL] IMAP недоступен, exit code 1
  * .env подхватывается, аватарки считаются
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def plain(text: str) -> str:
    """Убираем ANSI-коды, чтобы assert'ы сравнивали чистый текст."""
    return ANSI_RE.sub("", text)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from test_email_imap import MAILBOX, FakeIMAPServer, make_mail  # noqa: E402

PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000a49444154789c6300010000050001"
    "0d0a2db40000000049454e44ae426082"
)


def make_workspace(tmp: Path, imap_port: int, avatars: int) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    av = tmp / "avatars"
    av.mkdir(exist_ok=True)
    for i in range(avatars):
        (av / f"face_{i:03d}.png").write_bytes(PNG)

    env = f"""REG_METHOD=email
HEADLESS=1
MAX_ACCOUNTS=3
EMAIL_DOMAIN=example.com
IMAP_HOST=127.0.0.1
IMAP_PORT={imap_port}
IMAP_SSL=0
IMAP_USER=catchall@example.com
IMAP_PASS=app-password-{imap_port}
IMAP_MAILBOX=INBOX
PROXY=
CAPTCHA_API_KEY=
AVATARS_DIR={av}
COOKIES_DIR={tmp}/cookies
SUCCESS_FILE={tmp}/success.txt
FAILED_FILE={tmp}/failed.txt
LOG_FILE={tmp}/autoreg.log
"""
    (tmp / ".env").write_text(env, encoding="utf-8")
    return tmp


def run_checker(cwd: Path, only: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    # чистим переменные, которые перебили бы .env (load_dotenv использует setdefault)
    for k in list(env):
        if k in {"REG_METHOD", "EMAIL_DOMAIN", "IMAP_HOST", "IMAP_PORT", "IMAP_SSL",
                 "IMAP_USER", "IMAP_PASS", "PROXY", "CAPTCHA_API_KEY", "AVATARS_DIR",
                 "SMS_API_KEY", "MAX_ACCOUNTS"}:
            env.pop(k)
    return subprocess.run(
        [sys.executable, str(HERE / "check_setup.py"), "--only", only],
        cwd=str(cwd), env=env, capture_output=True, text=True, timeout=180,
    )


def main() -> int:
    server = FakeIMAPServer()
    MAILBOX.clear()
    MAILBOX.append(make_mail("ig.user_alpha@example.com", "482913"))
    MAILBOX.append(make_mail("ig.user_beta@example.com", "975310", html=False))
    server.start()
    print(f"[test] mock IMAP на 127.0.0.1:{server.port}, писем: {len(MAILBOX)}")

    try:
        # --- 1. живой IMAP + 12 аватарок + .env ------------------------------
        ws1 = make_workspace(Path.cwd() / "_tmp_check_ok", server.port, avatars=12)
        r = run_checker(ws1, "config,imap,avatars")
        out = plain(r.stdout + r.stderr)
        assert "[ OK ] IMAP: LOGIN + EXAMINE + SEARCH + FETCH прошли" in out, out
        assert "писем в INBOX: 2" in out, out
        assert "ig.user_alpha@example.com" in out or "Instagram" in out, out
        assert "[ OK ] .env найден" in out, out
        assert "[ OK ] 12 изображений" in out, out
        assert r.returncode == 0, f"exit={r.returncode}\n{out}"
        print("[1] ok: живой IMAP распознан, .env подхвачен, 12 аватарок учтены, exit=0")
        print("    фрагмент:", [ln.strip() for ln in out.splitlines() if "IMAP:" in ln][0])

        # --- 2. мёртвый IMAP-порт -> FAIL + exit 1 --------------------------
        ws2 = make_workspace(Path.cwd() / "_tmp_check_bad", 1, avatars=0)
        r2 = run_checker(ws2, "config,imap,avatars")
        out2 = plain(r2.stdout + r2.stderr)
        assert "[FAIL] IMAP недоступен" in out2, out2
        assert "app-пароль" in out2, out2                      # подсказки напечатаны
        assert "[WARN] папка пустая" in out2, out2
        assert r2.returncode == 1, f"exit={r2.returncode}\n{out2}"
        print("[2] ok: мёртвый IMAP -> FAIL + подсказки, пустая папка -> WARN, exit=1")

        # --- 3. проверка catch-all инструкции присутствует ------------------
        assert "ПРОВЕРКА CATCH-ALL" in out and "random-test-" in out, out
        print("[3] ok: инструкция по проверке catch-all печатается")

    finally:
        server.close()

    print("\nCHECK_SETUP TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
