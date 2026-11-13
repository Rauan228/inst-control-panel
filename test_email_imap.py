#!/usr/bin/env python3
"""
test_email_imap.py — проверка EmailVerifier против реального imaplib-клиента,
подключённого к минимальному локальному IMAP-серверу (catch-all сценарий).

Проверяется:
  * imaplib-подключение (LOGIN/EXAMINE/SEARCH/FETCH) в asyncio.to_thread
  * вырезание кода r'\\b\\d{6}\\b' из multipart HTML-письма с zero-width символами
  * фильтр чужих писем в catch-all ящике (по local-part получателя)
  * ожидание письма, которое приходит с задержкой
  * VerificationTimeoutError, если письма нет
"""
from __future__ import annotations

import asyncio
import os
import re
import socket
import sys
import threading
import time
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("PROXY", "")

import autoreg  # noqa: E402
from config import load_config  # noqa: E402

autoreg.setup_logging("test_imap.log", verbose=False)

MAILBOX: list[bytes] = []          # «письма» в catch-all ящике
LOGINS: list[str] = []


def make_mail(to_addr: str, code: str, *, html: bool = True,
              subject: str | None = None) -> bytes:
    """Письмо от Instagram: HTML + невидимые zero-width символы внутри кода."""
    m = EmailMessage()
    m["From"] = "Instagram <no-reply@mail.instagram.com>"
    m["To"] = to_addr
    m["Subject"] = subject or f"{code} is your Instagram code"
    m["Date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    scattered = "\u200b".join(code)              # 6\u200b5\u200b4... — как в реальных письмах
    if html:
        m.set_content("Turn on HTML to see the code.")
        m.add_alternative(
            f"<html><body><p>Hi,</p><p>Your confirmation code is "
            f"<b style='font-size:24px'>{scattered}</b></p>"
            f"<p>If you didn't request it, ignore this email.</p></body></html>",
            subtype="html",
        )
    else:
        m.set_content(f"Your Instagram code: {scattered}")
    return m.as_bytes()


# ----------------------------------------------------------------- IMAP mock
class FakeIMAPHandler:
    """
    Минимальный IMAP4-сервер, достаточный для imaplib:
    CAPABILITY / LOGIN / EXAMINE / SELECT / SEARCH / FETCH / LOGOUT / NOOP.
    """

    def __init__(self, conn: socket.socket) -> None:
        self.conn = conn
        self.buf = b""
        self.tag = ""
        self.selected = False

    def send(self, line: str) -> None:
        self.conn.sendall((line + "\r\n").encode())

    def handle(self) -> None:
        self.send("* OK [CAPABILITY IMAP4rev1 LITERAL+] FakeIMAP ready")
        while True:
            data = self.conn.recv(65536)
            if not data:
                break
            self.buf += data
            while b"\r\n" in self.buf:
                line, self.buf = self.buf.split(b"\r\n", 1)
                if not self.dispatch(line.decode("utf-8", "ignore")):
                    return

    def dispatch(self, line: str) -> bool:
        line = line.strip()
        if not line:
            return True
        parts = line.split(None, 2)
        self.tag = parts[0]
        cmd = parts[1].upper() if len(parts) > 1 else ""
        arg = parts[2] if len(parts) > 2 else ""

        if cmd == "CAPABILITY":
            self.send("* CAPABILITY IMAP4rev1 LITERAL+ AUTH=PLAIN")
            self.send(f"{self.tag} OK CAPABILITY completed")
        elif cmd in ("LOGIN", "AUTHENTICATE"):
            LOGINS.append(arg)
            self.send(f"{self.tag} OK LOGIN completed")
        elif cmd in ("SELECT", "EXAMINE"):
            self.selected = True
            self.send(f"* {len(MAILBOX)} EXISTS")
            self.send("* 0 RECENT")
            self.send("* OK [UIDVALIDITY 1] UIDs valid")
            self.send(f"* FLAGS (\\Seen \\Answered)")
            mode = "READ-ONLY" if cmd == "EXAMINE" else "READ-WRITE"
            self.send(f"{self.tag} OK [{mode}] {cmd} completed")
        elif cmd == "SEARCH":
            ids = " ".join(str(i + 1) for i in range(len(MAILBOX))) or ""
            self.send(f"* SEARCH {ids}".rstrip())
            self.send(f"{self.tag} OK SEARCH completed")
        elif cmd == "FETCH":
            m = re.match(r"(\d+)(?::(\d+))?\s+\(?(.*)\)?$", arg)
            if not m:
                self.send(f"{self.tag} BAD FETCH syntax")
                return True
            start = int(m.group(1))
            end = int(m.group(2) or m.group(1))
            for idx in range(start, min(end, len(MAILBOX)) + 1):
                raw = MAILBOX[idx - 1]
                self.send(f"* {idx} FETCH (FLAGS (\\Seen) BODY[] {{{len(raw)}}}")
                self.conn.sendall(raw + b")\r\n")
            self.send(f"{self.tag} OK FETCH completed")
        elif cmd == "LOGOUT":
            self.send("* BYE FakeIMAP signing off")
            self.send(f"{self.tag} OK LOGOUT completed")
            return False
        elif cmd == "NOOP":
            self.send(f"{self.tag} OK NOOP completed")
        else:
            self.send(f"{self.tag} OK {cmd} completed")
        return True


class FakeIMAPServer:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    @staticmethod
    def _client(conn: socket.socket) -> None:
        try:
            FakeIMAPHandler(conn).handle()
        except Exception:  # noqa: BLE001
            pass
        finally:
            with contextlib_suppress():
                conn.close()

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self._stop.set()
        self.sock.close()


class contextlib_suppress:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return True


# --------------------------------------------------------------------- tests
def new_cfg(host: str, port: int) -> autoreg.Config:
    cfg = load_config()
    cfg.REG_METHOD = "email"
    cfg.EMAIL_DOMAIN = "example.com"
    cfg.IMAP_HOST = host
    cfg.IMAP_PORT = port
    cfg.IMAP_SSL = False                 # тестовый сервер без TLS
    cfg.IMAP_USER = "catchall@example.com"
    cfg.IMAP_PASS = "app-password"
    cfg.IMAP_MAILBOX = "INBOX"
    cfg.IMAP_POLL_INTERVAL = 0.3
    cfg.IMAP_TIMEOUT = 6
    return cfg


async def main() -> int:
    server = FakeIMAPServer()
    server.start()
    print(f"[imap] mock-сервер на 127.0.0.1:{server.port}")
    cfg = new_cfg("127.0.0.1", server.port)
    ev = autoreg.EmailVerifier(cfg)

    try:
        # --- 1. письмо уже лежит в ящике: код вырезается из HTML ---
        MAILBOX.clear()
        MAILBOX.append(make_mail("ig.target_user@example.com", "482913"))
        since = time.time() - 60
        code = await ev.wait_for_code("ig.target_user@example.com", since)
        assert code == "482913", code
        assert LOGINS and "catchall@example.com" in LOGINS[-1], LOGINS
        print("[1] ok: код %s из multipart HTML (zero-width сняты), LOGIN=%s"
              % (code, LOGINS[-1][:40] + "…"))

        # --- 2. catch-all: чужие письма игнорируются ---
        MAILBOX.clear()
        MAILBOX.append(make_mail("ig.someone_else@example.com", "111111"))
        MAILBOX.append(make_mail("ig.target_user@example.com", "975310"))
        code = await ev.wait_for_code("ig.target_user@example.com", time.time() - 60)
        assert code == "975310", code
        print("[2] ok: в catch-all ящике найден код СВОЕГО адреса (%s), чужой пропущен" % code)

        # --- 3. письмо приходит с задержкой -> поллинг его дожидается ---
        MAILBOX.clear()

        def delayed_mail() -> None:
            time.sleep(1.5)
            MAILBOX.append(make_mail("ig.late_user@example.com", "246810", html=False))

        threading.Thread(target=delayed_mail, daemon=True).start()
        t0 = time.monotonic()
        code = await ev.wait_for_code("ig.late_user@example.com", time.time() - 5)
        dt = time.monotonic() - t0
        assert code == "246810", code
        assert dt >= 1.4, dt
        print("[3] ok: дождались письмо через %.1f c, код %s (plaintext)" % (dt, code))

        # --- 4. письма нет -> VerificationTimeoutError ---
        MAILBOX.clear()
        MAILBOX.append(make_mail("ig.someone_else@example.com", "111111"))
        try:
            await ev.wait_for_code("ig.absent_user@example.com", time.time() - 5)
            raise AssertionError("ожидался VerificationTimeoutError")
        except autoreg.VerificationTimeoutError as exc:
            print("[4] ok:", exc)

        # --- 5. старые письма (до отправки формы) не учитываются ---
        MAILBOX.clear()
        old = make_mail("ig.stale_user@example.com", "333333")
        old = old.replace(
            time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime()).encode(),
            time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(time.time() - 7200)).encode(),
        )
        MAILBOX.append(old)
        try:
            await ev.wait_for_code("ig.stale_user@example.com", time.time())
            raise AssertionError("ожидался VerificationTimeoutError для старого письма")
        except autoreg.VerificationTimeoutError:
            print("[5] ok: письмо двухчасовой давности проигнорировано")

    finally:
        server.close()

    print("\nALL IMAP TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
