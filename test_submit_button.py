#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_submit_button.py — регресс на баг «поле submit не найдено».

Живая страница Meta signup использует div[role=button][tabindex=0] с текстом
«Submit» (а не «Sign up»). Тест проверяет три сценария:
  1. текст «Submit»      -> находится основным путём (get_by_role)
  2. текст «Отправить»   -> тоже основной путь (русская локаль)
  3. неизвестный текст «Proceed» + служебные кнопки-приманки (Back, Hide
     password, I already have an account) -> срабатывает запасной поиск
     primary-CTA, кликается именно «Proceed», а не приманка.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
os.environ["PROXY"] = ""
os.environ["PROXY_LIST"] = ""

import autoreg  # noqa: E402
from config import Config  # noqa: E402

autoreg.setup_logging(str(Path(__file__).parent / "test_submit.log"), verbose=False)


def page_with_buttons(submit_text: str, decoys: bool = False) -> str:
    """Страница: несколько div[role=button], нужный — с текстом submit_text."""
    decoy_html = ""
    if decoys:
        decoy_html = """
        <div role="button" tabindex="0" aria-label="Back" id="bBack"><span>Back</span></div>
        <div role="button" tabindex="0" aria-label="Hide password" id="bHide"><span>Hide password</span></div>
        <div role="button" tabindex="0" id="bHave"><span>I already have an account</span></div>
        """
    return f"""<!doctype html><html><body>
    {decoy_html}
    <div role="button" tabindex="0" id="bSubmit"><span><span>{submit_text}</span></span></div>
    <script>
      document.querySelectorAll('div[role=button]').forEach(b =>
        b.addEventListener('click', () => {{ document.title = 'CLICKED:' + b.id; }}));
    </script></body></html>"""


async def run_case(bf, cfg, submit_text: str, decoys: bool, expect_id: str) -> None:
    ctx, page = await bf.new_context()
    await page.goto("about:blank")
    await page.set_content(page_with_buttons(submit_text, decoys))
    reg = autoreg.InstagramRegistrar(cfg, autoreg.HumanDriver(cfg),
                                     autoreg.ArkoseSolver(cfg))
    await reg.submit(page)
    await page.wait_for_function("document.title.startsWith('CLICKED:')", timeout=8000)
    title = await page.title()
    assert title == f"CLICKED:{expect_id}", f"{submit_text!r}: {title}"
    print(f"[ok] кнопка «{submit_text}» (decoys={decoys}) -> кликнут #{expect_id}")
    await ctx.close()


async def main() -> int:
    cfg = Config(PROXY="", PROXY_LIST="", PROXY_ROTATE_SLEEP=0,
                 LOG_FILE="test_submit.log")
    bf = autoreg.BrowserFactory(cfg)
    try:
        await run_case(bf, cfg, "Submit", False, "bSubmit")       # живая EN
        await run_case(bf, cfg, "Отправить", False, "bSubmit")     # живая RU
        await run_case(bf, cfg, "Proceed", True, "bSubmit")        # запасной поиск
        await run_case(bf, cfg, "Submit", True, "bSubmit")         # EN + приманки
    finally:
        await bf.close()
    print("\nSUBMIT BUTTON TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
