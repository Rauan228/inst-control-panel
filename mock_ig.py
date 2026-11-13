#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mock_ig.py — заглушки страниц Instagram, повторяющие РЕАЛЬНУЮ разметку Meta
signup (дамп от 2025-11: https://www.instagram.com/accounts/emailsignup/).

Ключевые особенности настоящей страницы, которые здесь воспроизведены:
  * у input'ов НЕТ атрибута name — только случайные id (_r_1f_) и type;
  * порядок полей: text(контакт) -> password -> text(ФИО) -> search(username);
  * дата рождения — НЕ <select>, а три div[role=combobox][aria-haspopup=listbox]
    с aria-label «Выберите день/месяц/год» и опциями div[role=option];
  * submit — div[role=button][tabindex=0] с текстом «Отправить», не <button>;
  * экран кода: один input[maxlength=6] без name + div[role=button] «Далее».
"""

from __future__ import annotations


def _day_options() -> str:
    return "".join(
        f'<div role="option" aria-selected="false" class="opt">{d}</div>'
        for d in range(1, 32)
    )


def _month_options() -> str:
    names = ["january", "february", "march", "april", "may", "june", "july",
             "august", "september", "october", "november", "december"]
    return "".join(
        f'<div role="option" aria-selected="false" class="opt">{n}</div>'
        for n in names
    )


def _year_options() -> str:
    return "".join(
        f'<div role="option" aria-selected="false" class="opt">{y}</div>'
        for y in range(2012, 1899, -1)
    )


SIGNUP_HTML = """<!doctype html><html lang="ru"><head><meta charset="utf-8">
<title>Instagram</title>
<style>
  .lb { display:none; border:1px solid #ccc; max-height:150px; overflow:auto; }
  .lb.open { display:block; }
  .opt { padding:4px 8px; cursor:pointer; }
  .cbx { border:1px solid #999; padding:6px; display:inline-block; min-width:110px; cursor:pointer; }
  .submit { background:#0095f6; color:#fff; padding:8px 16px; display:inline-block; cursor:pointer; }
</style></head><body>
<div id="mount_0_0_T0">
  <div id="signupStep">
    <input dir="ltr" autocomplete="off" inputmode="text" aria-invalid="false"
           id="_r_1f_" type="text" value="">
    <input dir="ltr" autocomplete="off" inputmode="text" aria-invalid="false"
           id="_r_1i_" type="password" value="">

    <div>Дата рождения</div>
    <div id="_r_1m_" role="combobox" tabindex="0" aria-haspopup="listbox"
         aria-expanded="false" aria-label="Выберите день" class="cbx" data-key="day">День</div>
    <div id="_r_1s_" role="combobox" tabindex="0" aria-haspopup="listbox"
         aria-expanded="false" aria-label="Выберите месяц" class="cbx" data-key="month">Месяц</div>
    <div id="_r_1y_" role="combobox" tabindex="0" aria-haspopup="listbox"
         aria-expanded="false" aria-label="Выберите год" class="cbx" data-key="year">Год</div>
    <div id="lb_day" role="listbox" class="lb">__DAY__</div>
    <div id="lb_month" role="listbox" class="lb">__MONTH__</div>
    <div id="lb_year" role="listbox" class="lb">__YEAR__</div>

    <input dir="ltr" autocomplete="off" inputmode="text" aria-invalid="false"
           id="_r_27_" type="text" value="">
    <input dir="ltr" aria-autocomplete="list" aria-expanded="false" role="combobox"
           aria-label="Имя пользователя" autocomplete="off" aria-invalid="false"
           id="_r_2d_" type="search" value="">

    <div class="submit" role="button" tabindex="0" id="submitBtn">
      <span><span>Submit</span></span>
    </div>
  </div>

  <div id="challenge" style="display:none">
    <script>
      window.arkoseEnforcement = {
        _config: { public_key: "EEEE1111-2222-3333-4444-555566667777",
                   surl: "https://client-api.arkoselabs.com",
                   blob: "eyJkYXRhIjp7ImUyZSI6dHJ1ZX19" },
        setConfig: function (c) { window.__injected = c; },
        run: function () { window.__ran = true; },
      };
    </script>
    <iframe src="https://client-api.arkoselabs.com/v2/1.5.2/enforcement.html?public_key=EEEE1111-2222-3333-4444-555566667777&surl=https%3A%2F%2Fclient-api.arkoselabs.com"
            style="width:340px;height:400px"></iframe>
    <input type="hidden" name="fc-token" value="">
    <div class="submit" role="button" tabindex="0" id="challengeBtn"><span>Далее</span></div>
  </div>

  <div id="codeScreen" style="display:none">
    <input dir="ltr" autocomplete="off" inputmode="numeric" maxlength="6"
           aria-invalid="false" id="_r_9c_" type="text" value="">
    <div class="submit" role="button" tabindex="0" id="codeBtn"><span>Далее</span></div>
  </div>

  <div id="feed" style="display:none"><img alt="Profile photo"></div>
</div>

<script>
  const state = { day: null, month: null, year: null };
  const show = (id) => document.getElementById(id).style.display = 'block';
  const hide = (id) => document.getElementById(id).style.display = 'none';
  const closeAll = () => document.querySelectorAll('.lb').forEach(l => l.classList.remove('open'));

  document.querySelectorAll('.cbx').forEach(cbx => {
    cbx.addEventListener('click', (e) => {
      e.stopPropagation();
      const key = cbx.dataset.key;
      const lb = document.getElementById('lb_' + key);
      const wasOpen = lb.classList.contains('open');
      closeAll();
      if (!wasOpen) { lb.classList.add('open'); cbx.setAttribute('aria-expanded', 'true'); }
    });
  });

  document.querySelectorAll('.lb').forEach(lb => {
    const key = lb.id.replace('lb_', '');
    lb.querySelectorAll('[role=option]').forEach(opt => {
      opt.addEventListener('click', (e) => {
        e.stopPropagation();
        state[key] = opt.textContent.trim();
        lb.querySelectorAll('[role=option]').forEach(o => o.setAttribute('aria-selected', 'false'));
        opt.setAttribute('aria-selected', 'true');
        document.querySelector('.cbx[data-key="' + key + '"]').textContent = state[key];
        lb.classList.remove('open');
      });
    });
  });

  document.getElementById('submitBtn').addEventListener('click', () => {
    const inputs = document.querySelectorAll('#signupStep input[type=text]');
    const pwd = document.querySelector('#signupStep input[type=password]');
    const uname = document.querySelector('#signupStep input[type=search]');
    if (!inputs[0].value) { document.title = 'INCOMPLETE:contact'; return; }
    if (!pwd.value) { document.title = 'INCOMPLETE:password'; return; }
    if (!inputs[1].value) { document.title = 'INCOMPLETE:fullname'; return; }
    if (!uname.value) { document.title = 'INCOMPLETE:username'; return; }
    if (!state.day || !state.month || !state.year) { document.title = 'INCOMPLETE:birthday'; return; }
    window.__form = { contact: inputs[0].value, password: pwd.value,
                      fullname: inputs[1].value, username: uname.value, ...state };
    hide('signupStep'); show('challenge');
    document.title = 'ARKOSE_CHALLENGE';
  });

  document.getElementById('challengeBtn').addEventListener('click', () => {
    const tok = document.querySelector('input[name="fc-token"]').value;
    if (!tok) { document.title = 'CHALLENGE_NOT_SOLVED'; return; }
    hide('challenge'); show('codeScreen');
    document.title = 'CODE_PROMPT';
  });

  document.getElementById('codeBtn').addEventListener('click', () => {
    const c = document.querySelector('#codeScreen input').value;
    if (/^\\d{6}$/.test(c)) { hide('codeScreen'); show('feed'); document.title = 'LOGGED_IN'; }
    else document.title = 'BAD_CODE:' + c;
  });
</script>
</body></html>"""

SIGNUP_HTML = (SIGNUP_HTML
               .replace("__DAY__", _day_options())
               .replace("__MONTH__", _month_options())
               .replace("__YEAR__", _year_options()))

#: страница редактирования профиля — загрузка аватара
EDIT_HTML = """<!doctype html><html><body>
<button>Change profile photo</button>
<input type="file" style="display:none">
<button>Done</button>
<script>
  document.querySelectorAll('button')[0].onclick = () =>
    document.querySelector('input[type=file]').click();
  document.querySelector('input[type=file]').onchange = () => { document.title = 'AVATAR_SET'; };
</script></body></html>"""

#: страница популярного аккаунта — кнопка Follow
PROFILE_HTML = """<!doctype html><html><body>
<div role="button">Follow</div>
<button>Not now</button>
<script>
  document.querySelector('div[role=button]').onclick = () => {
    document.title = 'FOLLOWED';
    document.querySelector('div[role=button]').textContent = 'Following';
  };
</script></body></html>"""


#: страница человеческого гейта («Confirm you're human») — /accounts/suspended
GATE_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Instagram</title></head>
<body>
  <div>Confirm you're human to use your profile, _user_</div>
  <div role="button" tabindex="0" id="cont"><span>Continue</span></div>
  <div>Takes about 30 seconds</div>
  <script>
    document.getElementById('cont').onclick = () => { location.href = 'feed.html'; };
  </script>
</body></html>"""

#: тот же гейт, но Continue ничего не делает (аккаунт «залип» в suspended)
GATE_STUCK_HTML = GATE_HTML.replace("location.href = 'feed.html';", "")

#: гейт с reCAPTCHA (sitekey вытаскивается из data-sitekey / k= во frame)
GATE_RECAPTCHA_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Instagram</title>
<script src="https://www.google.com/recaptcha/enterprise.js"></script></head>
<body>
  <div>Confirm you're human to use your profile, _user_</div>
  <div class="g-recaptcha" data-sitekey="6Lc_TESTKEY_ENTERPRISE"></div>
  <textarea name="g-recaptcha-response"></textarea>
  <div role="button" tabindex="0" id="cont"><span>Continue</span></div>
  <script>
    document.getElementById('cont').onclick = () => { location.href = 'feed.html'; };
  </script>
</body></html>"""

#: лента после гейта / входа
FEED_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>Instagram</title></head><body><section>
  <article><span><button><svg aria-label="Like"></svg></button></span></article>
</section></body></html>"""


def write_all(directory, with_challenge: bool = True, with_gate: bool = False) -> None:
    """
    Раскладывает заглушки: signup.html / index.html / edit.html / profile.html.

    with_challenge=False — после submit сразу открывается экран ввода кода
    (для тестов формы без капча-провайдера).
    with_gate=True — дополнительно кладёт gate*.html / feed.html.
    """
    from pathlib import Path
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)

    signup = SIGNUP_HTML
    if not with_challenge:
        signup = signup.replace(
            "hide('signupStep'); show('challenge');\n    document.title = 'ARKOSE_CHALLENGE';",
            "hide('signupStep'); show('codeScreen');\n    document.title = 'CODE_PROMPT';",
        )

    (d / "signup.html").write_text(signup, encoding="utf-8")
    (d / "index.html").write_text(signup, encoding="utf-8")
    (d / "edit.html").write_text(EDIT_HTML, encoding="utf-8")
    (d / "profile.html").write_text(PROFILE_HTML, encoding="utf-8")
    if with_gate:
        (d / "gate.html").write_text(GATE_HTML, encoding="utf-8")
        (d / "gate_stuck.html").write_text(GATE_STUCK_HTML, encoding="utf-8")
        (d / "gate_recaptcha.html").write_text(GATE_RECAPTCHA_HTML, encoding="utf-8")
        (d / "feed.html").write_text(FEED_HTML, encoding="utf-8")
