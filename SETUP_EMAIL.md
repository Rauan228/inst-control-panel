# Настройка почты: домен + catch-all + IMAP (вариант Zoho)

Цель — получить `REG_METHOD=email` целиком, **без SMS-сервиса**: скрипт сам
придумывает адрес `ig.<username>@твойдомен`, а код подтверждения выкачивает из
одного IMAP-ящика, куда падают все письма домена.

Всё, что нужно: **домен** (любой, ~$1–10/год) и **почтовый сервис с catch-all и
IMAP**. Ниже — Zoho Mail (бесплатный тариф на свой домен), в конце таблицы с
альтернативами.

---

## Шаг 1. Домен

Подойдёт любой регистратор: Namecheap, Porkbun, Cloudflare Registrar, reg.ru.
Советы:

- бери `.com` / `.net` / `.org`; экзотические дешёвые зоны (`xyz`, `top`, `icu`)
  чаще попадают в спам-листы и режут deliverability;
- домен не должен быть свежесозданным «в ноль» под рассылку — если есть старый,
  используй его;
- домен регистрируешь на себя, в чужие панели не лезешь.

## Шаг 2. Zoho Mail: подключаем домен

1. <https://www.zoho.com/mail/signup.html> → план **Forever Free** (до 5
   пользователей, только веб/IMAP, без POP).
2. В мастере добавь домен и пропиши MX-записи у регистратора:

   ```
   MX  10  mx.zoho.com.
   MX  20  mx2.zoho.com.
   MX  50  mx3.zoho.com.
   TXT       v=spf1 include:zoho.com ~all
   ```

3. Подтверди владение доменом (TXT-запись вида `zoho-verification=zb...`).
4. Создай основной ящик, например `admin@твойдомен.com` — в него будет падать
   catch-all.
5. Жди распространения DNS: `dig MX твойдомен.com +short` должен показать
   `mx.zoho.com`. Обычно 10–60 минут.

## Шаг 3. Включаем catch-all

Zoho → **Mail Admin** → *Domains* → твой домен → **Mail Accounts** →
**Catch-all Account** → указать `admin@твойдомен.com`.

После этого **любой** адрес `*@твойдомен.com` падает в `admin@`:
`ig.john_smith4821@твойдомен.com`, `ig.anything@твойдомен.com` — всё туда.

## Шаг 4. Включаем IMAP и делаем app-пароль

1. Zoho Mail → *Settings* (шестерёнка) → **Mail Accounts** → твой аккаунт →
   **IMAP Access** → включить.
2. Там же → **Generate App Password** (или *Settings → Security → App
   Passwords*). Обычный пароль аккаунта для IMAP не сработает — нужен именно
   app-пароль.
3. Скопируй его — он показывается один раз.

IMAP-хосты Zoho:

| Регион аккаунта | Хост | Порт |
|---|---|---|
| `.com` (глобальный) | `imap.zoho.com` | 993 (SSL) |
| `.eu` | `imap.zoho.eu` | 993 |
| `.in` | `imap.zoho.in` | 993 |

## Шаг 5. `.env`

```bash
cp .env.example .env
```

Минимальный набор для email-регистрации:

```env
REG_METHOD=email

EMAIL_DOMAIN=твойдомен.com
EMAIL_LOCAL_PREFIX=ig

IMAP_HOST=imap.zoho.com
IMAP_PORT=993
IMAP_SSL=1
IMAP_USER=admin@твойдомен.com
IMAP_PASS=<app-пароль из шага 4>
IMAP_MAILBOX=INBOX
IMAP_TIMEOUT=180
IMAP_POLL_INTERVAL=4

CAPTCHA_PROVIDER=capmonster
CAPTCHA_API_KEY=<ключ capmonster.cloud или 2captcha.com>

PROXY=http://user:pass@ip:port
PROXY_ROTATION_URL=https://<провайдер>/change-ip?key=...
PROXY_ROTATE_SLEEP=10

AVATARS_DIR=avatars
HEADLESS=1
MAX_ACCOUNTS=3
```

`.env` подхватывается автоматически при старте (свой парсер в `config.py`,
`python-dotenv` не нужен). Переменные окружения имеют приоритет над файлом.
Файл в `.gitignore` — не закоммитится.

**Ключи в чат не присылай** — кладу их только в `.env` на своей машине. В логах
и в ответах web-панели они маскируются (`mask_secret`, `***REDACTED***`).

## Шаг 6. Аватарки

Положи в `avatars/` 20–50 разных `.jpg`/`.png` (квадрат, 400×400 и больше).
Повторы при серии регистраций — плохой сигнал, поэтому файлов должно быть не
меньше, чем планируемых аккаунтов.

## Шаг 7. Preflight-диагностика

```bash
python check_setup.py
```

Проходит по пунктам и печатает `OK / WARN / FAIL`:

1. конфиг и `.env` — что реально подхватилось (секреты замаскированы);
2. Playwright + Chromium — запускает браузер и сверяет фингерпринт-пробу
   (`webdriver`, plugins, timezone, screen, WebGL);
3. прокси — внешний IP через прокси + ответ `PROXY_ROTATION_URL`;
4. **IMAP** — `LOGIN → EXAMINE → SEARCH → FETCH`, показывает количество писем и
   последние 5 тем; при ошибке печатает этап и типовые причины (app-пароль,
   выключенный IMAP, неверный порт/хост);
5. SMS-сервис — баланс и доступность сервиса Instagram (если `REG_METHOD=sms`);
6. капча-сервис — баланс CapMonster / 2Captcha;
7. аватарки — сколько файлов в папке.

Точечные запуски:

```bash
python check_setup.py --only imap          # только почта
python check_setup.py --only proxy,imap
python check_setup.py --skip-browser       # без запуска Chromium
```

Exit code `0` = можно запускать, `1` = есть блокирующие FAIL.

## Шаг 8. Проверка catch-all (одна минута)

С любого **другого** ящика (gmail и т.п.) отправь письмо на:

```
random-test-<любое-число>@твойдомен.com
```

Подожди минуту и запусти `python check_setup.py --only imap`. Письмо должно
появиться в списке последних тем. Появилось — catch-all работает, скрипт будет
находить свои письма.

Как скрипт отличает своё письмо в общем ящике:
фильтр по отправителю `*instagram.com` **и** по local-part получателя в `To` /
`Delivered-To` / `X-Original-To`, плюс отсечка писем старше момента отправки
формы. Код вырезается регуляркой `\b\d{6}\b`, при этом из HTML снимаются теги и
zero-width символы (Instagram вставляет их между цифрами).

## Шаг 9. Запуск

```bash
# сначала один аккаунт в видимом браузере — посмотреть глазами
python autoreg.py --run --count 1 --headed

# затем серия
python autoreg.py --run --count 3

# или web-панель: http://127.0.0.1:8088
python autoreg.py --serve
```

Результаты: `success.txt` (`login:password:email:proxy`),
`cookies/<user>_<ts>.json`, `accounts.json`, ошибки — `failed.txt`,
полный лог — `autoreg.log`.

---

## Альтернативы Zoho

| Сервис | Catch-all | IMAP | Заметки |
|---|---|---|---|
| **Zoho Mail** (Forever Free) | да | `imap.zoho.com:993` | бесплатный, самый простой путь |
| **Яндекс 360 для домена** | да | `imap.yandex.ru:993` | нужен app-пароль; почта для домена платная |
| **Mail.ru для бизнеса** | да | `imap.mail.ru:993` | app-пароль |
| **Fastmail** | да | `imap.fastmail.com:993` | платный, очень стабильный IMAP |
| **Mailcow / docker-mailserver / Stalwart / Poste.io** (self-hosted) | из коробки | из коробки | нужен VPS, порт 993 наружу, PTR-запись для deliverability |
| **Cloudflare Email Routing** | да | **нет IMAP** | работает только как форвардер на ящик с IMAP; приёмник обязан сохранять оригинальный `To` |

## Если что-то не так

| Симптом | Причина / лечение |
|---|---|
| `IMAP4.error ... AUTHENTICATIONFAILED` | вписан обычный пароль вместо app-пароля |
| `сеть/TLS на этапе connect` | неверный хост/порт, или IMAP выключен в настройках |
| письма нет в ящике | не включён catch-all, либо MX ещё не разошлись (`dig MX`) |
| `VerificationTimeoutError` при пустом ящике | Instagram не доставил письмо — домен в спам-листах, смени домен |
| письмо есть, кода нет | письмо от другого отправителя; проверь `FROM_MARKERS` в `EmailVerifier` |
