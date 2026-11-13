# IG Farm — регистрация и управление аккаунтами Instagram

Автоматизация полного цикла: создание аккаунтов, прохождение проверок Meta,
хранение сессий, управление (подписки, комментарии, прогрев), контроль
статусов и веб-панель.

## Что внутри

| Файл | Назначение |
|---|---|
| `autoreg.py` | движок браузерного канала + веб-панель: генерация личности, форма, капча, номер, SMS, селфи, апелляция, подписка, журнал |
| `api_reg.py` | канал мобильного API: регистрация тем же путём, что из приложения (device-профиль, подпись, app-заголовки) |
| `comments.py` | комментарии под постами: прогрев, публикация, проверка видимости, отчёт |
| `import_accounts.py` | приём готовых аккаунтов: логин/пароль или файл сессии, проверка входа, база |
| `check_accounts.py` | проверка статусов, дожим гейта, подписка на целевой профиль |
| `check_account.py` | диагностика одного аккаунта |
| `open_account.py` | открыть аккаунт для ручного просмотра |
| `check_setup.py` | preflight: конфиг, браузер, прокси, IMAP, балансы |
| `config.py` | конфигурация, пулы имён, фингерпринты |

База — `accounts.json`, журнал событий — `audit.jsonl`, сессии — `cookies/`,
отчёты по комментариям — `reports/`.

## Требования

- Python 3.12
- Chromium для Playwright
- catch-all домен с IMAP (письма от Instagram)
- прокси-пул (sticky-эндпоинты, один на аккаунт)
- номер и SMS-провайдер либо ручной номер

## Установка

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m playwright install chromium
cp .env.example .env          # заполнить почту, прокси, капчу, SMS
```

## Запуск

```bash
# панель управления
python autoreg.py --serve                  # http://127.0.0.1:8088

# регистрация: браузерный канал
python autoreg.py --run --count 5

# регистрация: мобильный API
python api_reg.py --count 3

# импорт готовых аккаунтов
python import_accounts.py --file accounts.txt

# проверка статусов
python check_accounts.py --age-hours 24

# дожим гейта у suspended
python check_accounts.py --all --username user --fix

# подписка на целевой профиль
python check_accounts.py --all --username user --follow

# комментарии под постами
python comments.py --post https://www.instagram.com/p/SHORTCODE/ --limit 10
python comments.py --post ... --accounts accounts.txt --texts texts.txt
```

## Форматы

`accounts.txt` — по строке на аккаунт:

```
user:password
user:/path/to/cookies.json
```

`texts.txt` — по строке на текст комментария.

## Комментарии

Порядок на аккаунт: вход по сессии, прогрев профиля конкурента, публикация,
пауза, проверка видимости с анонимной сессии. Статусы в отчёте: `visible`,
`hidden`, `not_checked`, `failed`. Аккаунт с погасшей сессией пробует вход
по паролю; не удалось — уходит в `failed` и не рвёт прогон.

## Конфигурация

Все параметры — в `.env` (шаблон в `.env.example`): почта/IMAP, капча, пул
прокси, SMS-провайдер, таймауты гейта, паузы прогрева, целевой профиль
(`TRUST_TARGETS`), каталог аватаров.

## Панель

Запуск и остановка прогонов, редактирование конфига, список аккаунтов со
статусами, журнал по каждому аккаунту, счётчики, скачивание базы.

## Тесты

```bash
python smoke_test.py
python test_gate.py
python test_form_flow.py
python test_services.py
python test_engine_e2e.py
python test_email_imap.py
python test_antifraud.py
python test_proxy_pool.py
```
