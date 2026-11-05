# Python Firewall Manager

Локальний програмний брандмауер на основі TCP/UDP-проксі. Він перевіряє лише з'єднання, що проходять через налаштовані порти проксі, і не фільтрує весь системний трафік Windows чи пакети сторонніх програм автоматично.

## Архітектура та файли

- `firewall.py` — проксі TCP/UDP, атомарне сховище правил, CLI та localhost HTTP API.
- `config.json` — налаштування API, сервісів, журналу та політики за замовчуванням.
- `rules.json` — таблиця правил, створюється автоматично та зберігається атомарно.
- `analyze_logs.py` — пошук, підсумки, експорт Markdown/CSV.
- `dynamic_demo.py` — локальна перевірка TCP/UDP і гарячої зміни правил.
- `test_firewall.py` — автоматизовані модульні тести.

## Встановлення та запуск (Windows CMD, Python 3.13)

```cmd
py -3.13 -m venv .venv
.venv\Scripts\activate
python -m pip install pytest
python firewall.py --config config.json run
```

За замовчуванням тестові проксі не запускаються, API доступне лише на `127.0.0.1:8081`, а непередбачені з'єднання заборонені. Для налаштування проксі додайте у `services` запис з `proto`, `listen_host` (тільки `127.0.0.1`), `listen_port`, фіксованими `target_host` і `target_port`. Зовнішня ціль вимагатиме явного `allow_external_target: true`. Клієнт не може сам вибрати адресу призначення.

## Правила

```cmd
python firewall.py rules
python firewall.py add --action deny --proto TCP --src 127.0.0.1/32 --dst 127.0.0.1/32 --dst-port 8080 --priority 10 --description "локальне блокування"
python firewall.py set 1 --enabled false
python firewall.py set 1 --action allow
python firewall.py delete 1
python firewall.py conflicts
python firewall.py logs --limit 30
python firewall.py check --src 127.0.0.1 --dst 127.0.0.1 --src-port 50000 --dst-port 8080 --proto TCP
```

Можна керувати правилами через `GET /rules`, `POST /rules`, `PATCH /rules/{id}`, `DELETE /rules/{id}` та переглядати конфлікти на `GET /conflicts`. API прив'язаний до IPv4 localhost; для змін передавайте `Authorization: Bearer <токен>`, який програма показує у консолі під час запуску. Тримайте його приватно. Зміни атомарно записуються у файл; кожне нове TCP-з'єднання та UDP-пакет читає актуальну таблицю. Вже встановлені TCP-з'єднання не перериваються й повторно не фільтруються.

Приклад UDP-правила: `python firewall.py add --action allow --proto UDP --src 127.0.0.1/32 --dst 127.0.0.1/32 --dst-port 5353 --priority 20`.

## Журнали й звіти

`dynamic_demo.py` за замовчуванням створює журнал у тимчасовій теці, яка видаляється після завершення. Щоб зберегти фактичні події TCP/UDP-сценарію у `logs/events.jsonl` (папка створюється автоматично), запустіть:

```cmd
python dynamic_demo.py --save-logs
python analyze_logs.py --markdown LOG_ANALYSIS_REPORT.md
```

Сценарій додає до журналу лише події, що виникли під час реального локального запуску; він не створює вигаданих записів. Для фільтрації та CSV-експорту, наприклад: `python analyze_logs.py logs/events.jsonl --action deny --protocol TCP --markdown reports.md --csv events.csv`. Звичайний сервіс також пише в `logs/events.jsonl` за конфігурацією, з ротацією. Якщо журнал відсутній, аналізатор виведе зрозуміле повідомлення й завершиться без traceback.

## Перевірки

```cmd
python -m pytest -q
python dynamic_demo.py
python dynamic_demo.py --save-logs
```

Тести використовують тимчасові файли та вільні порти localhost і не змінюють системні правила Windows Firewall.
