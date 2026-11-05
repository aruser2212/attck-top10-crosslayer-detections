# Контракты исходной телеметрии

Нормализаторы принимают экспортированные события и формируют плоские JSON-объекты с dotted keys для существующих правил. Проверка формата, полей и identity не удостоверяет происхождение файла: XML и journal JSON можно изготовить вручную. Доверенный сборщик, права доступа к журналам, защищённая доставка и синхронизация часов остаются обязанностью развёртывания. Сборщик на реальном Windows/Linux-хосте в этом проекте не установлен и не проверен.

| Источник | Поддержанный вход | Дальнейший путь |
|---|---|---|
| Windows Security | Один Event XML на файл, события 4624/4625 | Нормализация → Windows auth-v1 → Elastic Basic; [stateful pipeline](continuous.md) сохраняет ingestion/checkpoint/alert state |
| Windows Kerberos | Один Security 4769 Event XML на файл, версии 0/2 | Отдельный нормализатор → kerberos-v1 → [конечный RC4 burst replay](kerberos.md) на Basic |
| Подготовленные host/file + HTTP | Плоский JSONL с точными host/namespace/POSIX path и исходными event ID | Строгий web-correlation-v1 → [конечная корреляция](correlation.md) на Basic; нативный нормализатор не предоставляется |
| Linux OpenSSH | `journalctl --output=json`, один JSON record на строку | Нормализация → `linux.auth.sshd` → локальное исполнение Linux Hunt v1 |

Linux и Kerberos dataset не входят в stateful Windows auth pipeline. Контракт 4769, включая requester, ServiceSid, numeric status/etype и поведение при пропусках, описан в [Kerberos guide](kerberos.md). Экспорт бинарного EVTX, произвольный syslog, Winlogbeat/Elastic Agent ingestion и host-collector deployment не реализованы этими CLI.

## Windows Security XML

Из корня репозитория после установки dev-зависимостей:

```bash
mkdir -p artifacts/telemetry
.venv/bin/python tools/normalize_windows_auth.py \
  tests/fixtures/windows/4625.xml > artifacts/telemetry/windows.jsonl
.venv/bin/python -m pytest tests/test_normalize_windows.py -q
```

Это нормализация одного синтетического события; один 4625 не достигает порога brute force. Полный replay и запуск сервера описаны в [Elastic Basic](elastic.md). Готовые `.ready.xml` либо нормализованные `.ready.jsonl` можно передать [stateful pipeline](continuous.md): producer должен полностью записать файл и атомарно опубликовать неизменяемое ready-имя. Сам нормализатор не собирает события и не выполняет доставку.

Входной контракт:

- Корень — один `Event` со стандартным Windows Event namespace. Channel — `Security`, Provider — `Microsoft-Windows-Security-Auditing`, EventID — 4624 либо 4625. Обёртка из нескольких событий и бинарный EVTX не принимаются.
- `System`, обязательные System-поля, Provider и TimeCreated должны быть единственными. Повторяющиеся имена `EventData/Data` отклоняются; первый дубликат не выбирается молча.
- `Computer` приводится к ASCII lowercase. FQDN и короткое имя, DNS aliases и Unicode-эквивалентность не сопоставляются автоматически.
- `EventRecordID` — ASCII decimal uint64, от 0 до 18446744073709551615. Ведущие нули удаляются: `001001` и `1001` не создают разные события. Unicode-цифры, знак и выход за диапазон отклоняются.
- `TimeCreated/SystemTime` должен включать timezone и не более семи дробных цифр. Время переводится в UTC; остаток 100ns отбрасывается из выходного микросекундного `@timestamp` вниз, но сохраняется в identity. Например, `.1234561Z` и `.1234562Z` получают одинаковый `@timestamp`, но разные IDs. Невалидное смещение вроде `+03:60` отклоняется, а не исправляется автоматически.
- `TargetDomainName` и `TargetUserName` формируют `target.user`; Subject не подменяет Target. ASCII-регистр понижается, домен сохраняется, если присутствует. UPN/NetBIOS, переименования, Unicode accounts и совпадения локальных имён требуют отдельного directory-backed mapping. При отсутствии домена он не выдумывается.
- IPv4 и IPv6 канонизируются; IPv4-mapped IPv6 приводится к IPv4. Scoped IPv6 (`%interface`) требует явного collector mapping и отклоняется. Отсутствующие IP/аккаунт остаются отсутствующими: такие записи не создают вымышленную группу в агрегации.

Identity — hash от канонического Computer, Channel, EventRecordID, UTC-времени, оставшегося 100ns-разряда и EventID. При пересылке через несколько collectors эти исходные поля должны сохраняться. CLI проверяет весь batch до вывода, дедуплицирует эквивалентные события и отклоняет конфликтующие payload с одной identity. Это защита от повторной доставки в рамках контракта, а не универсальное разрешение идентичности хостов и аккаунтов.

## Linux sshd journal JSONL

```bash
mkdir -p artifacts/telemetry
.venv/bin/python tools/normalize_linux_auth.py \
  tests/fixtures/linux_auth/journal.jsonl > artifacts/telemetry/linux-auth.jsonl
.venv/bin/python tools/hunt_engine.py \
  techniques/T1110_Brute_Force/hunts/linux_ssh_failed_agg.hunt.yaml \
  --events artifacts/telemetry/linux-auth.jsonl
.venv/bin/python -m pytest tests/test_normalize_linux_auth.py -q
```

При успешной нормализации stdout содержит JSONL, stderr — счётчики. `-` вместо пути читает JSONL из stdin. Пример включает восемь failed-password событий и даёт один Linux Hunt-алерт с `fails=8`; два успешных входа не увеличивают счётчик. Происхождение примера описано в [fixture README](../tests/fixtures/linux_auth/README.md).

Входной контракт:

- Поддерживаются только точные имена `sshd`, `sshd-session`, `sshd-auth`. `_COMM` авторитетен при наличии: сообщение от другого процесса нельзя превратить в sshd-событие только через `SYSLOG_IDENTIFIER=sshd`. При отсутствии `_COMM` допускается SYSLOG_IDENTIFIER из того же точного списка; этот fallback не подтверждает подлинность процесса. Противоречивые source-поля отклоняются.
- Парсер сопоставляет всё сообщение с формами `Failed password for …`, включая `invalid user`, и `Accepted password/publickey for …`. Префиксы вида `sshd[PID]:`, отдельное `Invalid user …`, failed publickey, локализованные сообщения и другие форматы не интерпретируются как password failures. Неподдержанные сообщения и другие процессы учитываются как ignored.
- `__REALTIME_TIMESTAMP` — десятичная строка целого числа Unix microseconds; используется время journal record, а не догадка по тексту или локальной timezone. Год, timezone и drift часов не восстанавливаются из generic syslog. UTC-конвертация сохраняет микросекунды точно.
- `_MACHINE_ID` — 32 hex-символа, `__CURSOR` — непустой opaque journal cursor. Hash этой пары задаёт identity. Перепоставка одного события не увеличивает счётчик; противоречивое нормализованное содержимое с той же парой — ошибка.
- Linux usernames сохраняют регистр и означают указанное в сообщении имя, не подтверждённое существование аккаунта. IPv4/IPv6 канонизируются, IPv4-mapped IPv6 приводится к IPv4; scoped IPv6 отклоняется.
- Полный MESSAGE, public-key fingerprint и посторонние journal-поля не копируются. Выходное `message` — только `Failed password`, `Accepted password` или `Accepted publickey`; `event.outcome` различает failure/success.
- Для распознанного auth-сообщения отсутствие или ошибка обязательных полей приводит к отказу всего batch. Пустой вход, отсутствие поддержанных auth-событий, дубли JSON-ключей, blank records и NaN/Infinity также отклоняются. Никакие частичные события до проверки всего входа не печатаются.

Linux Hunt группирует по `source.ip × user.name`, без `host.id`. При объединении нескольких хостов в один replay их события могут попасть в общую группу. Окна фиксированные UTC `[start,end)` по пять минут, порог — восемь `Failed password`; разделение серии границей окна может привести к пропуску. Эти ограничения не устраняются нормализатором.

## Проверяемый результат и следующие проверки

Регрессии проверяют формат/identity, различение Subject/Target, case-политику, дубликаты, пороги и границы времени. Реальные события необходимо проверить на сохранность source-полей и соответствие входному контракту до подключения потока. Пропуски журналов, несовпадение версий сообщений OpenSSH, ошибки audit policy и clock drift нельзя обнаружить по одному корректно сформированному событию.

Корпус остаётся [синтетическим](../tests/fixtures/README.md). Успешный replay не является оценкой эксплуатационных precision/TPR/FPR и не доказывает полноту host collection.
