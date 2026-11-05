# Kerberos 4769: точный RC4 burst на Elasticsearch Basic

[Hunt](../techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml)
выдаёт кандидата T1558.003, когда один requester из одного домена и IP запросил
успешные RC4-HMAC TGS для **пяти разных сервисных SID за пять минут**. Совпадение
показывает эту активность; оно не доказывает кражу билетов, офлайн-подбор пароля
или компрометацию аккаунта.

Окно `(t−5m,t]` исключает нижнюю границу и включает верхнюю. В каждый подходящий
timestamp все события группы обрабатываются вместе. Группа состоит из
`user.domain`, `user.name`, `source.ip`; запросы к разным DC объединяются.
`distinct_service_accounts` считает точные разные `service.id`, без приблизительной
cardinality. `rc4_requests` считает только события, прошедшие фильтр и имеющие
все поля группы и сервисный SID. Событие без SID не увеличивает ни одну метрику
и не создаёт новый anchor. Несколько подходящих timestamps могут дать несколько
кандидатов с перекрывающимися окнами.

## Контракт источника

Вход нормализатора — один экспортированный Event XML на файл: Security 4769 от
`Microsoft-Windows-Security-Auditing`, native версии **0 и 2**, со стандартным XML
namespace. Бинарный EVTX напрямую не читается. Версия 2 содержит дополнительные
поля; решение использует приведённые ниже общие поля, а не текстовые списки
доступных алгоритмов или `SessionKeyEncryptionType`.

| Native XML | Нормализованное поле | Правило |
|---|---|---|
| `System/EventID` | `event.code` | Строка `"4769"`; dataset — `windows.security.kerberos_tgs` |
| `Status` | `win.status` | Точный uint32 из hex/decimal; успех — число `0` |
| `TicketEncryptionType` | `ticket.encryption_type` | Точный uint32; RC4-HMAC — число `23` (`0x17`) |
| `TargetUserName` | `user.name` | ASCII lowercase, исходная форма principal сохранена |
| `TargetDomainName` | `user.domain` | ASCII lowercase, отдельно от имени requester |
| `IpAddress` | `source.ip` | Канонический IP; IPv4-mapped IPv6 становится IPv4; scope ID отклоняется |
| `ServiceSid` | `service.id` | Проверенный канонический SID; null SID `S-1-0-0` пропускается |
| `ServiceName` | `service.name` | Исходный текст сервисного аккаунта для расследования |
| `System/Computer` | `host.name` | ASCII lowercase имени DC; не является ключом группы |
| `System/TimeCreated@SystemTime` | `@timestamp`, `win.timestamp_remainder` | UTC микросекунды и отдельный остаток native 100ns |
| `System/Channel`, `EventRecordID`, `Version` | `event.channel`, `event.record_id`, `event.version` | `Security`, каноническая uint64-строка, целое `0`/`2` |

`ServiceName` не представляет полный SPN. Несколько SPN одного аккаунта не
увеличивают число сервисных аккаунтов; разные SID считаются отдельно даже при
одинаковом `ServiceName`. Имя сервиса не подставляется вместо отсутствующего SID.
Проверяется структура SID revision 1: 48-bit authority и 1–15 uint32 subauthorities;
это проверка формы идентификатора, а не подтверждение существования аккаунта в AD.

`event.id` строится из нормализованных DC/channel/record ID/UTC времени/native
100ns остатка/event code. Разные 100ns ticks сохраняют разные ID, но оконная
арифметика использует микросекунды: седьмая дробная цифра отбрасывается, без
округления вверх. `date_nanos` сохраняет эти микросекунды; диапазон профиля —
`1970-01-01T00:00:00Z`…`2262-04-11T23:47:16.854775Z`. Повтор неизменного ID
дедуплицируется; другой payload с тем же ID отклоняется.

Отсутствующие значения и native `-` остаются отсутствующими. В нормализованном
JSON допустим `null` для необязательных полей. Нет requester/domain/IP/SID — нет
пригодной группы; нет status/encryption type — событие не проходит фильтр.
Некорректное присутствующее значение, например `"RC4"`, `23.0`, boolean вместо
числа, неканонический IP/SID или вложенный объект, отклоняется валидатором.
`SubjectUserName` не подменяет requester. DTD/entities, повторные и вложенные
Data-поля, неоднозначные обязательные System-поля отклоняются.

## Воспроизводимый пример

Команды выполняются из корня репозитория после `make setup`. Данные ниже
синтетические; ожидаемый результат задан вручную в
[cases.json](../tests/fixtures/kerberos/cases.json).

```bash
mkdir -p artifacts
.venv/bin/python tools/normalize_windows_kerberos.py \
  tests/fixtures/kerberos/xml/4769-v0.xml > artifacts/kerberos-one-event.jsonl
```

Это проверяет XML → нормализованное событие. Одного запроса недостаточно для
порога. Для примера с пятью сервисами извлечём отдельный сценарий и проверим его
профиль до офлайн-исполнения:

```bash
.venv/bin/python - <<'PY' > artifacts/kerberos-demo.jsonl
import json
from pathlib import Path
from tools.kerberos_profile import prepare_events

manifest = json.loads(Path("tests/fixtures/kerberos/cases.json").read_text())
case = next(item for item in manifest["cases"]
            if item["name"] == "five_service_accounts_threshold")
events, _ = prepare_events(case["events"])
for event in events:
    print(json.dumps(event, ensure_ascii=False))
PY

.venv/bin/python tools/rolling_hunt.py \
  techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml \
  --events artifacts/kerberos-demo.jsonl
```

Общий `rolling_hunt.py` проверяет контракт DSL, но **не проверяет профиль
kerberos-v1**. Для произвольного JSONL сначала вызовите
`tools.kerberos_profile.prepare_events`; XML-нормализатор уже делает эту проверку.
Ожидается один кандидат: `lab.example` / `alice` / `192.0.2.10`,
`distinct_service_accounts: 5`, `rc4_requests: 5`, окно
`(2026-01-01T00:00:00Z, 2026-01-01T00:05:00Z]`.

Запуск на локальном Basic-стенде с отдельным новым индексом:

```bash
make lab-up
.venv/bin/python tools/elastic_kerberos.py --index attck-kerberos-demo-v1 create-index
.venv/bin/python tools/elastic_kerberos.py --index attck-kerberos-demo-v1 ingest \
  artifacts/kerberos-demo.jsonl
.venv/bin/python tools/elastic_kerberos.py --index attck-kerberos-demo-v1 evaluate \
  techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml \
  --start 2026-01-01T00:05:00Z --end 2026-01-01T00:06:00Z --page-size 2
```

Адрес по умолчанию — `http://127.0.0.1:19200`. Для другого сервера поддержаны
`ELASTIC_URL`, `ELASTIC_API_KEY` или `ELASTIC_USERNAME`/`ELASTIC_PASSWORD`;
HTTPS проверяет сертификат. Compose использует бесплатную Basic-лицензию,
без trial и платных функций. Если индекс уже существует, `create-index`
отклоняется: повторяйте только ingest/evaluate либо выберите новое имя.
Неизменные повторные события не увеличивают счётчики.

Адаптер проверяет [mapping](../profiles/elastic/kerberos-v1.mapping.json) и профиль
до ingestion и после чтения. PIT/search_after получает точные исходные события;
окно и distinct вычисляются в Python. При границах `[A,B)` читается также контекст
`(A−5m,B)`. Несовместимый mapping, смена UUID индекса, неполный поиск или превышение
лимитов приводят к ошибке без частичного результата. Это конечный replay;
непрерывного 4769 pipeline, автоматического collector или расписания здесь нет.

## Интерпретация и настройка

В fixture `benign_legacy_application_rc4_fanout` легитимное приложение выдаёт
ожидаемого кандидата. Такой пример показывает ограничение правила и не считается
успешно отфильтрованным ложным срабатыванием. Порог 5/5m — проверяемая исходная
гипотеза; эксплуатационные precision/TPR/FPR и задержка не измерены.

Для расследования получите исходные события с теми же `user.domain`, `user.name`,
`source.ip`, `win.status=0`, `ticket.encryption_type=23` и timestamp в
`(window.start,window.end]` на всех DC. Сверьте SID и `ServiceName`, время, DC и
record ID; затем проверьте владельцев сервисных аккаунтов и ожидаемую активность
клиента. Сам агрегат содержит группу, границы и счётчики, а не список событий или
доказательство офлайн-подбора.

Правило не покрывает AES Kerberoasting и медленные запросы ниже порога. Оно не
разрешает SAM/UPN, короткие DNS/NetBIOS-домены и Unicode-алиасы через каталог:
эквивалентные записи могут разделить группу. NAT/proxy может объединить клиентов
одного requester под одним IP; смена IP разделит группу. Нужны корректный
namespace источников и сопоставимый сбор со всех DC; неполная телеметрия снижает
покрытие. Обогащение и baseline должны проверяться на данных конкретной среды.
Общих исключений по `$`, `app-*`, `iis-*` или `svc-*` нет.

Описание native полей:
[Microsoft Event 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769).
Смысл техники: [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/).
