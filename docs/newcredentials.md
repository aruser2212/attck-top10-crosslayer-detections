# NewCredentials и специальные привилегии одной сессии

Конечный пилот связывает Security `4624` с `LogonType=9`,
`LogonProcessName=seclogo` и Security `4672` одной локальной сессии.
Результат — кандидат NewCredentials с назначенными специальными привилегиями.
Легитимный `runas /netonly` может удовлетворять тем же условиям; совпадение
не доказывает Pass-the-Hash, использование чужого хеша или последующий доступ
к другой машине.

Исполнение: [`tools/correlate_newcredentials.py`](../tools/correlate_newcredentials.py)
офлайн и [`tools/elastic_newcredentials.py`](../tools/elastic_newcredentials.py)
на бесплатном Elasticsearch Basic. Нормализатор XML —
[`tools/normalize_windows_sessions.py`](../tools/normalize_windows_sessions.py).
Пилот не добавляет collector, непрерывный scheduler или постоянный alert sink.

## Источник и идентичность

Поддержаны экспортированные Windows Event XML со стандартным namespace,
provider `Microsoft-Windows-Security-Auditing` и channel `Security`:
`4624` версий **0 и 2**, `4672` версии **0**. Другие версии, отсутствующие
ключи, повторные поля и неоднозначная структура отклоняются.

| Нативный источник | Нормализованное поле | Контракт |
|---|---|---|
| `System/Computer` | `host.name` | Непустое имя, ASCII lowercase; алиасы машин не разрешаются |
| Доверенный контекст сбора / `--boot-id` | `host.boot.id` | Явная область одной загрузки ОС; из событий не угадывается |
| `4624.TargetLogonId`, `4672.SubjectLogonId` | `session.id` | Один ненулевой uint64 LUID, канонический lowercase hex без ведущих нулей |
| `4624.TargetUserSid`, `4672.SubjectUserSid` | `user.id` | Канонический ненулевой SID локального токена |
| `4624.LogonType`, `LogonProcessName` | `win.logon_type`, `win.logon_process` | Целое число и ASCII lowercase; только у LogonProcessName снимается нативное whitespace-padding |
| `4672.PrivilegeList` | `win.privileges` | Непустой отсортированный список уникальных имён `Se…Privilege`; нативные пробелы, табы и переводы строк разделяют элементы |
| `System/TimeCreated@SystemTime` | `@timestamp`, `win.timestamp_remainder` | UTC timestamp в микросекундах и сохранённый остаток native 100ns |
| `System/EventRecordID`, `Provider`, `Channel`, `Version` | `event.record_id`, `event.provider`, `event.channel`, `event.version` | Исходная metadata с проверенными типами и значениями |
| TargetUserName/Domain для 4624, SubjectUserName/Domain для 4672 | `user.name`, `user.domain` | Необязательный текстовый контекст, не ключ соединения |

`4624.TargetUserSid` описывает локальную identity токена. Поля Subject у 4624
и `TargetOutboundUserName`/`TargetOutboundDomainName` не подставляются вместо
этого SID. Совпадение имени пользователя, source IP или PID не заменяет LUID.

[Microsoft определяет LUID](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-allocatelocallyuniqueid)
как уникальный только на локальной системе и до её следующей перезагрузки.
Поэтому ключ соединения состоит из **host + boot + LogonId**, а SID должен
совпадать дополнительно. `host.boot.id` — доверенное утверждение источника:
оно должно быть одинаковым для событий одной загрузки конкретного хоста
и различаться после перезагрузки. Нормализатор требует `--boot-id` и включает
его в event identity, но не может проверить происхождение этого значения.
Нельзя автоматически подставлять имя машины, EventRecordID, случайный ID
каждого файла или одну постоянную строку для нескольких загрузок.

Для внешнего capture без подтверждённой boot-области ручная метка позволяет
выполнить только **условный replay с заявленным предположением**, а не проверить
реальную полноту и корректность boot scope. Синтетический пример ниже имеет
явно заданную общую область и не утверждает наличие рабочего коллектора.

## Строгий профиль и время

Профиль `attck-newcredentials-v1` принимает плоские JSON-объекты с буквальными
точками в именах полей. Dataset — `windows.security.sessions`. Для всех событий
обязательны `@timestamp`, `event.id`, `event.dataset`, `event.code`, `host.name`,
`host.boot.id`, `session.id`, `user.id`; для 4624 дополнительно обязательны
`win.logon_type` и `win.logon_process`, для 4672 — `win.privileges`.
Последнее поле — единственный разрешённый массив. Неизвестные поля, вложенные
алиасы, некорректные типы, нулевой LUID, null SID и пустые ключи отклоняются.
Нативная metadata проверяется при наличии в уже нормализованном входе;
XML-нормализатор требует её и сохраняет явно.

`@timestamp` — время записи из `System/TimeCreated`, не доказательство причинного
порядка действий. XML допускает до семи дробных цифр. Вычисления используют
первые шесть без округления; седьмая сохраняется в identity и
`win.timestamp_remainder`. Равные значения в микросекундах не обязательно
означают совпадение исходных 100ns ticks. Поддерживается диапазон `date_nanos`
от 1970-01-01 до 2262-04-11T23:47:16.854775Z.

Event identity включает host, boot, channel, record ID, нормализованное время,
остаток 100ns и event code. Одинаковая повторная доставка дедуплицируется;
другой payload под прежним event ID завершает batch ошибкой. Это не цифровая
аттестация источника. Дополнительные скалярные XML-поля вне поддержанного
контракта игнорируются нормализатором, а не объявляются проверенным enrichment.

## Условия корреляции

1. Anchor — 4624 с `win.logon_type=9` и `win.logon_process=seclogo`.
2. Связанные 4672 имеют те же `host.name`, `host.boot.id`, `session.id`
   и `user.id`.
3. Разность record timestamps удовлетворяет
   `abs(t4672 − t4624) <= max_skew_seconds`. По умолчанию это **30 секунд**;
   обе границы включены. Значение допускается от 0 до 86400 секунд;
   ноль допускает только совпадающие микросекундные timestamps.

Симметричный допуск — явная политика пилота, не гарантия порядка Windows
и не откалиброванный по рабочим данным порог. 4672 может находиться до,
вместе с или после anchor. Строгого условия «4672 обязательно позже 4624» нет:
в [закреплённом публичном примере](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/4ceed2f4706daf601c212a8f91c113dd85349a2c/Lateral%20Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx)
4624 v0 и 4672 v0 имеют одинаковое native TimeCreated. Это наблюдение
о конкретной записи, не универсальная временная гарантия.

Если у рассматриваемого anchor есть несколько различных 4624 с одинаковыми
host/boot/LUID в переданном конечном наборе, replay отклоняет неоднозначность.
Это относится и к конфликтующему 4624 вне выбранных output bounds. Повторы
фоновых 4624 с другими ключами сами по себе не запрещены. 4672 с тем же
host/boot/LUID, но другим SID внутри допуска — противоречивое evidence и ошибка,
а не тихий benign-результат. Другой host, boot или LUID не соединяются.
Неполные/некорректные события проверяются до фильтрации по output bounds.

На один подходящий 4624 возвращается один алерт со всеми связанными 4672:
`logon.event.id`, упорядоченные по `(timestamp,event.id)` `privilege.event.ids`,
соответствующие им signed `privilege.time_deltas_us`, ключ сессии и объединённый
отсортированный список привилегий. Идентификатор `newcredentials:<SHA256>`
привязан к rule ID, host/boot/LUID/SID и event ID anchor. Добавление допустимого
4672 меняет evidence этого кандидата; конечный CLI не реализует доставку
ревизий в постоянный sink.

## Воспроизводимый синтетический пример

Из корня репозитория после `make setup`:

```bash
mkdir -p artifacts
.venv/bin/python tools/normalize_windows_sessions.py --boot-id lab-boot-001 \
  tests/fixtures/newcredentials/native/newcredentials-v2.xml \
  tests/fixtures/newcredentials/native/special-privileges-v0.xml \
  > artifacts/newcredentials-normalized.jsonl
.venv/bin/python tools/correlate_newcredentials.py \
  --events artifacts/newcredentials-normalized.jsonl --max-skew-seconds 30
```

Ожидание — один кандидат с `session.id=0xabcde`, равными timestamp в примере
и привилегиями `SeDebugPrivilege`, `SeImpersonatePrivilege`. Это синтетическая
сессия, которая может описывать разрешённый `runas /netonly`; алерт не получает
автоматическую malicious-разметку. Для проверки нативной версии 0 замените
`newcredentials-v2.xml` на `newcredentials-v0.xml`, не добавляя оба варианта
одной исходной записи в тот же batch.

Для конечного Basic replay:

```bash
make lab-up
.venv/bin/python tools/elastic_newcredentials.py --index attck-newcredentials-demo create-index
.venv/bin/python tools/elastic_newcredentials.py --index attck-newcredentials-demo ingest \
  artifacts/newcredentials-normalized.jsonl
.venv/bin/python tools/elastic_newcredentials.py --index attck-newcredentials-demo evaluate \
  --max-skew-seconds 30 --page-size 1
```

Ожидается тот же алерт. `create-index` не перезаписывает существующий индекс;
повторять можно ingest/evaluate либо использовать новое имя. Точное повторение
событий не создаёт новые документы. Dedicated mapping
[`newcredentials-v1`](../profiles/elastic/newcredentials-v1.mapping.json)
отделён от auth-v1/v2 и других пилотов. URL/credentials описаны в
[руководстве Elastic](elastic.md); лаборатория использует бесплатный Basic.

## Bounds, лимиты и область исполнения

Опциональные `--start` и `--end` задаются вместе и выбирают 4624 anchors
в полуоткрытом интервале **[start,end)**. Связанные 4672 могут находиться
вне этого интервала, но внутри симметричного допуска своего anchor.

Basic всегда читает **полный конечный набор этого dataset в профильном индексе**
через один PIT с `search_after`, даже при указанных bounds. Это нужно для
одинакового с офлайн-расчётом обнаружения неоднозначных 4624 вне output bounds.
Временной фильтр поиска не используется; `--start`/`--end` не уменьшают объём
чтения. Индекс должен быть ограниченным входом replay, а не обещанием
неограниченного чтения рабочего журнала.

По умолчанию `--max-events=100000`, `--max-alerts=10000`, Basic
`--page-size=500`. Офлайн cap событий учитывает весь вход до dedup, Basic —
все прочитанные записи dataset. Проверяются профиль, канонические source
поля, event.id/_id, полнота shard-ответов, продвижение сортировки и UUID
индекса до/после чтения. Превышение лимита, неполное чтение, конфликт
или неоднозначность не возвращают частичный успешный результат.
Офлайн CLI отклоняет пустой файл.

## Sigma, legacy Hunt и доказательства

[Sigma](../techniques/T1550_Use_Alt_Auth/sigma/win_4624_newcredentials_seclogo.yml)
остаётся отдельным широким selector для LT9/seclogo. Ему не требуется 4672,
boot scope или SID join. Его source-scoped predicate fixtures не означают
эквивалентность dedicated correlation либо выполнение Sigma в SIEM.

Оба NewCredentials Hunt-файла остаются **design-only**: общий Hunt DSL
не исполняет новый session join или first-seen. Исторический DetCard ID
с `PTH` сохранён ради совместимости ссылок, а название и интерпретация
описывают наблюдаемый кандидат. Отдельный runtime не уменьшает число
legacy Hunt автоматически.

[Ручные scenarios](../tests/fixtures/newcredentials/cases.json),
[synthetic XML](../tests/fixtures/newcredentials/native/)
и [тест-план](../techniques/T1550_Use_Alt_Auth/tests/plan.md) фиксируют
ожидаемые совпадения, легитимные кандидаты, несовпадения и ошибки evidence.
Выполненные проверки приводятся в [validation report](validation_report.md).
Карточка остаётся `test`/`partial`; operational precision, TPR, FPR и latency
не измерены. Профили настоящего коллектора, полнота boot scope, baseline
легитимного администрирования и последующая активность требуют отдельных данных.
