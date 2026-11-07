# LSASS ProcessAccess: право чтения памяти на Elasticsearch Basic

Конечный детект `LSASS-PROCESS-VM-READ-001` выдаёт кандидата, когда Sysmon 10
сообщает доступ к образу с basename `lsass.exe`, а `GrantedAccess` содержит бит
`PROCESS_VM_READ` (`0x10`). Это наблюдение о выданном праве доступа. Оно не
подтверждает фактическое чтение памяти, получение учётных данных или создание
дампа. Совпадение имени также не удостоверяет, что цель — системный LSASS:
одноимённый файл в пользовательском каталоге проходит тот же предикат.

Runtime использует отдельный строгий профиль `attck-lsass-v1`. Один подходящий
исходный event даёт один алерт с полным SHA256 ID, ссылкой `event.id`, временем,
хостом, GUID обоих процессов, путями и маской доступа. Повторный доступ с новым
event ID сохраняется; подавления first-seen и объединения по PID нет.

## Источник и нормализация

[`normalize_windows_sysmon.py`](../tools/normalize_windows_sysmon.py) принимает
по одному экспортированному Event XML на файл. Поддерживается только
`Microsoft-Windows-Sysmon`, канал `Microsoft-Windows-Sysmon/Operational`,
Event ID **10**, native версия **3**, стандартный Windows Event XML namespace.
EVTX напрямую не читается; других версий и работающего Windows collector этот
пилот не предоставляет.

| Native XML | Нормализованное поле | Контракт |
|---|---|---|
| `System/Computer` | `host.name` | Непустое имя в ASCII lowercase; aliases не разрешаются |
| `System/TimeCreated@SystemTime` | `@timestamp`, `win.timestamp_remainder` | Время записи события в UTC, микросекунды и отдельный остаток native 100ns |
| `System/EventID` | `event.code`, `event.dataset` | Строка `"10"`, dataset `windows.sysmon.process_access` |
| `System/Provider`, `Channel`, `Version` | `event.provider`, `event.channel`, `event.version` | Точный источник, указанный выше, и целое `3` |
| `System/EventRecordID` | `event.record_id` | Каноническая uint64-строка |
| `SourceProcessGUID`, `TargetProcessGUID` | `source.process.guid`, `target.process.guid` | Обязательные ненулевые GUID, lowercase без braces |
| `SourceImage`, `TargetImage` | `source.image`, `target.image` | Обязательные абсолютные DOS paths с буквой диска; исходный регистр сохраняется |
| `GrantedAccess` | `process.access_mask` | Обязательная uint32-маска; hex или decimal XML преобразуется в JSON integer |
| `SourceProcessId`, `TargetProcessId` | `source.process.pid`, `target.process.pid` | Необязательные uint32-числа, только контекст |
| `SourceUser`, `TargetUser`, `CallTrace` | `source.user`, `target.user`, `process.call_trace` | Необязательный исходный текст для расследования |

`@timestamp` здесь — **System/TimeCreated**, а не время операции из
`EventData/UtcTime`. Дополнительные Data-поля, включая `UtcTime` и
`SourceThreadId`, нормализатор не переносит. Равенство этих времён не предполагается;
задержка записи влияет на отбор по временному диапазону. Native седьмая дробная
цифра сохраняется в identity и `win.timestamp_remainder`, но не даёт дополнительной
точности replay: она отбрасывается без округления при расчёте `@timestamp`.

`event.id` — SHA256 канонического набора host/channel/record ID/UTC времени/
100ns остатка/event code с префиксом `windows-sysmon:`. Идентичная повторная
доставка дедуплицируется; другой payload с прежним ID отклоняется. Контракт
предполагает, что Computer однозначно задаёт источник в переданном корпусе.
Одинаковые имена разных компьютеров, aliases и клонированные источники требуют
проверенного upstream mapping. Нормализатор не удостоверяет подлинность XML.

Идентичность процесса задаётся парой **host.name × ProcessGUID**. PID, имя файла
и имя пользователя не заменяют отсутствующий GUID. Формат GUID проверяется без
требования RFC4122 version/variant; Sysmon GUID не объявляется UUID v4. Runtime
сохраняет identity как evidence, но не строит lifecycle процесса и не выполняет
join с Sysmon 1 или Security 4688. Дополнительная проверка подписи, хэша и пути
реального процесса остаётся задачей источника/расследования.

## Строгий JSONL-профиль

Вход [`detect_lsass.py`](../tools/detect_lsass.py) — JSONL с плоскими dotted keys.
Для каждой записи обязательны `@timestamp`, `event.id`, `event.dataset`,
`event.code`, `host.name`, `source.process.guid`, `target.process.guid`,
`source.image`, `target.image`, `process.access_mask`. Необязательными являются
перечисленные в таблице provider/channel/version/record ID, 100ns остаток,
PID, пользователи и CallTrace. Только для необязательных полей допустим `null`.

Отсутствующий обязательный атрибут, неправильный dataset, числовая строка или
boolean вместо маски, неизвестное поле, вложенный объект, placeholder `-`,
неверный GUID и конфликтующий event ID завершают весь batch ошибкой. Они не
интерпретируются как отрицательные результаты детекта. XML DTD/entities,
повторные поля и вложенные Data-элементы также отклоняются. CLI нормализатора
проверяет весь набор до вывода первой JSONL-строки.

Пути проверяются лексически: например, `C:\Windows\System32\lsass.exe` допустим.
UNC, device paths, относительные пути, `.`/`..`, пустые компоненты, ADS,
завершающие точка/пробел и недопустимые символы отвергаются. Runtime не исправляет
такой путь и не разрешает symlinks или файловые aliases. Это граница поддержки,
а не признак отсутствия угрозы. Регистр пути сохраняется; basename сравнивается
с ASCII-понижением регистра без Unicode casefold.

ID ограничен 512 байтами UTF-8, текстовые поля — 32766 байтами. Профиль и
`date_nanos` поддерживают диапазон `1970-01-01T00:00:00Z`…
`2262-04-11T23:47:16.854775Z` с микросекундной точностью.

## Маска доступа и смысл кандидата

Точный тест — `(process.access_mask & 0x10) != 0`, а не список равенств известных
масок. Например, `0x10`, `0x410`, `0x1010`, `0x1410` и `0x1fffff` содержат право
чтения. `0x400` и `0x1000` обозначают query-права без `PROCESS_VM_READ` и не дают
кандидата; `0x40` без read-бита тоже не совпадает. Остальные биты не подавляют
совпадение и не расширяются в предполагаемые права. В частности, generic-access
или maximum-allowed флаг без явного `0x10` не подменяет его.

Легитимные AV/EDR и диагностические программы могут иметь такое право и
срабатывать. Ни basename `MsMpEng.exe`, ни известный путь, ни текст `CallTrace`
сами по себе не дают исключения. Ручные benign-candidate fixtures фиксируют
ожидаемое совпадение; проверка настоящего профиля конкретного AV/EDR требует
его телеметрии, происхождения разметки и контекста доверия.

События без read-бита, альтернативные способы доступа к credential material,
неполный аудит и неподдерживаемые path namespaces не входят в заявленное
покрытие. Успешный детект этого предиката не устанавливает TPR/FPR всей T1003.001.

## Воспроизводимый синтетический пример

После `make setup`, из корня репозитория:

```bash
mkdir -p artifacts
.venv/bin/python tools/normalize_windows_sysmon.py \
  tests/fixtures/lsass/native/process-access-v3.xml \
  tests/fixtures/lsass/native/benign-query-only-v3.xml \
  > artifacts/lsass-normalized.jsonl
.venv/bin/python tools/detect_lsass.py --events artifacts/lsass-normalized.jsonl
```

Первый XML — инертный синтетический кандидат с `GrantedAccess=0x1010`; второй
содержит только query-право `0x1000`. Ожидание — один алерт по первому событию.
Это ручной пример контракта, не захват атаки и не измерение реальных false positives.

Для конечного replay на бесплатном Basic:

```bash
make lab-up
.venv/bin/python tools/elastic_lsass.py --index attck-lsass-demo create-index
.venv/bin/python tools/elastic_lsass.py --index attck-lsass-demo ingest \
  artifacts/lsass-normalized.jsonl
.venv/bin/python tools/elastic_lsass.py --index attck-lsass-demo evaluate --page-size 1
```

Ожидается тот же алерт. `create-index` не перезаписывает существующий индекс;
для повторения используйте ingest/evaluate либо новое имя. Повтор неизменных
событий безопасен, а другой payload под прежним ID отклоняется. Локальный lab
использует Basic без trial. URL/credentials описаны в [Elastic guide](elastic.md).

Опциональные `--start A --end B` задаются вместе и отбирают события в **[A,B)**:
начало включено, конец исключён. Времена сравниваются в UTC с точностью
до микросекунд. Для одиночного события не требуется предыстория раньше A.

Адаптер проверяет mapping профиля [`lsass-v1`](../profiles/elastic/lsass-v1.mapping.json),
читает полный ограниченный набор через один PIT с `search_after` и выполняет
тот же Python-предикат. Проверяются `_id`/event.id, типы, точность времени,
продвижение страниц, полнота shard-ответов и неизменность UUID индекса.
Это конечный replay; постоянного сервиса сбора, расписания и alert sink здесь нет.

По умолчанию `--max-events` равен 100000, `--max-alerts` — 10000,
`--page-size` в Basic — 500. Размер страницы не является общим лимитом корпуса.
Офлайн event cap считает все входные записи до dedup и отбора по времени;
Basic cap считает прочитанные события dataset внутри диапазона, включая
неподходящие цели/маски. Счётчики этих входных областей могут отличаться.
Превышение лимита, неполный поиск или замена индекса завершаются ошибкой без
частичного успешного результата. Офлайн CLI отклоняет пустой файл.

## Sigma, Hunt и evidence

[Sigma](../techniques/T1003_OS_Credential_Dumping/sigma/win_sysmon_lsass_access.yml)
сохраняет более широкий source-scoped selector: Sysmon 10 к basename `lsass.exe`,
без bitmask/GUID контракта. Его совпадение может быть query-only. Эквивалентность
Sigma с VM_READ runtime или его выполнение в SIEM не заявляются.
[Legacy Hunt](../techniques/T1003_OS_Credential_Dumping/hunts/lsass_access.hunt.yaml)
остаётся design-only. Dedicated runtime не расширяет generic Hunt DSL и не
реализует first-seen; этот файл не считается мигрированным исполняемым Hunt.

[Ручные fixtures](../tests/fixtures/lsass/cases.json) задают ожидаемые события,
кандидаты и ошибки профиля. [Native-shaped XML](../tests/fixtures/lsass/native/)
проверяют заявленную форму экспорта. [Тест-план](../techniques/T1003_OS_Credential_Dumping/tests/plan.md)
перечисляет нормализацию, права, identity и Basic replay; фактически выполненные
запуски фиксируются в [validation report](validation_report.md).
Карточка остаётся `test`/`partial`, эксплуатационные метрики — `null`.

Описание прав: [Microsoft Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
Описание источника: [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

Публичные EVTX-проверки, ссылки на наборы и ограничения разметки описаны в [отдельном разборе](public-data.md). Сырые сторонние журналы не включены в synthetic fixtures проекта.
