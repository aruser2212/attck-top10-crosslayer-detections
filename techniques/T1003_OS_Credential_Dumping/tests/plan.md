# План тестирования: DET-WIN-T1003-LSASS-001

## Проверяемые контракты

Dedicated runtime выбирает Sysmon 10 к basename `lsass.exe` с явным
`PROCESS_VM_READ` (`GrantedAccess & 0x10`). Проверка identity требует host и
source/target ProcessGUID. Результат означает кандидата по выданному праву,
а не наблюдённый дамп. Sigma сохраняет более широкий selector без bitmask;
legacy Hunt остаётся design-only. Эквивалентность этих трёх артефактов не заявлена.

## Автоматизированные проверки

Команды выполняются из корня репозитория после `make setup`.

- `.venv/bin/python tools/check_sigma.py`: native pySigma parsing и
  [source-scoped predicate fixtures](../../../tests/fixtures/sigma/predicates.json)
  для широкого Sigma selector. Это не Sigma SIEM backend.
- `make check`: проверки профиля/конечного runtime, нормализации XML,
  [ручных случаев](../../../tests/fixtures/lsass/cases.json) и транспортного
  контракта. Ожидания кандидатов заданы отдельно от результата реализации.
- `make lab-up` и `make check-elastic`: реальный бесплатный Basic, включая
  [LSASS integration tests](../../../tests/integration/test_lsass_live.py).
  Конечный replay сравнивается с ручными ожиданиями и offline результатом.
- [Документированный XML → JSONL → Basic пример](../../../docs/lsass.md)
  использует инертные синтетические события, без запуска инструмента дампа.

Фактические команды и результаты запусков фиксируются в
[validation report](../../../docs/validation_report.md). Перечень тестов сам по
себе не является заявлением о прохождении native suite в любой новой среде.

Проверяемые случаи:

1. Маски с read-битом, в том числе составные и не перечисленные заранее;
   query-only, zero и права без `0x10`; типы, границы uint32 и ошибки hex.
2. Регистр basename, другое имя/суффикс, одноимённая цель в пользовательском
   каталоге; неподдерживаемые UNC/device paths и path aliases отклоняются.
3. Легитимный read-capable AV/EDR остаётся кандидатом, а похожий query-only доступ
   не совпадает. Поддельное имя AV из другого пути не исключается автоматически.
4. GUID braces/case в XML, каноническое представление JSONL, нулевой/отсутствующий
   GUID, повтор PID с новым GUID, разные hosts и повторные исходные события.
5. Duplicate retry, конфликт прежнего event ID, строгая валидация всего batch;
   ошибочный вход не превращается в успешный negative.
6. Только provider/channel Sysmon 10 version 3; duplicate/nested XML fields и
   DTD/entities отклоняются. Время берётся из System/TimeCreated; UtcTime не
   подменяет его, 100ns remainder влияет на identity, но не на точность bounds.
7. `[start,end)` с микросекундами, одинаковые timestamps через страницы,
   лимиты входа/алертов, неизменность индекса и отказ при неполном поиске.
8. Native immutable ingestion/retry, профиль и проверка `_source` после чтения:
   индексная coercion не должна незаметно менять смысл исходных полей.

## Работа с реальными источниками — отдельный этап

1. Собрать обезличенные Sysmon 10 с доказанным происхождением и политикой аудита.
   Записать версии Sysmon, полноту сбора и влияние конфигурационных исключений.
2. Зафиксировать профили легитимных AV/EDR/диагностики: GUID, пути, подписи, хэши,
   владельцы процессов, права и контекст. Synthetic benign-candidate не заменяет
   такую проверку и не обосновывает blanket allowlist.
3. Независимо сопоставить кандидатов с подтверждениями чтения памяти/дампа и
   легитимной работы. Basename цели не удостоверяет системный LSASS.
4. Определить единицу наблюдения, период и разметку корпуса, затем измерять
   precision/TPR/FPR. Публичный attack-only пример не задаёт частоту ложных тревог.
5. Отдельно проверять живой collector, пропуски и возобновление доставки.
   Экспорт XML, конечный replay и CI не подтверждают эксплуатационную полноту.

До этих измерений lifecycle остаётся `test`, validation — `partial`,
эксплуатационные TPR/FPR/latency — `null`.
