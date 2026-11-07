# План проверки NewCredentials и контекста T1550

## Область автоматических проверок

Команды выполняются из корня репозитория с установленными dev-зависимостями.

- `tools/check_sigma.py`: native pySigma parsing и
  [source-scoped predicate fixtures](../../../tests/fixtures/sigma/predicates.json).
  Широкий LT9/seclogo selector не требует 4672 и не является session correlation.
- `tests/test_newcredentials_profile.py`, `tests/test_normalize_windows_sessions.py`:
  строгие поля, XML 4624 v0/v2 и 4672 v0, boot scope, SID/LUID, time identity
  и отсутствие подмены local token identity полями outbound credentials.
- `tests/test_newcredentials_correlation.py`, `tests/test_newcredentials_fixtures.py`:
  [ручные expected pairs](../../../tests/fixtures/newcredentials/cases.json),
  симметричное окно, точное соединение, доказательства и ошибки неоднозначности.
- `tests/test_elastic_newcredentials.py` и
  `tests/integration/test_newcredentials_live.py`: контракт транспорта и конечный
  replay на настоящем Elasticsearch Basic, включая XML → CLI → ingest → алерт.

`make check` запускает локальный набор; `make lab-up` и `make check-elastic` —
native Basic-набор. Фактически выполненные запуски и их результаты фиксируются
в [validation report](../../../docs/validation_report.md), а не выводятся из
наличия файлов тестов. Сырые публичные записи имеют собственную provenance;
synthetic XML не выдаются за захват реального источника.

## Обязательные сценарии

1. Совпадающие host/boot/LUID/SID при LT9/seclogo и 4672; равный timestamp,
   оба направления времени, точные границы допуска и выход за них на 1 µs.
2. Легитимный `runas /netonly` как **ожидаемый кандидат**. Не переименовывать
   такое совпадение в отрицательный тест ради красивой метрики.
3. Разные LUID при одном пользователе и близком времени не соединяются.
   Одинаковые LUID на разных хостах или после разных boot IDs не соединяются.
4. Разные SID при одном участвующем host/boot/LUID внутри допуска дают ошибку.
   Account spelling, PID или source IP не исправляют противоречивую identity.
5. Несколько разных 4624 для участвующего ключа отклоняются, включая 4624
   вне output bounds. Фоновые повторные системные 4624 по другим ключам
   допустимы. Идентичная redelivery дедуплицируется; конфликт event ID отклоняется.
6. Несколько допустимых 4672 дают один anchor-кандидат, ordered event IDs,
   соответствующие signed deltas и отсортированное объединение привилегий.
7. `[start,end)` выбирает только 4624 anchors. 4672 по обе стороны bounds
   сохраняются как контекст. Basic не скрывает конфликтующий 4624 временным
   фильтром: cap применяется ко всему прочитанному конечному dataset.
8. Required boot/LUID/SID не отсутствуют и не заменяются нулями, null SID,
   Subject-полями 4624 или TargetOutbound-полями. UInt64, ведущие нули,
   decimal/hex spelling, ASCII casing и нативные whitespace-поля проверяются явно.
9. Неподдержанные версии/provider/channel, duplicate XML fields, nested aliases,
   неверные JSON-типы и неполные источники отклоняются до выдачи частичных результатов.
10. Native ingestion сохраняет immutable IDs; профиль, UUID, PIT pagination,
    shard completeness, лимиты и повторная доставка не дают тихих частичных алертов.

Синтетический CLI-пример приведён в [руководстве](../../../docs/newcredentials.md).
Файлы `newcredentials-v0.xml` и `newcredentials-v2.xml` — варианты одной
исходной записи: в один пример выбирается один из них и `special-privileges-v0.xml`.

## Дальнейшая проверка реального источника

- Подтвердить provenance boot ID и полноту событий одной загрузки хоста.
  Capture без этой информации позволяет только условный replay.
- Собрать репрезентативные разрешённые NewCredentials-сессии, включая работу
  администраторов, и независимо размеченные случаи злоупотребления. Определить
  единицу наблюдения и проверить record-time tolerance на источнике.
- Измерить precision/TPR/FPR после независимой разметки. Синтетические совпадения
  и отдельный опубликованный attack specimen не дают эксплуатационных показателей.
- Для PtT сравнить отсутствие AS в коротком окне с cached tickets, разными DC
  и потерями телеметрии. PtT и first-seen Hunt остаются проектными описаниями;
  dedicated NewCredentials runtime не расширяет их покрытие.
