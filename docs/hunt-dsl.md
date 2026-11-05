# Исполняемый Hunt DSL: v1 и rolling v2

Host/web-корреляция исполняется отдельными [runtime и Basic-адаптером](correlation.md). Она не добавляет join/first_seen/query parsing в Hunt DSL: оба T1190 Hunt остаются проектными описаниями. `query_key_in` в web selector обозначает требуемый разбор ключей, но не является поддержанным оператором v1/v2.

Runtime `tools/hunt_engine.py` исполняет только hunts с `schema_version: 1`, соответствующие `schema/hunt.schema.yaml`. Это три T1110 hunt: Windows brute, Windows spray и Linux SSH. Runtime `tools/rolling_hunt.py` исполняет четыре v2 Hunt: отдельные rolling-версии этих трёх сценариев и [RC4 service-account burst](kerberos.md). Остальные 18 hunts — проектные описания; неподдерживаемая схема завершается ошибкой.

## Сохранённый контракт v1

```bash
.venv/bin/python tools/hunt_engine.py \
  techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml \
  --events tests/fixtures/hunts/brute_positive.jsonl
```

Вход — JSONL с плоскими именами полей: event.code, source.ip, target.user. Обязательны непустые event.id, event.dataset и RFC3339 @timestamp с часовым поясом и точностью до микросекунд. Повтор одинакового нормализованного события считается один раз; конфликт содержимого при том же ID — ошибка, включая изменение типа значения.

Операторы и типы ограничены схемой; unsupported constructs явно отклоняются. Сравнения не приводят строки к числам. Отсутствующее/null или несовместимое значение даёт unknown, включая под NOT; unknown не становится совпадением. Поля группировки и distinct должны быть непустыми строками; непригодные события отражаются в счётчике rejected.

Окна v1 — фиксированные UTC tumbling intervals, выровненные относительно Unix epoch, `[start,end)`. Например, 00:04:59 и 00:05:00 попадают в разные пятиминутные окна. Серия на границе может не достичь порога ни в одном окне. В этом runtime скользящих окон нет. Сам replay обрабатывает конечный batch; persistent state и watermarks реализованы отдельно в [Windows pipeline](continuous.md). First_seen, count_if и event sequences здесь отсутствуют.

Count считает уникальные принятые события. Count_distinct использует точное множество строк. Project ссылается только на ключи группы, метрики и границы окна. Один алерт соответствует одной группе в одном окне; порядок детерминирован.

Fixtures в tests/fixtures/hunts/auth_cases.json задают вход и ожидаемые алерты. Проверяются пороги 9/10 для brute, 14/15 пользователей для spray, Linux 7/8, разделение групп, границы, дубликаты и пропуски. Совместимость SIEM устанавливается отдельным replay.

## Отдельный контракт rolling v2

`schema_version: 2` и `aggregate.window_type: rolling` проверяются по [rolling-hunt.schema.yaml](../schema/rolling-hunt.schema.yaml). V1-файлы не переименовываются и не меняют смысл. V1 runtime, адаптер и runner отклоняют v2; автоматической миграции SQLite state нет.

| Свойство | V1 | Rolling v2 |
|---|---|---|
| Окно | Фиксированное UTC `[start,end)` | `(t−W,t]` на каждом подходящем timestamp группы |
| Равные timestamps | Одна фиксированная группа/окно | Все события этой метки учитываются атомарно |
| Результат | Один на подходящую группу/фиксированное окно | Один на подходящую группу/timestamp |
| Having | Подмножество сравнений v1 | Только `gte` с положительным целочисленным порогом |
| Project | Поднабор доступных полей | Все поля группы, метрик и обе границы окна |
| Непрерывный pipeline | Два Windows Hunt, state v1 | Два Windows Hunt, отдельные state v2 и date_nanos indices |

Count и count_distinct точные. Дедупликация, трёхзначные предикаты, требования к непустым строковым ключам и микросекундная UTC-нормализация сохраняются. Событие, не прошедшее dataset/where/ключи, не создаёт anchor.

Опциональные bounds выбирают anchor timestamps `[A,B)`; для них сохраняется предшествующий контекст `(A−W,B)`. Нижняя граница rolling-окна исключительная. Лимиты сырого ввода и результатов завершают весь вызов ошибкой при превышении, без молчаливого усечения. Подавления последующих подходящих timestamps и объединения в инциденты нет.

Пошаговый пример, Elastic auth-v2 и ограничения приведены в [rolling windows](rolling-windows.md). Проверки используют [ручные ожидаемые результаты](../tests/fixtures/rolling/auth_cases.json) и независимый математический oracle; их результат не является измерением эксплуатационной точности.
