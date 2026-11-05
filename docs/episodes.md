# Эпизоды из rolling-алертов

`tools/run_episode_pipeline.py` строит отдельное представление связанных Windows rolling v2 алертов. Несколько подходящих временных меток одной группы могут образовать один эпизод. Все исходные алерты остаются в `alerts-v2` и в состоянии rolling runner; эпизод хранит ссылки на их ID и ревизии.

Источник — локальная `rolling-detections.sqlite`, открываемая для чтения согласованного snapshot. Приёмник — отдельный Elasticsearch Basic индекс с профилем [episodes-v1](../profiles/elastic/episodes-v1.mapping.json). Для доставки и повторной обработки используется своя SQLite-база. Сбор событий и расчёт исходных rolling-окон продолжает выполнять [rolling pipeline](continuous.md#непрерывный-rolling-v2).

## Правила объединения

В одну группу входят только active-алерты с одинаковыми source scope, семантическим rule ID и всеми значениями `group`. Brute и spray остаются разными правилами. Различные аккаунты у brute также остаются разными группами.

Anchors сортируются по точному времени `window.end`. Две соседние метки соединяются, если расстояние между ними **не больше gap**; по умолчанию gap равен пяти минутам. Связь транзитивна: метки `00:00`, `00:04` и `00:08` образуют один эпизод при gap=5m. Поэтому общая длительность эпизода может превышать gap. Разрыв в gap+1µs начинает новый эпизод. Gap относится к расстоянию между подходящими алертами, а не к отсутствию любых событий аутентификации.

| Поле | Смысл |
|---|---|
| `anchor_count` | Число исходных подходящих алертов в эпизоде |
| `first_anchor`, `last_anchor` | Первая и последняя подходящие метки |
| `member_alert_ids` | ID всех текущих участников в порядке anchors |
| `member_revisions` | Ревизия каждого участника в использованном snapshot |
| `peak_metrics` | Отдельный максимум каждой метрики среди окон участников |
| `revision` | Версия документа эпизода |

Метрики перекрывающихся rolling-окон не складываются. Например, алерты с `fails` 10, 11 и 12 дают `anchor_count: 3` и `peak_metrics.fails: 12`. Значение 33 не является числом попыток входа. Максимум distinct users также не означает число разных пользователей за весь эпизод. Максимумы разных метрик могут приходиться на разные anchors.

В Elastic поля `peak_metrics` и `member_revisions` сохраняются в `_source` без индексации. Они доступны при чтении документа, но поиск по их числовым значениям текущим mapping не предусмотрен. Для отбора текущих эпизодов используйте статусы `open`/`closed`: retracted-документы сохраняют прежние метрики.

Эпизод описывает временную близость сигналов по заданной политике. Подтверждение одной атаки, связь между разными аккаунтами/правилами и решение об инциденте требуют отдельного контекста.

## ID, поздние изменения и закрытие

Episode ID детерминированно зависит от версии политики, gap, source scope, rule/group и ID самого раннего текущего участника. Добавление более поздних участников и изменение метрик сохраняют ID. Появление более раннего участника или исчезновение первого меняет ID.

| Изменение исходных алертов | Результат |
|---|---|
| Продление серии | Прежний ID, обновлённые участники и revision |
| Поздний алерт соединяет две серии | Один объединённый эпизод; ID с самым ранним участником сохраняется |
| Отзыв соединяющего алерта разделяет серию | Несколько эпизодов; часть с прежним первым участником сохраняет ID |
| Прежний ID больше не соответствует текущей компоненте | `status: retracted` и ссылки `replacement_episode_ids` по пересечению участников |
| Прежняя компонента снова появляется | Тот же детерминированный ID активируется новой revision; ссылки на замену очищаются |

При отзыве сохраняются последние участники и метрики. Ссылки на замену описывают соответствие текущим компонентам через прежних участников и могут изменяться при последующем пересчёте. Документы содержат текущее состояние и происхождение результата; полного неизменяемого журнала всех исторических ревизий здесь нет.

У текущего эпизода два состояния: `open` и `closed`. Если checkpoint соответствующего исходного правила равен C, эпизод закрывается только при **`C > last_anchor + gap`**. Равенства недостаточно: anchor на границе C ещё не обработан и может присоединиться к эпизоду. Время учитывается до микросекунд.

Закрытие определяется checkpoint исходного детектора, а не часами episode-процесса. Остановленный upstream не позволяет закрыть эпизод только из-за прошедшего времени. `closed` остаётся пересматриваемым: поздние данные могут продлить, соединить или вновь открыть эпизод. Полнота этого пересмотра ограничена lookback и сохранностью контекста исходного rolling runner.

## Воспроизводимый пример: три алерта → один эпизод

Команды выполняются из корня репозитория после `make setup` и `make lab-up`. Используйте указанные отдельные demo-индексы и состояние либо новые собственные имена. Сначала атомарно опубликуйте инертную серию из 12 ошибок входа:

```bash
.venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
import tempfile
from uuid import uuid4

cases = json.loads(Path('tests/fixtures/rolling/auth_cases.json').read_text(encoding='utf-8'))['cases']
case = next(case for case in cases if case['name'] == 'brute_10_threshold')
events = [dict(event) for event in case['events']]
for suffix, timestamp in [('extension-1', '2026-01-01T00:05:30Z'),
                          ('extension-2', '2026-01-01T00:06:00Z')]:
    events.append({**events[0], 'event.id': 'episode-demo:' + suffix, '@timestamp': timestamp})
payload = ''.join(json.dumps(event) + '\n' for event in events).encode('utf-8')
spool = Path('artifacts/episode-demo/spool')
spool.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile(dir=spool, suffix='.tmp', delete=False) as stream:
    stream.write(payload)
    stream.flush()
    os.fsync(stream.fileno())
    temporary = Path(stream.name)
temporary.rename(spool / f'{uuid4().hex}.ready.jsonl')
directory = os.open(spool, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY

.venv/bin/python tools/run_rolling_pipeline.py --once --initialize \
  --source-index attck-episode-auth-demo --alerts-index attck-episode-raw-demo \
  --spool artifacts/episode-demo/spool --state-dir artifacts/episode-demo/rolling \
  --start 2026-01-01T00:05:00Z --at 2026-01-01T00:09:00Z

.venv/bin/python tools/run_episode_pipeline.py --once --initialize \
  --source-state artifacts/episode-demo/rolling/rolling-detections.sqlite \
  --state artifacts/episode-demo/episodes.sqlite --episodes-index attck-episodes-demo \
  --gap-seconds 300 --at 2026-01-01T00:09:00Z
```

Rolling runner создаёт три brute-алерта с anchors `00:05:00`, `00:05:30` и `00:06:00`; значения `fails` равны 10, 11 и 12. Spray-алерта нет. Episode runner создаёт один `open` эпизод с `anchor_count: 3`, `peak_metrics.fails: 12` и revision 1. Все три исходных алерта сохраняются.

Повторите последнюю команду с тем же состоянием и временем. Неизменившийся snapshot не создаёт новый эпизод и не увеличивает revision. `--initialize` можно опустить после первого создания sink. Чтобы получить согласованное закрытие, продвиньте исходный checkpoint:

```bash
.venv/bin/python tools/run_rolling_pipeline.py --once \
  --source-index attck-episode-auth-demo --alerts-index attck-episode-raw-demo \
  --spool artifacts/episode-demo/spool --state-dir artifacts/episode-demo/rolling \
  --start 2026-01-01T00:05:00Z --at 2026-01-01T00:13:00.000001Z

.venv/bin/python tools/run_episode_pipeline.py --once \
  --source-state artifacts/episode-demo/rolling/rolling-detections.sqlite \
  --state artifacts/episode-demo/episodes.sqlite --episodes-index attck-episodes-demo \
  --gap-seconds 300 --at 2026-01-01T00:13:00.000001Z
```

При allowed lateness 120 секунд C станет `00:11:00.000001`, что на 1µs больше `last_anchor + gap`. Прежний эпизод станет `closed`, revision 2. При C ровно `00:11:00` он оставался бы `open`.

Локальный статус episode-state читается отдельно:

```bash
.venv/bin/python tools/run_episode_pipeline.py --status \
  --source-state artifacts/episode-demo/rolling/rolling-detections.sqlite \
  --state artifacts/episode-demo/episodes.sqlite --episodes-index attck-episodes-demo
```

Для непрерывного потока запускайте rolling producer и episode-процесс как два контролируемых процесса. Замените `--once` на `--watch --interval 30` и уберите `--at`; сохраняйте пути, gap и имена индексов при restart. Episode-процесс читает только последний целостный upstream snapshot. Он может отставать на один или несколько проходов, не мешая расчёту исходных алертов. `SIGINT`/`SIGTERM` заканчивают текущий проход и прерывают ожидание следующего.

## Инкрементальный и полный пересчёт

По умолчанию `--projection-mode incremental` заново строит компоненты только для затронутых rule/group. Группа пересчитывается, если появился исходный алерт, выросла его revision или checkpoint пересёк границу закрытия одного из её open-эпизодов. При первом проходе обрабатываются все сохранённые группы. Если исходные алерты не изменились и граница закрытия не пересечена, повтор не требует построения компонентов.

Группа пересчитывается целиком, включая сохранённые retracted-алерты и прежние эпизоды этой группы. Это сохраняет точный результат позднего merge/split, смены первого участника и обновления `replacement_episode_ids`. Незатронутые группы сохраняют ID, документы и ревизии. Ограничения `--max-episodes` и `--max-members` проверяются также для сохранённых компонентов: уменьшение лимита нельзя обойти тем, что группа не менялась.

Успешный ответ содержит сведения о выполненной работе:

| Поле `recomputation` | Смысл |
|---|---|
| `mode` | Выбранный режим `incremental` или `full` |
| `groups_total` | Все сохранённые rule/group, включая группы только с retracted-алертами |
| `groups_recomputed` | Группы, для которых заново строились компоненты |
| `source_alerts_recomputed` | Исходные строки выбранных групп, включая retracted |

Режим `--projection-mode full` остаётся эталонным полным пересчётом. После приведённого выше шага закрытия можно проверить тот же snapshot:

```bash
.venv/bin/python tools/run_episode_pipeline.py --once --projection-mode full \
  --source-state artifacts/episode-demo/rolling/rolling-detections.sqlite \
  --state artifacts/episode-demo/episodes.sqlite --episodes-index attck-episodes-demo \
  --gap-seconds 300 --at 2026-01-01T00:13:00.000001Z
```

На неизменившемся snapshot сохраняются тот же closed-эпизод и revision 2. Режим — операционный параметр; его можно менять с тем же state и sink, без миграции SQLite schema 1 и изменения области идентификаторов. Дифференциальные тесты сравнивают документы и ревизии обоих режимов на последовательностях поздних изменений.

В обоих режимах по-прежнему читается весь исходный snapshot, проверяется история ревизий и просматривается сохранённое состояние эпизодов. Инкрементальный режим уменьшает работу по сортировке и построению компонентов; он не устраняет полный ввод-вывод и не снимает ограничения на общий объём истории. Счётчики пересчёта не являются измерением latency или пропускной способности.

## Состояние, доставка и ошибки

Чтение binding, checkpoints, source clock, алертов и исходного outbox выполняется в одной SQLite read transaction. Episode-state привязан к каноническому пути исходной БД, device/inode файла, source scope, gap и UUID episode sink. Замена файла даже по тому же пути, несовместимое состояние или смена UUID завершают проход ошибкой. Перенос и восстановление файлов требуют согласованного плана; автоматического принятия другой БД нет.

Исходный runner хранит отозванные алерты как строки с `status: retracted`. Исчезновение уже наблюдавшегося ID означает потерю истории. Episode runner также отклоняет уменьшение revision, изменение payload без новой revision и откат source clock/checkpoints. Позднее изменение с большей revision допустимо при прежнем checkpoint.

Пока исходный outbox не подтверждён полностью, новое представление не рассчитывается: `--once` возвращает `status: waiting_for_raw_delivery` и код 2. Уже сохранённый episode outbox может восстанавливаться независимо. После доставки исходных алертов повторите проход. Успешное завершение имеет код 0; ошибка имеет код 1. `--watch` сообщает ошибку и повторяет попытку, сохраняя состояние.

Новый source snapshot, изменения эпизодов и их outbox фиксируются одной транзакцией episode-state. Доставка использует стабильный document ID и `external_gte` revision. Повтор после сбоя между записью в Elasticsearch и локальным acknowledgement отправляет тот же payload/version. Смена sink UUID проверяется перед записью и после ответа. Общей транзакции SQLite/Elasticsearch нет: при merge/split отдельные записи могут временно показывать смесь прежних и новых компонентов, пока episode outbox не доставлен полностью. У raw и episode runner независимые outbox; успешный проход episode runner завершается с `pending_outbox: 0`, но атомарное переключение всей удалённой SIEM-картины не заявляется.

`--initialize` создаёт отдельный sink для нового состояния и не перезаписывает mapping. Первичная привязка требует пустой sink: новая БД состояния не может начать с revision 1 поверх уже сохранённых эпизодов. При исчезновении уже привязанного sink нельзя обойти восстановление повторным `--initialize` или удалением state. Для одного sink используйте один writer и одну долговечную БД состояния; блокировка не координирует разошедшиеся копии. Проверка пустоты не является распределённой блокировкой между двумя одновременно запускаемыми новыми writers.

URL и credentials задаются теми же переменными `ELASTIC_URL`, `ELASTIC_API_KEY` либо `ELASTIC_USERNAME`/`ELASTIC_PASSWORD`, что и у [Elastic adapters](elastic.md). Snapshot должен быть доступен как локальная SQLite-база с корректными WAL/locking semantics.

## Лимиты и дальнейшее развитие

Каждый проход перечитывает полную сохранённую историю исходных алертов. По умолчанию компоненты строятся для затронутых групп; `--projection-mode full` пересчитывает все группы. Оба режима сохраняют проверки полноты snapshot и отката исходной истории.

| Флаг | По умолчанию | Область ограничения |
|---|---:|---|
| `--max-source-alerts` | 100 000 | Все строки исходных алертов, включая retracted |
| `--max-source-bytes` | 64 MiB | UTF-8 JSON binding, alert payloads и pending raw outbox payloads до декодирования |
| `--max-episodes` | 10 000 | Все текущие компоненты: сохранённые и пересчитанные |
| `--max-members` | 10 000 | Участники одного текущего эпизода |
| `--max-changes` | 10 000 | Создание, обновление и отзыв документов за проход |

Превышение предела завершает весь новый расчёт ошибкой; неполный snapshot не становится успешным результатом. Уже committed outbox относится к прежней оценке и может быть доставлен до новой ошибки. Операционные лимиты можно менять без смены gap или семантической области. Размер SQLite-файла на диске, длительность запроса и потребление памяти не ограничены одним лишь `--max-source-bytes`.

История растёт, включая сохранённые retracted-эпизоды. `--max-episodes` ограничивает текущие компоненты, а не общий исторический размер episode-state. При достижении cap нужны достаточные ресурсы и явно выбранный новый лимит; удалять строки источника ради продолжения нельзя. [Архив evidence](episode-archives.md) сохраняет согласованные данные и проверяется офлайн, включая полный эталонный пересчёт. Он не очищает живые базы. Согласованное удаление истории, инкрементальное чтение источника, перенос состояния, распределённая координация и полный журнал ревизий остаются отдельными задачами. Унаследованные ограничения исходного rolling lookback сохраняются.

Фактически выполненные проверки перечислены в [validation report](validation_report.md). Синтетические сценарии проверяют описанные контракты и восстановление. Эксплуатационные precision/TPR/FPR и нагрузочные показатели требуют репрезентативной размеченной телеметрии.
