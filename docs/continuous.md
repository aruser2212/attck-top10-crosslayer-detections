# Непрерывный Windows T1110 pipeline

Два отдельных pipeline объединяют приём файлов, нормализацию, загрузку в Elasticsearch Basic и исполнение Windows T1110 hunts. Проверяются brute force по паре account × source и password spraying по числу разных аккаунтов. Оба поддерживают один конечный проход `--once` и повторные проходы `--watch` с сохранением состояния.

| Версия | Команда | Источник / приёмник | Окна |
|---|---|---|---|
| V1 | `tools/run_auth_pipeline.py` | `auth-v1` / `alerts-v1` | Фиксированные UTC `[start,end)` |
| V2 | `tools/run_rolling_pipeline.py` | `auth-v2` / `alerts-v2` | Скользящие `(t−W,t]` в моменты событий |

У каждой версии собственные индексы и директория состояния. V2 не мигрирует v1 и не подменяет его правила. Ниже сохранён пример v1; отдельный [пример v2](#непрерывный-rolling-v2) показывает серию, пересекающую фиксированную границу.

Поверх v2 доступен отдельный [episode pipeline](episodes.md): он читает согласованный snapshot `rolling-detections.sqlite` и объединяет близкие алерты одинакового rule/group. Исходные алерты сохраняются полностью; эпизоды доставляются в собственный `episodes-v1` индекс. Руководство содержит пример «три rolling-алерта → один эпизод», правила поздних объединений/разделений и границы закрытия.

Pipeline получает уже доставленные файлы. Windows collector, Elastic Agent, Winlogbeat и доставка из удалённой машины здесь не развёрнуты. Linux SSH hunts v1/v2 исполняются только офлайн. Остальные 19 Hunt-файлов остаются проектами логики вне исполняемых поднаборов.

## Воспроизводимый конечный пример v1

Из корня репозитория подготовьте зависимости и локальный бесплатный стенд:

```bash
make setup
make lab-up
```

Опубликуйте существующий inert fixture в spool. Временный файл записывается полностью, синхронизируется и атомарно переименовывается в той же директории. Уникальное имя позволяет повторять пример, сохраняя неизменность уже опубликованных файлов:

```bash
.venv/bin/python - <<'PY'
import os
from pathlib import Path
import tempfile
from uuid import uuid4

spool = Path('artifacts/auth-demo/spool')
spool.mkdir(parents=True, exist_ok=True)
payload = Path('tests/fixtures/hunts/brute_positive.jsonl').read_bytes()
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

.venv/bin/python tools/run_auth_pipeline.py --once --initialize \
  --source-index attck-auth-demo --alerts-index attck-alerts-demo \
  --spool artifacts/auth-demo/spool --state-dir artifacts/auth-demo/state \
  --start 2026-01-01T00:00:00Z --at 2026-01-01T00:12:00Z
```

`--at` фиксирует часы для этого конечного примера и разрешён только с `--once`. При стандартной задержке допуска 120 секунд оба правила рассматривают закрытые окна до `00:10:00Z`. Ожидается один brute-force алерт: 10 событий пользователя `alice` с `192.0.2.10` в окне `[00:00,00:05)`. Spray-алерта нет: пользователь один.

`--initialize` создаёт только отсутствующие source/sink индексы с заданными профилями. Существующие чужие mappings не перезаписываются. Повтор с теми же событиями и тем же состоянием не увеличивает их количество и не создаёт второй логический алерт. Повторный конечный запуск успешен и при отсутствии новой работы.

## Файловый контракт и backlog

Производитель должен публиковать уникальные, неизменяемые файлы:

- `*.ready.jsonl` — нормализованные события выбранного профиля auth-v1 или auth-v2, по одному JSON-объекту на строку; поддержаны `windows.security.logons` и `event.code` `4624`/`4625`.
- `*.ready.xml` — один экспортированный Windows Event XML; нормализация выполняется при чтении. Это не бинарный EVTX и не XML-контейнер с множеством событий.

До публикации файл должен иметь временное имя, например `*.tmp`. Закройте и синхронизируйте его, затем выполните атомарное переименование на том же локальном filesystem. После появления `ready` запрещены дописывание, подмена содержимого и повторное использование имени для другого batch. Стабильные `event.id` должны сохраняться при повторной доставке. Сам importer не удаляет и не перемещает входные файлы.

Некорректные и изменённые опубликованные файлы получают состояние `quarantined` в SQLite ledger. Физического переноса в другую папку нет. Исправленный файл публикуется под новым именем; ошибочный ready-файл нужно явно убрать из входной директории после разбора причины. Конфликт существующего `event.id` нельзя исправить незаметным изменением его содержимого. Временные ошибки Elasticsearch сохраняют состояние `pending` для повтора.

Подтверждение непустого файла требует успешного refresh source index со всеми shards. Проверка выполняется и при повторе уже существующих событий: наличие ID через realtime lookup ещё не означает видимость для поиска. Ошибка refresh сохраняет `pending` и не разрешает продвижение detection. Для защищённого кластера нужны права на эту операцию; см. [Elastic](elastic.md).

Один проход ограничен `--max-files` (по умолчанию 100) и `--max-file-bytes` (16 MiB на файл). Importer также ограничивает суммарное чтение одним проходом 64 MiB и число событий в файле 100 000. В CLI v1 эти два предела фиксированы; v2 позволяет задать `--max-scan-bytes` и `--max-ingest-events`. Сохранённый круговой курсор не позволяет старым подтверждённым файлам бесконечно вытеснять новый вход.

Сначала выполняется ingestion, затем detection. Если после ограниченного прохода остались известные неподтверждённые ready-файлы, результат имеет `status: catching_up`, а detection не выполняется. Это предотвращает продвижение временного checkpoint мимо уже известного backlog. Повторяйте `--once` с тем же состоянием либо используйте `--watch`, пока очередь не обработана. `deferred_files` может включать уже подтверждённые неизменные файлы; решающим счётчиком является `unacknowledged_files`.

| Результат `--once` | Код завершения |
|---|---:|
| Ingestion завершён, detection достиг текущего cutoff либо время начала ещё не наступило | 0 |
| `catching_up`: остался backlog файлов или, для v2, необработанная часть истории до cutoff | 2 |
| Ошибка входа, конфигурации, SQLite или Elasticsearch | 1 |

Ошибки синтаксиса аргументов argparse также завершаются кодом 2; они выводят usage/error в stderr, а не JSON `status: catching_up`. Для автоматизации проверяйте и код, и структурированный результат.

## Повторяющийся запуск v1

Для текущего потока используйте собственную директорию spool, отдельное состояние и явную начальную границу. Значение ниже — пример: выберите UTC-границу не позже первого нужного события, кратную десяти минутам, и сохраняйте её при перезапусках.

```bash
mkdir -p artifacts/auth-live/spool
.venv/bin/python tools/run_auth_pipeline.py --watch --initialize \
  --source-index attck-auth-live --alerts-index attck-alerts-live \
  --spool artifacts/auth-live/spool --state-dir artifacts/auth-live/state \
  --start 2026-11-05T00:00:00Z \
  --interval 30 --lookback-seconds 1800 --allowed-lateness-seconds 120
```

Для фонового запуска зарегистрируйте эту команду в своём supervisor, например systemd, с рабочей директорией репозитория и абсолютными путями к Python, spool и state. Сам проект сервис ОС не устанавливает. `SIGINT`/`SIGTERM` прекращают цикл после текущего конечного прохода; ожидание следующего прохода прерывается сразу. Не запускайте два экземпляра с копиями одного логического состояния.

В `--watch` неудачный проход выводит JSON с `ok: false` и повторяется после интервала; это не успешный checkpoint. `--at` в этом режиме запрещён. Не возвращайте часы demo-state назад после запуска его на реальном времени: runner отклоняет обратный ход времени.

## Время, закрытие окон и опоздания v1

Это три разных механизма:

| Настройка | Значение |
|---|---|
| Окно правила | Фиксированные UTC tumbling windows: 5 минут для brute, 10 минут для spray, `[start,end)` |
| `--allowed-lateness-seconds` | Задержка перед закрытием окна относительно текущих часов; по умолчанию 120 секунд |
| `--lookback-seconds` | Повторная оценка уже закрытых окон за checkpoint; по умолчанию 1800 секунд |

Cutoff каждого правила вычисляется как `floor_to_window(now - allowed_lateness)`. Повтор начинается от `checkpoint - lookback`, округлённого назад до полной границы окна и ограниченного первоначальным `--start`. Окна разных правил имеют отдельные checkpoints. Начало в будущем даёт пустой проход до появления подходящих закрытых окон.

Опоздавший десятый failed logon внутри горизонта повтора может создать ранее отсутствовавший алерт. Последующие события обновляют его метрики. Lookback не превращает правило в sliding-window detection: активность, разделённая границей пяти- или десятиминутного окна, по-прежнему может не достичь порога.

Без ingest timestamp невозможно посчитать все события, пришедшие позже горизонта повтора. Runner явно возвращает `late_arrivals_observable: false` и `late_arrivals_before_replay_horizon: null`. Это неизвестная величина, а не ноль потерянных событий. Файлы, появившиеся после проверки backlog, также ограничены выбранным lookback.

## Состояние и доставка алертов v1

`--state-dir` содержит два разных журнала:

- `spool.sqlite` — имена файлов, hashes, статусы обработки и ошибки; связь с source-директорией и конкретным source index UUID.
- `detections.sqlite` — SQLite WAL с per-rule checkpoints, логическими алертами и transactional outbox; связь с source/sink UUID, семантикой правил и конфигурацией расписания.

Храните оба журнала и WAL-файлы на локальном durable filesystem. Process locks защищают использование одного состояния; они не координируют разошедшиеся копии SQLite на разных машинах. Credentials в журналах не сохраняются, но в alert state присутствуют поля детектов, включая аккаунты и IP.

Checkpoints продвигаются только после успешной полной оценки всех правил и общей транзакции записи результатов вместе с outbox. Пустой результат также может продвинуть checkpoint. При ошибке поиска, неполных shards или смене source UUID продвижения нет. Пересоздание индекса с тем же именем не делает прежнее состояние совместимым: UUID проверяется отдельно.

Alert ID зависит от scope, семантики правила, окна и ключей группы; число событий в ID не входит. Увеличение метрики обновляет тот же документ. Если повторная полная оценка окна больше не подтверждает ранее найденный сигнал, его статус становится `retracted`; в документе остаются последние подтверждённые метрики. Возврат условия активирует тот же ID с новой revision.

Outbox доставляется в отдельный индекс [alerts-v1](../profiles/elastic/alerts-v1.mapping.json). Сбой после записи Elasticsearch и до локального acknowledgement приводит к безопасному повтору. `version_type=external_gte` вместе с revision не позволяет задержавшейся старой записи затереть новую. Неожиданный конфликт версии оставляет outbox неподтверждённым; состояние автоматически не сбрасывается.

Не удаляйте журналы и индексы ради обхода ошибки UUID или версии. Восстановление должно сохранять согласованность source, sink и состояния. Развёртывание HA, общая блокировка между хостами и автоматическая миграция state здесь не реализованы.

## Непрерывный rolling v2

`tools/run_rolling_pipeline.py` использует `auth-v2`, `alerts-v2` и отдельный `RollingDetectionRunner`. SQLite schema 2 хранит время целым числом микросекунд, source/sink mappings сохраняют эти микросекунды через `date_nanos`. Индексы v1 и его state здесь несовместимы; команда отклоняет директорию с `spool.sqlite` или `detections.sqlite`. Используйте отдельную директорию и новые имена индексов.

Из корня репозитория после `make setup` и `make lab-up` опубликуйте существующий синтетический fixture. В нём пять ошибок до `00:05:00Z` и пять после; фиксированные окна v1 не достигают порога, а rolling v2 достигает:

```bash
.venv/bin/python - <<'PY'
import json
import os
from pathlib import Path
import tempfile
from uuid import uuid4

cases = json.loads(Path('tests/fixtures/rolling/auth_cases.json').read_text(encoding='utf-8'))['cases']
case = next(case for case in cases if case['name'] == 'brute_straddles_v1_boundary')
payload = ''.join(json.dumps(event) + '\n' for event in case['events']).encode('utf-8')
spool = Path('artifacts/rolling-live-demo/spool')
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
  --source-index attck-rolling-live-demo --alerts-index attck-rolling-alerts-demo \
  --spool artifacts/rolling-live-demo/spool --state-dir artifacts/rolling-live-demo/state \
  --start 2026-01-01T00:05:00Z --at 2026-01-01T00:08:00Z
```

Cutoff равен `00:06:00Z` при стандартной allowed lateness 120 секунд. Ожидается один active brute-алерт с `window.end: 00:05:01Z`, `window.start: 00:00:01Z` и `fails: 10`; spray-алерта нет. События в `00:04:59Z` входят в контекст, хотя их время раньше `--start`.

Повторите ту же команду `--once`, сохраняя `--start`, `--at`, индексы и состояние. Повторное чтение/оценка не создаёт второй логический алерт и не увеличивает revision без изменения результата. Для перезапуска уже созданных индексов `--initialize` можно опустить. После появления любого из двух файлов состояния `--initialize` уже не создаёт заново исчезнувший source или sink: нужно восстановить соответствующий индекс и UUID, а не продолжать с пустой заменой. Не переиспользуйте demo-state с другими начальными параметрами.

Для текущего потока выберите отдельную spool/state директорию и начальный момент не позже первого нужного anchor. Пример даты ниже заменяется на нужную границу до первого запуска и сохраняется при перезапусках:

```bash
mkdir -p artifacts/rolling-live/spool
.venv/bin/python tools/run_rolling_pipeline.py --watch --initialize \
  --source-index attck-rolling-live --alerts-index attck-rolling-alerts-live \
  --spool artifacts/rolling-live/spool --state-dir artifacts/rolling-live/state \
  --start 2026-11-05T00:00:00Z \
  --interval 30 --lookback-seconds 1800 --allowed-lateness-seconds 120 \
  --max-forward-seconds 3600 --max-query-events 100000 --max-alerts 10000
```

Правила остановки и supervisor те же: `SIGINT`/`SIGTERM` заканчивают текущий конечный проход и прерывают ожидание. `--at` разрешён только с `--once`. Если начальная дата далеко в прошлом, понадобится несколько ограниченных проходов; `--watch` повторяет их, а `--once` сообщает `status: catching_up` с кодом 2, пока есть необработанная история или файловый backlog. Пустая история также продвигается ограниченными шагами. Запуск watch на январском demo-state с текущими часами намеренно начнёт догонять месяцы истории; для нового текущего потока используйте отдельный пример live, а не ожидайте мгновенной готовности demo-state.

### Диапазон прохода и лимиты v2

Начало `--start` допускает микросекунды и не требует выравнивания. Для стандартной пары правил оно не может быть раньше `1970-01-01T00:10:00Z`: десятиминутная нижняя граница окна должна помещаться в `date_nanos`. Верхняя допустимая граница времени — `2262-04-11T23:47:16.854775Z`. Часы с обратным ходом и выход за допустимый диапазон отклоняются.

Checkpoint C обозначает исключительный конец уже оценённых anchors. Следующий проход оценивает anchors `[A,B)`, где `A = max(initial_start, C − lookback)`, `B = min(now − allowed_lateness, C + max_forward_span)`. Каждый запрос дополнительно читает необходимый контекст `(A−W,B)`. В первый проход C равен `--start`; контекст перед ним не отбрасывается.

| Параметр | По умолчанию | Что ограничивает |
|---|---:|---|
| `--lookback-seconds` | 1800 | Повтор ранее обработанных anchors |
| `--allowed-lateness-seconds` | 120 | Отставание cutoff от текущего времени |
| `--max-forward-seconds` | 3600 | Продвижение C за один проход, независимо от lookback |
| `--page-size` | 500 | Страницу PIT/search_after |
| `--max-query-events` | 100 000 | Прочитанные события каждого правила вместе с контекстом, до локального where |
| `--max-alerts` | 10 000 | Сумму кандидатов и отзывов всех правил за проход |
| `--max-scan-bytes` | 64 MiB | Байты входных файлов за один scan |
| `--max-ingest-events` | 100 000 | События в одном входном файле |

Лимиты файлов из общего контракта также действуют. Размер страницы не ограничивает весь запрос. Превышение event/alert cap прерывает оценку без частичного checkpoint и без отзывов по неполному результату. `--max-alerts` относится к текущей оценке; уже сохранённый outbox предыдущего прохода доставляется до неё и может превышать новый уменьшенный лимит. Уменьшение forward span не сокращает заданный lookback или контекст W; плотная повторяемая история может потребовать увеличения caps и доступной памяти. Это пределы объёма работы, не измерение пропускной способности.

Late event с временем s раньше A ещё может повлиять на проверяемый anchor t, если `t−W < s ≤ t`. При этом старый anchor s уже не создаётся. Поэтому lookback задаёт горизонт переоценки **anchors**, а не строгий возраст допустимого события. Для anchors раньше A автоматического backfill нет. Без ingest timestamp число всех пропущенных поздних прибытий остаётся неизвестным. Файлы, опубликованные после проверки backlog, также подчиняются этому ограничению.

### Состояние и доставка v2

Новая директория содержит `rolling-spool.sqlite` и `rolling-detections.sqlite` с их служебными lock/WAL-файлами. Ledger ingestion привязан к auth-v2 профилю, source UUID и spool-директории. Detection state schema 2 привязан к конкретным source/sink UUID, началу, семантике правил, lookback и allowed lateness. Смена этих параметров требует отдельного состояния или явно разработанной миграции; автоматической миграции нет. Операционные caps, page size и forward span можно менять при перезапуске, сохраняя alert identity.

Alert ID включает scope, семантику правила, ключи группы и точный anchor в микросекундах. Число событий в ID не входит. Одна серия может создавать много документов: на каждый подходящий group/timestamp, без объединения в инцидент. Повторная оценка меняет revision существующего ID только при изменении результата. Отзыв применяется к ранее найденным алертам с `window.end` в `[A,B)`; `status: retracted` сохраняет последние подтверждённые метрики. Возврат сигнала активирует тот же ID новой revision.

Полная оценка всех правил предшествует общей транзакции checkpoints, alert state и outbox. SQLite WAL требует локального durable filesystem и одного владельца состояния. Перед каждой записью outbox и после подтверждения проверяется UUID sink. Между проверкой UUID и самой записью нет атомарного условия Elasticsearch по UUID; конкурентное пересоздание индекса не является поддержанным способом эксплуатации.

Доставка в [alerts-v2](../profiles/elastic/alerts-v2.mapping.json) использует тот же `external_gte` контракт revision. После записи Elasticsearch, но до локального acknowledgement, запрос может быть повторён с тем же payload и revision. Устаревшая версия не перезаписывает новую; неожиданный конфликт остаётся ошибкой с неподтверждённым outbox. Это повторяемая доставка с идемпотентной записью, без общей транзакции SQLite/Elasticsearch и без распределённой координации workers.

## Диагностика и остановка

Локальный статус v1 detection-state читается без обращения к Elasticsearch:

```bash
.venv/bin/python tools/detection_runner.py status \
  --source-index attck-auth-demo --alerts-index attck-alerts-demo \
  --state artifacts/auth-demo/state/detections.sqlite
```

В ответе доступны checkpoints, число логических алертов, pending outbox и время последней сохранённой оценки. Статусы отдельных входных файлов и `error_code` находятся в `spool.sqlite`. Не путайте локальный committed checkpoint с уже доставленным алертом: при недоступном sink outbox остаётся на диске.

У v2 те же сведения доступны через локальный `RollingDetectionRunner.status()`; отдельной status-команды CLI нет. Следующий пример читает demo-state без запросов к Elasticsearch:

```bash
.venv/bin/python - <<'PY'
import json
from tools.elastic_rolling import ElasticClient
from tools.rolling_runner import RollingDetectionRunner

runner = RollingDetectionRunner(
    source_client=ElasticClient('http://127.0.0.1:19200'),
    source_index='attck-rolling-live-demo', alerts_index='attck-rolling-alerts-demo',
    state_path='artifacts/rolling-live-demo/state/rolling-detections.sqlite',
)
print(json.dumps(runner.status(), ensure_ascii=False, indent=2))
PY
```

Статусы входных файлов v2 находятся в `rolling-spool.sqlite`. Для интерпретации event-time catch-up смотрите `detection.caught_up` и диапазоны последнего успешного JSON-результата pipeline.

`make lab-down` останавливает контейнер Compose-проекта `attck-detection-lab`, сохраняя named volume `elastic-data`. `make lab-up` снова использует эти данные. Локальные spool/state также сохраняются. Удаление тома или индексов — отдельная операция, которая потребует согласованного восстановления состояния.

Endpoint задаётся `ELASTIC_URL`; для защищённого сервера используйте `ELASTIC_API_KEY` либо `ELASTIC_USERNAME`/`ELASTIC_PASSWORD` через окружение supervisor. HTTPS проверяет сертификаты. В Compose authentication отключена только у локального синтетического стенда, привязанного к `127.0.0.1:19200`.

## Что подтверждают проверки

`make check` проверяет состояния, locks, ошибки, crash/restart, backlog и детерминированные события. `make check-elastic` дополнительно исполняет native Basic проверки: bounded queries, source UUID, late-event threshold crossing, обновление одного алерта, повтор доставки и защиту внешней версией. Пройденные сценарии не являются измерением эксплуатационных TPR/FPR или latency; такие измерения требуют репрезентативной телеметрии конкретной среды.
