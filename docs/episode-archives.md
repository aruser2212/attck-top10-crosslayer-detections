# Проверяемый архив эпизодов

`tools/episode_archive.py` сохраняет согласованный набор evidence из rolling v2 и episode-state в отдельный JSON-файл. Архив содержит все сохранённые raw-алерты и последние документы эпизодов, включая retracted, сведения об области работы, контрольные точки и оценку границы повторной обработки. Живые SQLite-базы и Elasticsearch-индексы сохраняются без очистки.

Архив можно проверить офлайн: команда проверяет формат, SHA256 содержимого, связи документов и равенство текущих эпизодов полному эталонному пересчёту. SHA256 обнаруживает изменение содержимого, но не удостоверяет происхождение данных и не заменяет цифровую подпись. Архив содержит последние состояния; все исторические ревизии в него не входят.

## Создание после согласованного прохода

Сначала выполните [пример эпизодов](episodes.md), включая шаг закрытия при `--at 2026-01-01T00:13:00.000001Z`. Завершите текущие проходы обоих writers. Для фоновых процессов используйте их штатную остановку по `SIGINT`/`SIGTERM`, чтобы они закончили текущую работу.

```bash
mkdir -p artifacts/episode-demo/archives
.venv/bin/python tools/episode_archive.py create \
  --source-state artifacts/episode-demo/rolling/rolling-detections.sqlite \
  --episode-state artifacts/episode-demo/episodes.sqlite \
  --output artifacts/episode-demo/archives/closed.json

.venv/bin/python tools/episode_archive.py verify \
  artifacts/episode-demo/archives/closed.json
```

В этом примере ожидаются `verified: true`, три raw-алерта, один текущий эпизод и `replay_stable_episodes: 0`. Эпизод уже closed, но его последний anchor ещё находится в пределах потенциального влияния будущего bounded replay. `pruning_applied` всегда равно `false`.

`create` получает существующие файловые блокировки rolling и episode writer. Занятая, отсутствующая или подменённая блокировка завершает команду ошибкой; создание не ждёт бесконечно и не создаёт новое состояние. Обе базы открываются для чтения. Для успешного экспорта необходимы:

- пустые raw и episode outbox;
- тот же исходный файл, scope и grouping policy, к которым привязан episode-state;
- точное совпадение source checkpoints/clock и сохранённых episode source progress;
- совпадение всех наблюдавшихся raw ID, revision и payload hash;
- согласованность текущих эпизодов с полным эталонным пересчётом и корректные ссылки отозванных эпизодов.

Если upstream продвинулся после последнего episode-прохода, сначала повторите episode runner и завершите доставку. Экспорт не объявляет отстающее представление согласованным архивом. Проверка происходит по локальным ledger: команда не связывается с Elasticsearch и не подтверждает наличие каждого документа в удалённом индексе в момент экспорта.

Результат публикуется под новым именем после записи и `fsync` временного файла. Существующий файл, symlink или одновременно занятое имя не перезаписывается. Родительский каталог должен уже существовать. Для следующего архива выберите другое имя; удаление прежнего архива не требуется.

## Что означает replay-stable

Для каждого исходного правила рассчитывается следующая нижняя граница повторной обработки anchors:

`A = max(initial_start, C − lookback)`

Здесь C — сохранённый checkpoint правила. Текущий closed-эпизод считается вышедшим за возможное влияние этой политики только при строгом условии:

`last_anchor + gap < A`

Равенство не подходит: новый anchor ровно в A ещё может соединиться с последним участником через включительную границу gap. Обычное закрытие проверяет более слабое условие `C > last_anchor + gap`; closed само по себе не означает неизменяемость.

В demo последний anchor равен `00:06:00`, gap — пять минут, lookback — 30 минут. Продвиньте source clock и затем episode-представление:

```bash
.venv/bin/python tools/run_rolling_pipeline.py --once \
  --source-index attck-episode-auth-demo --alerts-index attck-episode-raw-demo \
  --spool artifacts/episode-demo/spool --state-dir artifacts/episode-demo/rolling \
  --start 2026-01-01T00:05:00Z --at 2026-01-01T00:43:00.000001Z

.venv/bin/python tools/run_episode_pipeline.py --once \
  --source-state artifacts/episode-demo/rolling/rolling-detections.sqlite \
  --state artifacts/episode-demo/episodes.sqlite --episodes-index attck-episodes-demo \
  --gap-seconds 300 --at 2026-01-01T00:43:00.000001Z

.venv/bin/python tools/episode_archive.py create \
  --source-state artifacts/episode-demo/rolling/rolling-detections.sqlite \
  --episode-state artifacts/episode-demo/episodes.sqlite \
  --output artifacts/episode-demo/archives/beyond-replay.json

.venv/bin/python tools/episode_archive.py verify \
  artifacts/episode-demo/archives/beyond-replay.json
```

При allowed lateness 120 секунд C равен `00:41:00.000001`, а A — `00:11:00.000001`. Это на 1µs больше `last_anchor + gap`, поэтому ожидается `replay_stable_episodes: 1`. Сам эпизод и его revision не меняются; исходные три алерта остаются в ledger.

Оценка относится только к сохранённой политике bounded replay с неизменными scope, gap и lookback. Исторический backfill, изменение правил или ручное редактирование источника выходят за её предпосылки. Поле `retention_plan` — проверяемая оценка, а не разрешение удалить строки. Текущий episode runner по-прежнему отклоняет исчезновение уже наблюдавшегося raw ID. Для очистки нужен отдельный протокол, сохраняющий согласованность исходной истории, эпизодов и их ревизий при сбоях.

## Проверка и формат

Файл имеет envelope `format: attck-episode-evidence`, `version: 1`, `sha256` и `content`. Хеш считается по каноническому JSON `content`. Содержимое включает source identity/binding, checkpoints/clock, сведения episode projection, raw-алерты, документы эпизодов, счётчики и `retention_plan`.

`verify` не требует исходных SQLite-файлов или доступа к сети. Проверяются размер и неизменность файла при чтении, версия формата, строгие JSON-поля, checksum, raw identity/revision, область группировки, участники, ссылки на замены и границы времени. Текущие open/closed-компоненты повторно вычисляются полным `group_episodes`; отозванные документы проверяются как сохранённое прежнее evidence со ссылками на текущие компоненты.

Прежние raw payloads не восстанавливаются из последних ревизий. Поэтому старые peak-метрики retracted-эпизода сохраняются как заявленное историческое evidence: их нельзя полностью пересчитать без соответствующего журнала прежних версий. Проверка текущих компонентов остаётся точным сравнением с эталоном.

В отчёте доступны `raw_alerts`, `episodes`, `current_episodes`, `replay_stable_episodes`, `sha256` и `pruning_applied: false`. Успех имеет код выхода 0; ошибка — 1. Файл содержит нормализованные аккаунты/IP и локальные metadata источника: обращайтесь с ним как с копией соответствующих журналов.

## Лимиты и границы восстановления

| Флаг | По умолчанию | Что ограничивает |
|---|---:|---|
| `create --max-source-alerts` | 100 000 | Все исходные raw-строки, включая retracted |
| `create --max-source-bytes` | 64 MiB | UTF-8 JSON metadata, raw payloads и pending outbox payloads до декодирования |
| `create --max-episode-rows` | 100 000 | Все документы эпизодов, включая retracted |
| `create --max-episode-bytes` | 128 MiB | Прочитанные episode metadata, core/payload и текст raw-manifest |
| `--max-archive-bytes` | 256 MiB | Итоговый файл при create и ограниченное чтение при verify |

Превышение лимита завершается ошибкой, без публикации частичного архива. Счётчики байтов не задают общий предел памяти процесса, размер SQLite на диске или максимальную длительность полного пересчёта.

Архив сохраняет evidence для проверки и переноса файла. В нём нет полного содержимого Elasticsearch, входного spool, сырых Windows-событий и всех исторических ревизий. Он не восстанавливает работающий pipeline. Device/inode и пути сохранены как сведения об исходном состоянии; копирование файла не даёт автоматического права переиспользовать привязанную живую БД. Удаление истории, перенос/восстановление live state и резервное копирование индексов требуют отдельного согласованного механизма.

Фактические результаты проверок приведены в [validation report](validation_report.md). Совпадение с эталонной группировкой подтверждает описанный контракт evidence; эксплуатационные показатели точности и нагрузки этим не измеряются.
