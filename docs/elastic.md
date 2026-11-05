# Бесплатный Elasticsearch Basic

Отдельный [host/web replay](correlation.md) связывает запись файла и запрос по host/resource namespace/path через один PIT двух источников. Нужны подготовленные события `host.file` и `web.access` в профиле `web-correlation-v1`; развёртывание сборщиков и нативная нормализация этих журналов остаются внешним контрактом.

Для успешных RC4 TGS к нескольким сервисным аккаунтам добавлен отдельный [4769 replay](kerberos.md): строгий профиль `kerberos-v1`, XML-нормализация, точный rolling distinct по ServiceSid и ручные ожидания. Этот путь возвращает кандидатов на конечном наборе; непрерывные команды ниже относятся только к T1110.

Проверяемая версия — Elasticsearch 8.19.4, официальный образ закреплён digest в compose.yaml. Используются mappings, point-in-time search, composite aggregation, search_after и внешние версии документов. Платная лицензия и trial не требуются. Два Windows T1110 Hunt доступны в версиях v1 с фиксированными окнами и v2 со скользящими окнами. Для каждой версии есть ручной адаптер и отдельный [durable pipeline](continuous.md) с файловым ingestion, расписанием, SQLite checkpoints и outbox. Kibana и внешний Windows collector не развёртываются этим проектом.

## Запуск

Нужны Python 3.12, Make и Docker с Compose v2. Из корня репозитория:

```bash
make setup
make check
make lab-up
make check-elastic
```

Лабораторный сервер привязан к 127.0.0.1:19200; security отключена только для локального стенда с синтетическими данными. Compose-проект называется `attck-detection-lab`; данные лежат в persistent named volume `elastic-data`. `make lab-down` останавливает и удаляет контейнер, сохраняя том. `make lab-up` использует эти же данные. Удаление тома не входит в обычную остановку.

Для существующего защищённого сервера задайте `ELASTIC_URL` и `ELASTIC_API_KEY` либо `ELASTIC_USERNAME`/`ELASTIC_PASSWORD`; секреты не включаются в файлы проекта. HTTPS проверяет сертификат.

## От событий до алерта

```bash
.venv/bin/python tools/elastic_adapter.py --index attck-demo create-index
.venv/bin/python tools/elastic_adapter.py --index attck-demo ingest \
  tests/fixtures/hunts/brute_positive.jsonl
.venv/bin/python tools/elastic_adapter.py --index attck-demo evaluate \
  techniques/T1110_Brute_Force/hunts/win_4625_brute_agg.hunt.yaml
```

Создание существующего индекса отклоняется. Повтор ingest одинаковых событий не увеличивает счётчик; конфликт event.id — ошибка. Чужие mappings не перезаписываются. При конкурентной записи bulk может завершиться частично: ошибка сообщается, повтор с теми же событиями идемпотентен; транзакционность всего batch не заявляется.

Перед успешным завершением непустого ingest выполняется явный refresh с проверкой результата всех shards, в том числе при повторе уже существующих ID. Это делает события видимыми для следующего PIT/search после восстановления: realtime `_mget` сам по себе такой гарантии не даёт. Ошибка refresh оставляет spool-файл неподтверждённым. На защищённом сервере учётной записи ingestion требуется привилегия `maintenance` для source index либо включающая её `manage`, помимо прав чтения, записи и проверки метаданных. Refresh каждого batch выбран для корректности этого пилота; стоимость при высокой нагрузке ещё не измерена.

Этот ручной `evaluate` рассматривает весь индекс, если не переданы event-time bounds, и возвращает JSON результата. Он сам не сохраняет расписание и состояние алертов. Для постоянной обработки используйте [единый pipeline](continuous.md), который задаёт закрытые диапазоны и доставляет документы в отдельный alerts-v1 индекс.

Схема — [auth-v1.mapping.json](../profiles/elastic/auth-v1.mapping.json). Поддержаны нормализованный Windows logon dataset и проверенный поднабор Hunt v1. Для числа пользователей перечисляются все composite buckets с пагинацией; приблизительная cardinality не применяется. PIT фиксирует снимок; timeout/ошибка shard приводят к ошибке, а не частичному результату. Runner дополнительно связывает checkpoints с конкретным source index UUID и перепроверяет его перед commit.

## Rolling v2: replay и непрерывная обработка

`tools/elastic_rolling.py` работает с [auth-v2.mapping.json](../profiles/elastic/auth-v2.mapping.json) и двумя Windows rolling v2 Hunt. Он получает точные исходные события через PIT/search_after, затем исполняет алгоритм rolling в Python. Это не нативная rolling-агрегация Elasticsearch и не приблизительная cardinality.

Auth-v1 индексирует `@timestamp` как `date` с миллисекундной точностью. Для различения микросекундных границ auth-v2 использует `date_nanos`; входной контракт по-прежнему допускает не более шести дробных цифр. Нужен отдельный индекс; чужие mappings не перезаписываются. V1 runner и его SQLite state не используются для v2.

Диапазон целевых anchor timestamps `[A,B)` расширяется для чтения предшествующего контекста до `(A−W,B)`. Каждая подходящая группа/timestamp выдаёт отдельный результат. Ошибки PIT/search, неподтверждённые shards, смена UUID, некорректные события или превышение лимитов прерывают проход. Полный пример и ограничения — в [rolling-windows.md](rolling-windows.md).

`tools/run_rolling_pipeline.py` добавляет к этому адаптеру `--once`/`--watch`, bounded spool ingestion и `RollingDetectionRunner`. Нужны отдельный auth-v2 source index, [alerts-v2](../profiles/elastic/alerts-v2.mapping.json) sink и новая `--state-dir`. Файлы `rolling-spool.sqlite` и `rolling-detections.sqlite` не мигрируют состояние v1; detection schema 2 хранит checkpoints и anchors целыми микросекундами. Все временные поля alerts-v2 используют `date_nanos`. После появления любого state-файла даже `--initialize` не пересоздаёт исчезнувший индекс: восстановление должно сохранить его идентичность.

Начало `--start` не выравнивается по окнам, но для стандартных правил должно быть не раньше `1970-01-01T00:10:00Z`, чтобы нижняя граница окна помещалась в диапазон mapping. История перед `--start` остаётся необходимым контекстом. Новые anchors обрабатываются до `now − allowed_lateness`, с ограничением продвижения `--max-forward-seconds` (по умолчанию 3600). `--lookback-seconds` повторно проверяет ранее обработанные anchors. На каждом шаге нужен полный контекст окна; неполный набор не превращается в успешный checkpoint.

Стабильный alert ID включает точный anchor и группу. Повтор того же anchor обновляет revision при изменении результата; другой подходящий anchor создаёт новый документ. Все правила, checkpoints и outbox фиксируются общей SQLite-транзакцией. Retraction применяется к anchors текущего диапазона. `external_gte` обеспечивает повторяемую доставку без перезаписи новой revision старой. Перед записью и после подтверждения проверяется UUID sink; атомарного условия записи по UUID Elasticsearch нет.

Лимит `--max-query-events` считается на каждый запрос правила вместе с контекстом; `--max-alerts` ограничивает суммарную работу с кандидатами и отзывами за проход. Превышение лимита требует полного повтора с достаточными ресурсами. Оставшаяся история или backlog файлов дают `catching_up` и код 2 в режиме `--once`. Пример запуска, restart и все параметры — в [continuous.md](continuous.md#непрерывный-rolling-v2).

## Постоянная обработка v1

`tools/run_auth_pipeline.py` сначала обрабатывает опубликованные `.ready.jsonl`/`.ready.xml`, затем запускает два детекта. Он поддерживает `--once` и `--watch`; source/sink индексы создаются только при явном `--initialize`. Нужны существующая spool-директория, `--state-dir` и начальная UTC-граница `--start`, кратная десяти минутам. Инструкции атомарной публикации, готовый finite demo с `--at`, restart и supervisor приведены в [continuous.md](continuous.md).

SQLite state хранит подтверждённые файлы, per-rule checkpoints и transactional outbox. Обновление метрики сохраняет alert ID. Доставка повторяется идемпотентно; `external_gte` предотвращает запись старой revision поверх новой. При смене source/sink UUID либо семантики правил старое состояние отклоняется. Копии одного SQLite state не являются механизмом HA.

Ограниченный проход с оставшимся известным backlog возвращает `catching_up` и код 2 в режиме `--once`; detection пока не продвигается. Ошибки не преобразуются в успешные checkpoints. В режиме `--watch` проход повторяется после указанного интервала.

## Нормализация Windows

```bash
.venv/bin/python tools/normalize_windows_auth.py \
  tests/fixtures/windows/4625.xml > /tmp/auth-event.jsonl
```

Вход — один экспортированный Event XML на файл, не бинарный EVTX. Поддержаны Security 4624/4625 от Microsoft-Windows-Security-Auditing. TargetUserName и TargetDomainName формируют target.user; SubjectUserName не подменяет целевой аккаунт. ASCII-регистр домена/аккаунта приводится к нижнему, домен сохраняется. Unicode/UPN-алиасы требуют нормализации по каталогу: универсальная эквивалентность principal не заявляется. Для failed logons валидный SID может отсутствовать.

IPv4-mapped IPv6 преобразуется к IPv4; scoped IPv6 отклоняется. Отсутствующий IP/аккаунт остаётся отсутствующим и не создаёт выдуманную группу. Семь дробных цифр Windows времени округляются вниз до микросекунд; оставшийся 100ns-разряд сохраняется в ID. Стабильный ID включает host/channel/record/time/code. ASCII-регистр Computer нормализуется, а RecordID проверяется как ASCII uint64 и приводится к канонической десятичной форме: `001001` и `1001` обозначают одно событие. Повторные System-поля и неоднозначные метаданные отклоняются. Namespace нужно сохранять при доставке из нескольких collectors.

## Доказательства и ограничения

`make check-elastic` создаёт свои временные индексы, проверяет активную Basic-лицензию, исполняет Windows fixtures в Elasticsearch и удаляет только эти индексы. Проверяются маленькие страницы, точные пороги, повтор ingest, конфликты ID, пропуски, XML → normalization → alert, bounded ranges, late-event replay и crash/restart outbox. Native-проверка внешней версии подтверждает, что устаревшая запись получает HTTP 409, а повтор текущей revision не создаёт второй документ.

V1 повторяет конечные оценки закрытых фиксированных окон. V2 оценивает anchors до cutoff и ограниченный lookback; позднее событие раньше начала диапазона anchors ещё может влиять на них как контекст. Anchors за пределами lookback автоматически не пересматриваются. Без ingest timestamp полнота обработки всех опозданий и их число неизвестны. Семантика каждой версии описана в [Hunt DSL](hunt-dsl.md) и [rolling guide](rolling-windows.md).

Linux Elastic, first_seen, межсобытийные последовательности и внешний сбор телеметрии пока не поддержаны. Эксплуатационные TPR/FPR и latency не измерены: synthetic fixtures подтверждают только перечисленные сценарии.
