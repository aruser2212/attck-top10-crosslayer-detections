# Windows ProcessCreate: десять исполняемых сценариев

Отдельный профиль `attck-process-v1` связывает экспорт Sysmon Event ID **1,
Version 5** с десятью правилами каталога
[`process-rules.json`](../profiles/elastic/process-rules.json).
Один и тот же набор можно проверить офлайн и выполнить нативными keyword-запросами
на бесплатном Elasticsearch Basic. Наблюдение — запуск процесса с определённым
текстом команды. Оно не удостоверяет executable, успешность запрошенной операции
или злонамеренность пользователя.

## Сценарии и смысл результата

| ATT&CK | Наблюдаемый текст запуска | Основное ограничение |
|---|---|---|
| T1059.001 | PowerShell с поддержанной формой encoded-command | Содержимое не декодируется и не исполняется; разрешённая автоматизация совпадает |
| T1218.010 | regsvr32 с URL scriptlet и scrobj.dll | Успешное получение и исполнение scriptlet не наблюдаются |
| T1105 | certutil с URL cache и HTTP(S) URL | Намерение загрузки; факт передачи файла не подтверждён |
| T1047 | WMIC с удалённым узлом и process call create | Поддержан WMIC CLI; другие WMI/CIM клиенты вне правила |
| T1136.001 | net/net1 user с локальным /add | Создание аккаунта требует подтверждения отдельным audit event |
| T1098.007 | net/net1 localgroup Administrators с /add | Имя группы на английском; SID группы и изменение членства не удостоверяются |
| T1018 | net/net1 view с /domain: | Разрешённая инвентаризация компьютеров тоже совпадает |
| T1087.002 | net/net1 user /domain | Узкий сценарий перечисления; произвольные изменения аккаунтов не считаются discovery |
| T1547.001 | reg add конкретного Run key с именем и данными значения | Команда не доказывает успешную запись или следующий запуск; RunOnce вне правила |
| T1016 | ipconfig /all | Информационный сигнал; обычная диагностика сети ожидаемо совпадает |

У каждого правила есть собственный dossier и тест-план. Списки поддержанных
границ параметров, кавычек и исключённых вариантов находятся там. Сопоставляется
сырая командная строка; Windows argv, shell expansion, вложенные скрипты и намерение
пользователя не восстанавливаются. Некоторые цитируемые упоминания параметров
остаются кандидатами. Исходные строки fixtures никогда не запускаются как команды.

## Профиль источника

Вход — плоские JSON-объекты с буквальными точками в именах полей.
Обязательны `@timestamp`, `event.id`, `event.dataset=windows.sysmon.process`,
`event.code="1"`, `host.name`, `process.guid`, `process.parent.guid`,
`process.executable`, `process.parent.executable`, `process.command_line`.
GUID должны быть ненулевыми и каноническими; PID не заменяет GUID.
Доверие к host identity и полноте доставки обеспечивается источником.

**В этой версии три поля предикатов — Image, ParentImage и CommandLine —
поддерживают только ASCII.** Unicode в них вызывает ошибку всего batch, а не
отрицательный результат. Это явная граница одинаковой семантики регистра
офлайн и в native wildcard-запросах. Unicode в допустимом текстовом контексте,
например имени пользователя, не используется для предикатов.

Пути должны быть абсолютными DOS-путями с буквой диска, без UNC/device/ADS,
пустых или dot-компонентов и зарезервированных алиасов. Командная строка сохраняет
регистр, пробелы и табы; прочие управляющие символы, пустые значения и placeholder
`-` отклоняются. Ограничения keyword — 32766 байт, `event.id` — 512 байт.
Неизвестные поля, вложенные алиасы и некорректные типы отвергаются.

XML-нормализатор проверяет `Microsoft-Windows-Sysmon/Operational`, Event ID 1
и native Version 5, включая точные имена `ProcessGuid`/`ParentProcessGuid`.
Время берётся из `System/TimeCreated`: микросекунды без округления и оставшийся
100ns-разряд входят в стабильную identity вместе с host/channel/record/code.
`EventData/UtcTime` не подменяет это время. Экспорт проверяется структурно;
это не аттестация настоящего Windows collector.

## Быстрый replay

После `make setup` из корня репозитория:

```bash
mkdir -p artifacts
.venv/bin/python tools/normalize_windows_process.py \
  tests/fixtures/process/native/process-create-v5.xml \
  tests/fixtures/process/native/benign-process-v5.xml \
  > artifacts/process-demo.jsonl
.venv/bin/python tools/process_detection.py --events artifacts/process-demo.jsonl
```

Ожидается один кандидат T1218.010 для синтетического regsvr32; обычный notepad
не совпадает. Упрощённый запуск вместе с другими сценариями — `make demo`.

Для нативного Basic replay:

```bash
make lab-up
.venv/bin/python tools/elastic_process.py --index attck-process-demo create-index
.venv/bin/python tools/elastic_process.py --index attck-process-demo ingest \
  artifacts/process-demo.jsonl
.venv/bin/python tools/elastic_process.py --index attck-process-demo evaluate --page-size 1
```

Ожидается тот же алерт со ссылками на исходное событие, host и оба GUID.
`create-index` не заменяет существующий индекс. Повторяйте ingest/evaluate либо
выбирайте новое имя индекса; точный повтор события не добавляет новый документ.
Подключение и credentials описаны в [Elastic guide](elastic.md). Общий клиент
требует конечный URL и отклоняет HTTP redirects.

## Нативное исполнение и ограничения

Поддержаны boolean AND/OR/NOT и строковые leaves Sigma для `Image`, `ParentImage`,
`CommandLine`. Весь AST и logsource проверяются до запросов. Regex, числа,
агрегации, correlation rules и прочие поля не подменяются приблизительным поиском.
Каталог явно перечисляет разрешённые файлы; это ограниченный backend, а не
полная реализация Sigma для любого источника.

Один PIT читает **все события dataset в выбранном временном диапазоне**.
Каждому правилу соответствует именованный запрос; `matched_queries` сообщает
результат нативного вычисления. Не совпавшие с правилами события тоже читаются
и валидируются. Для каждого события native rule IDs сравниваются с офлайн-
результатом; расхождение завершает весь replay ошибкой.

Проверяются `_id`, канонический `_source`, точность sort timestamps, продвижение
`search_after`, shard completeness, закрытие PIT и UUID индекса. События другого
dataset и записи вне выбранного диапазона не входят в native проверку.
Офлайн-вход валидируется целиком до фильтрации диапазоном.

Параметры `--start`/`--end` задаются вместе и выбирают **[start,end)** с
микросекундными границами в диапазоне `date_nanos`. По умолчанию `--max-events`
равен 100000, `--max-alerts` — 10000, `--page-size` — 500. Один event может
удовлетворять нескольким правилам; на каждую пару rule/event возвращается
свой стабильный alert ID. Повторы event ID дедуплицируются, конфликтующий payload
вызывает ошибку. Лимиты и неполный ответ не дают успешного частичного результата.

Пилот конечный: нет постоянного alert sink, расписания, распределённого worker
или готового развёртывания Sysmon. Непрерывные T1110 pipelines описаны отдельно
в [continuous guide](continuous.md). Эти десять правил не добавляют новые
неисполняемые Hunt и не изменяют старые профили.

Ручные fixtures, XML-примеры и native replay проверяют заданные условия.
Эксплуатационные precision, TPR/FPR и latency требуют отдельной репрезентативной
разметки; benign-кандидаты сохранены явно. Выполненные результаты находятся
в [validation report](validation_report.md).
