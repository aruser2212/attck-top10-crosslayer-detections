# План тестирования: Phishing (T1566)

## Автоматизировано

Команды запускаются из корня репозитория в окружении с dev-зависимостями.

- `python tools/check_sigma.py`: pySigma parsing и [source-scoped predicate fixtures](../../../tests/fixtures/sigma/predicates.json), включая правила этой техники; выполнение Sigma в SIEM не проверяется.
- `python tools/check_network.py`: pinned Suricata 8.0.4, загрузка правил и [синтетический PCAP replay](../../../tests/fixtures/network/cases.json) с ожидаемыми SID и количеством алертов; нужен Docker.
- `python tools/check_yara.py`: native libyara и [инертные source fixtures](../../../tests/fixtures/yara/cases.json), которые не исполняются.

Эти проверки подтверждают поведение перечисленных fixtures. Они не измеряют эксплуатационные TPR/FPR и не доказывают полное покрытие техники.

VBA fixtures включают statement-форму `Shell "command", vbHide`, переменную
аргумента, parenthesized/`Call`-формы, простое присваивание результата, регистр,
tabs и CRLF. Отрицательные примеры содержат настоящий `AutoOpen`, но только
комментарий или строковое упоминание Shell/CreateObject, похожее имя функции
или присваивание имени Shell. Отдельно зафиксированы неподдержанные inline
`If`, colon-separated и line-continuation формы. Вызов из другой процедуры
того же source остаётся кандидатом: контроль потока эвристика не строит.

Office Sigma отдельно проверяется на `-e`, `-enc`, полной форме
`-EncodedCommand`, смешанном регистре и всех сочетаниях ASCII space/tab вокруг
флага. Отрицательные примеры включают suffix/prefix-совпадения, отсутствие
правого разделителя, другой parent/child, обычный `-File` и явно неподдержанные
сокращения/quoted tokens/разделители. URL-ветка проверяется для каждого
поддержанного child image. Упоминание флага внутри quoted command text и
невалидный encoded-аргумент остаются ожидаемыми кандидатами: правило проверяет
буквальную командную строку, не Windows argv или семантику payload.

## Следующий ручной/лабораторный этап — не выполнен

1. Получить обезличенные process-creation события Office/Outlook → script/LOLBIN и benign add-ins. Проверить выбранные формы параметров и разделителей на реальных Windows process-creation источниках, учесть quoting и URL/флаги внутри литералов. Сверить конкретный Sigma backend; один запуск процесса или raw-text match не доказывает phishing.
2. Для YARA извлечь и декомпрессировать VBA source из инертного OLE/OOXML-образца отдельным инструментом, зафиксировав его версию. Сканировать извлечённый source; прямое сканирование raw .docm/.xlsm не является поддерживаемым входом.
3. Проверить benign VBA без auto-execution или shell-вызова и легитимную автоматизацию с обоими признаками. Последняя может совпасть и требует контекста.
4. Для сети проверить видимые HTTP request/response с HTA content type, HTA/docm/xlsm path и benign query-text/похожими расширениями. HTTPS без раскрытия содержимого не покрывается.
5. Связь email → file → process → network и first-seen Hunt ещё требуют реализации и полных данных стенда; текущий replay проверяет отдельные признаки.
