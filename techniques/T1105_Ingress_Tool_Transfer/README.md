# T1105 — Certutil HTTP URLCache Command Candidate

[DetCard](DET-WIN-T1105-CERTUTIL-URLCACHE-001.yaml) · [Sigma](sigma/win_certutil_urlcache_http.yml) · [План проверки](tests/plan.md)

## Наблюдаемое поведение

Image заканчивается на `\certutil.exe`. Требуется отдельный `-urlcache`, ограниченный ASCII-пробелом/табом и справа также концом строки, плюс URL-shaped аргумент `http://` или `https://` после пробела/таба. Перед URL допускается одна открывающая двойная кавычка. `-split` и `-f` необязательны.

Источник — Windows process creation; для отдельного конечного replay используется строгий Sysmon Event ID 1 версии 5 и профиль `process-v1`. Поля предиката — `Image` и `CommandLine`. [Общее руководство](../../docs/windows-process.md) определяет нормализацию, event identity, ASCII-контракт и Basic replay.

## Интерпретация и ограничения

Это наблюдение командного текста, а не HTTP-запроса или успешного скачивания. Валидность URL, закрытие кавычек, наличие и запись выходного файла не проверяются. Slash-вариант `/urlcache`, иные схемы и другие downloader-инструменты вне явного покрытия. Цитируемый текст тоже может совпасть.

Ожидаемое легитимное совпадение: Администратор скачивает разрешённый пакет через certutil; одинаковый текст не устанавливает происхождение или назначение файла.

Алерт означает кандидата с указанным командным текстом. Само имя образа не удостоверяет файл, подпись или подлинность инструмента; Sysmon 1 не показывает успешность всей операции. Lifecycle остаётся `test`, confidence — `low`; эксплуатационная precision/TPR/FPR не измерена. Правило не добавляет общий Hunt DSL, сетевую корреляцию или исключения по одному имени процесса.

## Проверки

Ручные ожидания для Sigma UUID `dc55d70f-5bbf-4b87-b72d-61e8812d8eae` находятся в [общем manifest](../../tests/fixtures/sigma/predicates.json). Отдельно отмечены совпадающие легитимные сценарии и события с отсутствующими обязательными полями: runtime должен отклонять такие события, а не выдавать benign-результат. Выполненные проверки фиксируются в [validation report](../../docs/validation_report.md).

## Ссылки

- [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- [Sysmon Event ID 1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
