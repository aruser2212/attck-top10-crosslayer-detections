# T1218.010 — Regsvr32 URL Scriptlet Command Candidate

[DetCard](DET-WIN-T1218-REGSVR32-URL-001.yaml) · [Sigma](sigma/win_regsvr32_url_scriptlet.yml) · [План проверки](tests/plan.md)

## Наблюдаемое поведение

Image заканчивается на `\regsvr32.exe`. В CommandLine есть `/i:http://` или `/i:https://` после ASCII-пробела/таба и отдельный незаключённый в кавычки `scrobj.dll` либо Windows-путь с таким basename. После DLL требуется ASCII-пробел, таб или конец строки. Регистр ASCII несущественен.

Источник — Windows process creation; для отдельного конечного replay используется строгий Sysmon Event ID 1 версии 5 и профиль `process-v1`. Поля предиката — `Image` и `CommandLine`. [Общее руководство](../../docs/windows-process.md) определяет нормализацию, event identity, ASCII-контракт и Basic replay.

## Интерпретация и ограничения

URL не разбирается и не проверяется на достижимость. Кавычки вокруг DLL-токена/пути и другие способы proxy execution вне покрытия. Имя образа не подтверждает подпись Microsoft; наличие командной строки не доказывает загрузку или выполнение scriptlet. В ATT&CK v20.0 первичная тактика этого mapping — `stealth`.

Ожидаемое легитимное совпадение: Авторизованная лабораторная проверка scriptlet и цитируемое упоминание поддержанных аргументов.

Алерт означает кандидата с указанным командным текстом. Само имя образа не удостоверяет файл, подпись или подлинность инструмента; Sysmon 1 не показывает успешность всей операции. Lifecycle остаётся `test`, confidence — `low`; эксплуатационная precision/TPR/FPR не измерена. Правило не добавляет общий Hunt DSL, сетевую корреляцию или исключения по одному имени процесса.

## Проверки

Ручные ожидания для Sigma UUID `f3c2dcdc-d61b-422b-b2cc-de495e7c80ee` находятся в [общем manifest](../../tests/fixtures/sigma/predicates.json). Отдельно отмечены совпадающие легитимные сценарии и события с отсутствующими обязательными полями: runtime должен отклонять такие события, а не выдавать benign-результат. Выполненные проверки фиксируются в [validation report](../../docs/validation_report.md).

## Ссылки

- [MITRE ATT&CK T1218.010](https://attack.mitre.org/techniques/T1218/010/)
- [Sysmon Event ID 1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
