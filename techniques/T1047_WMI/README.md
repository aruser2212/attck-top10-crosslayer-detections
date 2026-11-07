# T1047 — WMIC Remote Process-Create Command Candidate

[DetCard](DET-WIN-T1047-WMIC-REMOTE-CREATE-001.yaml) · [Sigma](sigma/win_wmic_remote_process_create.yml) · [План проверки](tests/plan.md)

## Наблюдаемое поведение

Image заканчивается на `\wmic.exe`. CommandLine содержит `/node:` после ASCII-пробела/таба и последовательность `process call create`. Между этими тремя словами поддержан ровно один пробел или таб; после `create` — пробел/таб либо конец строки. Регистр ASCII несущественен.

Источник — Windows process creation; для отдельного конечного replay используется строгий Sysmon Event ID 1 версии 5 и профиль `process-v1`. Поля предиката — `Image` и `CommandLine`. [Общее руководство](../../docs/windows-process.md) определяет нормализацию, event identity, ASCII-контракт и Basic replay.

## Интерпретация и ограничения

Значение node и дочерняя команда не разбираются. Пустой или неправильный аргумент не подтверждает исполнение; конец строки после `create` всё равно даёт кандидата. Несколько пробелов между словами, quoted keyword tokens, PowerShell CIM и другие WMI-клиенты вне покрытия. `/node:` внутри цитируемого payload также может совпасть.

Ожидаемое легитимное совпадение: Авторизованный удалённый запуск служебной команды. Успех операции и действия на целевом хосте требуют отдельной телеметрии.

Алерт означает кандидата с указанным командным текстом. Само имя образа не удостоверяет файл, подпись или подлинность инструмента; Sysmon 1 не показывает успешность всей операции. Lifecycle остаётся `test`, confidence — `low`; эксплуатационная precision/TPR/FPR не измерена. Правило не добавляет общий Hunt DSL, сетевую корреляцию или исключения по одному имени процесса.

## Проверки

Ручные ожидания для Sigma UUID `c8e15858-8742-426d-a35a-91f8d692d6ab` находятся в [общем manifest](../../tests/fixtures/sigma/predicates.json). Отдельно отмечены совпадающие легитимные сценарии и события с отсутствующими обязательными полями: runtime должен отклонять такие события, а не выдавать benign-результат. Выполненные проверки фиксируются в [validation report](../../docs/validation_report.md).

## Ссылки

- [MITRE ATT&CK T1047](https://attack.mitre.org/techniques/T1047/)
- [Sysmon Event ID 1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
