# T1059.001 — PowerShell Explicit Encoded-Command Option Candidate

[DetCard](DET-WIN-T1059-ENCODED-PS-001.yaml) · [Sigma](sigma/win_powershell_encoded_option.yml) · [План проверки](tests/plan.md)

## Наблюдаемое поведение

Image заканчивается на `\powershell.exe` или `\pwsh.exe`. Поддержаны только `-e`, `-enc`, `-EncodedCommand`: перед флагом требуется ASCII-пробел или таб, после — пробел, таб либо конец строки. Регистр ASCII несущественен.

Источник — Windows process creation; для отдельного конечного replay используется строгий Sysmon Event ID 1 версии 5 и профиль `process-v1`. Поля предиката — `Image` и `CommandLine`. [Общее руководство](../../docs/windows-process.md) определяет нормализацию, event identity, ASCII-контракт и Basic replay.

## Интерпретация и ограничения

Другие сокращения, флаг в кавычках и другие разделители находятся вне этого правила. Наличие payload, его Base64-валидность и содержимое не проверяются; поэтому флаг в конце строки тоже даёт кандидата. Цитируемое упоминание ` -enc ` может совпасть.

Ожидаемое легитимное совпадение: Штатная encoded PowerShell-автоматизация и печать текста с упоминанием поддержанного флага.

Алерт означает кандидата с указанным командным текстом. Само имя образа не удостоверяет файл, подпись или подлинность инструмента; Sysmon 1 не показывает успешность всей операции. Lifecycle остаётся `test`, confidence — `low`; эксплуатационная precision/TPR/FPR не измерена. Правило не добавляет общий Hunt DSL, сетевую корреляцию или исключения по одному имени процесса.

## Проверки

Ручные ожидания для Sigma UUID `e7f06efa-e684-42fa-b3ed-7bbb34e6cd49` находятся в [общем manifest](../../tests/fixtures/sigma/predicates.json). Отдельно отмечены совпадающие легитимные сценарии и события с отсутствующими обязательными полями: runtime должен отклонять такие события, а не выдавать benign-результат. Выполненные проверки фиксируются в [validation report](../../docs/validation_report.md).

## Ссылки

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Sysmon Event ID 1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
