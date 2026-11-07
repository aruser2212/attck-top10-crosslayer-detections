# План проверки: WMIC Remote Process-Create Command Candidate

Правило: `c8e15858-8742-426d-a35a-91f8d692d6ab`. Источник: Windows `process_creation`.

1. Вручную заданные positive cases проверяют поддержанный синтаксис, ASCII casing и пробел/таб; ожидается совпадение только с этим явно описанным предикатом.
2. Near-negative cases меняют executable, операцию, границу токена или обязательное условие. Prefix/suffix похожего аргумента не подменяет отдельный токен.
3. Benign candidates сохраняют ожидаемое совпадение. Они проверяют исполнение предиката и не используются как доказательство низкого FPR.
4. Missing-field cases имеют `profile_valid: false`: Sigma predicate не совпадает, а строгий process runtime обязан завершить вход ошибкой до записи.
5. Поддержанные source fixtures проходят нормализацию и конечный Basic replay по [process guide](../../../docs/windows-process.md). Сравниваются независимо заданные ID совпавших правил и события; отсутствие частичного результата при ошибке проверяется отдельно.

Данные инертны. Командные строки в fixtures не исполняются, URL `example.invalid` не загружаются. Не запускать их как attack emulation.

Из корня репозитория: `make check`; для реального Basic: `make lab-up` и `make check-elastic`. Статус выполнения и границы источника — в [отчёте](../../../docs/validation_report.md).
