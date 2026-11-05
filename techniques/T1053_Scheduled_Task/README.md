# T1053 — Scheduled Task / Job

## Коротко
T1053 — использование планировщиков для execution и persistence. На Windows это Scheduled Tasks; на Linux — cron/systemd timers. MITRE detection strategy рекомендует искать создание/изменение задач через `schtasks.exe`, `at.exe`, COM objects и последующее исполнение необычных процессов.

## Attack flow
1. Атакующий получает право писать задачу или cron.
2. Создаёт запуск payload по расписанию, при логоне или `@reboot`.
3. Payload восстанавливает доступ, запускает loader или выполняет next stage.
4. Задача может маскироваться под системное имя.

## Телеметрия
- Windows Security: `4698` — scheduled task created.
- Windows TaskScheduler/Operational: `106` — task registered.
- Process creation: `schtasks.exe`, PowerShell ScheduledTasks module.
- Linux auditd/FIM: `/etc/crontab`, `/etc/cron.*`, `/var/spool/cron/`. Для текущего Sigma нужны write-only watches `-p w -k cron_write`, объединение SYSCALL/PATH по audit serial и поля `path`, `key`, `success` с native `yes/no`.

## Detection strategy
- Windows: new task + suspicious action path/arguments.
- Linux Sigma: успешная write-class операция по watched cron path (`key=cron_write`, `success=yes`). Это write intent, а не доказанное изменение содержимого; подозрительные команды требуют дополнительного анализа.
- First-seen по `task.name`, `task.action.path`, `file.path`, `{user × host}`.

## Реализовано в проекте
- DetCards: `DET-WIN-T1053-SCHTASK-4698-001`, `DET-LNX-T1053-CRON-MOD-002`.
- Sigma: `sigma/win_4698_scheduled_task_created.yml`, `sigma/win_tasks_op_106_created.yml`, `sigma/linux_auditd_cron_file_mod.yml`.
- Hunt DSL: `hunts/win_schtask_creation_unusual.hunt.yaml`, `hunts/linux_cron_mod_first_seen.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
RMM, patch management, backup и конфигурационные менеджеры создают задачи постоянно. Нужен baseline. Особенно подозрительны задачи, указывающие на user-writable paths, temp, encoded PowerShell, download cradle или новые cron-записи с сетевой загрузкой.

## Response checklist
- Проверить автора задачи, action path, arguments, trigger.
- Проверить файл payload, подпись и hash.
- Проверить, запускалась ли задача и какие процессы породила.
- Удалить malicious task/cron, проверить persistence-соседей.

## Автоматические проверки и границы

Команды выполняются из корня репозитория после установки dev-зависимостей.

- `python tools/check_sigma.py` — разбор pySigma и сопоставление предикатов с [общими fixtures](../../tests/fixtures/sigma/predicates.json), включая правила этой техники. Это проверка синтетических событий, а не выполнение Sigma в SIEM или оценка TPR/FPR.
- Hunt-файлы этой техники остаются `design-only`: исполнение first-seen, временных корреляций и готовый SIEM-адаптер для них не проверены. Текущий Hunt v1 исполняет только три T1110-агрегации.

Проверенные fixtures и будущие ручные эксперименты разделены в [тест-плане](tests/plan.md).

## References
- MITRE ATT&CK T1053: https://attack.mitre.org/techniques/T1053/
- Microsoft Event 4698: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698
- Elastic scheduled task detection: https://www.elastic.co/guide/en/security/8.19/a-scheduled-task-was-created.html
