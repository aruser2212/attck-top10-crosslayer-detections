# T1070 — Indicator Removal on Host

## Коротко
T1070 — удаление или изменение артефактов на хосте: очистка логов, удаление файлов, зачистка history, timestomping. MITRE описывает это как попытку уменьшить признаки присутствия и смешаться с легитимной активностью. Это техника «убрать следы лап», но часто лапы уже в краске.

## Attack flow
1. Атакующий выполняет действия на хосте.
2. Чистит Security/System logs, shell history, temp-файлы.
3. Удаляет tools, изменяет timestamps или обнуляет логи.
4. Отдельно может удалять shadow copies/VSS — это уже ближе к MITRE T1490 Inhibit System Recovery, но в проекте оставлено как ransomware-adjacent companion для T1070.
4. Усложняет расследование и восстановление.

## Телеметрия
- Windows Security: `1102` — Security audit log cleared.
- Windows System: `104` — event log cleared.
- Process creation: `wevtutil cl` для очистки журналов; `vssadmin delete shadows`, `wmic shadowcopy delete`, `diskshadow` — как связанный T1490-сигнал про подавление восстановления.
- Linux auditd/syslog: `truncate`, `shred`, `rm -rf /var/log`, `history -c`, `.bash_history`.

## Detection strategy
- Событийный сигнал: `1102`/`104` почти всегда должен быть расследован.
- Процессный сигнал: команды очистки логов. VSS deletion отмечаем отдельно как связанный T1490-сигнал, полезный для ransomware-chain.
- Linux: wipe patterns + first-seen по пользователю/хосту.
- Усиление: связать с предшествующим входом, privilege escalation или ransomware-паттернами.

## Реализовано в проекте
- DetCards: `DET-WIN-T1070-LOGCLEAR-001`; дополнительно `DET-WIN-T1070-VSS-DELETE-002` покрывает связанный T1490-сценарий удаления shadow copies.
- Sigma: `sigma/win_eventlog_cleared_1102_104.yml`, `sigma/win_shadowcopy_deletion_tools.yml`, `sigma/linux_auditd_log_wipe_patterns.yml`.
- Hunt DSL: `hunts/win_eventlog_cleared.hunt.yaml`, `hunts/win_shadowcopy_deletion.hunt.yaml`, `hunts/linux_log_wipe_patterns.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
Плановое обслуживание и backup/restore иногда чистят/ротацируют артефакты. Но `1102` — не тот шум, который стоит просто замести под ковёр. Коррелируй пользователя, host role, change window и команды вокруг события.

## Response checklist
- Определить аккаунт и Logon ID, который очистил журнал.
- Проверить события до очистки через централизованный сбор логов.
- Проверить, было ли удаление shadow copies/backups и ransomware indicators.
- Сохранить triage, изолировать хост при подтверждении.

## References
- MITRE ATT&CK T1070: https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK T1490: https://attack.mitre.org/techniques/T1490/
- Microsoft Event 1102: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
