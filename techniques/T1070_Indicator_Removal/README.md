# T1070 — Indicator Removal on Host

## Коротко
T1070 — удаление или изменение артефактов на хосте: очистка логов, удаление файлов, зачистка history, timestomping. MITRE описывает это как попытку уменьшить признаки присутствия и смешаться с легитимной активностью. The goal is to reduce visible forensic traces after activity has already occurred.

Каталог и идентификаторы карточек сохраняют историческое имя T1070. В закреплённом [ATT&CK v20.0](../../profiles/attack/README.md) прежняя T1070.002 отозвана; Linux log-wipe артефакты теперь размечены как **T1685.006 — Clear Linux or Mac System Logs**, тактика `defense-impairment`. Это изменение mapping, а не расширение проверенного Linux-детекта на macOS.

## Attack flow
1. Атакующий выполняет действия на хосте.
2. Чистит Security/System logs, shell history, temp-файлы.
3. Удаляет tools, изменяет timestamps или обнуляет логи.
4. Отдельно может удалять shadow copies/VSS — это уже ближе к MITRE T1490 Inhibit System Recovery, но в проекте оставлено как ransomware-adjacent companion для T1070.
5. Усложняет расследование и восстановление.

## Телеметрия
- Windows Security: `1102` — Security audit log cleared.
- Windows System: `104` от `Microsoft-Windows-Eventlog` — event log cleared. Адаптер
  должен передать исходное имя провайдера в Sigma-поле `Provider_Name`; отсутствующее
  поле и другой провайдер не совпадают. Один EventID не определяет смысл события.
- Process creation: `wevtutil cl` для очистки журналов; `vssadmin delete shadows`, `wmic shadowcopy delete`, `diskshadow` — как связанный T1490-сигнал про подавление восстановления.
- Linux auditd: объединённые SYSCALL/EXECVE записи с `exe` и восстановленной `CommandLine` для `truncate`, `shred`, `rm` по `/var/log`. Shell builtins (`history -c`) и перенаправления не покрываются этим процессным Sigma; им нужны другие источники.

## Detection strategy
- Событийный кандидат: Security `1102` либо System `104` с указанным провайдером.
  Очистка журнала может быть разрешённым обслуживанием; событие само по себе не доказывает атаку.
- Процессный сигнал: команды очистки логов. VSS deletion отмечаем отдельно как связанный T1490-сигнал, полезный для ransomware-chain.
- Linux Sigma: запуск `truncate` с нулевым размером либо `rm`/`shred`, направленный на `/var/log`. Событие запуска не подтверждает успешное удаление; first-seen остаётся частью Hunt-дизайна.
- Усиление: связать с предшествующим входом, privilege escalation или ransomware-паттернами.

## Реализовано в проекте
- DetCards: `DET-WIN-T1070-LOGCLEAR-001`; `DET-LNX-T1070-LOGWIPE-003` теперь имеет mapping T1685.006 при сохранении ID/пути; дополнительно `DET-WIN-T1070-VSS-DELETE-002` покрывает связанный T1490-сценарий удаления shadow copies.
- Sigma: `sigma/win_eventlog_cleared_1102_104.yml`, `sigma/win_shadowcopy_deletion_tools.yml`, `sigma/linux_auditd_log_wipe_patterns.yml`.
- Hunt DSL: `hunts/win_eventlog_cleared.hunt.yaml`, `hunts/win_shadowcopy_deletion.hunt.yaml`, `hunts/linux_log_wipe_patterns.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
Плановое обслуживание и backup/restore иногда чистят/ротацируют артефакты. Event `1102` should remain investigation-worthy and should not be broadly suppressed. Коррелируй пользователя, host role, change window и команды вокруг события.

## Response checklist
- Определить аккаунт и Logon ID, который очистил журнал.
- Проверить события до очистки через централизованный сбор логов.
- Проверить, было ли удаление shadow copies/backups и ransomware indicators.
- Сохранить triage, изолировать хост при подтверждении.

## Автоматические проверки и границы

Команды выполняются из корня репозитория после установки dev-зависимостей.

- `python tools/check_sigma.py` — разбор pySigma и сопоставление предикатов с [общими fixtures](../../tests/fixtures/sigma/predicates.json), включая правила этой техники. Это проверка синтетических событий, а не выполнение Sigma в SIEM или оценка TPR/FPR.
- Hunt-файлы этой техники остаются `design-only`: исполнение first-seen, временных корреляций и готовый SIEM-адаптер для них не проверены. Текущий Hunt v1 исполняет только три T1110-агрегации.

Проверенные fixtures и будущие ручные эксперименты разделены в [тест-плане](tests/plan.md).

## References
- MITRE ATT&CK T1070: https://attack.mitre.org/techniques/T1070/
- MITRE ATT&CK T1685.006: https://attack.mitre.org/techniques/T1685/006/
- MITRE ATT&CK T1490: https://attack.mitre.org/techniques/T1490/
- Microsoft Event 1102: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
