# T1569.002 — Service Execution

## Коротко
Service Execution — запуск кода через Windows Service Control Manager: создание нового сервиса, изменение существующего или удалённый запуск через инструменты вроде PsExec. MITRE описывает технику как использование Windows service mechanisms для исполнения payload, persistence или privilege escalation.

## Attack flow
1. У атакующего есть права администратора на целевом хосте или украденные креды.
2. Создаётся сервис с произвольным `ImagePath` или запускается PsExec-подобный механизм.
3. Payload стартует от имени `LocalSystem` или сервисной учётки.
4. После выполнения сервис может быть удалён, а следы — очищены.

## Телеметрия
- Windows System: `7045` — новый сервис установлен.
- Sysmon: `17/18` — named pipe events, полезны для PsExec-паттернов.
- Network/IDPS: SMB named pipe `PSEXESVC` там, где виден SMB.

## Detection strategy
- Сигнал 1: `7045` с `ServiceName=PSEXESVC` или подозрительным `ImagePath` (`Temp`, `Users\Public`, профили пользователей).
- Сигнал 2: Sysmon pipe names `-stdin`, `-stdout`, `-stderr`, характерные для PsExec-like инструментов.
- Сигнал 3: SMB named pipe `PSEXESVC` на сетевом слое.

## Реализовано в проекте
- DetCards: `DET-WIN-T1569-SVC-7045-001`, `DET-WIN-T1569-PSEXEC-PIPES-002`.
- Sigma: `sigma/win_7045_suspicious_or_psexesvc.yml`, `sigma/win_sysmon_psexec_pipes.yml`.
- IDPS: `network/psexec_named_pipe.rules`.
- Hunt DSL: `hunts/service_install_suspicious.hunt.yaml`, `hunts/psexec_pipes.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
RMM, EDR, backup и deployment-системы тоже создают сервисы. Отличай «ожидаемый админский сервис» от «бинарь из Temp в 03:17». Хороший фильтр — путь, подпись, родительский процесс, пользователь, окно изменений и jump-host.

## Response checklist
- Проверить `ServiceName`, `ImagePath`, автора установки и время.
- Проверить процесс, созданный сервисом, и сетевые соединения.
- Проверить lateral movement вокруг source/destination.
- При подтверждении: остановить сервис, сохранить бинарь, собрать triage, проверить используемые учётки.

## References
- MITRE ATT&CK T1569.002: https://attack.mitre.org/techniques/T1569/002/
- MITRE ATT&CK T1569 detection strategy: https://attack.mitre.org/techniques/T1569/
- Splunk Windows Event Log System 7045 data source: https://research.splunk.com/sources/614dedc8-8a14-4393-ba9b-6f093cbcd293/
- Suricata SMB named pipe keyword: https://docs.suricata.io/en/suricata-7.0.15/rules/smb-keywords.html
