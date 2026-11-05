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
- Network/IDPS: видимый SMB2 CREATE с именем `PSEXESVC`. Шифрованный SMB скрывает этот признак; сетевое имя само по себе не подтверждает pipe или выполнение сервиса.

## Detection strategy
- Сигнал 1: `7045` с `ServiceName=PSEXESVC` или подозрительным `ImagePath` (`Temp`, `Users\Public`, профили пользователей).
- Сигнал 2: Sysmon pipe names `-stdin`, `-stdout`, `-stderr`, характерные для PsExec-like инструментов.
- Сигнал 3: ограниченная SMB2 CREATE/PSEXESVC-name эвристика. В Suricata `smb.named_pipe` относится к TREE_CONNECT, поэтому правило проверяет имя в CREATE. Легитимный PsExec и одноимённый файл могут совпасть; подтверждение требует host/service событий.

## Реализовано в проекте
- DetCards: `DET-WIN-T1569-SVC-7045-001`, `DET-WIN-T1569-PSEXEC-PIPES-002`.
- Sigma: `sigma/win_7045_suspicious_or_psexesvc.yml`, `sigma/win_sysmon_psexec_pipes.yml`.
- IDPS: `network/psexec_named_pipe.rules`.
- Hunt DSL: `hunts/service_install_suspicious.hunt.yaml`, `hunts/psexec_pipes.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
RMM, EDR, backup и deployment-системы тоже создают сервисы. Отличай «ожидаемый админский сервис» from unexpected service binaries staged from temporary or user-writable paths. Хороший фильтр — путь, подпись, родительский процесс, пользователь, окно изменений и jump-host.

## Response checklist
- Проверить `ServiceName`, `ImagePath`, автора установки и время.
- Проверить процесс, созданный сервисом, и сетевые соединения.
- Проверить lateral movement вокруг source/destination.
- При подтверждении: остановить сервис, сохранить бинарь, собрать triage, проверить используемые учётки.

## Автоматические проверки и границы

Команды выполняются из корня репозитория после установки dev-зависимостей.

- `python tools/check_sigma.py` — разбор pySigma и сопоставление предикатов с [общими fixtures](../../tests/fixtures/sigma/predicates.json), включая правила этой техники. Это проверка синтетических событий, а не выполнение Sigma в SIEM или оценка TPR/FPR.
- `python tools/check_network.py` — загрузка всех правил и replay [синтетического PCAP-корпуса](../../tests/fixtures/network/cases.json) в закреплённой Suricata 8.0.4; нужен Docker. Совместимость со Snort не проверена.
- Hunt-файлы этой техники остаются `design-only`: исполнение first-seen, временных корреляций и готовый SIEM-адаптер для них не проверены. Текущий Hunt v1 исполняет только три T1110-агрегации.

Проверенные fixtures и будущие ручные эксперименты разделены в [тест-плане](tests/plan.md).

## References
- MITRE ATT&CK T1569.002: https://attack.mitre.org/techniques/T1569/002/
- MITRE ATT&CK T1569 detection strategy: https://attack.mitre.org/techniques/T1569/
- Splunk Windows Event Log System 7045 data source: https://research.splunk.com/sources/614dedc8-8a14-4393-ba9b-6f093cbcd293/
- Suricata SMB named pipe keyword: https://docs.suricata.io/en/suricata-8.0.4/rules/smb-keywords.html
