# T1003 — OS Credential Dumping

## Коротко
Злоумышленник пытается получить учётные данные ОС: пароли, хэши, Kerberos-материал или файлы с credential-данными. Для Windows главный фокус — доступ к памяти LSASS и артефактам AD; для Linux — доступ к `/etc/shadow`, ключам и дампам процессов. MITRE описывает T1003 как получение credential material из кэшей, памяти или структур ОС, после чего эти данные используются для lateral movement и доступа к защищённым ресурсам.

## Attack flow
1. Получен начальный доступ или локальные права.
2. Процесс пытается читать LSASS, SAM/NTDS.dit или чувствительные Linux-файлы.
3. Credential material используется для PtH/PtT, Kerberoasting, DCSync или входа под валидной учёткой.

## Телеметрия
- Windows Sysmon: `Event ID 10 ProcessAccess` к `lsass.exe`.
- Windows Security: `4688` для процессов дампа, `4662` для DCSync при включённом аудите DS.
- Linux auditd/FIM: доступ к `/etc/shadow`, `/etc/passwd`, SSH-ключам, `/proc/<pid>/mem`.

## Detection strategy
- Базовый кандидат: Sysmon 10 сообщает доступ процесса к `lsass.exe`. Правило не определяет доверенность процесса и не доказывает чтение учётных данных или создание дампа.
- Усиление: first-seen по `SourceImage`, подпись бинаря, путь запуска, родительский процесс, сетевые действия после дампа.
- Для AD: отдельно добавить DCSync-детект по репликационным GUID в `4662`.

## Реализовано в проекте
- DetCard: `DET-WIN-T1003-LSASS-001`.
- Sigma: `sigma/win_sysmon_lsass_access.yml`.
- Hunt DSL: `hunts/lsass_access.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
Легитимные EDR/AV/backup-компоненты могут обращаться к LSASS. Поэтому allow-list нужен, но не должен превращаться в волшебную мусорную корзину: фиксируй путь, подпись, хэш и владельца процесса. Глобальных исключений по именам AV/EDR в Sigma нет: путь и доверенность требуют профиля конкретной среды. Первый доступ и `GrantedAccess` полезны для расследования, но состояние first-seen пока описано только в Hunt-дизайне.

## Response checklist
- Проверить `SourceImage`, родителя, пользователя и host role.
- Проверить, создавался ли dump-файл или запускались ли `procdump`, `rundll32 comsvcs.dll`, `taskmgr` dump.
- Проверить последующие логины, Kerberos/NTLM-активность и lateral movement.
- При подтверждении: изолировать хост, сбросить затронутые креды, проверить привилегированные сессии.

## Автоматические проверки и границы

Команды выполняются из корня репозитория после установки dev-зависимостей.

- `python tools/check_sigma.py` — разбор pySigma и сопоставление предикатов с [общими fixtures](../../tests/fixtures/sigma/predicates.json), включая правила этой техники. Это проверка синтетических событий, а не выполнение Sigma в SIEM или оценка TPR/FPR.
- Hunt-файлы этой техники остаются `design-only`: исполнение first-seen, временных корреляций и готовый SIEM-адаптер для них не проверены. Текущий Hunt v1 исполняет только три T1110-агрегации.

Проверенные fixtures и будущие ручные эксперименты разделены в [тест-плане](tests/plan.md).

## References
- MITRE ATT&CK T1003: https://attack.mitre.org/techniques/T1003/
- Microsoft Sysmon documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Elastic Sysmon Event ID 10 guidance: https://www.elastic.co/docs/reference/security/prebuilt-rules/audit_policies/windows/sysmon_eventid10_process_access
