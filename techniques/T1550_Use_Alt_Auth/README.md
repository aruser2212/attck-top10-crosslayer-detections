# T1550 — Use Alternate Authentication Material

## Коротко
T1550 — использование альтернативного материала аутентификации: password hashes, Kerberos tickets, access tokens. MITRE описывает это как использование материала, который легитимно появляется после аутентификации, но затем может быть украден и использован для lateral movement без знания пароля.

## Attack flow
1. Атакующий получает hash/ticket/token через T1003, Kerberoasting или session theft.
2. Использует PtH/PtT/token replay для доступа к другим системам.
3. Обходит часть контроля, потому что аутентификация выглядит технически валидной.
4. Двигается по сети и повышает доступ.

## Телеметрия
- Windows Security: `4624` LogonType `9` и `LogonProcessName=seclogo` для PtH-like сценариев.
- Windows Security: `4672` для специальных привилегий после входа.
- Kerberos: `4768`/`4769` для AS/TGS-паттернов.
- EDR/Sysmon: запуск `mimikatz`, `sekurlsa::pth`, Rubeus/Impacket-like активность.

## Detection strategy
- PtH: `4624` LT=9 + `seclogo`, особенно first-seen по `{user × source}`.
- Усиление: рядом `4672`, новый destination host, admin share/SCM activity.
- PtT: всплеск `4769` без ожидаемого `4768` в окне — эвристика, не абсолютная истина.

## Реализовано в проекте
- DetCards: `DET-WIN-T1550-PTH-NEWCRED-001`, `DET-WIN-T1550-PTT-KRB-ANOM-002`.
- Sigma: `sigma/win_4624_newcredentials_seclogo.yml`.
- Hunt DSL: `hunts/win_pth_newcredentials_first_seen.hunt.yaml`, `hunts/win_pth_newcred_followed_by_4672.hunt.yaml`, `hunts/win_ptt_tgs_without_as_window.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
`runas /netonly` может легитимно создавать LT=9. App-серверы могут генерировать необычные Kerberos-паттерны. Нужны role-based allow-list, first-seen и корреляция с действиями после входа. Одно событие — это след, не приговор.

## Response checklist
- Проверить источник, учётку, destination и последующие действия.
- Проверить, был ли перед этим LSASS access, Kerberoasting, credential dumping.
- Проверить доступ к admin shares, сервисам, WinRM/SMB.
- При подтверждении: сбросить credentials, отозвать tickets/sessions, проверить privileged groups.

## References
- MITRE ATT&CK T1550: https://attack.mitre.org/techniques/T1550/
- Microsoft Event 4624: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
