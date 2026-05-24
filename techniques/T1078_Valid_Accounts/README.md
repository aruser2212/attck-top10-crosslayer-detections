# T1078 — Valid Accounts

## Коротко
Valid Accounts — использование настоящих учётных записей: доменных, локальных, SSH, VPN, облачных или сервисных. MITRE подчёркивает, что валидные креды позволяют обходить часть контролей доступа и выглядеть как нормальная активность. The activity can look legitimate because authentication succeeds with valid credentials.

## Attack flow
1. Креды получены через phishing, brute force, credential dumping, утечки или Kerberoasting.
2. Атакующий входит через VPN/RDP/SMB/SSH/админ-панель.
3. Дальше выполняет discovery, lateral movement, persistence или privilege escalation.

## Телеметрия
- Windows Security: `4624` successful logon, особенно LogonType `3` и `10`.
- Linux auth/sshd: `Accepted password/publickey`.
- VPN/IdP/Proxy: успешные логины, MFA events, impossible travel.

## Detection strategy
- Не искать «логин = зло». Искать отклонение от привычного поведения.
- First-seen по паре `{user × source.ip/host}`.
- Аномалии по времени, географии, user-agent, типу логина, источнику.
- Связка с предшествующими T1110/T1003/T1558.

## Реализовано в проекте
- DetCards: `DET-WIN-T1078-VALIDLOGON-001`, `DET-LNX-T1078-SSH-VALID-002`.
- Sigma: `sigma/win_4624_remote_success.yml`, `sigma/linux_sshd_success_base.yml`.
- Hunt DSL: `hunts/win_valid_logon_unusual_src.hunt.yaml`, `hunts/linux_ssh_valid_unusual_src.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
Админы, bastion/jump-hosts, CI/CD, backup и сервисные учётки будут шуметь. Для них нужны отдельные профили нормального поведения, rather than broad suppressions that hide meaningful anomalies. Самое ценное — первый новый источник для важного аккаунта.

## Response checklist
- Проверить источник, географию, тип логина, хост назначения и роль аккаунта.
- Проверить, были ли перед этим неуспешные логины, Kerberoasting или credential dumping.
- Проверить действия после входа: discovery, SMB, WinRM, SSH, sudo/su.
- При подтверждении: сбросить креды, отозвать сессии/токены, проверить MFA и persistence.

## References
- MITRE ATT&CK T1078: https://attack.mitre.org/techniques/T1078/
- Microsoft Event 4624: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
