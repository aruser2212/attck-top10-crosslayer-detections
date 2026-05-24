# T1110 — Brute Force / Password Spraying

## Коротко
Brute Force — систематический подбор паролей или использование списков учётных данных. MITRE описывает T1110 как попытки получить доступ, когда пароль неизвестен или есть хэш/утёкший credential material. В реальности важно разделять brute force и password spraying: they produce different telemetry patterns and should be detected separately.

## Attack flow
1. Атакующий выбирает сервис: VPN, SSH, RDP, OWA, web-login, SMB.
2. Brute force: много попыток по одной учётке.
3. Password spraying: один/несколько популярных паролей по многим учёткам.
4. Успешная попытка переходит в T1078 Valid Accounts.

## Телеметрия
- Windows Security: `4625` failed logon, lockout-события, source IP, target user.
- Linux sshd/auth: `Failed password`, `Invalid user`.
- VPN/IdP/WAF/Web logs: login failures, MFA failures, source IP.
- Network/IDPS: частые SSH-сессии или повторные попытки к login endpoint.

## Detection strategy
- Brute: много провалов по `{source.ip × target.user}` за короткое окно.
- Spray: много разных пользователей с одного source за окно.
- Усиление: успешный `4624`/SSH login после серии `4625`/Failed password.

## Реализовано в проекте
- DetCards: `DET-WIN-T1110-4625-BRUTE-001`, `DET-LNX-T1110-SSH-BRUTE-002`.
- Sigma: `sigma/win_4625_base.yml`, `sigma/linux_sshd_failed_base.yml`.
- IDPS: `network/ssh_bruteforce_suricata.rules`.
- Hunt DSL: `hunts/win_4625_brute_agg.hunt.yaml`, `hunts/win_4625_spray_agg.hunt.yaml`, `hunts/linux_ssh_failed_agg.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
Сканеры, misconfigured services, забытые пароли в сервисах и мониторинг могут имитировать brute force. Разделяй internal/external sources, service accounts, known scanners и user-driven failures. Для password spraying полезнее `distinct_users`, а не просто общий count.

## Response checklist
- Определить источник и целевые аккаунты.
- Проверить, был ли успешный логин после провалов.
- Заблокировать источник на perimeter/IDPS/WAF при необходимости.
- Проверить MFA bypass, password policy, leaked credentials и lockout impact.

## References
- MITRE ATT&CK T1110: https://attack.mitre.org/techniques/T1110/
- Microsoft Event 4625: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- Suricata rules documentation: https://docs.suricata.io/en/suricata-8.0.4/rules/index.html
