# T1558.003 — Kerberoasting

## Коротко
Kerberoasting — получение Kerberos TGS для сервисного аккаунта с SPN и последующий офлайн-подбор пароля. MITRE относит это к Steal or Forge Kerberos Tickets: атакующий может получить TGS, который уязвим к brute force, а затем извлечь пароль сервисной учётки.

## Attack flow
1. У атакующего уже есть доменная учётка, даже низкопривилегированная.
2. Он перечисляет SPN и запрашивает TGS для сервисных аккаунтов.
3. Билет сохраняется и ломается офлайн.
4. Найденный пароль используется для lateral movement или privilege escalation.

## Телеметрия
- Domain Controller Security: `4769` — Kerberos service ticket request.
- Поля: `SubjectUserName`, `ServiceName`, `TicketEncryptionType`, `IpAddress`.
- Дополнительно: процессная активность на клиенте, откуда запускались PowerView/Rubeus/Impacket.

## Detection strategy
- Сигнал 1: `4769` с RC4/etype `0x17`, особенно если RC4 не должен использоваться.
- Сигнал 2: один пользователь или источник запрашивает много разных SPN за короткое окно.
- Усиление: исключать машинные учётки (`$`), app-серверы и известные сервисные источники.

## Реализовано в проекте
- DetCards: `DET-WIN-T1558-KRB-RC4-001`, `DET-WIN-T1558-KRB-SPNBURST-002`.
- Sigma: `sigma/win_kerberoast_rc4_4769.yml`.
- Hunt DSL: `hunts/kerberoast_rc4.hunt.yaml`, `hunts/kerberoast_spn_burst.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
`4769` — нормальное и очень частое событие в домене. Не алерти «каждый TGS», иначе SIEM превратится в кофемолку с истерикой. Рабочий путь: baseline сервисных источников, пороги по distinct SPN, отдельная логика для RC4 и исключение машинных учёток.

## Response checklist
- Проверить пользователя, source IP и список `ServiceName`.
- Проверить, нет ли рядом LDAP enumeration, PowerShell, Rubeus/Impacket/BloodHound-активности.
- Проверить сервисный аккаунт: привилегии, last password set, тип шифрования, SPN.
- При подтверждении: сменить пароль сервисной учётки, перейти на длинный пароль/gMSA, отключить RC4 там, где возможно.

## References
- MITRE ATT&CK T1558.003: https://attack.mitre.org/techniques/T1558/003/
- MITRE detection strategy DET0157: https://attack.mitre.org/detectionstrategies/DET0157/
- Microsoft Event 4769: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
