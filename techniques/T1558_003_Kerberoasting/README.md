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
- Native поля 4769: `TargetUserName`, `TargetDomainName`, `ServiceSid`, `ServiceName`, `TicketEncryptionType`, `IpAddress`, `Status`. `ServiceName` обозначает сервисный аккаунт, а не полный SPN. Профиль сборщика должен сохранять исходные поля; нормализатор поддерживает XML версий 0 и 2.
- Дополнительно: процессная активность на клиенте, откуда запускались PowerView/Rubeus/Impacket.

## Detection strategy
- Сигнал 1: успешный `4769` (`Status=0x0`) с RC4/etype `0x17` — кандидат для расследования. Сам по себе он не подтверждает Kerberoasting или последующий офлайн-подбор.
- Сигнал 2: один requester/domain/IP запрашивает успешные RC4 TGS для ≥5 разных сервисных SID в скользящем окне `(t−5m,t]`. Запросы разных DC объединяются, одинаковое имя сервиса не заменяет SID.
- Усиление: учесть роль аккаунта, app-сервера, клиента и сервиса. Sigma не исключает машинные аккаунты по суффиксу `$`; допустимость таких исключений устанавливается профилем среды.

## Реализовано в проекте
- DetCards: `DET-WIN-T1558-KRB-RC4-001`, `DET-WIN-T1558-KRB-SPNBURST-002`.
- Sigma: `sigma/win_kerberoast_rc4_4769.yml`.
- Исполняемый Hunt v2: `hunts/kerberoast_spn_burst.hunt.yaml`. Имя файла и ID карточки сохранены для совместимости ссылок; метрика теперь называется `distinct_service_accounts`.
- `hunts/kerberoast_rc4.hunt.yaml` остаётся legacy-описанием отдельного RC4 selector.
- XML-нормализатор, строгий профиль `kerberos-v1` и конечный replay на Elastic Basic: [инструкция](../../docs/kerberos.md).
- Test plan: `tests/plan.md`.

## False positives / tuning
`4769` — обычное событие домена. Легитимный запуск legacy-приложения может дать тот же RC4-всплеск: такой пример включён в fixtures и должен совпадать с кандидатом. Порог 5/5m пока не калиброван на рабочей телеметрии. Исключения по `$` и префиксам `app-*`, `iis-*`, `svc-*` не применяются. Уточнение требует проверенного контекста аккаунтов, сервисов и клиентского процесса. AES, медленные запросы, неполные журналы и неоднозначные aliases остаются слепыми зонами этого правила.

## Response checklist
- Проверить requester/domain/IP и исходные `ServiceSid`/`ServiceName` в указанном окне. Учесть NAT, разные формы доменного имени и полноту журналов всех DC.
- Проверить, нет ли рядом LDAP enumeration, PowerShell, Rubeus/Impacket/BloodHound-активности.
- Проверить сервисный аккаунт: привилегии, last password set, тип шифрования, SPN.
- При подтверждении: сменить пароль сервисной учётки, перейти на длинный пароль/gMSA, отключить RC4 там, где возможно.

## Автоматические проверки и границы

Команды выполняются из корня репозитория после установки dev-зависимостей.

- `python tools/check_sigma.py` — разбор pySigma и сопоставление предикатов с [общими fixtures](../../tests/fixtures/sigma/predicates.json), включая правила этой техники. Это проверка синтетических событий, а не выполнение Sigma в SIEM или оценка TPR/FPR.
- `.venv/bin/python -m pytest tests/test_normalize_kerberos.py tests/test_kerberos_hunt.py tests/test_elastic_kerberos.py` — XML/profile и вручную заданные ожидания rolling-кандидата.
- `make lab-up && make check-elastic` — native Basic replay, включая Kerberos и совместимость существующих T1110-адаптеров. Это конечный replay: непрерывный pipeline пока поддерживает только T1110.

Окно вычисляется в Python после полного ограниченного PIT/search_after чтения. Метрика distinct точная, не приблизительная cardinality. Отсутствие requester/domain/IP или service SID исключает запись из обеих метрик. Совпадение не доказывает извлечение билета, офлайн-подбор или компрометацию аккаунта.

Проверенные fixtures и будущие ручные эксперименты разделены в [тест-плане](tests/plan.md).

## References
- MITRE ATT&CK T1558.003: https://attack.mitre.org/techniques/T1558/003/
- MITRE detection strategy DET0157: https://attack.mitre.org/detectionstrategies/DET0157/
- Microsoft Event 4769: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
