# План тестирования: Kerberoasting (T1558.003)

## Автоматизировано

Команды запускаются из корня репозитория в окружении с dev-зависимостями.

- `python tools/check_sigma.py`: pySigma parsing и [source-scoped predicate fixtures](../../../tests/fixtures/sigma/predicates.json), включая правила этой техники; выполнение Sigma в SIEM не проверяется.
- `.venv/bin/python -m pytest tests/test_normalize_kerberos.py tests/test_kerberos_hunt.py tests/test_elastic_kerberos.py`: native-shaped XML 4769 v0/v2, строгие типы и канонизация, [ручные ожидания](../../../tests/fixtures/kerberos/cases.json) для исполняемого burst Hunt v2. Порог 4/5 SID, повторные билеты, aliases одного SID, одинаковые имена разных SID, failure/AES, missing, domain/user/IP isolation, несколько DC, machine requester, атомарные равные timestamps и граница `(t−5m,t]`.
- `ELASTIC_URL=http://127.0.0.1:19200 .venv/bin/python -m pytest tests/integration/test_kerberos_live.py`: настоящий Basic, pagination, повторный ingestion, несовместимый профиль и end-to-end XML → CLI → алерт. Перед этим нужен `make lab-up`.

Легитимный RC4-всплеск приложения обозначен `benign_candidate` и ожидаемо совпадает. Отрицательный тест означает отсутствие условия конкретного правила, а не доказательство безвредности любой подобной активности. Синтетические источники и интерпретация описаны в [README fixtures](../../../tests/fixtures/kerberos/README.md).

Эти проверки подтверждают поведение перечисленных fixtures. Они не измеряют эксплуатационные TPR/FPR и не доказывают полное покрытие техники.

## Следующий ручной/лабораторный этап — не выполнен

1. В доменном стенде собрать обезличенные 4769 с native TargetUserName, TargetDomainName, ServiceSid, ServiceName, IpAddress, TicketEncryptionType и Status. Проверить преобразования, внесённые сборщиком, сохранность всех DC и clock drift.
2. Сравнить успешный RC4 (Status=0x0), failed RC4 и успешный AES. Sigma выбирает успешный RC4-кандидат; это не доказательство извлечения/взлома билета.
3. Сравнить пользовательские и машинные аккаунты, обычные legacy app-servers и известный тестовый сценарий. Глобальное исключение машинных аккаунтов по суффиксу не применяется.
4. Калибровать distinct service SID порог/окно на размеченных периодах нормальной работы и контролируемых атак. Проверить медленные и AES-варианты отдельно: RC4 burst их не покрывает. Для legacy RC4 Hunt исполнение пока не реализовано.
