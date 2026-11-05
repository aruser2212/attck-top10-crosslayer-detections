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
- Linux sshd journal: `Failed password`, включая форму `invalid user`; `Accepted password/publickey` нормализуются отдельно как success. Самостоятельное `Invalid user …` не считается ещё одной ошибкой пароля.
- VPN/IdP/WAF/Web logs: login failures, MFA failures, source IP.
- Network/IDPS: частота наблюдаемых SSH flows. Сетевое правило не видит результат аутентификации и требует сопоставления с sshd logs.

## Detection strategy
- Brute: много провалов по `{source.ip × target.user}` за короткое окно.
- Spray: много разных пользователей с одного source за окно.
- Исполняемые Hunt v1 используют фиксированные UTC-окна `[start,end)`: Windows brute ≥10 за 5 минут, spray ≥15 разных пользователей за 10 минут, Linux SSH ≥8 за 5 минут. Это не скользящие окна: серия на границе может быть пропущена.
- Отдельные Hunt v2 с теми же порогами проверяют точные скользящие окна `(t−W,t]` в моменты подходящих событий каждой группы. События с одинаковым временем учитываются вместе; дубликаты ID не увеличивают счётчик. Для Windows есть конечный replay и отдельный непрерывный pipeline v2 с микросекундными checkpoints и outbox; Linux остаётся офлайн.
- Усиление для будущей корреляции: успешный `4624`/SSH login после серии `4625`/Failed password.

## Реализовано в проекте
- DetCards: `DET-WIN-T1110-4625-BRUTE-001`, `DET-LNX-T1110-SSH-BRUTE-002`.
- Sigma: `sigma/win_4625_base.yml`, `sigma/linux_sshd_failed_base.yml`.
- IDPS: `network/ssh_bruteforce_suricata.rules` — одно учитываемое совпадение на SSH flow; алерт при превышении 10 flows за 60 секунд с одного источника, а не при 10 failed logins.
- Hunt DSL: `hunts/win_4625_brute_agg.hunt.yaml`, `hunts/win_4625_spray_agg.hunt.yaml`, `hunts/linux_ssh_failed_agg.hunt.yaml`.
- Rolling v2: отдельные `*_rolling.hunt.yaml` для этих трёх сценариев; контракты, auth-v2 профиль и пример пересечения границы окна — в [руководстве](../../docs/rolling-windows.md).
- Test plan: `tests/plan.md`.

Экспорт Windows XML проходит общую нормализацию и может поступать в [stateful Elastic Basic pipeline](../../docs/continuous.md): профиль auth-v1 для tumbling или отдельный auth-v2 для rolling. Linux journal JSONL от точных process names `sshd`, `sshd-session`, `sshd-auth` нормализуется для локального Linux Hunt; в текущий Elastic pipeline этот dataset не входит. Контракты identity, case, времени и source filtering описаны в [телеметрии](../../docs/telemetry.md); развёртывание сборщика на реальном хосте не проверено.

## False positives / tuning
Сканеры, misconfigured services, забытые пароли в сервисах и мониторинг могут имитировать brute force. Разделяй internal/external sources, service accounts, known scanners и user-driven failures. Для password spraying полезнее `distinct_users`, а не просто общий count.

## Response checklist
- Определить источник и целевые аккаунты.
- Проверить, был ли успешный логин после провалов.
- Заблокировать источник на perimeter/IDPS/WAF при необходимости.
- Проверить MFA bypass, password policy, leaked credentials и lockout impact.

## Автоматические проверки и границы

Команды выполняются из корня репозитория после установки dev-зависимостей.

- `python tools/check_sigma.py` — разбор pySigma и сопоставление предикатов с [общими fixtures](../../tests/fixtures/sigma/predicates.json), включая правила этой техники. Это проверка синтетических событий, а не выполнение Sigma в SIEM или оценка TPR/FPR.
- `python tools/check_network.py` — загрузка всех правил и replay [синтетического PCAP-корпуса](../../tests/fixtures/network/cases.json) в закреплённой Suricata 8.0.4; нужен Docker. Совместимость со Snort не проверена.
- `python -m pytest tests/test_hunt_engine.py -q` — исполнение трёх T1110 Hunt v1 на [граничных и отрицательных случаях](../../tests/fixtures/hunts/auth_cases.json).
- `python -m pytest tests/test_rolling_hunt.py tests/test_rolling_fixtures.py tests/test_rolling_oracle.py tests/test_rolling_compatibility.py -q` — отдельный rolling v2: ручные ожидаемые результаты, независимый математический oracle, микросекундные границы, контекст при разбиении replay и отказ v1 от несовместимых правил.
- `python -m pytest tests/test_normalize_windows.py tests/test_normalize_linux_auth.py -q` — исходные XML/journal fixtures, стабильная identity, Source/Target, case, микросекунды, дубликаты и выполнение Linux Hunt на нормализованных событиях.
- `make check-elastic` — Windows replay и stateful pipeline integration на запущенном Elasticsearch Basic; запуск описан в [Elastic](../../docs/elastic.md). Linux Hunt в Elastic-адаптер пока не входит. При прямом запуске integration suite без `ELASTIC_URL` эти проверки пропускаются; стандартный стенд использует порт 19200.

Тот же integration suite проверяет отдельный Windows rolling replay с auth-v2/date_nanos, PIT/search_after и выполнением rolling-алгоритма в Python. Это не встроенная SIEM-корреляция и не миграция v1 state. Каждая подходящая пара group/timestamp сохраняется как отдельный алерт. Дополнительное [представление эпизодов](../../docs/episodes.md) объединяет соседние алерты одного rule/group, сохраняя ссылки на каждый сигнал. Peak-метрики отражают максимумы отдельных окон; число попыток за весь эпизод не выводится из суммы пересекающихся счётчиков.

Проверенные fixtures и будущие ручные эксперименты разделены в [тест-плане](tests/plan.md).

## References
- MITRE ATT&CK T1110: https://attack.mitre.org/techniques/T1110/
- Microsoft Event 4625: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
- Suricata rules documentation: https://docs.suricata.io/en/suricata-8.0.4/rules/index.html
