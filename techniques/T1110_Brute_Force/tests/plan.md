# План тестирования T1110

## Автоматизировано

Команды запускаются из корня репозитория в окружении с dev-зависимостями.

- `python tools/check_sigma.py`: pySigma parsing и [source-scoped predicate fixtures](../../../tests/fixtures/sigma/predicates.json), включая правила этой техники; выполнение Sigma в SIEM не проверяется.
- `python tools/check_network.py`: pinned Suricata 8.0.4, загрузка правил и [синтетический PCAP replay](../../../tests/fixtures/network/cases.json) с ожидаемыми SID и количеством алертов; нужен Docker.
- `python -m pytest tests/test_hunt_engine.py -q`: три исполняемые T1110-агрегации и [ожидаемые алерты](../../../tests/fixtures/hunts/auth_cases.json), включая пороги, границы UTC-окон, группировку, дубликаты и отсутствующие поля.
- `python -m pytest tests/test_rolling_hunt.py tests/test_rolling_fixtures.py tests/test_rolling_oracle.py tests/test_rolling_compatibility.py -q`: три отдельные rolling v2 версии, [ручные ожидаемые результаты](../../../tests/fixtures/rolling/auth_cases.json), независимый O(n²) oracle, микросекундные границы, равные timestamps и эквивалентность раздельного replay с предшествующим контекстом. V1 должен отклонять v2 до сетевых запросов и изменения state.
- `python -m pytest tests/test_normalize_windows.py tests/test_normalize_linux_auth.py -q`: [Windows XML](../../../tests/fixtures/windows/4625.xml) и [Linux journal JSONL](../../../tests/fixtures/linux_auth/journal.jsonl), включая canonical source identity, 100ns-остаток Windows, точные journal microseconds, modern OpenSSH process names и Linux 7/8-event threshold.
- `make check-elastic`: Windows brute/spray и [stateful pipeline](../../../docs/continuous.md) на работающем Elasticsearch Basic, точный подсчёт, pagination, повторная доставка и восстановление состояния. Standalone integration pytest без ELASTIC_URL пропускается; стандартный lab port — 19200. Linux dataset здесь не покрывается.

Эти проверки подтверждают поведение перечисленных fixtures. Они не измеряют эксплуатационные TPR/FPR и не доказывают полное покрытие техники.

Windows rolling v2 дополнительно проверяется в `tests/integration/test_rolling_live.py` на отдельном auth-v2/date_nanos индексе: очень маленькие страницы PIT/search_after, точные ожидаемые алерты, UUID, ограничения размера и повторная загрузка. Отдельные `test_rolling_runner_live.py` и `test_rolling_pipeline_live.py` проверяют durable v2: микросекундные anchors, поздние изменения, retraction/reactivation, восстановление outbox, ограниченный catch-up и CLI. Результаты выполненного прогона публикуются в [отчёте](../../../docs/validation_report.md); v1 scheduler сохраняет прежний контракт.

Отдельный episode layer проверяется ручными [fixtures](../../../tests/fixtures/episodes/cases.json), `tests/test_episode_*.py` и native `tests/integration/test_episode_live.py` / `test_episode_cli_live.py`: включительная граница gap, транзитивное объединение, разделение rule/group, поздние merge/split, отзыв/восстановление ID, строгое закрытие по checkpoint, peak без суммирования, целостность snapshot и восстановление доставки. Все исходные алерты сохраняются. Эти проверки не подтверждают, что временно близкие сигналы относятся к одной реальной атаке.

Инкрементальный режим сопоставляется с полным эталоном в `test_episode_incremental.py` и native `test_incremental_episode_live.py`, включая прежние группы, новые ревизии, closure и глобальные лимиты. Архивные проверки `test_episode_archive.py` / `test_episode_archive_live.py` подтверждают согласованный экспорт, offline verification, границу bounded replay и отсутствие очистки живых строк. Экспорт не считается резервной копией или доказательством эксплуатационной точности.

## Следующий ручной/лабораторный этап — не выполнен

1. Для Windows проверить нормализацию реального обезличенного 4625 по [контракту](../../../docs/telemetry.md): canonical Computer/record identity, UTC timestamp, domain-qualified target.user и source.ip. Сохранить исходные поля при доставке через несколько collectors; установить реальный сборщик отдельно. XML parsing само по себе не удостоверяет источник.
2. Для Linux проверить экспорт journalctl JSONL с _MACHINE_ID, __CURSOR, __REALTIME_TIMESTAMP и точным sshd/sshd-session/sshd-auth source. Сохранять _COMM из доверенного journal export; один SYSLOG_IDENTIFIER не удостоверяет процесс. Сопоставить Failed password, success и ignored сообщения; отдельное Invalid user не должно удваивать ошибку пароля. Linux replay пока локальный, без deployment collector или Elastic adapter.
3. Сравнить на репрезентативных логах фиксированные UTC-окна v1 и скользящие v2: пороги 10/5m (brute), 15 пользователей/10m (spray), 8/5m (Linux). V1 может пропустить серию на границе; v2 может выдать несколько алертов для одной серии. Оценить обе формы поведения по явной единице наблюдения, а не только по количеству алертов.
4. Для сетевого сигнала сопоставить SSH flows с sshd outcomes. Native replay проверяет 10 потоков без алерта, 11 с алертом и один активный поток без алерта; это не тест угадывания пароля.
5. Измерить шум от сканеров, сервисных ошибок и общего NAT; последующая успешная аутентификация — отдельная будущая корреляция.
