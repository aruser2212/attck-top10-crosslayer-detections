# T1550 — Use Alternate Authentication Material

## Область техники

T1550 описывает использование альтернативного материала аутентификации, включая
password hashes и Kerberos tickets. В этом каталоге собраны кандидаты для
расследования соответствующего контекста. NewCredentials logon или короткое
отсутствие AS-события сами по себе не показывают, какой материал был использован.

## Телеметрия и наблюдаемый смысл

- Windows Security 4624 с `LogonType=9`, `LogonProcessName=seclogo` сообщает
  о NewCredentials logon. Такой вход возможен при легитимном `runas /netonly`.
- Security 4672 сообщает о назначении специальных привилегий сессии. Соседство
  событий у одного пользователя не подтверждает, что речь об одной сессии.
- 4768/4769 позволяют исследовать AS/TGS-паттерны. Cached tickets и пропуски
  DC-телеметрии не должны превращаться в доказательство PtT.

## Реализованный конечный NewCredentials-пилот

[Нормализатор, офлайн-коррелятор и Elasticsearch Basic adapter](../../docs/newcredentials.md)
связывают 4624 LT9/seclogo и 4672 по **host + доверенный boot ID + LogonId**,
с дополнительным совпадением SID локального токена:
`4624.TargetLogonId` ↔ `4672.SubjectLogonId`,
`4624.TargetUserSid` ↔ `4672.SubjectUserSid`.
Имена пользователей, IP и поля outbound credentials не подменяют эту identity.

4672 допускается раньше, одновременно с или позже anchor в симметричном
record-time окне, по умолчанию ±30 секунд включительно. Этот допуск — политика
пилота, не гарантия порядка Windows. На один anchor возвращается кандидат со
ссылками на все подходящие 4672, signed time deltas и объединением привилегий.
Неоднозначные 4624 для участвующей сессии и конфликтующий SID отклоняются.

Native XML поддерживает 4624 v0/v2 и 4672 v0. Boot ID передаётся явно;
происхождение этой области должен подтвердить источник. Если capture не
содержит такого доказательства, ручная метка даёт только условный replay.
Полный контракт, границы времени, лимиты и воспроизводимый пример приведены
в [руководстве](../../docs/newcredentials.md).

## Артефакты и различие областей

- `DET-WIN-T1550-PTH-NEWCRED-001` сохраняет исторический ID, но описывает
  NewCredentials и same-session privilege candidates, а не подтверждённый PtH.
- `sigma/win_4624_newcredentials_seclogo.yml` — отдельный широкий LT9/seclogo
  selector. В нём нет 4672 join, SID или boot-контракта.
- Оба NewCredentials Hunt-файла остаются `design-only`. Отдельный runtime
  не реализует общий join/first_seen DSL и не мигрирует эти файлы автоматически.
- `DET-WIN-T1550-PTT-KRB-ANOM-002` и PtT Hunt сохраняют собственную проектную
  область; новый runtime не исполняет их логику.

## Разбор кандидата и tuning

Подтвердить происхождение host/boot identity, правильность локального SID и
соответствие LUID. Проверить, было ли создание сессии разрешённым действием
администратора, и сопоставить последующий доступ к ресурсам с независимой
телеметрией. Проверка LSASS access может быть дополнительным контекстом,
но отдельный ProcessAccess тоже не доказывает дамп или использование хеша.

Легитимный `runas /netonly` со специальными привилегиями остаётся ожидаемым
кандидатом. Исключения по одному имени пользователя, процесса или учётной
записи не добавлены. First-seen требует отдельной истории и оценки cold start;
новая сессия не объявляется автоматически опасной.

## Проверки и границы

`tools/check_sigma.py` проверяет разбор pySigma и source-scoped predicate
fixtures. Для dedicated runtime подготовлены [ручные сценарии](../../tests/fixtures/newcredentials/cases.json),
synthetic XML и проверки на настоящем Basic; выполненные результаты находятся
в [validation report](../../docs/validation_report.md).

Это конечный replay без развёрнутого Windows collector, непрерывного scheduler
и постоянного alert sink. Basic читает весь конечный профильный dataset, включая
4624 вне выбранных output bounds для обнаружения неоднозначности. Жизненный
цикл карточки остаётся `test`, проверка `partial`, эксплуатационные метрики —
`null`. [Тест-план](tests/plan.md) отделяет эти проверки от дальнейшей оценки
реального сбора и ложных срабатываний.

## References

- [MITRE ATT&CK T1550](https://attack.mitre.org/techniques/T1550/)
- [Microsoft Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
- [Microsoft Event 4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672)
- [LUID scope until restart](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-allocatelocallyuniqueid)
