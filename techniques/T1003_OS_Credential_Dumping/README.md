# T1003 — OS Credential Dumping

Техника описывает получение credential material из памяти, кэшей и структур ОС.
Реализованный здесь пилот ограничен Sysmon 10: **выданное право PROCESS_VM_READ
к образу с basename `lsass.exe`**. Оно создаёт кандидата для расследования, но не
доказывает чтение памяти, наличие дампа или подлинность системного LSASS.

## Реализованный пилот

- [Нормализатор XML](../../tools/normalize_windows_sysmon.py) принимает Sysmon 10
  версии 3, проверяет provider/channel, process GUID, абсолютные DOS image paths
  и uint32 GrantedAccess. PID не подменяет GUID.
- [Конечный runtime](../../tools/detect_lsass.py) проверяет basename без учёта
  ASCII-регистра и бит `0x10`. Маски query-only без этого бита не совпадают.
  Каждый подходящий исходный event даёт отдельный алерт с host-scoped process
  GUID и ссылкой на source event. First-seen и PID joins отсутствуют.
- [Basic-адаптер](../../tools/elastic_lsass.py) читает отдельный профиль `lsass-v1`
  через PIT/search_after и применяет тот же предикат к полному конечному набору.
  Платная лицензия и trial не требуются.
- [Инструкция и пример](../../docs/lsass.md) описывают контракт, временные границы
  `[start,end)`, повторную доставку, лимиты и ограничения.

Время — `System/TimeCreated`, а не `EventData/UtcTime`. Арифметика использует
микросекунды; native 100ns остаток сохраняется в identity. Host определяется
именем Computer без разрешения aliases. Источник должен обеспечивать его
однозначность в выбранном корпусе; XML не удостоверяет подлинность машины.

## Артефакты и разные области действия

- [DetCard](DET-WIN-T1003-LSASS-001.yaml) хранит область проверки и ограничения.
- [Sigma](sigma/win_sysmon_lsass_access.yml) остаётся широким selector для любого
  Sysmon 10 к basename `lsass.exe`, включая query-only. Bitmask/GUID контракт
  dedicated runtime не является условием этой Sigma; parity не заявляется.
- [Legacy Hunt](hunts/lsass_access.hunt.yaml) остаётся design-only. Наличие
  отдельного LSASS runtime не делает generic Hunt DSL исполняемым для этого файла.
- [Тест-план](tests/plan.md) разделяет синтетические проверки и работу с реальной
  телеметрией. Фактические запуски перечислены в [отчёте](../../docs/validation_report.md).

## Легитимные совпадения и расследование

AV/EDR и диагностические инструменты могут законно получить право читать память.
Они остаются кандидатами; исключений по `MsMpEng.exe`, `SenseIR.exe`,
`winlogon.exe` и другим basename нет. Известный путь или строка CallTrace не
заменяют проверку подписи, хэша и происхождения процесса. Файл, названный
`lsass.exe` в пользовательском каталоге, тоже совпадает: удостоверение системного
процесса требует дополнительного доверенного контекста.

При расследовании следует сопоставить event ID и GUID с процессной телеметрией,
пользователем и ролью хоста; отдельно проверить подтверждения чтения памяти или
создания файла дампа. Sysmon 1/4688, подписи, parent process и последующие логины
этим пилотом автоматически не соединяются. Реальные профили AV/EDR и
эксплуатационные precision/TPR/FPR пока не измерены.

## Границы покрытия

UNC/device paths и другие версии Sysmon требуют отдельного контракта. Работа с
SAM/NTDS.dit, DCSync, Linux credential files, альтернативные способы получения
credential material и непрерывный сбор событий здесь не реализованы. Native XML
fixtures и Basic replay проверяют конкретную логику; они не подтверждают полноту
T1003 или T1003.001.

## References

- [MITRE ATT&CK T1003.001](https://attack.mitre.org/techniques/T1003/001/)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
