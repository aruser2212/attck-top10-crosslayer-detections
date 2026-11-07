# Приоритеты качества детектов

Цель ближайшей работы — точные условия срабатывания, проверяемые связи между источниками и исполняемый путь в бесплатном Elasticsearch Basic. Для каждого сценария сначала определяются наблюдаемое поведение и ограничения, затем fixtures и backend. Расширение хранения, планировщиков и архивирования в этот этап не входит.

## Что означает «точный детект»

Точность выполнения предиката и способность отличить атаку от легитимной работы — разные результаты. Совпадение офлайн-расчёта с Elasticsearch подтверждает реализацию заданной логики. Оно не доказывает, что каждый найденный кандидат вредоносен.

Набор проверки должен отдельно содержать:

- сценарий, удовлетворяющий заявленным условиям, с явными ожидаемыми событиями и алертами;
- похожую легитимную активность, которая не удовлетворяет условиям и не должна срабатывать;
- легитимную активность, которая удовлетворяет условиям и поэтому должна срабатывать как кандидат: например, RC4-запросы приложения к нескольким service accounts;
- атаки или варианты поведения вне заявленного покрытия, для которых пропуск явно документируется.

Третий случай нельзя объявлять отрицательным тестом только ради красивой метрики. Предикат может быть выполнен правильно, а сигнал при расследовании оказаться benign. Для эксплуатационных precision/recall нужны независимая разметка, определённая единица наблюдения и репрезентативная телеметрия; синтетические fixtures их не заменяют. См. [методологию](methodology.md) и [оценку по разметке](evaluation.md).

## Порядок работы

1. **Завершённый пилот — T1558.003, успешные RC4 TGS к нескольким service accounts.** Burst Hunt переведён в точное rolling-окно; добавлены нормализация нативного 4769, профиль полей и проверенный конечный replay в Elasticsearch Basic. Здесь есть конкретные ошибки исходной семантики, а существующий rolling-движок уже поддерживает нужный `count_distinct`; новые планировщики и хранилища не требуются.
2. **Host + web — конечный Basic пилот реализован.** Исправлено описание слишком широкого web-предиката. Отдельный runtime связывает host/resource namespace/path/time и воспроизводит ручные deploy/upload/admin сценарии на Basic. Связь записи и запроса не доказывает выполнение webshell; следующий этап — нативная нормализация источников и контекст процессов/deploy.
3. **LSASS ProcessAccess — отдельный конечный пилот.** [Контракт](lsass.md) требует бит `PROCESS_VM_READ` и идентичность обоих процессов по GUID, предоставляет нормализацию Sysmon 10 v3 и Basic replay. Доступ к образу с basename `lsass.exe` остаётся кандидатом; он не удостоверяет системный процесс и не доказывает чтение или дамп. Далее нужны реальные профили легитимных AV/EDR. Исключений по одному basename нет; legacy Hunt остаётся проектным описанием.
4. **NewCredentials + special privileges — отдельный конечный пилот.** [Runtime](newcredentials.md) заменяет соседство событий точной связью host/boot/LogonId/SID, сохраняет привилегии и временные смещения и отклоняет неоднозначные сессии. Формулировка о сильном индикаторе PtH удалена. Легитимный `runas /netonly` остаётся ожидаемым кандидатом; дальше нужны проверенный boot scope и реальные labels. Legacy Hunt остаются проектными описаниями.
5. **Службы и PsExec-подобные pipes.** Связывать установку службы, её процесс и pipe по проверяемой идентичности и порядку событий. Начинать с одного источникового контракта и fixtures авторизованного удалённого администрирования; установка службы сама по себе не подтверждает её запуск.

Каждый пункт завершается до расширения набора операторов или платформ: контракт → ожидаемые совпадения и несовпадения → исполнение → сравнение с реальным Basic → обновление DetCard с фактически полученными evidence. Порог и исключения выбираются по данным, а не объявляются универсальными.

## Пилот T1558.003: критерии завершения

Исходный [burst Hunt](../techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml) называл количество разных `service.name` количеством SPN, группировал по `subject.user`, исключал requester с `$` и не проверял успешность запроса. В 4769 requester задаётся `TargetUserName`/`TargetDomainName`, а `ServiceName` обозначает service account; он не даёт точного множества SPN. [DetCard burst](../techniques/T1558_003_Kerberoasting/DET-WIN-T1558-KRB-SPNBURST-002.yaml) поэтому требует отдельной проверки реализованной семантики.

Область пилота: успешные 4769 с RC4, точное число разных service accounts по валидированному SID в `(t−5m,t]`, разделение requester/domain/source IP. Конкретные поля и правила нормализации закреплены в [профиле и инструкции](kerberos.md). Нельзя молча объединять неизвестные identity, считать алиасы имен разными сервисами или исключать все machine accounts. Наличие RC4 burst означает кандидата для расследования; офлайн-подбор пароля по этим событиям не наблюдается. AES-варианты и активность ниже порога остаются вне этой логики.

Ручные ожидаемые результаты покрывают следующие случаи:

- четыре и пять разных service SID; одинаковый SID с разными именами; разные SID с одинаковым именем;
- успешный RC4, AES и неуспешные запросы; machine requester; ошибочные или отсутствующие поля;
- разделение пользователей, доменов и IP; нормализация IPv4-mapped IPv6 без слияния разных клиентов;
- точная нижняя граница rolling-окна, микросекунды, совпадающие timestamps, burst через границу фиксированных окон;
- дубликаты, порядок доставки и нативные XML-версии с дополнительными полями;
- легитимный RC4 burst, который остаётся ожидаемым кандидатом, и похожая активность без достижения порога;
- одинаковые алерты на конечном офлайн-наборе и на реальном Elasticsearch Basic, включая завершение с ошибкой при неполном чтении.

Пилот прошёл 44 ручных сценария и 53 native-проверки Basic, включая отказ при некорректном профиле. Выполненные команды и общая регрессия зафиксированы в [validation report](validation_report.md). Эксплуатационная точность не измерена.

## Инвентаризация 19 legacy Hunt до миграции

Это снимок исходной логики на момент выбора пилота, а не автоматически обновляемый счётчик. Все 19 файлов на входе ревью были legacy-описаниями без исполняемого контракта текущих Hunt runtimes. №1 реализован и проверен в текущем этапе; осталось 18 legacy-описаний. Простое добавление `schema_version` не считается миграцией. Ранг определяет порядок проработки, а не тяжесть угрозы или измеренную эффективность.

| Ранг | Hunt: точный путь | Пробел исходной логики | Следующая обязательная проверка |
|---|---|---|---|
| 1 | [T1558.003 / kerberoast_spn_burst](../techniques/T1558_003_Kerberoasting/hunts/kerberoast_spn_burst.hunt.yaml) | `subject.user`, `ServiceName` как SPN, исключение `$`, нет success-фильтра; burst ещё не исполнялся. | Реализовано и проверено: requester/domain/IP, успешный RC4, distinct service SID, rolling-границы, benign burst и Basic replay; далее — репрезентативная телеметрия. |
| 2 | [T1190 / web_access_suspicious_params](../techniques/T1190_Exploit_Public_Facing_App/hunts/web_access_suspicious_params.hunt.yaml) | `cmd=` **ИЛИ** `.php/.jsp/.aspx` совпадает с обычными динамическими страницами; группировка не связывает запрос с файлом и хостом. | Точные query keys и разбор URL; обычные страницы, benign admin-запросы, однократное декодирование, связь с записью файла и Basic replay. |
| 3 | [T1190 / webroot_new_exec_first_seen](../techniques/T1190_Exploit_Public_Facing_App/hunts/webroot_new_exec_first_seen.hunt.yaml) | Sysmon 11 и Linux write intent имеют разный смысл; фиксированные webroots и first_seen не доказывают появление webshell. | Контракт host/path и write semantics, обычный deploy/upload, чувствительность путей к регистру, связь с HTTP; first_seen только как контекст. |
| 4 | [T1003 / lsass_access](../techniques/T1003_OS_Credential_Dumping/hunts/lsass_access.hunt.yaml) | Любой Sysmon 10 к `lsass.exe`; отсутствует условие по `GrantedAccess` и недостаточно данных для вывода о дампе. | Нормализация маски прав, source/target process GUID, регистр пути, AV/EDR-профили и кандидаты с разными правами доступа. |
| 5 | [T1550 / win_pth_newcred_followed_by_4672](../techniques/T1550_Use_Alt_Auth/hunts/win_pth_newcred_followed_by_4672.hunt.yaml) | `count_if` по host/user в 5m может соединить разные сессии; порядок не задан. | 4624 `TargetLogonId` ↔ 4672 `SubjectLogonId`, один host, границы жизненного цикла сессии/перезагрузки, чужая сессия и `runas /netonly`. |
| 6 | [T1550 / win_pth_newcredentials_first_seen](../techniques/T1550_Use_Alt_Auth/hunts/win_pth_newcredentials_first_seen.hunt.yaml) | LT9 + seclogo не отличает PtH от легитимного NewCredentials; `subject.user` и IP требуют уточнения, host отсутствует в ключе. | Развести Subject/Target/сетевую identity по нативному 4624; missing IP, повторная активность, host scope и легитимный NewCredentials. |
| 7 | [T1569.002 / service_install_suspicious](../techniques/T1569_002_Service_Execution/hunts/service_install_suspicious.hunt.yaml) | 7045 означает установку; substring имени/пути не доказывает запуск или злоупотребление. | Кавычки и аргументы ImagePath, регистр и переменные окружения, легитимные installers; точная связь с процессом службы. |
| 8 | [T1569.002 / psexec_pipes](../techniques/T1569_002_Service_Execution/hunts/psexec_pipes.hunt.yaml) | Любая подстрока `-stdin/-stdout/-stderr`; pipe-паттерн не устанавливает происхождение процесса или намерение. | Посторонние pipes с такими строками, process identity, связь с service-событием, авторизованный PsExec и неполная телеметрия. |
| 9 | [T1558.003 / kerberoast_rc4](../techniques/T1558_003_Kerberoasting/hunts/kerberoast_rc4.hunt.yaml) | Предикат успешного RC4 уже ограничен, но Hunt остаётся неисполняемым и эквивалентность Sigma не проверена. | Использовать контракт пилота 4769, проверить hex/текстовый encryption type и Sigma matching; legacy RC4 как ожидаемый benign-кандидат. |
| 10 | [T1070 / win_shadowcopy_deletion](../techniques/T1070_Indicator_Removal/hunts/win_shadowcopy_deletion.hunt.yaml) | Наблюдается командная строка, не успешное удаление; внешние scripts вне scope. ATT&CK-поведение — T1490. | Регистр, варианты аргументов удаления и чтения, обычный backup/maintenance; явная граница между попыткой и результатом. |
| 11 | [T1070 / win_eventlog_cleared](../techniques/T1070_Indicator_Removal/hunts/win_eventlog_cleared.hunt.yaml) | Event ID без provider/channel недостаточен; first_seen по host на 90d может ошибочно трактоваться как подавление. | Provider/channel для 1102/104, повторная очистка, инициатор и легитимное обслуживание; ни одна очистка не теряется из-за first_seen. |
| 12 | [T1566 / office_susp_children](../techniques/T1566_Phishing/hunts/office_susp_children.hunt.yaml) | Parent/child/command — кандидат запуска; first_seen без host в ключе, строковые аргументы имеют ограниченное покрытие. | Проверить связь родителя, Windows casing и поддержанные аргументы; benign automation и повтор на другом host; phishing не выводится только из процесса. |
| 13 | [T1566 / hta_loader_chain](../techniques/T1566_Phishing/hunts/hta_loader_chain.hunt.yaml) | Один `mshta` с `.hta` или URL пока не цепочка доставки/запуска и не доказательство phishing. | Легитимные HTA, точный process event, URL parsing; связывать с сетью только при наличии общего ключа и определённого порядка. |
| 14 | [T1053 / win_schtask_creation_unusual](../techniques/T1053_Scheduled_Task/hunts/win_schtask_creation_unusual.hunt.yaml) | 4698 и 106 имеют разные схемы; first_seen task/action не учитывает host и сам по себе не означает необычность. | Provider и XML actions, несколько actions, host scope; легитимные задачи/обновления и повторное создание без подавления. |
| 15 | [T1053 / linux_cron_mod_first_seen](../techniques/T1053_Scheduled_Task/hunts/linux_cron_mod_first_seen.hunt.yaml) | Успешный write intent не подтверждает изменение cron; нужен join SYSCALL/PATH, first_seen не исполняется. | Audit serial, несколько PATH, missing records, read-only доступ и штатное обновление cron; first_seen как контекст. |
| 16 | [T1070 / linux_log_wipe_patterns](../techniques/T1070_Indicator_Removal/hunts/linux_log_wipe_patterns.hunt.yaml) | Строковые `/var/log` и аргументы rm/shred/truncate не показывают результат; shell builtins вне покрытия. | Реконструкция argv из EXECVE, ложные подстроки/цитирование, легитимная ротация; попытка и подтверждённая потеря логов разделены. |
| 17 | [T1078 / win_valid_logon_unusual_src](../techniques/T1078_Valid_Accounts/hunts/win_valid_logon_unusual_src.hunt.yaml) | `subject.user` вместо явной target identity; отдельный верхнеуровневый `and`, first_seen и «редкий cnt» не имеют исполняемой семантики. | 4624 LT3/LT10, target/domain/host и IP, NAT/VPN, cold start и horizon; сначала определить, что означает необычность. |
| 18 | [T1078 / linux_ssh_valid_unusual_src](../techniques/T1078_Valid_Accounts/hunts/linux_ssh_valid_unusual_src.hunt.yaml) | Подстрока `Accepted ` не задаёт строгий sshd-контракт; 24h count без порога, first_seen user/IP без host. | Использовать поддержанные accepted-сообщения нормализатора, password/publickey, NAT/VPN и host scope; baseline и cold start до реализации first_seen. |
| 19 | [T1550 / win_ptt_tgs_without_as_window](../techniques/T1550_Use_Alt_Auth/hunts/win_ptt_tgs_without_as_window.hunt.yaml) | Отсутствие 4768 в 5m нормально при кэшированном TGT или неполной видимости DC; «нет события» не доказывает PtT. | Сначала подтвердить полноту DC-источников, native requester mapping и срок жизни tickets; кэшированный TGT, разные DC и пропуски должны быть явными ограничениями. |

Ранг 2–3 относится к одному cross-layer сценарию. Для него реализованы отдельные [runtime и Basic replay](correlation.md) с доверенной файловой областью и ручными сценариями. Web selector исправлен, но оба legacy Hunt остаются проектными описаниями: dedicated runtime не реализует generic join/first_seen DSL. Аналогично наличие проверенного Sigma-предиката не подтверждает нормализатор, Hunt runtime или backend этого Hunt.

После исходного ревью также реализованы отдельные [LSASS](lsass.md) и
[NewCredentials](newcredentials.md) пилоты, а Office Sigma получил полную форму
`-EncodedCommand` и проверки границ аргумента. Пробелы в таблице описывают
исходное состояние; актуальные контракты и выполненные проверки приведены
в руководствах и [validation report](validation_report.md). Эти изменения
не переводят соответствующие legacy Hunt в исполняемый общий DSL.

## Границы расширения

Существующие state/outbox, эпизоды и evidence-архивы сохраняются как реализованная основа. Журнал изменений источника, pruning, распределённые workers и новые планировщики отложены: они не являются следующим результатом этого плана. Ограничения живого сбора и поздних данных продолжают действовать и должны учитываться при каждом пилоте. Приоритет — один завершённый и честно ограниченный детект за раз.
