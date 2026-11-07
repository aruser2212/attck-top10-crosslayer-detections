# Портфель из 20 семейств

Это подборка сценариев для инженерной проверки, не рейтинг распространённости
атак MITRE. Каталог расширен с десяти до двадцати семейств. Подтехники и
дополнительный контекст указаны в карточках; один каталог не означает полное
покрытие соответствующего семейства.

| Семейство | Наблюдение | Исполняемая область |
|---|---|---|
| [T1003](../techniques/T1003_OS_Credential_Dumping/README.md) | Право чтения памяти LSASS-named процесса | Sysmon 10 XML, конечный offline/Basic replay |
| [T1053](../techniques/T1053_Scheduled_Task/README.md) | Windows task / Linux cron артефакты | Проверенные Sigma-предикаты; Hunt остаются design-only |
| [T1070](../techniques/T1070_Indicator_Removal/README.md) | Очистка журналов и команды удаления копий | Проверенные предикаты; отдельные mappings T1685.006/T1490 |
| [T1078](../techniques/T1078_Valid_Accounts/README.md) | Успешная аутентификация | Проверенные предикаты; novelty/first_seen не исполняется |
| [T1110](../techniques/T1110_Brute_Force/README.md) | Ошибки входа и password spraying | Fixed/rolling replay; два Windows durable pipelines; Linux offline |
| [T1190](../techniques/T1190_Exploit_Public_Facing_App/README.md) | Webroot-файл и HTTP-запрос | Host/web finite replay, network/YARA; эксплуатация не доказана |
| [T1550](../techniques/T1550_Use_Alt_Auth/README.md) | NewCredentials с привилегиями той же сессии | Security XML, точная finite-корреляция offline/Basic; PtH не доказан |
| [T1558.003](../techniques/T1558_003_Kerberoasting/README.md) | Успешный RC4 TGS burst к разным service SID | 4769 XML, rolling offline/Basic replay |
| [T1566](../techniques/T1566_Phishing/README.md) | Office/HTA/script-host кандидаты | Sigma/YARA/network проверки; связь с письмом не установлена |
| [T1569.002](../techniques/T1569_002_Service_Execution/README.md) | Service/PsExec-like артефакты | Sigma/network проверки; общий service/process/pipe join не реализован |
| [T1059.001](../techniques/T1059_Command_Scripting/README.md) | Encoded PowerShell option | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1218.010](../techniques/T1218_System_Binary_Proxy/README.md) | regsvr32 URL scriptlet | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1105](../techniques/T1105_Ingress_Tool_Transfer/README.md) | certutil URL cache command | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1047](../techniques/T1047_WMI/README.md) | Удалённый WMIC process create | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1136.001](../techniques/T1136_Create_Account/README.md) | Локальный net user /add | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1098.007](../techniques/T1098_Account_Manipulation/README.md) | Добавление в Administrators | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1018](../techniques/T1018_Remote_System_Discovery/README.md) | net view /domain: | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1087.002](../techniques/T1087_Account_Discovery/README.md) | net user /domain enumeration | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1547.001](../techniques/T1547_Boot_Logon_Autostart/README.md) | reg add конкретного Run key | Sysmon 1 XML → process-v1 offline/native Basic |
| [T1016](../techniques/T1016_Network_Configuration_Discovery/README.md) | ipconfig /all | Информационный process-v1 кандидат, offline/native Basic |

У новых десяти сценариев общий [профиль источника](windows-process.md) с явным
ASCII-контрактом полей предиката и native Sysmon 1 v5. Допустимые формы команд
и ограничения каждого правила описаны в его dossier. Легитимное совпадение
сохраняется как кандидат; каталог не присваивает каждому алерту malicious label.

Состав файлов, карточек и ссылок генерируется в [coverage](coverage.md).
[Validation report](validation_report.md) фиксирует выполненные проверки.
18 исторических Hunt остаются проектными описаниями и не участвуют в обещании
исполняемого нового process-пакета. Все карточки сохраняют lifecycle `test`;
операционная точность требует размеченной телеметрии выбранной среды.

Начало работы — [quickstart](quickstart.md). После проверки библиотеки следующий
шаг для рабочей среды — подтвердить полноту и происхождение источника, выполнить
replay на её легитимных событиях и только затем выбирать пороги/контекст реакции.
