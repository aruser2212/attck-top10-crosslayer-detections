# T1566 — Phishing

## Коротко
Phishing — доставка вредоносной ссылки или вложения пользователю. MITRE detection strategy для T1566 рекомендует коррелировать email metadata, file creation, network activity и suspicious document behavior после получения письма. Это не просто «письмо плохое»; интересна цепочка «письмо → файл/URL → процесс → сеть».

## Attack flow
1. Пользователь получает письмо со ссылкой или вложением.
2. Вложение/страница запускает Office, HTML/HTA, script engine или LOLBIN.
3. Payload скачивает следующий stage, крадёт креды или даёт initial access.
4. Дальше цепочка уходит в T1078/T1003/T1053/T1569.

## Телеметрия
- Email gateway: sender, recipient, URL, attachment hash/name/type.
- Endpoint process creation: Office/Outlook → PowerShell, WScript, MSHTA, CMD.
- Network/Proxy/IDPS: загрузка `.hta`, `.docm`, `.xlsm`, подозрительные URLs.
- AV/EDR/YARA: макросы, AutoOpen, WScript.Shell, Shell, mshta.

## Detection strategy
- Host: Office/Outlook spawning script interpreters or LOLBINs.
- Network: HTA or macro-enabled documents downloaded from external sources.
- File: YARA heuristic for macro-enabled OLE with AutoOpen + Shell/WScript patterns.
- Лучший сигнал — корреляция нескольких слоёв, а не одиночная сигнатура.

## Реализовано в проекте
- DetCards: `DET-WIN-T1566-OFFICE-CHILD-001`, `DET-WIN-T1566-HTA-LOADER-002`.
- Sigma: `sigma/win_office_spawns_script.yml`, `sigma/win_mshta_suspicious.yml`.
- IDPS: `network/http_hta_download.rules`, `network/http_macro_doc_download.rules`.
- YARA: `yara/ole_vba_autoopen_shell.yara`.
- Hunt DSL: `hunts/office_susp_children.hunt.yaml`, `hunts/hta_loader_chain.hunt.yaml`.
- Test plan: `tests/plan.md`.

## False positives / tuning
Office add-ins, отчётные макросы и старые корпоративные HTA-инсталляторы могут шуметь. Не бей молотком по каждому `mshta.exe`: смотри parent, command line, URL, пользовательский контекст и first-seen пары parent→child.

## Response checklist
- Найти исходное письмо, получателей и attachment/URL.
- Проверить, кто открыл файл или перешёл по ссылке.
- Проверить дочерние процессы и сетевые соединения.
- Удалить/заблокировать письмо, URL, hash; проверить распространение внутри.

## References
- MITRE ATT&CK T1566: https://attack.mitre.org/techniques/T1566/
- Suricata HTTP rules documentation: https://docs.suricata.io/en/latest/rules/http-keywords.html
- YARA writing rules: https://yara.readthedocs.io/en/stable/writingrules.html
