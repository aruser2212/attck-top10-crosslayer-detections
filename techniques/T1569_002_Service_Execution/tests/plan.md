# План тестирования: Service Execution (T1569.002)

Цели:
- Проверить ловлю 7045 (service install) на подозрительных путях и/или PSEXESVC.
- Проверить паттерн Sysmon-пайпов (-stdin/-stdout/-stderr).
- (Опция) Проверить сетевое правило на SMB pipe \\PSEXESVC.

Шаги (лаба/безопасно):
1) Локально: `sc.exe create TestSvc binPath= "C:\\Windows\\Temp\\svc.exe"` → ожидать 7045 с temp-путём.
2) Инструмент PsExec-подобный (лабораторка или Impacket psexec к тестовому хосту):
   - ожидать появление службы PSEXESVC и событий Sysmon 17/18 с pipe `*-stdin/out/err`.
3) (Сеть/IDPS) Сгенерировать SMB-трафик с использованием PsExec → ожидать срабатывание Suricata-правила.
4) Зафиксировать ложноположительные (RMM/EDR/backup/soft-deploy) и оформить allow-list в DetCard.
