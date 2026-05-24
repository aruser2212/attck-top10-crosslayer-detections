# План тестирования: T1070 Indicator Removal

Цели:
- Зафиксировать очистку журналов (1102/104).
- Поймать удаление теневых копий (vssadmin/wmic/diskshadow/PS).
- Обнаружить Linux wipe-паттерны.

Шаги (лабораторно/описательно):
1) Windows (лаба): выполнить `wevtutil cl Security` — ожидать Security 1102; проверить Hunt и Sigma.
2) Windows (лаба): выполнить `vssadmin delete shadows /All /Quiet` — ожидать детект Sigma и Hunt.
3) Linux (лаба): `truncate -s 0 /var/log/auth.log` или `echo > ~/.bash_history` — ожидать Linux Sigma/Hunt.
4) Зафиксировать легит-процессы (backup/maintenance) и добавить в allow-lists (DetCards).