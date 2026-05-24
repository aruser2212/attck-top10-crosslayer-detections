# План тестирования: T1053 Scheduled Task / Cron

Цели:
- Поймать создание задач (4698/106) в Windows.
- Поймать изменения cron в Linux.
- Проверить first-seen и отстроить allow-list.

Шаги (лабораторно/описательно):
1) Windows: создать тестовую задачу (`schtasks /create ...`) — ожидать 4698/106 и срабатывание Hunt first-seen.
2) Linux: отредактировать `/etc/crontab` или `crontab -e` для тестового пользователя — ожидать событие auditd и Hunt first-seen.
3) Добавить легит-источники (деплой/агенты) в allow-lists DetCards; зафиксировать тюнинг.
