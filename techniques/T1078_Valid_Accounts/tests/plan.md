# План тестирования T1078
1) В логе Windows сымитировать успешные логины 4624 (LT 3/10) от нового источника для тестового пользователя — проверить Hunt first-seen.
2) В логе Linux сымитировать "Accepted password/publickey" для нового src.ip — проверить Hunt first-seen.
3) Зафиксировать легит-источники (jump-host/automation) и добавить в allowlists.
