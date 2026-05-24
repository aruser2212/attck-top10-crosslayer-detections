# Coverage Matrix

This table is generated from the current repository structure.

| Technique folder | ATT&CK IDs in DetCards | DetCards | Sigma | Hunts | IDPS | YARA | Tests | Status |
|---|---|---:|---:|---:|---:|---:|---:|---|
| `T1003_OS_Credential_Dumping` | `T1003.001` | 1 | 1 | 1 | 0 | 0 | 1 | stable |
| `T1053_Scheduled_Task` | `T1053` | 2 | 3 | 2 | 0 | 0 | 1 | stable,test |
| `T1070_Indicator_Removal` | `T1070, T1490` | 2 | 3 | 3 | 0 | 0 | 1 | stable |
| `T1078_Valid_Accounts` | `T1078` | 2 | 2 | 2 | 0 | 0 | 1 | test |
| `T1110_Brute_Force` | `T1110` | 2 | 2 | 3 | 1 | 0 | 1 | test |
| `T1190_Exploit_Public_Facing_App` | `T1190, T1505.003` | 2 | 2 | 2 | 2 | 1 | 1 | stable,test |
| `T1550_Use_Alt_Auth` | `T1550` | 2 | 1 | 3 | 0 | 0 | 1 | stable,test |
| `T1558_003_Kerberoasting` | `T1558.003` | 2 | 1 | 2 | 0 | 0 | 1 | stable,test |
| `T1566_Phishing` | `T1566` | 2 | 2 | 2 | 2 | 1 | 1 | stable,test |
| `T1569_002_Service_Execution` | `T1569.002` | 2 | 2 | 2 | 1 | 0 | 1 | stable,test |

## Detection IDs

### `T1003_OS_Credential_Dumping`

- `DET-WIN-T1003-LSASS-001` — T1003.001

### `T1053_Scheduled_Task`

- `DET-LNX-T1053-CRON-MOD-002` — T1053
- `DET-WIN-T1053-SCHTASK-4698-001` — T1053

### `T1070_Indicator_Removal`

- `DET-WIN-T1070-LOGCLEAR-001` — T1070
- `DET-WIN-T1070-VSS-DELETE-002` — T1490

### `T1078_Valid_Accounts`

- `DET-LNX-T1078-SSH-VALID-002` — T1078
- `DET-WIN-T1078-VALIDLOGON-001` — T1078

### `T1110_Brute_Force`

- `DET-LNX-T1110-SSH-BRUTE-002` — T1110
- `DET-WIN-T1110-4625-BRUTE-001` — T1110

### `T1190_Exploit_Public_Facing_App`

- `DET-WEB-T1190-WEBROOT-FILECREATE-001` — T1190, T1505.003
- `DET-WEB-T1190-WEBSHELL-ACCESS-002` — T1190, T1505.003

### `T1550_Use_Alt_Auth`

- `DET-WIN-T1550-PTH-NEWCRED-001` — T1550
- `DET-WIN-T1550-PTT-KRB-ANOM-002` — T1550

### `T1558_003_Kerberoasting`

- `DET-WIN-T1558-KRB-RC4-001` — T1558.003
- `DET-WIN-T1558-KRB-SPNBURST-002` — T1558.003

### `T1566_Phishing`

- `DET-WIN-T1566-HTA-LOADER-002` — T1566
- `DET-WIN-T1566-OFFICE-CHILD-001` — T1566

### `T1569_002_Service_Execution`

- `DET-WIN-T1569-PSEXEC-PIPES-002` — T1569.002
- `DET-WIN-T1569-SVC-7045-001` — T1569.002

