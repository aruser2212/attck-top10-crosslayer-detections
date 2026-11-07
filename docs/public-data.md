# Открытые данные для проверки LSASS-кандидата

Проверено 2026-11-06. Найдены публичные лабораторные записи с реальной структурой Sysmon. Они позволяют проверить [LSASS-предикат и нормализацию](lsass.md), но не дают репрезентативной оценки эксплуатационных precision/TPR/FPR. Название атаки, файл или техника ATT&CK не являются разметкой каждой записи.

Полные commit SHA, URL, размеры, SHA256 исходников, сведения о лицензиях и ограничения полей сохранены в [манифесте](data/lsass-public-sources.json). В репозиторий включены только наши описания и результаты; исходные журналы и сторонний парсер остаются в игнорируемом `artifacts/`.

## Что фактически проверено

| Источник | Проверенные события | Результат |
|---|---:|---|
| [EVTX-ATTACK-SAMPLES: Mimikatz / LSASS](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/4ceed2f4706daf601c212a8f91c113dd85349a2c/Credential%20Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx) | 1 Sysmon 10 v3 | Маска `0x00001010`, полные GUID и native metadata. Один ожидаемый кандидат офлайн и на Basic. |
| [Splunk: ProcDump capture](https://github.com/splunk/attack_data/blob/c8af10d015d392fca97f9eb65181e9f06bc18e40/datasets/attack_techniques/T1003.001/atomic_red_team/procdump_t1003.001_capattack.zip) | 54 Sysmon-записи, из них 20 Sysmon 10 v3 | В этих 20 записях нет цели `lsass.exe`: ноль кандидатов офлайн и на Basic. Две записи содержат LSASS как **источник**, не цель. |
| [OTRF: Dumpert](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip) | 118 JSON-записей, 44 Sysmon 10 | Два LSASS-target события с `0x1fffff`. Просмотр полей; native replay не заявляется. |
| [OTRF: comsvcs](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs.zip) | 184 JSON-записи, 68 Sysmon 10 | Два LSASS-target события с `0x1410`/`0x1fffff`. Просмотр полей; native replay не заявляется. |
| [OTRF: Task Manager](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip) | 5489 JSON-записей, 1962 Sysmon 10 | 27 LSASS-target событий: только три имеют VM_READ; остальные 24 записи не имеют этого бита. Просмотр полей; native replay не заявляется. |

Для двух EVTX-источников проверены строгая нормализация, одинаковые полные алерты офлайн/Basic, чтение страницами по одному событию и повтор ingestion без новых документов. Предварительные ожидания — `1 → 1` и `20 → 0` — заданы по содержимому источника. Эти 20 несовпадений не объявляются независимо размеченными benign-событиями. Один совпавший экземпляр не является оценкой recall.

OTRF Dumpert/comsvcs не содержат native version/record identity. В Task Manager есть `Version` и `RecordNumber`, но нет исходного `System/TimeCreated`. `UtcTime` и время коллектора имеют другую семантику. Нельзя выдумывать отсутствующие поля, приписывать timezone или переименовывать collector time в native envelope time ради прохождения строгого профиля. Для этих JSON нужен отдельный явный контракт импорта.

## Лицензии и происхождение

У закреплённого EVTX-ATTACK-SAMPLES указана [GPL-3.0](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/4ceed2f4706daf601c212a8f91c113dd85349a2c/LICENSE.GPL), у Splunk — [Apache-2.0](https://github.com/splunk/attack_data/blob/c8af10d015d392fca97f9eb65181e9f06bc18e40/LICENSE). В закреплённом OTRF есть противоречие: [LICENSE](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE) и значок README говорят MIT, а раздел лицензии в том же README — GPL-3.0. В манифесте это оставлено как неразрешённое различие. MIT-лицензия нашего кода не заменяет условия внешних наборов.

## Воспроизведение двух EVTX-проверок

Команды выполняются из корня репозитория при работающем `make lab-up`. Парсер установлен отдельно от зависимостей проекта; сетевой доступ нужен только для загрузки закреплённых файлов. Скрипт читает один известный EVTX-член ZIP в память и не распаковывает архив целиком, не запускает содержимое записей. Создаётся только временный индекс с уникальным именем, который удаляется после проверки.

```bash
.venv/bin/python -m pip install --target artifacts/public-data/parser python-evtx==0.8.1 hexdump==3.3
```

`python-evtx 0.8.1` по умолчанию преобразует FILETIME через `float`, что может округлять даже микросекунды. Для записи 4807 стандартный экспорт дал `.661928`, а исходное целое FILETIME соответствует `.6619304`: разница 2,4 µs. Поэтому этот лабораторный пример переопределяет только представление FILETIME через целочисленное деление. Это ограниченный рецепт для указанной версии парсера, не production EVTX collector.

```bash
.venv/bin/python - <<'PY'
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
from importlib.metadata import version
import json
from pathlib import Path
import sys
from urllib.request import urlopen
from uuid import uuid4
from zipfile import ZipFile
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path('artifacts/public-data/parser').resolve()))
from Evtx.Evtx import Evtx
from Evtx.Nodes import FiletimeTypeNode
assert version('python-evtx') == '0.8.1'
from tools.normalize_windows_sysmon import normalize_event
from tools.detect_lsass import evaluate_events
from tools import elastic_lsass as basic

def exact_filetime(node):
    seconds, ticks = divmod(node.unpack_qword(0), 10_000_000)
    stamp = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return stamp.strftime('%Y-%m-%dT%H:%M:%S') + f'.{ticks:07d}Z'

FiletimeTypeNode.string = exact_filetime
manifest = json.loads(Path('docs/data/lsass-public-sources.json').read_text())
directory = Path('artifacts/public-lsass-replay')
directory.mkdir(parents=True, exist_ok=True)
client = basic.ElasticClient('http://127.0.0.1:19200')
license = client.request('GET', '/_license')['license']
assert license['type'] == 'basic' and license['status'] == 'active'
ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

for entry in manifest['sources']:
    if 'expected_candidates' not in entry:
        continue  # OTRF JSON is intentionally outside the native XML contract.
    size = entry.get('archive_bytes', entry.get('bytes'))
    with urlopen(entry['url'], timeout=30) as response:
        data = response.read(size + 1)
    assert len(data) == size and sha256(data).hexdigest() == entry['sha256']
    if 'member' in entry:
        with ZipFile(BytesIO(data)) as archive:
            assert archive.getinfo(entry['member']).file_size == entry['member_bytes']
            data = archive.read(entry['member'])
        assert sha256(data).hexdigest() == entry['member_sha256']
    path = directory / (sha256(data).hexdigest() + '.evtx')
    if path.exists():
        assert path.read_bytes() == data
    else:
        path.write_bytes(data)
    events = []
    with Evtx(str(path)) as source:
        for record in source.records():
            xml = record.xml()
            if ET.fromstring(xml).findtext('e:System/e:EventID', namespaces=ns) == '10':
                events.append(normalize_event(xml))
    assert len(events) == entry['event10_records']
    offline = evaluate_events(events)
    assert len(offline['alerts']) == entry['expected_candidates']
    index = 'attck-test-public-lsass-' + uuid4().hex
    basic.create_index(client, index)
    try:
        basic.ingest_events(client, index, events)
        native = basic.evaluate_index(client, index, page_size=1)
        assert native['alerts'] == offline['alerts']
        assert basic.ingest_events(client, index, events)['inserted_events'] == 0
        print(entry['provider'], len(events), len(native['alerts']), 'offline == Basic')
    finally:
        client.request('DELETE', basic.index_path(index))
PY
```

Эти результаты дополняют ручные synthetic fixtures. Для измерения эксплуатационной точности дальше нужны независимые labels, определённая единица наблюдения, репрезентативная легитимная активность, период наблюдения и проверенная полнота сбора. В текущих найденных и проверенных файлах такой выборки нет.

## Дополнительная пара NewCredentials / 4672

Для [сессионного пилота](newcredentials.md) отдельно прочитан закреплённый
[EVTX с исходной машины](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/4ceed2f4706daf601c212a8f91c113dd85349a2c/Lateral%20Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx).
В нём два события: 4624 v0 с LT9/seclogo и 4672 v0, совпадающие по LUID/SID.
Оба имеют исходное `SystemTime=2019-03-18T11:06:29.9115792Z`; строгое требование
«4672 позже 4624» потеряло бы эту пару. Запись не устанавливает универсального
порядка публикации Windows audit events.

Источник не содержит подтверждённого boot ID. Проверка проведена **условно**:
для выбранной пары явно задано исследовательское предположение одной загрузки
`public-capture-assumed-single-boot`. Оно не является извлечённым boot ID или
проверкой реального collector. При этом предположении строгая нормализация,
офлайн-расчёт и Basic дают один одинаковый кандидат с временным смещением 0;
повтор ingestion добавляет ноль записей. Для рабочих данных boot scope должен
быть подтверждён отдельно, как требует контракт пилота.

URL, SHA256, GPL-3.0, версия парсера, точные метаданные и ограничение предположения
сохранены в [отдельном манифесте](data/newcredentials-public-source.json).
EVTX и экспортированный XML находятся только в игнорируемых исследовательских
артефактах. Здесь также использовано целочисленное представление FILETIME,
описанное выше. Эта пара не даёт оценки precision/TPR/FPR.
