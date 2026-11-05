#!/usr/bin/env python3
"""Load all network rules and replay inert generated PCAPs using pinned Suricata.

The container has no network access. Only rule files and synthetic PCAP data are
copied into it. Docker failures are fatal, never reported as passing checks.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "jasonish/suricata:8.0.4@sha256:8058c0580c48cae4013bb8d576e5fe7cfe59884ea5526239056825b70c849ec8"


def load_inventory(root: Path = ROOT) -> tuple[list[Path], dict]:
    paths = sorted(root.glob("techniques/*/network/*.rules"))
    if not paths:
        raise ValueError("No network rule files found")
    sids = [int(sid) for p in paths for sid in re.findall(
        r"\bsid\s*:\s*(\d+)\s*;", re.sub(r"(?m)^\s*#.*$", "", p.read_text()))]
    if len(sids) != len(set(sids)):
        raise ValueError("Duplicate network SID")
    manifest = json.loads((root / "tests/fixtures/network/cases.json").read_text())
    if not sids or set(sids) != set(manifest["expected_sids"]):
        raise ValueError("Network rule inventory differs from fixture manifest")
    if not manifest["cases"] or len({c["id"] for c in manifest["cases"]}) != len(manifest["cases"]):
        raise ValueError("Network case inventory is empty or has duplicate IDs")
    covered = {int(sid) for c in manifest["cases"] for sid, count in c["expected"].items() if count > 0}
    if covered != set(sids):
        raise ValueError("Every network SID must have a positive replay fixture")
    return paths, manifest


def generate_pcap(cases: list[dict], path: Path) -> dict[str, str]:
    """Generate checksummed TCP conversations; never send packets to a socket."""
    from scapy.all import Ether, IP, TCP, Raw, wrpcap
    from scapy.layers.netbios import NBTSession
    from scapy.layers.smb2 import (SMB2_Header, SMB2_Create_Request,
                                   SMB2_Tree_Connect_Request, SMB2_Tree_Connect_Response)

    packets = []
    clients = {}
    for index, case in enumerate(cases, start=1):
        outgoing = case.get("direction") == "outbound"
        client = f"10.0.1.{index}" if outgoing else f"198.51.100.{index}"
        server = "203.0.113.1" if outgoing else "10.0.0.1"
        clients[client] = case["id"]
        for flow in range(case.get("flows", 1)):
            sport = 40000 + index * 100 + flow
            dport = {"ssh": 22, "smb": 445}.get(case["kind"], 80)
            cseq, sseq = 1000, 2000
            now = 1760000000 + index * 120 + flow * 0.1

            def emit(client_to_server, flags, seq, ack, payload=b""):
                nonlocal now
                src, dst = (client, server) if client_to_server else (server, client)
                sp, dp = (sport, dport) if client_to_server else (dport, sport)
                packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack)
                if payload:
                    packet /= Raw(payload)
                packet.time = now
                now += 0.001
                packets.append(packet)

            def send(client_to_server, payload):
                nonlocal cseq, sseq
                payload = bytes(payload)
                emit(client_to_server, "PA", cseq if client_to_server else sseq,
                     sseq if client_to_server else cseq, payload)
                if client_to_server:
                    cseq += len(payload)
                else:
                    sseq += len(payload)
                emit(not client_to_server, "A", sseq if client_to_server else cseq,
                     cseq if client_to_server else sseq)

            emit(True, "S", cseq, 0)
            cseq += 1
            emit(False, "SA", sseq, cseq)
            sseq += 1
            emit(True, "A", cseq, sseq)
            if case["kind"] in {"http", "upload"}:
                uri = case.get("uri", "/upload")
                if case["kind"] == "upload":
                    body = ("--fixture\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
                            + case["filename"] + "\"\r\nContent-Type: text/plain\r\n\r\n"
                            "INERT TEXT mentioning .php .jsp .aspx; no executable content.\r\n--fixture--\r\n").encode()
                    request = (f"POST {uri} HTTP/1.1\r\nHost: fixture.example\r\nContent-Type: multipart/form-data; boundary=fixture\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
                else:
                    request = f"GET {uri} HTTP/1.1\r\nHost: fixture.example\r\n\r\n".encode()
                send(True, request)
                response = f"HTTP/1.1 200 OK\r\nContent-Type: {case.get('content_type', 'text/plain')}\r\nContent-Length: 5\r\n\r\nINERT".encode()
                send(False, response)
            elif case["kind"] == "ssh":
                send(False, b"SSH-2.0-OpenSSH_fixture_server\r\n")
                send(True, b"SSH-2.0-OpenSSH_fixture_client\r\n")
                for _ in range(case.get("extra_packets", 0)):
                    send(True, b"\x00\x00\x00\x0c\x04\x02fixture\x00\x00\x00\x00")
            elif case["kind"] == "smb":
                send(True, NBTSession() / SMB2_Header(Command=3, MID=1, SessionId=1) /
                     SMB2_Tree_Connect_Request(Path="\\\\fixture\\IPC$"))
                send(False, NBTSession() / SMB2_Header(Command=3, MID=1, SessionId=1, TID=1, Flags=1) /
                     SMB2_Tree_Connect_Response(ShareType=2))
                send(True, NBTSession() / SMB2_Header(Command=5, MID=2, SessionId=1, TID=1) /
                     SMB2_Create_Request(Name=case["pipe"]))
            else:
                raise ValueError(f"Unsupported fixture kind {case['kind']}")
            emit(True, "FA", cseq, sseq)
            cseq += 1
            emit(False, "FA", sseq, cseq)
            sseq += 1
            emit(True, "A", cseq, sseq)
    packets.sort(key=lambda p: p.time)
    if not packets:
        raise ValueError("No packets generated")
    wrpcap(str(path), packets)
    return clients


def run_suricata(directory: Path, *, replay: bool) -> str:
    env = {k: v for k, v in os.environ.items() if k not in
           {"DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"}}
    base = ["docker", "--host=unix:///var/run/docker.sock"]

    def docker(*args, timeout=120):
        result = subprocess.run([*base, *args], env=env, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"Docker/Suricata command failed ({result.returncode}):\n{result.stdout}{result.stderr}")
        return result.stdout + result.stderr

    args = ["-v", "-c", "/etc/suricata/suricata.yaml", "-S", "/tmp/all.rules", "-l", "/tmp",
            "--set", "vars.address-groups.HOME_NET=[10.0.0.0/8]", "--runmode", "single"]
    args += ["-r", "/tmp/fixtures.pcap"] if replay else ["-T"]
    cid = docker("create", "--network", "none", "--user", "suricata", "--cap-drop", "ALL",
                 "--entrypoint", "suricata", IMAGE, *args).strip()
    try:
        docker("cp", str(directory / "all.rules"), f"{cid}:/tmp/all.rules")
        if replay:
            docker("cp", str(directory / "fixtures.pcap"), f"{cid}:/tmp/fixtures.pcap")
        output = docker("start", "-a", cid)
        # Explicit exit status check: docker attach behavior must not hide failure.
        exit_code = int(docker("inspect", "--format", "{{.State.ExitCode}}", cid).strip())
        if exit_code:
            raise RuntimeError(f"Suricata exited {exit_code}:\n{output}")
        if replay:
            docker("cp", f"{cid}:/tmp/eve.json", str(directory / "eve.json"))
        return output
    finally:
        docker("rm", "-f", "-v", cid)


def check_network(root: Path = ROOT, *, compile_only: bool = False) -> dict:
    paths, manifest = load_inventory(root)
    with tempfile.TemporaryDirectory(prefix="attck-suricata-") as name:
        directory = Path(name)
        rules = directory / "all.rules"
        rules.write_text("\n".join(p.read_text() for p in paths))
        rules.chmod(0o644)
        compile_log = run_suricata(directory, replay=False)
        counts = re.search(r"(\d+) rules successfully loaded, (\d+) rules failed, (\d+) rules skipped", compile_log)
        expected_counts = (len(manifest["expected_sids"]), 0, 0)
        if not counts or tuple(map(int, counts.groups())) != expected_counts:
            raise AssertionError(f"Suricata did not load the complete expected inventory:\n{compile_log}")
        result = {"engine": "Suricata 8.0.4", "image": IMAGE,
                  "rules": len(manifest["expected_sids"]), "compile": "passed",
                  "scope": "native loading and synthetic offline replay; operational accuracy unmeasured"}
        if compile_only:
            result["replay"] = "not_run"
            return result
        clients = generate_pcap(manifest["cases"], directory / "fixtures.pcap")
        (directory / "fixtures.pcap").chmod(0o644)
        replay_log = run_suricata(directory, replay=True)
        packet_count = re.search(r"read 1 file, (\d+) packets", replay_log)
        if not packet_count or int(packet_count.group(1)) == 0:
            raise AssertionError(f"Suricata did not process fixture packets:\n{replay_log}")
        observed = defaultdict(Counter)
        for line in (directory / "eve.json").read_text().splitlines():
            event = json.loads(line)
            if event.get("event_type") != "alert":
                continue
            cid = clients.get(event.get("src_ip")) or clients.get(event.get("dest_ip"))
            if cid is None:
                raise AssertionError(f"Alert not attributable to a fixture: {event}")
            observed[cid][str(event["alert"]["signature_id"])] += 1
        results, failures = [], []
        for case in manifest["cases"]:
            actual = dict(observed[case["id"]])
            results.append({"id": case["id"], "alerts": actual})
            if actual != case["expected"]:
                failures.append(f"{case['id']}: expected {case['expected']}, got {actual}")
        if failures:
            raise AssertionError("\n".join(failures) + "\n" + replay_log)
        result["cases"] = results
        result["packets"] = int(packet_count.group(1))
        result["replay"] = "passed"
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--compile-only", action="store_true")
    args = parser.parse_args()
    print(json.dumps(check_network(args.root, compile_only=args.compile_only), indent=2))


if __name__ == "__main__":
    main()
