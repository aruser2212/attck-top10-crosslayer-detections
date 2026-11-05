import pytest
from subprocess import CompletedProcess

from tools.check_network import check_network, load_inventory, run_suricata


@pytest.mark.parametrize("replay", [False, True])
def test_docker_cold_pull_diagnostics_do_not_become_container_identity(monkeypatch, tmp_path, replay):
    """Fresh workers may pull on create; only stdout is Docker's machine result."""
    cid = "a" * 64
    copied = []
    removed = []

    def fake_run(command, **kwargs):
        operation, *args = command[2:]
        if operation == "create":
            return CompletedProcess(command, 0, cid + "\n",
                                    "Unable to find image locally\nPulling layers...\n")
        if operation == "cp":
            copied.append(args)
            assert args[0].startswith(cid + ":") or args[1].startswith(cid + ":")
            assert all("Pulling" not in arg for arg in args)
            return CompletedProcess(command, 0, "", "")
        if operation == "start":
            assert args == ["-a", cid]
            return CompletedProcess(command, 0, "engine stdout\n", "engine diagnostics\n")
        if operation == "inspect":
            assert args[-1] == cid
            return CompletedProcess(command, 0, "0\n", "Docker diagnostic on stderr\n")
        if operation == "rm":
            removed.append(args[-1])
            return CompletedProcess(command, 0, cid + "\n", "")
        pytest.fail(f"Unexpected Docker operation: {operation}")

    monkeypatch.setattr("tools.check_network.subprocess.run", fake_run)
    assert run_suricata(tmp_path, replay=replay) == "engine stdout\nengine diagnostics\n"
    assert copied[0] == [str(tmp_path / "all.rules"), cid + ":/tmp/all.rules"]
    assert len(copied) == (3 if replay else 1)
    assert removed == [cid]


def test_docker_failure_preserves_stdout_and_stderr_diagnostics(monkeypatch, tmp_path):
    def fake_run(command, **kwargs):
        return CompletedProcess(command, 125, "create output\n", "registry request failed\n")

    monkeypatch.setattr("tools.check_network.subprocess.run", fake_run)
    with pytest.raises(RuntimeError, match=r"(?s)125.*create output.*registry request failed"):
        run_suricata(tmp_path, replay=False)


def test_network_fixture_inventory_covers_all_signatures():
    paths, manifest = load_inventory()
    assert len(paths) == 6
    assert len(manifest["expected_sids"]) == 9


@pytest.mark.network
def test_suricata_compiles_and_replays_every_signature():
    result = check_network()
    assert result["compile"] == "passed"
    assert result["replay"] == "passed"
    assert len(result["cases"]) >= 25
