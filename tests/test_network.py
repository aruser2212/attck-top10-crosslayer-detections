import pytest

from tools.check_network import check_network, load_inventory


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
