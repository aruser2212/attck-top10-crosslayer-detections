from tools.check_yara import check_yara


def test_all_yara_rules_compile_and_match_inert_fixtures():
    result = check_yara()
    assert result["rules"] == 2
    assert len(result["cases"]) >= 15
