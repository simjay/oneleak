import json

import pytest

import oneleaks
from oneleaks import sarif
from oneleaks.cli import main

MIXED = 'key = "sk-proj-' + "a" * 24 + '"\nemail = "alice@corp.com"\n'


@pytest.fixture
def findings():
    return oneleaks.scan(MIXED).findings


class TestSarifDocument:
    def test_declares_schema_and_version(self, findings):
        doc = sarif.to_sarif(findings, version="1.2.3")
        assert doc["version"] == "2.1.0"
        assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
        assert doc["runs"][0]["tool"]["driver"]["version"] == "1.2.3"

    def test_every_result_rule_is_declared(self, findings):
        # GitHub silently drops results whose ruleId has no descriptor.
        run = sarif.to_sarif(findings, version="0")["runs"][0]
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        assert {r["ruleId"] for r in run["results"]} <= declared

    def test_rules_are_declared_once_each(self):
        text = MIXED + '\nother = "sk-proj-' + "b" * 24 + '"\n'
        run = sarif.to_sarif(oneleaks.scan(text).findings, version="0")["runs"][0]
        ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert len(ids) == len(set(ids))

    def test_severity_maps_onto_sarif_levels(self):
        # SARIF has three levels, not four severities.
        assert sarif._LEVELS["critical"] == "error"
        assert sarif._LEVELS["high"] == "warning"
        assert sarif._LEVELS["medium"] == "warning"
        assert sarif._LEVELS["low"] == "note"

    def test_region_is_one_based_even_without_a_line(self, findings):
        # startLine is required, and text input carries no line number.
        for result in sarif.to_sarif(findings, version="0")["runs"][0]["results"]:
            region = result["locations"][0]["physicalLocation"]["region"]
            assert region["startLine"] >= 1 and region["startColumn"] >= 1

    def test_fingerprints_let_github_dedup_across_runs(self, findings):
        for result in sarif.to_sarif(findings, version="0")["runs"][0]["results"]:
            assert result["partialFingerprints"]["oneleaksFingerprint/v1"]

    def test_no_raw_secret_reaches_the_report(self, findings):
        blob = sarif.dumps(findings, version="0")
        assert "sk-proj-" + "a" * 24 not in blob
        assert "alice@corp.com" not in blob

    def test_empty_findings_is_still_a_valid_log(self):
        doc = sarif.to_sarif([], version="0")
        assert doc["runs"][0]["results"] == []
        assert doc["runs"][0]["tool"]["driver"]["rules"] == []


class TestSarifViaCLI:
    def test_writes_the_file_and_keeps_the_exit_code(self, tmp_path, capsys):
        (tmp_path / "app.py").write_text(MIXED)
        out = tmp_path / "r.sarif"
        code = main(["scan", str(tmp_path), "--sarif", str(out)])
        capsys.readouterr()
        assert code == 1
        assert json.loads(out.read_text())["runs"][0]["results"]

    def test_respects_category_filtering(self, tmp_path, capsys):
        (tmp_path / "app.py").write_text(MIXED)
        out = tmp_path / "r.sarif"
        main(["scan", str(tmp_path), "--category", "secret", "--sarif", str(out)])
        capsys.readouterr()
        run = json.loads(out.read_text())["runs"][0]
        assert {r["ruleId"] for r in run["results"]} == {"openai-api-key"}
