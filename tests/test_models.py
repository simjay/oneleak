from oneleak.models import Finding, ScanResult


def _finding(severity):
    return Finding(rule_id="r", category="secret", type="t", severity=severity, start=0, end=1)


class TestScanResult:
    def test_safe_true_when_no_findings(self):
        assert ScanResult(findings=[]).safe is True

    def test_safe_false_when_findings(self):
        assert ScanResult(findings=[_finding("low")]).safe is False

    def test_risk_none_when_no_findings(self):
        assert ScanResult(findings=[]).risk is None

    def test_risk_is_highest_severity(self):
        result = ScanResult(findings=[_finding("low"), _finding("critical"), _finding("medium")])
        assert result.risk == "critical"
