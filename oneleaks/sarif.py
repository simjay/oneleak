"""SARIF 2.1.0 output, for GitHub code scanning and other SARIF consumers."""

from __future__ import annotations

import json

from oneleaks.models import Finding

SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

# SARIF has three result levels, not four severities. `medium` maps to
# `warning` alongside `high`: SARIF's `note` is advisory, and a medium finding
# is not advisory.
_LEVELS = {"critical": "error", "high": "warning", "medium": "warning", "low": "note"}


def _rule_descriptor(finding: Finding) -> dict:
    return {
        "id": finding.rule_id,
        "name": finding.type,
        "shortDescription": {"text": f"{finding.category}: {finding.type}"},
        "defaultConfiguration": {"level": _LEVELS.get(finding.severity, "warning")},
        "properties": {"category": finding.category, "severity": finding.severity},
    }


def _result(finding: Finding) -> dict:
    result = {
        "ruleId": finding.rule_id,
        "level": _LEVELS.get(finding.severity, "warning"),
        "message": {"text": f"{finding.severity} {finding.type} detected ({finding.preview})"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path or "stdin"},
                    # SARIF regions are 1-based and startLine is required, so a
                    # finding from raw text with no line still needs a value.
                    "region": {
                        "startLine": finding.line or 1,
                        "startColumn": finding.column or 1,
                    },
                }
            }
        ],
    }
    if finding.fingerprint:
        # Lets GitHub track one finding across runs instead of reopening it.
        result["partialFingerprints"] = {"oneleaksFingerprint/v1": finding.fingerprint}
    return result


def to_sarif(findings: list[Finding], *, version: str) -> dict:
    """A SARIF log for `findings`.

    Every rule that produced a result is declared in `tool.driver.rules`;
    GitHub drops results whose `ruleId` has no descriptor.
    """
    rules: dict[str, dict] = {}
    for finding in findings:
        rules.setdefault(finding.rule_id, _rule_descriptor(finding))
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "oneleaks",
                        "version": version,
                        "informationUri": "https://github.com/simjay/oneleaks",
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }


def dumps(findings: list[Finding], *, version: str) -> str:
    return json.dumps(to_sarif(findings, version=version), indent=2)
