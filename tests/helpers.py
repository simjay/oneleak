"""Small helpers shared by more than one test file."""


def rule_ids(result):
    """The ids of the rules that fired, e.g. ["openai-api-key", "email"]."""
    return [f.rule_id for f in result.findings]
