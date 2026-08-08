import pytest


@pytest.fixture(autouse=True)
def stable_fingerprint_key(monkeypatch):
    """Give every test a deterministic HMAC key so fingerprints are stable
    across test runs without relying on the random per-process session key.
    """
    monkeypatch.setenv("ONELEAK_FINGERPRINT_KEY", "test-fingerprint-key")
