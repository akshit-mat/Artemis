import json
import logging
from artemis.obs.logging import _is_sensitive, _scrub, _digest, redact_processor

def test_is_sensitive():
    assert _is_sensitive("token")
    assert _is_sensitive("Auth_Token")
    assert _is_sensitive("PASSWORD")
    assert not _is_sensitive("username")
    assert not _is_sensitive("token_fingerprint")

def test_scrub_and_digest():
    raw = "super_secret_value"
    digested = _digest(raw)
    assert "redacted" in digested
    assert "super_secret" not in digested
    
    # Test dictionary scrubbing
    data = {
        "token": "secret",
        "nested": {
            "password": "pass",
            "safe": "value"
        }
    }
    scrubbed = _scrub(data)
    assert "redacted" in scrubbed["token"]
    assert "redacted" in scrubbed["nested"]["password"]
    assert scrubbed["nested"]["safe"] == "value"

def test_redact_processor():
    event = {"event": "login", "password": "123", "normal": "abc"}
    processed = redact_processor(None, "info", event)
    assert "redacted" in processed["password"]
    assert processed["normal"] == "abc"
    assert processed["event"] == "login"
