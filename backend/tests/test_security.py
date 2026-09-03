import pytest
from artemis.api.security import AuthToken, TokenError, TransportPolicy, OriginVerdict

def test_auth_token_valid():
    token_str = "a" * 64
    token = AuthToken(token_str)
    assert token.verify_bearer(f"Bearer {token_str}")
    
def test_auth_token_invalid_hex():
    with pytest.raises(TokenError):
        AuthToken("z" * 64)
        
def test_auth_token_short():
    with pytest.raises(TokenError):
        AuthToken("a" * 32)
        
def test_auth_token_verify_invalid():
    token = AuthToken("a" * 64)
    assert not token.verify_bearer(f"Bearer {'b' * 64}")
    assert not token.verify_bearer("Bearer ")
    assert not token.verify_bearer("InvalidFormat")
    assert not token.verify_bearer(None)

def test_auth_token_subprotocol():
    token_str = "a" * 64
    token = AuthToken(token_str)
    assert token.verify_subprotocols(["artemis.v1", f"bearer.{token_str}"])
    assert not token.verify_subprotocols(["artemis.v1", f"bearer.{'b'*64}"])
    assert not token.verify_subprotocols([f"bearer.{token_str}"]) # Missing artemis.v1
    assert not token.verify_subprotocols(None)

def test_transport_policy_host():
    policy = TransportPolicy.for_binding("127.0.0.1", 8080, dev_mode=False)
    assert policy.check_host("127.0.0.1:8080")
    assert not policy.check_host("localhost:8080") # We bound strictly to 127.0.0.1
    assert not policy.check_host("evil.com")

def test_transport_policy_origin():
    policy = TransportPolicy.for_binding("127.0.0.1", 8080, dev_mode=False)
    assert policy.check_origin("http://tauri.localhost") == OriginVerdict.OK
    assert policy.check_origin("http://evil.com") == OriginVerdict.REJECTED
    assert policy.check_origin(None) == OriginVerdict.MISSING
