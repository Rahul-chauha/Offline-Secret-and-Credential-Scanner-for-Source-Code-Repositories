# Test credentials - obvious dummy placeholders that false-positive filter should identify as Low/Placeholder
TEST_PASSWORD = "changeme"
TEST_CLIENT_KEY = "stale-client-key"
DUMMY_TOKEN = "dummy_token_12345678"

def test_login():
    assert TEST_PASSWORD == "changeme"
