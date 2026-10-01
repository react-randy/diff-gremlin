"""Publication metadata uses canonical official routes and rejects HTTP failures."""

import pytest

from scripts.image_publication_support import identity, transport


@pytest.mark.parametrize("endpoint", ["", "releases/tags/v1.0.1", "commits/main"])
def test_metadata_uses_canonical_repository_and_nested_routes(monkeypatch, endpoint):
    calls = []

    def observed(url, headers):
        calls.append((url, headers))
        return 200, {"identity": "controlled response"}

    monkeypatch.setattr(transport, "http_json", observed)
    assert identity.github_metadata(endpoint) == {"identity": "controlled response"}
    expected = "https://api.github.com/repos/react-randy/diff-gremlin"
    if endpoint:
        expected += "/" + endpoint
    assert calls[0][0] == expected
    assert "Authorization" not in calls[0][1]


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500])
def test_canonical_metadata_keeps_http_failure_gate(monkeypatch, status):
    monkeypatch.setattr(transport, "http_json", lambda *_: (status, {}))
    with pytest.raises(ValueError, match=rf"identity lookup failed \(HTTP {status}\)"):
        identity.github_metadata("")
