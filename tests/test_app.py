from fastapi.testclient import TestClient

from app import app


client = TestClient(app)


def test_healthz():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_audit_detects_and_redacts_secret():
    response = client.post("/api/audit", json={"client_name": "Acme", "code_snippet": 'API_KEY = "super-secret-value"'})
    assert response.status_code == 200
    payload = response.json()
    assert any(item["cwe"] == "CWE-798" for item in payload["ast_findings"])
    assert "super-secret-value" not in payload["ast_findings"][0]["snippet"]
    assert payload["thread_id"] is None
    assert payload["sarif"]["version"] == "2.1.0"
    assert payload["metrics"]["finding_count"] >= 1


def test_audit_rejects_unknown_fields():
    response = client.post("/api/audit", json={"client_name": "Acme", "code_snippet": "print(1)", "unexpected": True})
    assert response.status_code == 422


def test_ui_uses_text_content_for_findings():
    response = client.get("/")
    assert response.status_code == 200
    assert "textContent" in response.text
    assert "innerHTML" not in response.text
