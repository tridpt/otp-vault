"""Test cho backend/main.py qua FastAPI TestClient (Req 10-11)."""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

import main

SECRET = "JBSWY3DPEHPK3PXP"
PW = "matkhau123"


@pytest.fixture
def client():
    return TestClient(main.app)


# ----------------------- Trạng thái & quy tắc khóa (Req 10) -----------------------
def test_status_uninitialized(client):
    # Req 10.1
    r = client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert body["initialized"] is False
    assert body["locked"] is True


def test_accounts_locked_returns_401(client):
    # Req 10.2
    assert client.get("/api/accounts").status_code == 401


@pytest.mark.parametrize(
    "method,path,json",
    [
        ("post", "/api/accounts", {"secret": SECRET}),
        ("post", "/api/accounts/import-uri", {"uri": "otpauth://totp/A?secret=" + SECRET}),
        ("delete", "/api/accounts/abc", None),
        ("get", "/api/accounts/abc/reveal", None),
        ("post", "/api/export", {"password": PW}),
        ("post", "/api/import", {"password": PW, "backup": {}}),
    ],
)
def test_protected_endpoints_require_unlock(client, method, path, json):
    # Req 10.3
    resp = getattr(client, method)(path, json=json) if json is not None else getattr(client, method)(path)
    assert resp.status_code == 401


def test_setup_short_password_400(client):
    # Req 10.4
    assert client.post("/api/setup", json={"password": "123"}).status_code == 400


def test_unlock_wrong_password_401(client):
    # Req 10.5
    client.post("/api/setup", json={"password": PW})
    main.session.lock()
    assert client.post("/api/unlock", json={"password": "saibet"}).status_code == 401


# ----------------------- Luồng đầu-cuối (Req 11) -----------------------
def test_setup_add_list_flow(client):
    # Req 11.1
    assert client.post("/api/setup", json={"password": PW}).status_code == 200
    assert client.post("/api/accounts", json={"name": "Shop A", "secret": SECRET}).status_code == 200
    r = client.get("/api/accounts")
    assert r.status_code == 200
    accs = r.json()["accounts"]
    assert len(accs) == 1
    assert accs[0]["code"] and len(accs[0]["code"]) == 6


def test_lock_unlock_flow(client):
    # Req 11.2
    client.post("/api/setup", json={"password": PW})
    client.post("/api/accounts", json={"name": "Shop A", "secret": SECRET})
    assert client.post("/api/lock").status_code == 200
    assert client.get("/api/accounts").status_code == 401
    assert client.post("/api/unlock", json={"password": PW}).status_code == 200
    r = client.get("/api/accounts")
    assert r.status_code == 200 and len(r.json()["accounts"]) == 1


def test_generate_without_unlock(client):
    # Req 11.3
    r = client.post("/api/generate", json={"secret": SECRET})
    assert r.status_code == 200
    assert len(r.json()["code"]) == 6


def test_generate_invalid_secret_400(client):
    # Req 11.4
    assert client.post("/api/generate", json={"secret": "10101010"}).status_code == 400


def test_delete_missing_returns_404(client):
    # Req 11.5
    client.post("/api/setup", json={"password": PW})
    assert client.delete("/api/accounts/khong-ton-tai").status_code == 404


def test_reveal_returns_qr_and_secret(client):
    # Bổ sung: reveal trả secret + otpauth + QR.
    client.post("/api/setup", json={"password": PW})
    add = client.post("/api/accounts", json={"name": "Shop A", "secret": SECRET}).json()
    r = client.get(f"/api/accounts/{add['id']}/reveal")
    assert r.status_code == 200
    body = r.json()
    assert body["secret"] == SECRET
    assert body["otpauth"].startswith("otpauth://")
    assert body["qr_svg"] and "<svg" in body["qr_svg"]


def test_import_via_api_roundtrip(client):
    # Bổ sung: export rồi import qua API.
    client.post("/api/setup", json={"password": PW})
    client.post("/api/accounts", json={"name": "Shop A", "secret": SECRET})
    backup = client.post("/api/export", json={"password": "backup99"}).json()
    # Xóa hết.
    for a in client.get("/api/accounts").json()["accounts"]:
        client.delete(f"/api/accounts/{a['id']}")
    res = client.post("/api/import", json={"password": "backup99", "backup": backup})
    assert res.status_code == 200
    assert res.json()["added"] == 1
