"""Test cho backend/store.py — kho mã hóa, phiên, sao lưu (Req 6-9)."""
from __future__ import annotations

import time

import pytest

import store

SECRET = "JBSWY3DPEHPK3PXP"
PW = "matkhau123"


def fresh_session():
    """Tạo một Session mới (mô phỏng tiến trình mới mở app)."""
    return store.Session()


# ----------------------- setup / unlock / lock (Req 6) -----------------------
def test_setup_initializes_and_unlocks():
    # Req 6.1
    assert store.is_initialized() is False  # Req 6.5
    store.session.setup(PW)
    assert store.is_initialized() is True
    assert store.session.is_unlocked() is True


def test_unlock_with_correct_password():
    # Req 6.2 — phiên mới mở khóa được vault đã setup.
    store.session.setup(PW)
    s2 = fresh_session()
    s2.unlock(PW)
    assert s2.is_unlocked() is True


def test_unlock_wrong_password_raises_and_stays_locked():
    # Req 6.3
    store.session.setup(PW)
    s2 = fresh_session()
    with pytest.raises(store.WrongPassword):
        s2.unlock("saibet")
    assert s2.is_unlocked() is False


def test_lock_clears_unlock():
    # Req 6.4
    store.session.setup(PW)
    store.session.lock()
    assert store.session.is_unlocked() is False


# ----------------------- auto-lock (Req 7) -----------------------
def test_auto_lock_after_idle():
    # Req 7.1 — quá AUTO_LOCK_SECONDS thì coi như khóa.
    store.session.setup(PW)
    store.session.last_activity = time.time() - (store.AUTO_LOCK_SECONDS + 5)
    assert store.session.is_unlocked() is False


def test_activity_extends_lock_deadline():
    # Req 7.2 — thao tác cập nhật last_activity, dời mốc auto-lock.
    store.session.setup(PW)
    store.session.last_activity = time.time() - (store.AUTO_LOCK_SECONDS - 10)
    before = store.session.last_activity
    store.session.add_account("Acc", SECRET)  # thao tác ghi -> touch()
    assert store.session.last_activity > before
    assert store.session.is_unlocked() is True


def test_remaining_idle_zero_when_locked():
    # Req 7.3
    store.session.setup(PW)
    store.session.lock()
    assert store.session.remaining_idle() == 0


def test_missing_vault_file_treated_as_locked():
    # Hardening: file vault bị xóa khi phiên còn mở -> coi như khóa, không 500.
    store.session.setup(PW)
    assert store.session.is_unlocked() is True
    store.VAULT_PATH.unlink()  # xóa file vault
    assert store.session.is_unlocked() is False
    with pytest.raises(store.VaultLocked):
        store.session.load_accounts()


# ----------------------- CRUD tài khoản (Req 8) -----------------------
def test_add_and_load_account():
    # Req 8.1
    store.session.setup(PW)
    acc = store.session.add_account("Shop A", SECRET)
    assert acc["id"]
    loaded = store.session.load_accounts()
    assert any(a["id"] == acc["id"] for a in loaded)


def test_get_account_found_and_missing():
    # Req 8.2
    store.session.setup(PW)
    acc = store.session.add_account("Shop A", SECRET)
    assert store.session.get_account(acc["id"])["name"] == "Shop A"
    assert store.session.get_account("khongton tai") is None


def test_delete_existing_and_missing():
    # Req 8.3, 8.4
    store.session.setup(PW)
    acc = store.session.add_account("Shop A", SECRET)
    assert store.session.delete_account(acc["id"]) is True
    assert store.session.get_account(acc["id"]) is None
    assert store.session.delete_account("khong-co") is False


def test_operations_require_unlock():
    # Req 8.5
    store.session.setup(PW)
    store.session.lock()
    with pytest.raises(store.VaultLocked):
        store.session.load_accounts()


def test_vault_encrypted_at_rest():
    # Req 8.6 — file thô KHÔNG chứa secret ở dạng văn bản rõ.
    store.session.setup(PW)
    store.session.add_account("Shop A", SECRET)
    raw = store.VAULT_PATH.read_bytes()
    assert SECRET.encode() not in raw
    assert b"Shop A" not in raw


# ----------------------- export / import (Req 9) -----------------------
def test_export_import_roundtrip():
    # Req 9.1
    store.session.setup(PW)
    store.session.add_account("Shop A", SECRET, digits=6, period=30, algorithm="SHA1")
    store.session.add_account("Shop B", "GEZDGNBVGY3TQOJQ")
    backup = store.session.export_backup("backup99")

    # Xóa hết rồi khôi phục.
    for a in list(store.session.load_accounts()):
        store.session.delete_account(a["id"])
    assert store.session.load_accounts() == []

    added = store.session.import_backup("backup99", backup)
    assert added == 2
    names = {a["name"] for a in store.session.load_accounts()}
    assert names == {"Shop A", "Shop B"}


def test_import_wrong_password_raises():
    # Req 9.2
    store.session.setup(PW)
    store.session.add_account("Shop A", SECRET)
    backup = store.session.export_backup("backup99")
    with pytest.raises(store.WrongPassword):
        store.session.import_backup("saibet", backup)


def test_import_invalid_type_raises():
    # Req 9.3
    store.session.setup(PW)
    with pytest.raises(ValueError):
        store.session.import_backup(PW, {"type": "khong-hop-le", "salt": "x", "data": "y"})


def test_import_skips_duplicates():
    # Req 9.4
    store.session.setup(PW)
    store.session.add_account("Shop A", SECRET)
    backup = store.session.export_backup("backup99")
    # Import lại vào kho đã có chính nó -> bỏ qua trùng.
    added = store.session.import_backup("backup99", backup)
    assert added == 0
    assert len(store.session.load_accounts()) == 1


def test_import_assigns_new_ids():
    # Req 9.5
    store.session.setup(PW)
    store.session.add_account("Shop A", SECRET)
    backup = store.session.export_backup("backup99")
    old_ids = {a["id"] for a in store.session.load_accounts()}
    # Xóa hết rồi import lại -> id mới khác id trong backup.
    for a in list(store.session.load_accounts()):
        store.session.delete_account(a["id"])
    store.session.import_backup("backup99", backup)
    new_ids = {a["id"] for a in store.session.load_accounts()}
    assert new_ids.isdisjoint(old_ids)


# ----------------------- rename / reorder -----------------------
def test_rename_account():
    store.session.setup(PW)
    acc = store.session.add_account("Cu", SECRET)
    out = store.session.rename_account(acc["id"], "Moi")
    assert out["name"] == "Moi"
    assert store.session.get_account(acc["id"])["name"] == "Moi"


def test_rename_missing_returns_none():
    store.session.setup(PW)
    assert store.session.rename_account("khong-co", "X") is None


def test_rename_empty_falls_back_default():
    store.session.setup(PW)
    acc = store.session.add_account("Cu", SECRET)
    out = store.session.rename_account(acc["id"], "   ")
    assert out["name"] == "Tài khoản"


def test_reorder_accounts():
    store.session.setup(PW)
    a = store.session.add_account("A", SECRET)
    b = store.session.add_account("B", SECRET)
    c = store.session.add_account("C", SECRET)
    store.session.reorder_accounts([c["id"], a["id"], b["id"]])
    names = [x["name"] for x in store.session.load_accounts()]
    assert names == ["C", "A", "B"]


def test_reorder_keeps_unmentioned_at_end():
    store.session.setup(PW)
    a = store.session.add_account("A", SECRET)
    b = store.session.add_account("B", SECRET)
    c = store.session.add_account("C", SECRET)
    # Chỉ nhắc tới b -> b lên đầu, a và c giữ thứ tự cũ ở sau.
    store.session.reorder_accounts([b["id"], "id-rac"])
    names = [x["name"] for x in store.session.load_accounts()]
    assert names == ["B", "A", "C"]
