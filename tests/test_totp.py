"""Test cho backend/totp.py — sinh mã TOTP theo RFC 6238 (Req 2-5)."""
from __future__ import annotations

import base64

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

import totp


# ----------------------- RFC 6238 test vectors -----------------------
# Seed ASCII theo RFC 6238, mã hóa base32 để truyền cho generate_code.
def _b32(seed: bytes) -> str:
    return base64.b32encode(seed).decode("ascii")


SEED_SHA1 = _b32(b"12345678901234567890")
SEED_SHA256 = _b32(b"12345678901234567890123456789012")
SEED_SHA512 = _b32(b"1234567890123456789012345678901234567890123456789012345678901234")

# (algorithm, seed, at, expected 8-digit code) — bảng chuẩn RFC 6238.
RFC_VECTORS = [
    ("SHA1", SEED_SHA1, 59, "94287082"),
    ("SHA1", SEED_SHA1, 1111111109, "07081804"),
    ("SHA1", SEED_SHA1, 1234567890, "89005924"),
    ("SHA1", SEED_SHA1, 2000000000, "69279037"),
    ("SHA256", SEED_SHA256, 59, "46119246"),
    ("SHA256", SEED_SHA256, 1111111109, "68084774"),
    ("SHA256", SEED_SHA256, 1234567890, "91819424"),
    ("SHA256", SEED_SHA256, 2000000000, "90698825"),
    ("SHA512", SEED_SHA512, 59, "90693936"),
    ("SHA512", SEED_SHA512, 1111111109, "25091201"),
    ("SHA512", SEED_SHA512, 1234567890, "93441116"),
    ("SHA512", SEED_SHA512, 2000000000, "38618901"),
]


@pytest.mark.parametrize("algo,seed,at,expected", RFC_VECTORS)
def test_rfc6238_vectors(algo, seed, at, expected):
    # Req 2.1, 2.2, 2.3 — bắt buộc đúng cặp thời điểm–mã.
    assert totp.generate_code(seed, digits=8, period=30, algorithm=algo, at=at) == expected


@pytest.mark.parametrize("digits", [6, 7, 8])
def test_code_length_matches_digits(digits):
    # Req 2.4
    code = totp.generate_code(SEED_SHA1, digits=digits, at=59)
    assert len(code) == digits


def test_same_period_same_code():
    # Req 2.5 — hai lần gọi trong cùng chu kỳ cho cùng mã.
    a = totp.generate_code(SEED_SHA1, at=1000)
    b = totp.generate_code(SEED_SHA1, at=1019)  # cùng chu kỳ 30s (990..1019)
    assert a == b


def test_invalid_algorithm_raises():
    # Req 2.6
    with pytest.raises(totp.TOTPError):
        totp.generate_code(SEED_SHA1, algorithm="MD5", at=59)


# ----------------------- normalize_secret (Req 3) -----------------------
def test_normalize_strips_and_uppercases():
    # Req 3.1, 3.2
    out = totp.normalize_secret("jbsw y3dp ehpk-3pxp")
    assert out == out.upper()
    assert " " not in out and "-" not in out
    assert len(out) % 8 == 0
    base64.b32decode(out, casefold=True)  # không nâng lỗi


def test_normalize_empty_raises():
    # Req 3.3
    with pytest.raises(totp.TOTPError):
        totp.normalize_secret("")


@pytest.mark.parametrize("bad", ["10101010", "0000", "secret!!", "189"])
def test_normalize_invalid_base32_raises(bad):
    # Req 3.4 — ký tự '0','1','8','9','!' không thuộc bảng base32.
    with pytest.raises(totp.TOTPError):
        totp.normalize_secret(bad)


def test_normalize_idempotent():
    # Req 3.5
    once = totp.normalize_secret("jbsw y3dp ehpk 3pxp")
    twice = totp.normalize_secret(once)
    assert once == twice


# ----------------------- otpauth parse/build (Req 4) -----------------------
def test_parse_otpauth_valid():
    # Req 4.1, 4.2
    uri = "otpauth://totp/Shopee:user@x.com?secret=JBSWY3DPEHPK3PXP&issuer=Shopee&digits=6&period=30&algorithm=SHA1"
    parsed = totp.parse_otpauth(uri)
    assert parsed["secret"] == "JBSWY3DPEHPK3PXP"
    assert parsed["digits"] == 6
    assert parsed["period"] == 30
    assert parsed["algorithm"] == "SHA1"
    assert "Shopee" in parsed["name"] and "user@x.com" in parsed["name"]


def test_parse_not_otpauth_raises():
    # Req 4.3
    with pytest.raises(totp.TOTPError):
        totp.parse_otpauth("https://example.com")


def test_parse_missing_secret_raises():
    # Req 4.4
    with pytest.raises(totp.TOTPError):
        totp.parse_otpauth("otpauth://totp/Acc?issuer=X&digits=6")


def test_parse_hotp_type_raises():
    # Req 4.5
    with pytest.raises(totp.TOTPError):
        totp.parse_otpauth("otpauth://hotp/Acc?secret=JBSWY3DPEHPK3PXP&counter=0")


@settings(max_examples=60)
@given(
    name=st.text(
        alphabet=st.characters(min_codepoint=48, max_codepoint=122),
        min_size=1,
        max_size=20,
    ),
    seed=st.binary(min_size=10, max_size=40),
    digits=st.sampled_from([6, 7, 8]),
    period=st.sampled_from([15, 30, 60]),
    algorithm=st.sampled_from(["SHA1", "SHA256", "SHA512"]),
)
def test_build_parse_roundtrip(name, seed, digits, period, algorithm):
    # Req 4.6 — round-trip parse(build(...)) bảo toàn tham số.
    secret = base64.b32encode(seed).decode("ascii")
    uri = totp.build_otpauth(
        name, secret, digits=digits, period=period, algorithm=algorithm
    )
    parsed = totp.parse_otpauth(uri)
    expected_secret = totp.normalize_secret(secret).rstrip("=")
    assert parsed["secret"] == expected_secret
    assert parsed["digits"] == digits
    assert parsed["period"] == period
    assert parsed["algorithm"] == algorithm


# ----------------------- seconds_remaining (Req 5) -----------------------
@settings(max_examples=200)
@given(at=st.integers(min_value=0, max_value=10 ** 12), period=st.sampled_from([15, 30, 60]))
def test_seconds_remaining_bounds(at, period):
    # Req 5.1, 5.3 — luôn trong [1, period], không bao giờ 0.
    r = totp.seconds_remaining(period, at=at)
    assert 1 <= r <= period


@pytest.mark.parametrize("period", [15, 30, 60])
def test_seconds_remaining_on_boundary(period):
    # Req 5.2 — tại bội số đúng của period thì còn lại = period.
    assert totp.seconds_remaining(period, at=period * 5) == period
