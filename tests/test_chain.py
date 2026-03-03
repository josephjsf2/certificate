from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import pytest

from certificate.chain import (
    parse_pem_certificates,
    validate_chain,
    build_chain,
    export_chain_pem,
    _is_self_signed,
    _format_dn,
)


# ── 測試用憑證產生工具 ──────────────────────────────────────────


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_cert(
    subject_cn: str,
    issuer_cn: str | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
    key: rsa.RSAPrivateKey | None = None,
    is_ca: bool = False,
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """產生一張測試用憑證，回傳 (cert, subject_key)。"""
    subject_key = key or _generate_key()
    signing_key = issuer_key or subject_key

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = not_valid_before or now - datetime.timedelta(days=1)
    not_after = not_valid_after or now + datetime.timedelta(days=365)

    subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer_name = (
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
        if issuer_cn
        else subject_name
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )

    cert = builder.sign(signing_key, hashes.SHA256())
    return cert, subject_key


def _make_chain() -> tuple[
    x509.Certificate, x509.Certificate, x509.Certificate,
    rsa.RSAPrivateKey, rsa.RSAPrivateKey, rsa.RSAPrivateKey,
]:
    """產生 root → intermediate → leaf 三層憑證鏈。"""
    root_cert, root_key = _build_cert("Root CA", is_ca=True)
    int_cert, int_key = _build_cert(
        "Intermediate CA",
        issuer_cn="Root CA",
        issuer_key=root_key,
        is_ca=True,
    )
    leaf_cert, leaf_key = _build_cert(
        "leaf.example.com",
        issuer_cn="Intermediate CA",
        issuer_key=int_key,
    )
    return root_cert, int_cert, leaf_cert, root_key, int_key, leaf_key


def _cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


# ── TestParsePemCertificates ────────────────────────────────────


class TestParsePemCertificates:
    def test_parse_single_cert(self):
        cert, _ = _build_cert("test.example.com")
        pem = _cert_to_pem(cert)
        result = parse_pem_certificates(pem)
        assert len(result) == 1
        assert result[0].subject == cert.subject

    def test_parse_multiple_certs(self):
        root, intermediate, leaf, *_ = _make_chain()
        pem = _cert_to_pem(leaf) + _cert_to_pem(intermediate) + _cert_to_pem(root)
        result = parse_pem_certificates(pem)
        assert len(result) == 3

    def test_parse_empty_input(self):
        result = parse_pem_certificates(b"")
        assert result == []

    def test_parse_no_certificate_markers(self):
        result = parse_pem_certificates(b"this is not a certificate")
        assert result == []

    def test_parse_mixed_content(self):
        cert, _ = _build_cert("test.example.com")
        pem = b"some junk\n" + _cert_to_pem(cert) + b"\nmore junk"
        result = parse_pem_certificates(pem)
        assert len(result) == 1


# ── TestValidateChain ───────────────────────────────────────────


class TestValidateChain:
    def test_valid_full_chain(self):
        root, intermediate, leaf, *_ = _make_chain()
        result = validate_chain([leaf, intermediate, root])
        assert result["valid"] is True
        assert result["errors"] == []
        assert len(result["details"]) == 3

    def test_issuer_mismatch(self):
        """leaf 的 issuer 跟下一張的 subject 不符"""
        root, _, leaf, *_ = _make_chain()
        # leaf → root 直接跳過 intermediate
        result = validate_chain([leaf, root])
        assert result["valid"] is False
        assert any("issuer" in e or "簽章驗證失敗" in e for e in result["errors"])

    def test_expired_cert(self):
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=730)
        expired = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        cert, _ = _build_cert(
            "expired.example.com",
            not_valid_before=past,
            not_valid_after=expired,
        )
        result = validate_chain([cert])
        assert result["valid"] is False
        assert any("過期" in e for e in result["errors"])

    def test_not_yet_valid_cert(self):
        future_start = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)
        future_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        cert, _ = _build_cert(
            "future.example.com",
            not_valid_before=future_start,
            not_valid_after=future_end,
        )
        result = validate_chain([cert])
        assert result["valid"] is False
        assert any("尚未生效" in e for e in result["errors"])

    def test_empty_chain(self):
        result = validate_chain([])
        assert result["valid"] is False
        assert any("沒有提供" in e for e in result["errors"])

    def test_single_self_signed(self):
        root, _ = _build_cert("Root CA", is_ca=True)
        result = validate_chain([root])
        assert result["valid"] is True

    def test_chain_not_ending_with_root(self):
        """鏈尾不是 self-signed"""
        root, intermediate, leaf, *_ = _make_chain()
        result = validate_chain([leaf, intermediate])
        assert result["valid"] is False
        assert any("不是 self-signed" in e for e in result["errors"])

    def test_signature_verification_failure(self):
        """用錯誤的 key 簽發，簽章驗證應失敗"""
        wrong_key = _generate_key()
        root, _ = _build_cert("Root CA", is_ca=True)
        # 產生一張 issuer 寫著 Root CA 但不是用 root key 簽的
        fake_child, _ = _build_cert(
            "fake.example.com",
            issuer_cn="Root CA",
            issuer_key=wrong_key,
        )
        result = validate_chain([fake_child, root])
        assert result["valid"] is False
        assert any("簽章驗證失敗" in e for e in result["errors"])


# ── TestBuildChain ──────────────────────────────────────────────


class TestBuildChain:
    def test_correct_order(self):
        root, intermediate, leaf, *_ = _make_chain()
        # 故意打亂順序
        result = build_chain([root, leaf, intermediate])
        assert len(result) == 3
        # leaf 應在最前面
        assert result[0].subject == leaf.subject
        assert result[1].subject == intermediate.subject
        assert result[2].subject == root.subject

    def test_deduplication(self):
        root, intermediate, leaf, *_ = _make_chain()
        result = build_chain([leaf, intermediate, root, leaf, intermediate])
        assert len(result) == 3

    def test_incomplete_chain(self):
        """只有 leaf + root（缺 intermediate），應只串出能驗證的部分"""
        root, intermediate, leaf, *_ = _make_chain()
        result = build_chain([leaf, root])
        # leaf 找不到正確的 issuer（intermediate 不在），所以只有 leaf
        assert len(result) >= 1
        assert result[0].subject == leaf.subject

    def test_empty_input(self):
        result = build_chain([])
        assert result == []

    def test_single_cert(self):
        cert, _ = _build_cert("single.example.com")
        result = build_chain([cert])
        assert len(result) == 1

    def test_all_self_signed(self):
        """多張 self-signed 憑證"""
        cert1, _ = _build_cert("root1.example.com", is_ca=True)
        cert2, _ = _build_cert("root2.example.com", is_ca=True)
        result = build_chain([cert1, cert2])
        # Each is self-signed, should return at least one
        assert len(result) >= 1


# ── TestExportChainPem ──────────────────────────────────────────


class TestExportChainPem:
    def test_export_format(self):
        root, intermediate, leaf, *_ = _make_chain()
        chain = [leaf, intermediate, root]
        pem = export_chain_pem(chain)
        assert pem.count(b"-----BEGIN CERTIFICATE-----") == 3
        assert pem.count(b"-----END CERTIFICATE-----") == 3

    def test_roundtrip(self):
        root, intermediate, leaf, *_ = _make_chain()
        chain = [leaf, intermediate, root]
        pem = export_chain_pem(chain)
        parsed = parse_pem_certificates(pem)
        assert len(parsed) == 3
        for orig, parsed_cert in zip(chain, parsed):
            assert orig.subject == parsed_cert.subject

    def test_empty_chain(self):
        pem = export_chain_pem([])
        assert pem == b""


# ── TestHelpers ─────────────────────────────────────────────────


class TestHelpers:
    def test_is_self_signed_true(self):
        root, _ = _build_cert("Root CA", is_ca=True)
        assert _is_self_signed(root) is True

    def test_is_self_signed_false(self):
        root_cert, root_key = _build_cert("Root CA", is_ca=True)
        child, _ = _build_cert(
            "child.example.com",
            issuer_cn="Root CA",
            issuer_key=root_key,
        )
        assert _is_self_signed(child) is False

    def test_format_dn(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Org"),
        ])
        result = _format_dn(name)
        assert "CN=example.com" in result
        assert "O=My Org" in result

    def test_format_dn_empty(self):
        name = x509.Name([])
        assert _format_dn(name) == "(empty)"
