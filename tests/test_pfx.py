from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

import pytest

from certificate.pfx import load_pfx, format_certificate_info


# ── 測試用工具 ──────────────────────────────────────────────────


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_cert(
    subject_cn: str,
    issuer_cn: str | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
    key: rsa.RSAPrivateKey | None = None,
    is_ca: bool = False,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    subject_key = key or _generate_key()
    signing_key = issuer_key or subject_key

    now = datetime.datetime.now(datetime.timezone.utc)
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
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

    cert = builder.sign(signing_key, hashes.SHA256())
    return cert, subject_key


def _make_pfx(
    password: bytes | None = None,
    include_additional: bool = False,
) -> tuple[bytes, rsa.RSAPrivateKey, x509.Certificate, list[x509.Certificate]]:
    """產生測試用 PFX，回傳 (pfx_data, key, cert, additional_certs)"""
    root_cert, root_key = _build_cert("Root CA", is_ca=True)
    leaf_cert, leaf_key = _build_cert(
        "leaf.example.com", issuer_cn="Root CA", issuer_key=root_key
    )

    additional = [root_cert] if include_additional else None

    pfx_data = pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=leaf_key,
        cert=leaf_cert,
        cas=additional,
        encryption_algorithm=(
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        ),
    )
    return pfx_data, leaf_key, leaf_cert, additional or []


# ── TestLoadPfx ────────────────────────────────────────────────


class TestLoadPfx:
    def test_load_with_correct_password(self):
        pfx_data, _, cert, _ = _make_pfx(password=b"test123")
        result = load_pfx(pfx_data, "test123")
        assert result["private_key_pem"] is not None
        assert result["certificate_pem"] is not None
        assert result["certificate_info"] is not None

    def test_load_wrong_password_raises(self):
        pfx_data, _, _, _ = _make_pfx(password=b"correct")
        with pytest.raises(Exception):
            load_pfx(pfx_data, "wrong")

    def test_load_no_password(self):
        pfx_data, _, cert, _ = _make_pfx(password=None)
        result = load_pfx(pfx_data, None)
        assert result["private_key_pem"] is not None
        assert result["certificate_pem"] is not None

    def test_load_empty_string_password_treated_as_none(self):
        pfx_data, _, _, _ = _make_pfx(password=None)
        result = load_pfx(pfx_data, "")
        assert result["private_key_pem"] is not None

    def test_pem_format_private_key(self):
        pfx_data, _, _, _ = _make_pfx()
        result = load_pfx(pfx_data, None)
        assert result["private_key_pem"].startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_pem_format_certificate(self):
        pfx_data, _, _, _ = _make_pfx()
        result = load_pfx(pfx_data, None)
        assert result["certificate_pem"].startswith(b"-----BEGIN CERTIFICATE-----")

    def test_with_additional_certs(self):
        pfx_data, _, _, additional = _make_pfx(include_additional=True)
        result = load_pfx(pfx_data, None)
        assert len(result["additional_certs_pem"]) == 1
        assert len(result["additional_certs_info"]) == 1
        assert result["additional_certs_pem"][0].startswith(
            b"-----BEGIN CERTIFICATE-----"
        )

    def test_without_additional_certs(self):
        pfx_data, _, _, _ = _make_pfx(include_additional=False)
        result = load_pfx(pfx_data, None)
        assert result["additional_certs_pem"] == []
        assert result["additional_certs_info"] == []

    def test_corrupted_data_raises(self):
        with pytest.raises(Exception):
            load_pfx(b"not a pfx file", None)


# ── TestFormatCertificateInfo ──────────────────────────────────


class TestFormatCertificateInfo:
    def test_subject(self):
        cert, _ = _build_cert("test.example.com")
        info = format_certificate_info(cert)
        assert "CN=test.example.com" in info["subject"]

    def test_issuer(self):
        root_cert, root_key = _build_cert("Root CA", is_ca=True)
        child, _ = _build_cert(
            "child.example.com", issuer_cn="Root CA", issuer_key=root_key
        )
        info = format_certificate_info(child)
        assert "CN=Root CA" in info["issuer"]

    def test_date_format(self):
        cert, _ = _build_cert("test.example.com")
        info = format_certificate_info(cert)
        assert "UTC" in info["not_before"]
        assert "UTC" in info["not_after"]
        # Should contain year
        assert "20" in info["not_before"]

    def test_serial_number(self):
        cert, _ = _build_cert("test.example.com")
        info = format_certificate_info(cert)
        # Serial should be a hex string
        assert len(info["serial"]) > 0
        int(info["serial"], 16)  # should not raise
