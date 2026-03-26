from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from certificate.aia import get_aia_ca_issuer_urls


# ── Test helpers ──────────────────────────────────────────────


def _generate_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _build_cert_with_aia(
    subject_cn: str,
    aia_urls: list[str] | None = None,
    issuer_cn: str | None = None,
    issuer_key: rsa.RSAPrivateKey | None = None,
    is_ca: bool = False,
) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
    """Build a test certificate, optionally with AIA extension."""
    key = _generate_key()
    signing_key = issuer_key or key

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
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
    )

    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )

    if aia_urls:
        descriptions = [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(url),
            )
            for url in aia_urls
        ]
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(descriptions), critical=False
        )

    cert = builder.sign(signing_key, hashes.SHA256())
    return cert, key


# ── TestGetAiaCaIssuerUrls ────────────────────────────────────


class TestGetAiaCaIssuerUrls:
    def test_cert_with_single_aia_url(self):
        cert, _ = _build_cert_with_aia(
            "leaf.example.com",
            aia_urls=["http://ca.example.com/intermediate.der"],
        )
        urls = get_aia_ca_issuer_urls(cert)
        assert urls == ["http://ca.example.com/intermediate.der"]

    def test_cert_with_multiple_aia_urls(self):
        cert, _ = _build_cert_with_aia(
            "leaf.example.com",
            aia_urls=[
                "http://ca.example.com/ca1.der",
                "http://ca.example.com/ca2.der",
            ],
        )
        urls = get_aia_ca_issuer_urls(cert)
        assert urls == [
            "http://ca.example.com/ca1.der",
            "http://ca.example.com/ca2.der",
        ]

    def test_cert_without_aia_returns_empty(self):
        cert, _ = _build_cert_with_aia("leaf.example.com", aia_urls=None)
        urls = get_aia_ca_issuer_urls(cert)
        assert urls == []


# ── TestDownloadCert ──────────────────────────────────────────


from unittest.mock import patch, MagicMock
from urllib.error import URLError

from cryptography.hazmat.primitives.serialization import Encoding

from certificate.aia import _download_cert


class TestDownloadCert:
    def test_download_der_format(self):
        """DER-encoded certificate should be parsed correctly."""
        cert, _ = _build_cert_with_aia("Intermediate CA", is_ca=True)
        der_data = cert.public_bytes(Encoding.DER)

        mock_response = MagicMock()
        mock_response.read.return_value = der_data
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("certificate.aia.urlopen", return_value=mock_response):
            result = _download_cert("http://ca.example.com/ca.der", timeout=10)

        assert result is not None
        assert result.subject == cert.subject

    def test_download_pem_format(self):
        """PEM-encoded certificate should be parsed correctly."""
        cert, _ = _build_cert_with_aia("Intermediate CA", is_ca=True)
        pem_data = cert.public_bytes(Encoding.PEM)

        mock_response = MagicMock()
        mock_response.read.return_value = pem_data
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("certificate.aia.urlopen", return_value=mock_response):
            result = _download_cert("http://ca.example.com/ca.pem", timeout=10)

        assert result is not None
        assert result.subject == cert.subject

    def test_download_invalid_data_returns_none(self):
        """Invalid certificate data should return None."""
        mock_response = MagicMock()
        mock_response.read.return_value = b"not a certificate"
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("certificate.aia.urlopen", return_value=mock_response):
            result = _download_cert("http://ca.example.com/bad.der", timeout=10)

        assert result is None

    def test_download_url_error_returns_none(self):
        """Network errors should return None."""
        with patch(
            "certificate.aia.urlopen",
            side_effect=URLError("connection refused"),
        ):
            result = _download_cert("http://unreachable.example.com/ca.der", timeout=10)

        assert result is None
