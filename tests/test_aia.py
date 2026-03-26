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


from certificate.aia import fetch_intermediate_chain, AiaResult


def _make_chain_with_aia() -> (
    tuple[x509.Certificate, x509.Certificate, x509.Certificate, rsa.RSAPrivateKey]
):
    """Build a 3-level chain: leaf → intermediate → root, each with AIA pointing up."""
    root_cert, root_key = _build_cert_with_aia("Root CA", is_ca=True)

    inter_cert, inter_key = _build_cert_with_aia(
        "Intermediate CA",
        aia_urls=["http://ca.example.com/root.der"],
        issuer_cn="Root CA",
        issuer_key=root_key,
        is_ca=True,
    )

    leaf_cert, _ = _build_cert_with_aia(
        "leaf.example.com",
        aia_urls=["http://ca.example.com/intermediate.der"],
        issuer_cn="Intermediate CA",
        issuer_key=inter_key,
    )

    return leaf_cert, inter_cert, root_cert, root_key


class TestFetchIntermediateChain:
    def test_single_level_fetch(self):
        """Fetch one intermediate from leaf's AIA."""
        leaf_cert, inter_cert, root_cert, _ = _make_chain_with_aia()
        inter_der = inter_cert.public_bytes(Encoding.DER)

        mock_response = MagicMock()
        mock_response.read.return_value = inter_der
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("certificate.aia.urlopen", return_value=mock_response):
            result = fetch_intermediate_chain(leaf_cert, max_depth=1)

        assert len(result.certificates) == 1
        assert result.certificates[0].subject == inter_cert.subject

    def test_recursive_multi_level_fetch(self):
        """Recursively fetch intermediate → root."""
        leaf_cert, inter_cert, root_cert, _ = _make_chain_with_aia()
        inter_der = inter_cert.public_bytes(Encoding.DER)
        root_der = root_cert.public_bytes(Encoding.DER)

        call_count = 0

        def mock_urlopen(req, timeout=None):
            nonlocal call_count
            mock_resp = MagicMock()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)

            if call_count == 0:
                mock_resp.read.return_value = inter_der
            else:
                mock_resp.read.return_value = root_der
            call_count += 1
            return mock_resp

        with patch("certificate.aia.urlopen", side_effect=mock_urlopen):
            result = fetch_intermediate_chain(leaf_cert)

        assert len(result.certificates) == 2
        assert result.certificates[0].subject == inter_cert.subject
        assert result.certificates[1].subject == root_cert.subject
        assert result.root_found is True

    def test_dedup_with_existing_certs(self):
        """Certificates already in existing_certs should not appear in result."""
        leaf_cert, inter_cert, root_cert, _ = _make_chain_with_aia()
        inter_der = inter_cert.public_bytes(Encoding.DER)

        mock_response = MagicMock()
        mock_response.read.return_value = inter_der
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("certificate.aia.urlopen", return_value=mock_response):
            result = fetch_intermediate_chain(
                leaf_cert, existing_certs=[inter_cert]
            )

        assert len(result.certificates) == 0

    def test_max_depth_limit(self):
        """Should stop at max_depth even if more AIA URLs exist."""
        leaf_cert, inter_cert, _, _ = _make_chain_with_aia()
        inter_der = inter_cert.public_bytes(Encoding.DER)

        mock_response = MagicMock()
        mock_response.read.return_value = inter_der
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("certificate.aia.urlopen", return_value=mock_response):
            result = fetch_intermediate_chain(leaf_cert, max_depth=0)

        assert len(result.certificates) == 0
        assert any("最大深度" in e for e in result.errors)

    def test_no_aia_extension(self):
        """Cert without AIA should return empty result with error."""
        cert, _ = _build_cert_with_aia("no-aia.example.com", aia_urls=None)

        result = fetch_intermediate_chain(cert)

        assert len(result.certificates) == 0
        assert any("AIA" in e for e in result.errors)
        assert result.root_found is False

    def test_partial_failure_continues(self):
        """If first URL fails but cert has AIA, record error and return partial."""
        leaf_cert, inter_cert, root_cert, _ = _make_chain_with_aia()

        with patch(
            "certificate.aia.urlopen",
            side_effect=URLError("connection refused"),
        ):
            result = fetch_intermediate_chain(leaf_cert)

        assert len(result.certificates) == 0
        assert len(result.errors) > 0
        assert result.root_found is False
