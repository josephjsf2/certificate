from __future__ import annotations

from dataclasses import dataclass
from urllib.request import urlopen, Request

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import AuthorityInformationAccessOID

from certificate.chain import _is_self_signed


@dataclass(frozen=True)
class AiaResult:
    """AIA chain fetch result."""

    certificates: list[x509.Certificate]
    errors: list[str]
    root_found: bool


def get_aia_ca_issuer_urls(cert: x509.Certificate) -> list[str]:
    """Extract CA Issuers URLs from a certificate's AIA extension.

    Returns an empty list if the certificate has no AIA extension.
    """
    try:
        aia_ext = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        )
    except x509.ExtensionNotFound:
        return []

    urls: list[str] = []
    for desc in aia_ext.value:
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            if isinstance(desc.access_location, x509.UniformResourceIdentifier):
                urls.append(desc.access_location.value)
    return urls


def _download_cert(url: str, timeout: int = 10) -> x509.Certificate | None:
    """Download a certificate from a URL. Supports DER and PEM formats.

    Returns None if the download fails or data cannot be parsed.
    """
    try:
        req = Request(url, headers={"User-Agent": "certificate-tool/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    except Exception:
        return None

    # Try DER first (most common for AIA), then PEM
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        pass

    try:
        return x509.load_pem_x509_certificate(data)
    except Exception:
        return None


def _cert_fingerprint(cert: x509.Certificate) -> bytes:
    """Compute SHA-256 fingerprint for dedup."""
    return cert.fingerprint(hashes.SHA256())


def fetch_intermediate_chain(
    cert: x509.Certificate,
    existing_certs: list[x509.Certificate] | None = None,
    max_depth: int = 10,
    timeout: int = 10,
) -> AiaResult:
    """Recursively fetch intermediate certificates via AIA extension.

    Starts from cert, follows AIA CA Issuers URLs up the chain until
    reaching a self-signed (root) certificate or running out of AIA URLs.

    Args:
        cert: The starting certificate (typically the leaf).
        existing_certs: Certificates already available (for dedup).
        max_depth: Maximum number of levels to follow.
        timeout: HTTP timeout in seconds per request.

    Returns:
        AiaResult with downloaded certificates, errors, and root_found flag.
    """
    seen_fps: set[bytes] = set()
    if existing_certs:
        for c in existing_certs:
            seen_fps.add(_cert_fingerprint(c))
    seen_fps.add(_cert_fingerprint(cert))

    downloaded: list[x509.Certificate] = []
    errors: list[str] = []
    root_found = False

    current = cert
    for depth in range(max_depth):
        urls = get_aia_ca_issuer_urls(current)
        if not urls:
            if depth == 0:
                errors.append("憑證未包含 AIA 擴展")
            break

        fetched = None
        for url in urls:
            fetched = _download_cert(url, timeout=timeout)
            if fetched is not None:
                break
            errors.append(f"無法從 {url} 下載憑證")

        if fetched is None:
            break

        fp = _cert_fingerprint(fetched)
        if fp in seen_fps:
            break

        seen_fps.add(fp)
        downloaded.append(fetched)

        if _is_self_signed(fetched):
            root_found = True
            break

        current = fetched
    else:
        # Loop exhausted max_depth without break — chain may be incomplete
        if not _is_self_signed(current):
            errors.append("已達最大深度限制，憑證鏈可能不完整")

    return AiaResult(
        certificates=downloaded,
        errors=errors,
        root_found=root_found,
    )
