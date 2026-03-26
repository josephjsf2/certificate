from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID


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
