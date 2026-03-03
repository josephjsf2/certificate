import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certificate.csr import _parse_san_entries


def build_self_signed_cert(
    private_key: rsa.RSAPrivateKey,
    common_name: str,
    organization: str = "",
    organizational_unit: str = "",
    country: str = "",
    state: str = "",
    locality: str = "",
    email: str = "",
    san_entries: list[str] | None = None,
    validity_days: int = 365,
    is_ca: bool = False,
) -> tuple[bytes, bytes]:
    """產生自簽憑證，回傳 (cert_pem, key_pem)"""
    name_attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]

    field_map = [
        (NameOID.ORGANIZATION_NAME, organization),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        (NameOID.COUNTRY_NAME, country),
        (NameOID.STATE_OR_PROVINCE_NAME, state),
        (NameOID.LOCALITY_NAME, locality),
        (NameOID.EMAIL_ADDRESS, email),
    ]
    for oid, value in field_map:
        if value.strip():
            name_attrs.append(x509.NameAttribute(oid, value.strip()))

    subject_name = x509.Name(name_attrs)

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
    )

    # BasicConstraints
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=None if is_ca else None),
        critical=True,
    )

    # SubjectKeyIdentifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )

    # SAN
    san_names = _parse_san_entries(san_entries or [])
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )

    cert = builder.sign(private_key, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem
