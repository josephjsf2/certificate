import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_private_key(key_size: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )


def build_csr(
    private_key: rsa.RSAPrivateKey,
    common_name: str,
    organization: str = "",
    organizational_unit: str = "",
    country: str = "",
    state: str = "",
    locality: str = "",
    email: str = "",
    san_entries: list[str] | None = None,
) -> tuple[bytes, bytes]:
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

    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(name_attrs)
    )

    san_names = _parse_san_entries(san_entries or [])
    if san_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        )

    csr = builder.sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return csr_pem, key_pem


def validate_san_entries(entries: list[str]) -> list[str]:
    errors = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if entry.startswith("DNS:"):
            continue
        elif entry.startswith("IP:"):
            ip_str = entry[3:]
            try:
                ipaddress.ip_address(ip_str)
            except ValueError:
                errors.append(f"Invalid IP address: {ip_str}")
        else:
            errors.append(f"Invalid SAN format: '{entry}'. Must start with DNS: or IP:")
    return errors


def _parse_san_entries(entries: list[str]) -> list[x509.GeneralName]:
    names = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if entry.startswith("DNS:"):
            names.append(x509.DNSName(entry[4:]))
        elif entry.startswith("IP:"):
            names.append(x509.IPAddress(ipaddress.ip_address(entry[3:])))
    return names
