from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from certificate.chain import _format_dn


def load_pfx(pfx_data: bytes, password: str | None) -> dict:
    """載入 PFX 檔案並提取內容。

    回傳 {
        "private_key_pem": bytes | None,
        "certificate_pem": bytes | None,
        "certificate_info": dict | None,
        "additional_certs_pem": list[bytes],
        "additional_certs_info": list[dict],
    }
    """
    password_bytes = (
        password.encode("utf-8") if password and password.strip() else None
    )

    private_key, certificate, additional_certs = (
        pkcs12.load_key_and_certificates(pfx_data, password_bytes)
    )

    private_key_pem = None
    if private_key is not None:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    certificate_pem = None
    certificate_info = None
    if certificate is not None:
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        certificate_info = format_certificate_info(certificate)

    additional_certs_pem: list[bytes] = []
    additional_certs_info: list[dict] = []
    if additional_certs:
        for cert in additional_certs:
            additional_certs_pem.append(
                cert.public_bytes(serialization.Encoding.PEM)
            )
            additional_certs_info.append(format_certificate_info(cert))

    return {
        "private_key_pem": private_key_pem,
        "certificate_pem": certificate_pem,
        "certificate_info": certificate_info,
        "additional_certs_pem": additional_certs_pem,
        "additional_certs_info": additional_certs_info,
    }


def format_certificate_info(cert: x509.Certificate) -> dict:
    """提取憑證可讀資訊（subject, issuer, 有效期, 序號）"""
    return {
        "subject": _format_dn(cert.subject),
        "issuer": _format_dn(cert.issuer),
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "serial": format(cert.serial_number, "X"),
    }
