import datetime
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID

from certificate.csr import generate_private_key
from certificate.selfsigned import build_self_signed_cert


class TestBuildSelfSignedCert:
    def test_cn_only(self):
        key = generate_private_key(2048)
        cert_pem, key_pem = build_self_signed_cert(
            private_key=key, common_name="example.com"
        )
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")

        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "example.com"

    def test_all_subject_fields(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key,
            common_name="example.com",
            organization="My Org",
            organizational_unit="IT",
            country="TW",
            state="Taiwan",
            locality="Taipei",
            email="admin@example.com",
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        attrs = {attr.oid: attr.value for attr in cert.subject}
        assert attrs[NameOID.COMMON_NAME] == "example.com"
        assert attrs[NameOID.ORGANIZATION_NAME] == "My Org"
        assert attrs[NameOID.ORGANIZATIONAL_UNIT_NAME] == "IT"
        assert attrs[NameOID.COUNTRY_NAME] == "TW"
        assert attrs[NameOID.STATE_OR_PROVINCE_NAME] == "Taiwan"
        assert attrs[NameOID.LOCALITY_NAME] == "Taipei"
        assert attrs[NameOID.EMAIL_ADDRESS] == "admin@example.com"

    def test_empty_fields_skipped(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key,
            common_name="example.com",
            organization="",
            country="",
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert len(cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)) == 0
        assert len(cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)) == 0

    def test_self_signed_issuer_equals_subject(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key, common_name="example.com"
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.issuer == cert.subject

    def test_self_signed_signature_valid(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key, common_name="example.com"
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        # Should not raise
        cert.verify_directly_issued_by(cert)

    def test_dns_san(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key,
            common_name="example.com",
            san_entries=["DNS:example.com", "DNS:www.example.com"],
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "example.com" in dns_names
        assert "www.example.com" in dns_names

    def test_ip_san(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key,
            common_name="example.com",
            san_entries=["IP:192.168.1.1"],
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("192.168.1.1") in ips

    def test_no_san(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key,
            common_name="example.com",
            san_entries=[],
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        with __import__("pytest").raises(x509.ExtensionNotFound):
            cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)

    def test_validity_days(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key,
            common_name="example.com",
            validity_days=30,
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert delta.days == 30

    def test_ca_mode(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key,
            common_name="My CA",
            is_ca=True,
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True
        assert bc.critical is True

    def test_non_ca_mode(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key,
            common_name="example.com",
            is_ca=False,
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_subject_key_identifier(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key, common_name="example.com"
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        assert ski.value.digest is not None

    def test_serial_number_positive(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key, common_name="example.com"
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.serial_number > 0

    def test_pem_format(self):
        key = generate_private_key(2048)
        cert_pem, key_pem = build_self_signed_cert(
            private_key=key, common_name="example.com"
        )
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert cert_pem.strip().endswith(b"-----END CERTIFICATE-----")
        assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert key_pem.strip().endswith(b"-----END PRIVATE KEY-----")

    def test_signature_algorithm_sha256(self):
        key = generate_private_key(2048)
        cert_pem, _ = build_self_signed_cert(
            private_key=key, common_name="example.com"
        )
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert "sha256" in cert.signature_algorithm_oid._name.lower()
