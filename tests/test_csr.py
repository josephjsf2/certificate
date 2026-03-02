import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import pytest

from certificate.csr import generate_private_key, build_csr, validate_san_entries, decode_csr


class TestGeneratePrivateKey:
    def test_generates_2048_bit_key(self):
        key = generate_private_key(2048)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_generates_4096_bit_key(self):
        key = generate_private_key(4096)
        assert key.key_size == 4096


class TestBuildCSR:
    def test_csr_with_cn_only(self):
        key = generate_private_key(2048)
        csr_pem, key_pem = build_csr(
            private_key=key,
            common_name="example.com",
        )
        # Verify PEM format
        assert csr_pem.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")
        assert key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")

        # Parse and verify subject
        csr = x509.load_pem_x509_csr(csr_pem)
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "example.com"
        assert csr.is_signature_valid

    def test_csr_with_all_subject_fields(self):
        key = generate_private_key(2048)
        csr_pem, _ = build_csr(
            private_key=key,
            common_name="example.com",
            organization="My Org",
            organizational_unit="IT",
            country="TW",
            state="Taiwan",
            locality="Taipei",
            email="admin@example.com",
        )
        csr = x509.load_pem_x509_csr(csr_pem)
        subject_attrs = {attr.oid: attr.value for attr in csr.subject}
        assert subject_attrs[x509.oid.NameOID.COMMON_NAME] == "example.com"
        assert subject_attrs[x509.oid.NameOID.ORGANIZATION_NAME] == "My Org"
        assert subject_attrs[x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME] == "IT"
        assert subject_attrs[x509.oid.NameOID.COUNTRY_NAME] == "TW"
        assert subject_attrs[x509.oid.NameOID.STATE_OR_PROVINCE_NAME] == "Taiwan"
        assert subject_attrs[x509.oid.NameOID.LOCALITY_NAME] == "Taipei"
        assert subject_attrs[x509.oid.NameOID.EMAIL_ADDRESS] == "admin@example.com"

    def test_csr_skips_empty_fields(self):
        key = generate_private_key(2048)
        csr_pem, _ = build_csr(
            private_key=key,
            common_name="example.com",
            organization="",
            country="",
        )
        csr = x509.load_pem_x509_csr(csr_pem)
        assert len(csr.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)) == 0
        assert len(csr.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)) == 0

    def test_csr_with_dns_san(self):
        key = generate_private_key(2048)
        csr_pem, _ = build_csr(
            private_key=key,
            common_name="example.com",
            san_entries=["DNS:example.com", "DNS:www.example.com"],
        )
        csr = x509.load_pem_x509_csr(csr_pem)
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "example.com" in dns_names
        assert "www.example.com" in dns_names

    def test_csr_with_ip_san(self):
        key = generate_private_key(2048)
        csr_pem, _ = build_csr(
            private_key=key,
            common_name="example.com",
            san_entries=["IP:192.168.1.1"],
        )
        csr = x509.load_pem_x509_csr(csr_pem)
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("192.168.1.1") in ips

    def test_csr_without_san(self):
        key = generate_private_key(2048)
        csr_pem, _ = build_csr(
            private_key=key,
            common_name="example.com",
            san_entries=[],
        )
        csr = x509.load_pem_x509_csr(csr_pem)
        assert len(csr.extensions) == 0


class TestValidateSanEntries:
    def test_valid_dns(self):
        errors = validate_san_entries(["DNS:example.com"])
        assert errors == []

    def test_valid_ip(self):
        errors = validate_san_entries(["IP:192.168.1.1"])
        assert errors == []

    def test_valid_ipv6(self):
        errors = validate_san_entries(["IP:::1"])
        assert errors == []

    def test_invalid_format(self):
        errors = validate_san_entries(["example.com"])
        assert len(errors) == 1

    def test_invalid_ip(self):
        errors = validate_san_entries(["IP:999.999.999.999"])
        assert len(errors) == 1

    def test_empty_list(self):
        errors = validate_san_entries([])
        assert errors == []

    def test_skips_blank_lines(self):
        errors = validate_san_entries(["", "  ", "DNS:example.com"])
        assert errors == []


class TestDecodeCSR:
    def _make_csr(self, **kwargs):
        """Helper: generate a CSR and return its PEM bytes."""
        key = generate_private_key(2048)
        csr_pem, _ = build_csr(private_key=key, common_name="example.com", **kwargs)
        return csr_pem

    def test_decode_subject_cn_only(self):
        csr_pem = self._make_csr()
        info = decode_csr(csr_pem)
        assert info["subject"]["CN"] == "example.com"
        assert info["subject"]["O"] == ""

    def test_decode_all_subject_fields(self):
        csr_pem = self._make_csr(
            organization="My Org",
            organizational_unit="IT",
            country="TW",
            state="Taiwan",
            locality="Taipei",
            email="admin@example.com",
        )
        info = decode_csr(csr_pem)
        assert info["subject"]["CN"] == "example.com"
        assert info["subject"]["O"] == "My Org"
        assert info["subject"]["OU"] == "IT"
        assert info["subject"]["C"] == "TW"
        assert info["subject"]["ST"] == "Taiwan"
        assert info["subject"]["L"] == "Taipei"
        assert info["subject"]["Email"] == "admin@example.com"

    def test_decode_san_entries(self):
        csr_pem = self._make_csr(san_entries=["DNS:example.com", "IP:192.168.1.1"])
        info = decode_csr(csr_pem)
        assert "DNS:example.com" in info["san"]
        assert "IP:192.168.1.1" in info["san"]

    def test_decode_no_san(self):
        csr_pem = self._make_csr(san_entries=[])
        info = decode_csr(csr_pem)
        assert info["san"] == []

    def test_decode_public_key_info(self):
        csr_pem = self._make_csr()
        info = decode_csr(csr_pem)
        assert info["public_key"]["algorithm"] == "RSA"
        assert info["public_key"]["key_size"] == 2048

    def test_decode_signature_algorithm(self):
        csr_pem = self._make_csr()
        info = decode_csr(csr_pem)
        assert "sha256" in info["signature_algorithm"].lower()

    def test_decode_invalid_pem(self):
        with pytest.raises(ValueError):
            decode_csr(b"not a valid CSR")
