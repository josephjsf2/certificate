from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def parse_pem_certificates(pem_data: bytes) -> list[x509.Certificate]:
    """從 PEM bytes 中解析出所有憑證（可包含多個 BEGIN CERTIFICATE 區塊）"""
    certs: list[x509.Certificate] = []
    # Split on PEM boundaries and reconstruct each block
    rest = pem_data
    while b"-----BEGIN CERTIFICATE-----" in rest:
        start = rest.index(b"-----BEGIN CERTIFICATE-----")
        end_marker = b"-----END CERTIFICATE-----"
        if end_marker not in rest[start:]:
            break
        end = rest.index(end_marker, start) + len(end_marker)
        block = rest[start:end]
        rest = rest[end:]
        try:
            cert = x509.load_pem_x509_certificate(block)
            certs.append(cert)
        except Exception:
            continue
    return certs


def validate_chain(certs: list[x509.Certificate]) -> dict:
    """驗證已排序的憑證鏈（leaf → intermediate(s) → root）。

    回傳 {"valid": bool, "errors": [...], "details": [...]}
    """
    errors: list[str] = []
    details: list[str] = []

    if not certs:
        return {"valid": False, "errors": ["沒有提供任何憑證"], "details": []}

    now = datetime.datetime.now(datetime.timezone.utc)

    for i, cert in enumerate(certs):
        subject = _format_dn(cert.subject)
        issuer = _format_dn(cert.issuer)
        details.append(
            f"[{i}] Subject: {subject}\n"
            f"    Issuer:  {issuer}\n"
            f"    有效期: {cert.not_valid_before_utc:%Y-%m-%d} ~ "
            f"{cert.not_valid_after_utc:%Y-%m-%d}"
        )

        # 檢查有效日期
        if now < cert.not_valid_before_utc:
            errors.append(f"[{i}] {subject}: 憑證尚未生效")
        if now > cert.not_valid_after_utc:
            errors.append(f"[{i}] {subject}: 憑證已過期")

    # 檢查相鄰憑證的 issuer/subject 與簽章
    for i in range(len(certs) - 1):
        child = certs[i]
        parent = certs[i + 1]
        child_subject = _format_dn(child.subject)

        if child.issuer != parent.subject:
            errors.append(
                f"[{i}] {child_subject}: issuer 與 [{i + 1}] 的 subject 不符"
            )

        try:
            child.verify_directly_issued_by(parent)
        except Exception as e:
            errors.append(f"[{i}] {child_subject}: 簽章驗證失敗 ({e})")

    # 最後一張應為 self-signed
    last = certs[-1]
    if not _is_self_signed(last):
        errors.append(
            f"鏈尾 [{len(certs) - 1}] {_format_dn(last.subject)}: "
            f"不是 self-signed，憑證鏈可能不完整"
        )

    return {"valid": len(errors) == 0, "errors": errors, "details": details}


def build_chain(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    """將無序憑證自動排成 leaf → intermediate(s) → root 的正確順序"""
    if not certs:
        return []

    # 1. 以 SHA-256 fingerprint 去重
    seen: dict[bytes, x509.Certificate] = {}
    unique: list[x509.Certificate] = []
    for cert in certs:
        fp = cert.fingerprint(cert.signature_hash_algorithm or x509.SHA256())
        if fp not in seen:
            seen[fp] = cert
            unique.append(cert)

    if len(unique) == 1:
        return unique

    # 2. 建立 subject DN → cert 索引（用 DN bytes 當 key）
    subject_index: dict[bytes, x509.Certificate] = {}
    for cert in unique:
        key = cert.subject.public_bytes()
        subject_index[key] = cert

    # 3. 找出 leaf：subject 不是任何其他憑證的 issuer
    issuer_set = {cert.issuer.public_bytes() for cert in unique}
    leaves = [
        cert for cert in unique
        if cert.subject.public_bytes() not in issuer_set
        or (cert.subject.public_bytes() in issuer_set and _is_self_signed(cert))
    ]

    # 排除 self-signed（root）作為 leaf
    leaves = [cert for cert in leaves if not _is_self_signed(cert)]

    if not leaves:
        # 所有憑證都是某人的 issuer，嘗試找非 self-signed 的作為起點
        non_root = [cert for cert in unique if not _is_self_signed(cert)]
        if non_root:
            # Pick the one whose subject is NOT in anyone else's issuer set
            # except possibly itself
            for cert in non_root:
                is_issuer_of_other = any(
                    other.issuer.public_bytes() == cert.subject.public_bytes()
                    for other in unique
                    if other is not cert and not _is_self_signed(other)
                )
                if not is_issuer_of_other or cert.subject.public_bytes() not in {
                    c.issuer.public_bytes() for c in unique if c is not cert
                }:
                    leaves = [cert]
                    break
            if not leaves:
                leaves = [non_root[0]]
        else:
            # All are self-signed, just return as-is
            return unique

    leaf = leaves[0]

    # 4. 從 leaf 往上串
    chain: list[x509.Certificate] = [leaf]
    visited: set[bytes] = {leaf.fingerprint(leaf.signature_hash_algorithm or x509.SHA256())}

    current = leaf
    while True:
        issuer_key = current.issuer.public_bytes()
        parent = subject_index.get(issuer_key)

        if parent is None:
            break  # issuer 不在集合中

        parent_fp = parent.fingerprint(
            parent.signature_hash_algorithm or x509.SHA256()
        )
        if parent_fp in visited:
            break  # 循環參照

        # 驗證簽章
        try:
            current.verify_directly_issued_by(parent)
        except Exception:
            break

        chain.append(parent)
        visited.add(parent_fp)

        if _is_self_signed(parent):
            break  # 到達 root

        current = parent

    return chain


def export_chain_pem(certs: list[x509.Certificate]) -> bytes:
    """將排序好的憑證鏈輸出為 PEM bytes"""
    parts: list[bytes] = []
    for cert in certs:
        parts.append(cert.public_bytes(Encoding.PEM))
    return b"".join(parts)


# ── 輔助函式 ──────────────────────────────────────────────────


def _is_self_signed(cert: x509.Certificate) -> bool:
    """判斷憑證是否為 self-signed（issuer == subject 即視為 self-signed）"""
    if cert.issuer != cert.subject:
        return False
    try:
        cert.verify_directly_issued_by(cert)
    except Exception:
        # issuer == subject 但簽章驗證失敗（如 SHA-1 等舊演算法），
        # 仍視為 self-signed
        pass
    return True


def _format_dn(name: x509.Name) -> str:
    """將 x509.Name 格式化為可讀字串"""
    oid_labels = {
        NameOID.COMMON_NAME: "CN",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
    }
    parts = []
    for attr in name:
        label = oid_labels.get(attr.oid, attr.oid.dotted_string)
        parts.append(f"{label}={attr.value}")
    return ", ".join(parts) if parts else "(empty)"
