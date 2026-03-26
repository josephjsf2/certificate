# PFX AIA Intermediate Certificate Fetch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add AIA-based automatic intermediate certificate fetching to the PFX conversion tab, with fullchain PEM output.

**Architecture:** New `aia.py` logic module handles AIA extension parsing and recursive HTTP certificate downloading. GUI changes in `gui.py` add a manual "補齊憑證鏈" button and "包含 Root CA" checkbox to the PFX tab, plus `_fullchain.crt` output on save.

**Tech Stack:** Python 3.10+, `cryptography` (x509, AIA extensions), `urllib.request` (HTTP downloads), `tkinter` (GUI)

**Spec:** `docs/superpowers/specs/2026-03-26-pfx-aia-intermediate-fetch-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/certificate/aia.py` | Create | AIA URL extraction, cert download (DER/PEM), recursive chain fetch, dedup |
| `tests/test_aia.py` | Create | Unit tests for all `aia.py` functions with mocked HTTP |
| `src/certificate/gui.py` | Modify | PFX tab: add button, checkbox, AIA display, fullchain save logic |

---

## Task 1: `get_aia_ca_issuer_urls()` — Extract AIA URLs from certificate

**Files:**
- Create: `src/certificate/aia.py`
- Create: `tests/test_aia.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_aia.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_aia.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'certificate.aia'`

- [ ] **Step 3: Write the implementation**

Create `src/certificate/aia.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_aia.py::TestGetAiaCaIssuerUrls -v`
Expected: 3 PASSED

- [ ] **Step 5: Commit**

```bash
git add src/certificate/aia.py tests/test_aia.py
git commit -m "feat(aia): add get_aia_ca_issuer_urls to extract AIA URLs from cert"
```

---

## Task 2: `_download_cert()` — Download and parse a single certificate

**Files:**
- Modify: `src/certificate/aia.py`
- Modify: `tests/test_aia.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aia.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_aia.py::TestDownloadCert -v`
Expected: FAIL — `ImportError: cannot import name '_download_cert'`

- [ ] **Step 3: Write the implementation**

Add to `src/certificate/aia.py`:

```python
from urllib.request import urlopen, Request


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_aia.py::TestDownloadCert -v`
Expected: 4 PASSED

- [ ] **Step 5: Commit**

```bash
git add src/certificate/aia.py tests/test_aia.py
git commit -m "feat(aia): add _download_cert with DER/PEM auto-detection"
```

---

## Task 3: `fetch_intermediate_chain()` — Recursive AIA chain fetch

**Files:**
- Modify: `src/certificate/aia.py`
- Modify: `tests/test_aia.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_aia.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_aia.py::TestFetchIntermediateChain -v`
Expected: FAIL — `ImportError: cannot import name 'fetch_intermediate_chain'` (it exists but has no body yet)

- [ ] **Step 3: Write the implementation**

Add to `src/certificate/aia.py`:

```python
from certificate.chain import _is_self_signed


def _cert_fingerprint(cert: x509.Certificate) -> bytes:
    """Compute SHA-256 fingerprint for dedup."""
    from cryptography.hazmat.primitives import hashes

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
        if not _is_self_signed(current):
            errors.append("已達最大深度限制，憑證鏈可能不完整")

    return AiaResult(
        certificates=downloaded,
        errors=errors,
        root_found=root_found,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_aia.py -v`
Expected: ALL PASSED (10 tests total)

- [ ] **Step 5: Commit**

```bash
git add src/certificate/aia.py tests/test_aia.py
git commit -m "feat(aia): add fetch_intermediate_chain with recursive AIA download"
```

---

## Task 4: GUI — Add "補齊憑證鏈" button, "儲存" button, and "包含 Root CA" checkbox

**Files:**
- Modify: `src/certificate/gui.py:18` (add import)
- Modify: `src/certificate/gui.py:421-550` (PFX tab section)

The current `_on_convert_pfx` combines display + save in one action. We need to separate these so the user can optionally press "補齊憑證鏈" between convert and save. The flow becomes: 轉換 (display info) → optionally 補齊憑證鏈 → 儲存.

- [ ] **Step 1: Add import**

At the top of `gui.py`, after the existing imports (line 18), add:

```python
from certificate.aia import fetch_intermediate_chain
```

- [ ] **Step 2: Modify `_build_pfx_tab` — add buttons and checkbox**

In `_build_pfx_tab`, replace the single "轉換" button block (line 452-453) with a button row containing four elements:

```python
        # --- Action Buttons ---
        action_frame = ttk.Frame(tab)
        action_frame.pack(fill="x", **pad)

        ttk.Button(
            action_frame, text="轉換", command=self._on_convert_pfx
        ).pack(side="left", padx=(0, 8))

        self._pfx_fetch_chain_btn = ttk.Button(
            action_frame,
            text="補齊憑證鏈",
            command=self._on_fetch_aia_chain,
            state="disabled",
        )
        self._pfx_fetch_chain_btn.pack(side="left", padx=(0, 8))

        self._pfx_include_root = tk.BooleanVar()
        ttk.Checkbutton(
            action_frame,
            text="包含 Root CA",
            variable=self._pfx_include_root,
        ).pack(side="left", padx=(0, 8))

        self._pfx_save_btn = ttk.Button(
            action_frame,
            text="儲存",
            command=self._on_save_pfx,
            state="disabled",
        )
        self._pfx_save_btn.pack(side="left")
```

Add state variables at the end of `_build_pfx_tab`:

```python
        self._pfx_result: dict | None = None
        self._pfx_aia_certs: list = []
        self._pfx_aia_errors: list[str] = []
```

- [ ] **Step 3: Modify `_on_convert_pfx` — display only, no save**

Rewrite `_on_convert_pfx` to only display certificate info and enable buttons (remove all save logic from this method):

```python
    def _on_convert_pfx(self):
        if not self._pfx_data:
            messagebox.showerror("錯誤", "請先載入 PFX 檔案")
            return

        password = self._pfx_password.get()

        try:
            result = load_pfx(self._pfx_data, password)
        except Exception as e:
            messagebox.showerror("轉換失敗", f"無法解析 PFX 檔案:\n{e}")
            return

        self._pfx_result = result
        self._pfx_aia_certs = []
        self._pfx_aia_errors = []
        self._pfx_fetch_chain_btn.configure(state="normal")
        self._pfx_save_btn.configure(state="normal")

        # Display certificate info
        lines = []
        if result["certificate_info"]:
            info = result["certificate_info"]
            lines.append("═══ 主憑證 ═══")
            lines.append(f"Subject: {info['subject']}")
            lines.append(f"Issuer:  {info['issuer']}")
            lines.append(f"有效期:  {info['not_before']} ~ {info['not_after']}")
            lines.append(f"序號:    {info['serial']}")

        if result["additional_certs_info"]:
            lines.append("")
            lines.append(f"═══ 附加憑證 ({len(result['additional_certs_info'])} 張) ═══")
            for i, info in enumerate(result["additional_certs_info"]):
                lines.append(f"[{i}] Subject: {info['subject']}")
                lines.append(f"    Issuer:  {info['issuer']}")
                lines.append(f"    有效期:  {info['not_before']} ~ {info['not_after']}")

        if result["private_key_pem"]:
            lines.append("")
            lines.append("私鑰: 已提取")
        else:
            lines.append("")
            lines.append("私鑰: 無")

        self._pfx_info.configure(state="normal")
        self._pfx_info.delete("1.0", tk.END)
        self._pfx_info.insert("1.0", "\n".join(lines))
        self._pfx_info.configure(state="disabled")
```

- [ ] **Step 4: Add `_on_fetch_aia_chain` handler**

Add new method after `_on_convert_pfx`:

```python
    def _on_fetch_aia_chain(self):
        if not self._pfx_result or not self._pfx_result.get("certificate_pem"):
            return

        # Parse the leaf certificate
        leaf_cert = x509.load_pem_x509_certificate(
            self._pfx_result["certificate_pem"]
        )

        # Parse existing additional certs from PFX
        existing: list[x509.Certificate] = []
        for pem in self._pfx_result.get("additional_certs_pem", []):
            existing.append(x509.load_pem_x509_certificate(pem))

        # Determine start cert: if PFX has intermediates, start from the topmost
        from certificate.chain import _is_self_signed

        if existing:
            sorted_chain = build_chain([leaf_cert] + existing)
            start_cert = sorted_chain[-1] if sorted_chain else leaf_cert
            if _is_self_signed(start_cert) and len(sorted_chain) > 1:
                start_cert = sorted_chain[-2]
        else:
            start_cert = leaf_cert

        aia_result = fetch_intermediate_chain(
            start_cert, existing_certs=[leaf_cert] + existing
        )

        self._pfx_aia_certs = aia_result.certificates
        self._pfx_aia_errors = aia_result.errors

        # Update info display — append to existing content
        from certificate.pfx import format_certificate_info

        self._pfx_info.configure(state="normal")

        lines = []
        if aia_result.certificates:
            lines.append("")
            lines.append(
                f"═══ AIA 補齊結果 ({len(aia_result.certificates)} 張) ═══"
            )
            for i, cert in enumerate(aia_result.certificates):
                info = format_certificate_info(cert)
                lines.append(f"[{i}] Subject: {info['subject']}")
                lines.append(f"    Issuer:  {info['issuer']}")
                lines.append(
                    f"    有效期:  {info['not_before']} ~ {info['not_after']}"
                )

        if aia_result.errors:
            lines.append("")
            for err in aia_result.errors:
                lines.append(f"⚠ {err}")

        if not aia_result.certificates and not aia_result.errors:
            lines.append("")
            lines.append("⚠ 無法透過 AIA 取得 intermediate 憑證")

        self._pfx_info.insert(tk.END, "\n".join(lines))
        self._pfx_info.configure(state="disabled")
```

- [ ] **Step 5: Add `_on_save_pfx` handler with fullchain support**

Add new method after `_on_fetch_aia_chain`:

```python
    def _on_save_pfx(self):
        result = self._pfx_result
        if not result:
            return

        file_path = filedialog.asksaveasfilename(
            title="儲存憑證檔案",
            defaultextension=".crt",
            filetypes=[("Certificate files", "*.crt"), ("All files", "*.*")],
        )
        if not file_path:
            return

        base = file_path[:-4] if file_path.endswith(".crt") else file_path
        key_path = base + ".key"
        chain_path = base + "_chain.crt"
        fullchain_path = base + "_fullchain.crt"

        saved = []

        # Main certificate
        if result["certificate_pem"]:
            with open(file_path, "wb") as f:
                f.write(result["certificate_pem"])
            saved.append(f"憑證: {file_path}")

        # Private key
        if result["private_key_pem"]:
            with open(key_path, "wb") as f:
                f.write(result["private_key_pem"])
            saved.append(f"私鑰: {key_path}")

        # Chain file: PFX additional certs + AIA-fetched certs
        from cryptography.hazmat.primitives.serialization import Encoding
        from certificate.chain import _is_self_signed

        all_chain_pem: list[bytes] = list(result.get("additional_certs_pem", []))
        for cert in self._pfx_aia_certs:
            all_chain_pem.append(cert.public_bytes(Encoding.PEM))

        if all_chain_pem:
            with open(chain_path, "wb") as f:
                for pem in all_chain_pem:
                    f.write(pem)
            saved.append(f"憑證鏈: {chain_path}")

        # Fullchain: leaf + PFX intermediates + AIA intermediates (optional root)
        if self._pfx_aia_certs and result["certificate_pem"]:
            fullchain_parts: list[bytes] = [result["certificate_pem"]]

            # Add PFX additional certs (in original order)
            for pem in result.get("additional_certs_pem", []):
                fullchain_parts.append(pem)

            # Add AIA-fetched certs (filter root based on checkbox)
            for cert in self._pfx_aia_certs:
                if _is_self_signed(cert) and not self._pfx_include_root.get():
                    continue
                fullchain_parts.append(cert.public_bytes(Encoding.PEM))

            with open(fullchain_path, "wb") as f:
                for part in fullchain_parts:
                    f.write(part)
            saved.append(f"完整鏈: {fullchain_path}")

        messagebox.showinfo("成功", "已儲存:\n" + "\n".join(saved))
```

- [ ] **Step 6: Verify the app launches without errors**

Run: `uv run certificate`
Expected: App opens, PFX tab shows "轉換", "補齊憑證鏈" (disabled), "包含 Root CA" checkbox, and "儲存" (disabled). After loading a PFX and pressing "轉換", "補齊憑證鏈" and "儲存" become enabled.

- [ ] **Step 7: Commit**

```bash
git add src/certificate/gui.py
git commit -m "feat(gui): add AIA chain fetch button, save button, and fullchain output to PFX tab"
```

---

## Task 5: Run full test suite and verify

**Files:**
- All files from previous tasks

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: ALL tests pass (existing + new)

- [ ] **Step 2: Verify AIA tests specifically**

Run: `uv run pytest tests/test_aia.py -v`
Expected: All 10 AIA tests pass

- [ ] **Step 3: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix: address test issues from AIA integration"
```

(Only if fixes were needed.)
