# CSR Generator Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a cross-platform GUI tool that generates Certificate Signing Requests (CSR) with the same output as OpenSSL.

**Architecture:** Tkinter GUI (`gui.py`) collects user input and delegates to a pure logic layer (`csr.py`) for RSA key generation and CSR construction using the `cryptography` library. Entry point via `main.py`.

**Tech Stack:** Python 3.10+, Tkinter, `cryptography`, `uv` for package management.

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/certificate/__init__.py`
- Create: `src/certificate/main.py`

**Step 1: Initialize uv project**

Run: `uv init --lib --name certificate`

Then replace `pyproject.toml` with:

```toml
[project]
name = "certificate"
version = "0.1.0"
description = "Cross-platform CSR generator with GUI"
requires-python = ">=3.10"
dependencies = [
    "cryptography",
]

[project.scripts]
certificate = "certificate.main:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

**Step 2: Create entry point**

Create `src/certificate/__init__.py` (empty file).

Create `src/certificate/main.py`:

```python
from certificate.gui import App


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
```

**Step 3: Install dependencies**

Run: `uv sync`

**Step 4: Commit**

```bash
git add pyproject.toml uv.lock src/
git commit -m "feat: scaffold project with uv and entry point"
```

---

### Task 2: CSR Generation Logic

**Files:**
- Create: `src/certificate/csr.py`
- Create: `tests/test_csr.py`

**Step 1: Write failing tests**

Create `tests/test_csr.py`:

```python
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from certificate.csr import generate_private_key, build_csr, validate_san_entries


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
```

**Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_csr.py -v`

Expected: FAIL — `ModuleNotFoundError: No module named 'certificate.csr'`

**Step 3: Implement csr.py**

Create `src/certificate/csr.py`:

```python
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
```

**Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_csr.py -v`

Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/certificate/csr.py tests/test_csr.py
git commit -m "feat: implement CSR generation logic with tests"
```

---

### Task 3: Tkinter GUI

**Files:**
- Create: `src/certificate/gui.py`

**Step 1: Implement gui.py**

Create `src/certificate/gui.py`:

```python
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from certificate.csr import generate_private_key, build_csr, validate_san_entries


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CSR 產生器")
        self.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        # --- Subject Fields ---
        subject_frame = ttk.LabelFrame(self, text="Subject 欄位")
        subject_frame.pack(fill="x", **pad)

        fields = [
            ("通用名稱 (CN)*", "cn"),
            ("組織 (O)", "org"),
            ("部門 (OU)", "ou"),
            ("國家代碼 (C)", "country"),
            ("州/省 (ST)", "state"),
            ("城市 (L)", "locality"),
            ("電子郵件", "email"),
        ]
        self._entries = {}
        for row, (label, key) in enumerate(fields):
            ttk.Label(subject_frame, text=label).grid(
                row=row, column=0, sticky="w", padx=4, pady=2
            )
            entry = ttk.Entry(subject_frame, width=40)
            entry.grid(row=row, column=1, padx=4, pady=2)
            self._entries[key] = entry

        # Default country to TW
        self._entries["country"].insert(0, "TW")

        # --- RSA Key Settings ---
        key_frame = ttk.LabelFrame(self, text="RSA 金鑰設定")
        key_frame.pack(fill="x", **pad)

        ttk.Label(key_frame, text="金鑰長度").grid(
            row=0, column=0, sticky="w", padx=4, pady=2
        )
        self._key_size = ttk.Combobox(
            key_frame, values=["2048", "4096"], state="readonly", width=10
        )
        self._key_size.set("2048")
        self._key_size.grid(row=0, column=1, sticky="w", padx=4, pady=2)

        # --- SAN ---
        san_frame = ttk.LabelFrame(self, text="Subject Alternative Names (SAN)")
        san_frame.pack(fill="x", **pad)

        ttk.Label(
            san_frame,
            text="每行一個，格式: DNS:example.com 或 IP:192.168.1.1",
            foreground="gray",
        ).pack(anchor="w", padx=4)
        self._san_text = tk.Text(san_frame, height=5, width=50)
        self._san_text.pack(fill="x", padx=4, pady=4)

        # --- Generate Button ---
        ttk.Button(self, text="產生 CSR", command=self._on_generate).pack(pady=12)

    def _on_generate(self):
        cn = self._entries["cn"].get().strip()
        if not cn:
            messagebox.showerror("錯誤", "通用名稱 (CN) 為必填欄位")
            return

        # Parse SAN
        san_raw = self._san_text.get("1.0", tk.END).strip()
        san_entries = [line for line in san_raw.splitlines() if line.strip()] if san_raw else []

        # Validate SAN
        san_errors = validate_san_entries(san_entries)
        if san_errors:
            messagebox.showerror("SAN 格式錯誤", "\n".join(san_errors))
            return

        # Ask save path
        file_path = filedialog.asksaveasfilename(
            title="儲存 CSR 檔案",
            defaultextension=".csr",
            filetypes=[("CSR files", "*.csr"), ("All files", "*.*")],
            initialfile=f"{cn}.csr",
        )
        if not file_path:
            return

        # Derive key path
        if file_path.endswith(".csr"):
            key_path = file_path[:-4] + ".key"
        else:
            key_path = file_path + ".key"

        try:
            key_size = int(self._key_size.get())
            private_key = generate_private_key(key_size)
            csr_pem, key_pem = build_csr(
                private_key=private_key,
                common_name=cn,
                organization=self._entries["org"].get(),
                organizational_unit=self._entries["ou"].get(),
                country=self._entries["country"].get(),
                state=self._entries["state"].get(),
                locality=self._entries["locality"].get(),
                email=self._entries["email"].get(),
                san_entries=san_entries,
            )

            with open(file_path, "wb") as f:
                f.write(csr_pem)
            with open(key_path, "wb") as f:
                f.write(key_pem)

            messagebox.showinfo(
                "成功",
                f"CSR 已儲存至:\n{file_path}\n\n私鑰已儲存至:\n{key_path}",
            )
        except Exception as e:
            messagebox.showerror("產生失敗", str(e))
```

**Step 2: Smoke test — launch the app**

Run: `uv run certificate`

Expected: Tkinter window opens with all fields, dropdown, SAN text area, and generate button.

**Step 3: Manual test — generate a CSR**

1. Fill in CN = `test.example.com`
2. Add SAN: `DNS:test.example.com`
3. Click "產生 CSR", save to a temp location
4. Verify with OpenSSL: `openssl req -text -noout -in /path/to/test.example.com.csr`

Expected: OpenSSL prints the CSR details with matching CN and SAN.

**Step 4: Commit**

```bash
git add src/certificate/gui.py
git commit -m "feat: add Tkinter GUI for CSR generation"
```

---

### Task 4: Wire Entry Point and Final Verification

**Files:**
- Verify: `src/certificate/main.py`
- Verify: `pyproject.toml`

**Step 1: Run all tests**

Run: `uv run pytest tests/ -v`

Expected: All tests PASS.

**Step 2: End-to-end test with OpenSSL comparison**

Generate a CSR via the GUI, then verify:

```bash
openssl req -text -noout -in output.csr
openssl rsa -check -in output.key -noout
```

Expected: CSR shows correct subject/SAN, key check passes.

**Step 3: Commit final state**

```bash
git add -A
git commit -m "feat: complete CSR generator v0.1.0"
```
