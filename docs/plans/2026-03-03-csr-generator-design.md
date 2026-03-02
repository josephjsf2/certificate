# CSR Generator Design

## Overview

A cross-platform GUI tool for generating Certificate Signing Requests (CSR), built with Python + Tkinter + `cryptography` library. Produces output identical to OpenSSL's `openssl req` command.

## Architecture

```
certificate/
├── pyproject.toml
├── src/
│   └── certificate/
│       ├── __init__.py
│       ├── main.py         # Entry point
│       ├── gui.py          # Tkinter GUI
│       └── csr.py          # CSR/key generation logic
```

- **csr.py**: Pure logic layer — RSA key generation and CSR construction, no GUI dependency
- **gui.py**: Tkinter interface — collects user input and calls csr.py
- **main.py**: Entry point — `uv run certificate` starts the app

## GUI Layout

Single window, top-to-bottom layout:

### Subject Fields

| Field | Label | Required | Default |
|-------|-------|----------|---------|
| Common Name (CN) | 通用名稱 | Yes | — |
| Organization (O) | 組織 | No | — |
| Organizational Unit (OU) | 部門 | No | — |
| Country (C) | 國家代碼 | No | TW |
| State (ST) | 州/省 | No | — |
| Locality (L) | 城市 | No | — |
| Email | 電子郵件 | No | — |

### RSA Key Settings

- Key size dropdown: 2048 / 4096 (default 2048)

### Subject Alternative Names (SAN)

- Multi-line text area, one entry per line
- Format: `DNS:example.com` or `IP:192.168.1.1`
- Hint text explaining the format

### Actions

- "產生 CSR" button — opens file save dialog, saves `.csr` and `.key` files
- Success/failure message dialog after generation

## CSR Generation Logic

### Key Generation
- `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key`
- public_exponent=65537, key_size from user selection
- Output: PEM format, no password (matches `openssl genrsa` default)

### CSR Construction
- `cryptography.x509.CertificateSigningRequestBuilder`
- Subject via `x509.Name`, only includes non-empty fields
- SAN via `x509.SubjectAlternativeName` extension, parses DNS/IP entries
- Signature algorithm: SHA-256 (`hashes.SHA256()`), matches `openssl req -sha256`

### Output Format
- CSR: PEM encoding (`serialization.Encoding.PEM`)
- Private key: PEM encoding, PKCS8 format, no encryption (`serialization.NoEncryption()`)

### Validation
- CN is required
- SAN format: each line must start with `DNS:` or `IP:`, IP must be valid IPv4/IPv6
- Validation errors returned as messages for GUI display

## Dependencies

- Python >= 3.10
- `cryptography` (sole third-party dependency)
- Tkinter (Python built-in)

## Execution

```
uv run certificate
```

Entry point configured via `[project.scripts]` in pyproject.toml.
