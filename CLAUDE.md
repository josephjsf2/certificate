# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Cross-platform certificate management GUI (Traditional Chinese UI) built with Python/Tkinter. Features: CSR generation, CSR decoding, certificate chain validation & sorting, PFX→PEM conversion, self-signed certificate generation.

## Commands

```bash
uv sync --all-groups        # Install all deps (dev + build)
uv run certificate          # Launch the GUI app
uv run pytest tests/ -v     # Run all tests
uv run pytest tests/test_csr.py -v              # Run single test file
uv run pytest tests/test_csr.py::test_name -v   # Run single test
```

## Architecture

```
src/certificate/
├── main.py        # Entry point → instantiates App
├── gui.py         # Tkinter App class, 6-tab Notebook (all UI logic)
├── csr.py         # CSR generation, decoding, SAN validation
├── chain.py       # Certificate chain parsing, validation, sorting, export
├── pfx.py         # PFX/P12 loading and PEM extraction
└── selfsigned.py  # Self-signed cert generation (with CA mode)
```

**Pattern**: Pure logic modules (`csr`, `chain`, `pfx`, `selfsigned`) are separated from the GUI (`gui.py`). All crypto operations live in the logic modules; `gui.py` only handles widgets, layout, and user interaction. Tests cover only the logic modules — no GUI tests.

## Key Constraints

- **`cryptography` import cost**: The library has ~1.5s cold import time. Currently `gui.py` imports all logic modules at the top level, absorbing the cost at startup. If adding new entry points or lazy-loaded modules, defer `cryptography` imports inside functions to avoid blocking.
- **Python ≥ 3.10**: Uses modern type syntax (`X | None`, etc.).
- **SAN format**: Users enter `DNS:hostname` or `IP:address` (one per line). Bare hostnames fall back to `DNSName`.

## Build & Release

CI builds standalone executables via **Nuitka** (not PyInstaller) with the `tk-inter` plugin. Releases trigger on pushing a `v*` tag. The pipeline:
1. Runs tests on both macOS and Windows
2. Builds Nuitka standalone binaries → packages as `certificate-macos.zip` (.app bundle) and `certificate-windows.zip` (.exe)
3. Creates a GitHub Release with both artifacts
4. Auto-updates the Homebrew tap (`josephjsf2/homebrew-tap`) with the new version and SHA256

**macOS install**: `brew install --cask josephjsf2/tap/certificate`

```bash
# Local Nuitka build (macOS example)
uv run python -m nuitka --standalone --enable-plugin=tk-inter --output-dir=dist src/certificate/main.py
```
