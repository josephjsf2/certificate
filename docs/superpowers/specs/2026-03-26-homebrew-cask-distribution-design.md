# Homebrew Cask Distribution for macOS

**Date**: 2026-03-26
**Status**: Approved

## Problem

從 GitHub Release 下載的 macOS `.app` bundle 因缺少 code signing 和 notarization，被 Gatekeeper 擋下並顯示「已損壞」錯誤。使用者沒有 Apple Developer 帳號，無法進行 notarization。

## Solution

透過 Homebrew Cask 發布 macOS 版本。Homebrew 會自動處理 quarantine 屬性移除，使用者不需手動執行 `xattr` 指令。

## Architecture

```
josephjsf2/certificate (existing repo)
  └── .github/workflows/build.yml
        ├── build-macos job      (unchanged — build .app zip)
        ├── build-windows job    (unchanged)
        ├── release job          (unchanged — upload both zips to Release)
        └── update-tap job       (NEW — auto-update homebrew-tap)

josephjsf2/homebrew-tap (new repo, already created)
  └── Casks/certificate.rb      (cask formula)
```

## Cask Formula (`Casks/certificate.rb`)

```ruby
cask "certificate" do
  version "0.3.1"
  sha256 "<sha256-of-macos-zip>"

  url "https://github.com/josephjsf2/certificate/releases/download/v#{version}/CSR%E5%B7%A5%E5%85%B7-macos.zip"
  name "CSR工具"
  desc "Cross-platform certificate management tool"
  homepage "https://github.com/josephjsf2/certificate"

  app "CSR工具.app"
end
```

Key points:
- `url` points to the GitHub Release asset (URL-encoded Chinese characters)
- `app` directive moves the `.app` into `/Applications`
- Homebrew handles quarantine removal automatically

## CI Changes (`build.yml`)

### New job: `update-tap`

Runs after `release` job completes:

1. Download the macOS zip from the newly created Release
2. Calculate SHA256 of the zip
3. Extract version from the git tag (`${{ github.ref_name }}` → strip `v` prefix)
4. Checkout `josephjsf2/homebrew-tap` using `TAP_GITHUB_TOKEN` secret
5. Update `Casks/certificate.rb` with new `version` and `sha256` via `sed`
6. Commit and push to `homebrew-tap`

### Required secret

- `TAP_GITHUB_TOKEN`: Personal Access Token with `repo` scope for `josephjsf2/homebrew-tap` (already configured)

## README Changes

macOS installation section changes from direct download to:

```bash
brew tap josephjsf2/tap
brew install --cask josephjsf2/tap/certificate
```

Windows section remains as direct download from Release page.

## User Experience

### macOS (new)
```bash
# Install
brew tap josephjsf2/tap
brew install --cask josephjsf2/tap/certificate

# Update
brew upgrade josephjsf2/tap/certificate

# Uninstall
brew uninstall josephjsf2/tap/certificate
```

### Windows (unchanged)
Download from GitHub Release page.

## Release Flow

1. Developer pushes `v*` tag
2. CI builds macOS `.app` + Windows `.exe`
3. CI creates GitHub Release with both zips
4. CI auto-updates `homebrew-tap` cask formula with new version + SHA256
5. macOS users run `brew upgrade` to get the new version
