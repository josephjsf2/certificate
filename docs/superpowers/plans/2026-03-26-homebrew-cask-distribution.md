# Homebrew Cask Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Distribute the macOS app via Homebrew Cask to bypass Gatekeeper quarantine issues, with CI auto-updating the tap on each release.

**Architecture:** Add a cask formula to `josephjsf2/homebrew-tap`, then extend the existing `build.yml` with an `update-tap` job that auto-pushes version/SHA256 updates after each release. Fix zip filenames to ASCII (Chinese characters get stripped by GitHub Release uploads).

**Tech Stack:** GitHub Actions, Homebrew Cask (Ruby DSL), gh CLI

---

### Task 1: Create initial cask formula in `josephjsf2/homebrew-tap`

**Files:**
- Create: `Casks/certificate.rb` (in the `josephjsf2/homebrew-tap` repo)

Note: This is an external repo. Use `gh` CLI to clone, commit, and push.

- [ ] **Step 1: Clone the tap repo**

```bash
cd /tmp && gh repo clone josephjsf2/homebrew-tap
```

- [ ] **Step 2: Create the cask formula**

Create `Casks/certificate.rb`:

```ruby
cask "certificate" do
  version "0.3.1"
  sha256 :no_check

  url "https://github.com/josephjsf2/certificate/releases/download/v#{version}/certificate-macos.zip"
  name "CSR工具"
  desc "Cross-platform certificate management tool"
  homepage "https://github.com/josephjsf2/certificate"

  app "CSR工具.app"
end
```

Notes:
- `sha256 :no_check` for now — the CI `update-tap` job will overwrite this with the real SHA256 on the next release.
- The `url` uses the new ASCII filename `certificate-macos.zip` (will be produced after Task 2).
- `app "CSR工具.app"` is fine — Chinese characters work inside the zip, just not in the GitHub Release asset name.

```bash
mkdir -p /tmp/homebrew-tap/Casks
cat > /tmp/homebrew-tap/Casks/certificate.rb << 'RUBY'
cask "certificate" do
  version "0.3.1"
  sha256 :no_check

  url "https://github.com/josephjsf2/certificate/releases/download/v#{version}/certificate-macos.zip"
  name "CSR工具"
  desc "Cross-platform certificate management tool"
  homepage "https://github.com/josephjsf2/certificate"

  app "CSR工具.app"
end
RUBY
```

- [ ] **Step 3: Commit and push**

```bash
cd /tmp/homebrew-tap
git add Casks/certificate.rb
git commit -m "feat: add certificate cask formula"
git push origin main
```

---

### Task 2: Fix `build.yml` — ASCII zip filenames and dynamic version

**Files:**
- Modify: `.github/workflows/build.yml:36-53` (macOS bundle & zip step)
- Modify: `.github/workflows/build.yml:77-82` (Windows package step)
- Modify: `.github/workflows/build.yml:99-104` (release asset paths)

**Why:** Chinese characters `工具` in zip filenames are silently stripped by `softprops/action-gh-release`, producing `CSR.-macos.zip` instead of `CSR工具-macos.zip`. Also, Info.plist hardcodes version `0.3.0`.

- [ ] **Step 1: Update the "Create .app bundle" step**

Replace the entire `Create .app bundle` step (lines 36-48) with a version that:
1. Extracts the version from the git tag dynamically
2. Uses the tag version in Info.plist instead of hardcoded `0.3.0`
3. Names the zip `certificate-macos.zip` (ASCII)

```yaml
      - name: Create .app bundle
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          mkdir -p "dist/CSR工具.app/Contents"
          mv dist/main.dist "dist/CSR工具.app/Contents/MacOS"
          chmod +x "dist/CSR工具.app/Contents/MacOS/main.bin"
          /usr/libexec/PlistBuddy -c "Add :CFBundleExecutable string main.bin" "dist/CSR工具.app/Contents/Info.plist"
          /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string com.certificate.tool" "dist/CSR工具.app/Contents/Info.plist"
          /usr/libexec/PlistBuddy -c "Add :CFBundleName string CSR工具" "dist/CSR工具.app/Contents/Info.plist"
          /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string $VERSION" "dist/CSR工具.app/Contents/Info.plist"
          /usr/libexec/PlistBuddy -c "Add :CFBundleShortVersionString string $VERSION" "dist/CSR工具.app/Contents/Info.plist"
          /usr/libexec/PlistBuddy -c "Add :CFBundlePackageType string APPL" "dist/CSR工具.app/Contents/Info.plist"
          /usr/libexec/PlistBuddy -c "Add :NSHighResolutionCapable bool true" "dist/CSR工具.app/Contents/Info.plist"
          cd dist && zip -r "certificate-macos.zip" "CSR工具.app"
```

- [ ] **Step 2: Update the macOS artifact upload path**

Change the upload artifact path (line 53):

```yaml
      - uses: actions/upload-artifact@v4
        with:
          name: macos-zip
          path: dist/certificate-macos.zip
```

- [ ] **Step 3: Update the Windows package step**

Replace the Windows `Package distribution` step (lines 77-82) to use ASCII zip name:

```yaml
      - name: Package distribution
        shell: pwsh
        run: |
          Rename-Item -Path "dist\main.dist\main.exe" -NewName "CSR工具.exe"
          Rename-Item -Path "dist\main.dist" -NewName "CSR工具"
          Compress-Archive -Path "dist\CSR工具" -DestinationPath "dist\certificate-windows.zip"
```

- [ ] **Step 4: Update Windows artifact upload path**

```yaml
      - uses: actions/upload-artifact@v4
        with:
          name: windows-zip
          path: dist/certificate-windows.zip
```

- [ ] **Step 5: Update release asset paths**

Replace the release `files` section (lines 102-104):

```yaml
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            artifacts/macos-zip/certificate-macos.zip
            artifacts/windows-zip/certificate-windows.zip
```

- [ ] **Step 6: Verify the complete build.yml is valid YAML**

Read the file back and visually verify indentation and structure are correct.

---

### Task 3: Add `update-tap` job to `build.yml`

**Files:**
- Modify: `.github/workflows/build.yml` (append new job after `release`)

- [ ] **Step 1: Add the `update-tap` job**

Append this job at the end of `build.yml`:

```yaml
  update-tap:
    needs: [release]
    runs-on: ubuntu-latest
    steps:
      - name: Download macOS zip from release
        run: |
          gh release download "${{ github.ref_name }}" \
            --repo "${{ github.repository }}" \
            --pattern "certificate-macos.zip" \
            --dir .
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Calculate SHA256
        id: sha
        run: |
          SHA=$(sha256sum certificate-macos.zip | awk '{print $1}')
          echo "sha256=$SHA" >> "$GITHUB_OUTPUT"

      - name: Update Homebrew tap
        run: |
          VERSION="${{ github.ref_name }}"
          VERSION="${VERSION#v}"
          SHA="${{ steps.sha.outputs.sha256 }}"

          gh repo clone josephjsf2/homebrew-tap /tmp/homebrew-tap
          cd /tmp/homebrew-tap

          sed -i "s/version \".*\"/version \"$VERSION\"/" Casks/certificate.rb
          sed -i "s/sha256 .*/sha256 \"$SHA\"/" Casks/certificate.rb

          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add Casks/certificate.rb
          git commit -m "chore: bump certificate to $VERSION"
          git push
        env:
          GH_TOKEN: ${{ secrets.TAP_GITHUB_TOKEN }}
```

Key details:
- Uses `gh release download` to get the exact zip from the release (not rebuilding)
- `sha256sum` calculates the hash on ubuntu
- `sed -i` updates both `version` and `sha256` in the formula
- Uses `TAP_GITHUB_TOKEN` (not `GITHUB_TOKEN`) for push access to the tap repo
- `GH_TOKEN` env var is used by `gh` CLI for both `gh release download` and `gh repo clone`

- [ ] **Step 2: Verify the complete build.yml is valid YAML**

Read the entire file back and verify structure, indentation, and job dependency chain:
`build-macos` + `build-windows` → `release` → `update-tap`

---

### Task 4: Update README.md

**Files:**
- Modify: `README.md:33-38` (download section)

- [ ] **Step 1: Replace the macOS download section**

Replace the "下載預建版本" section (lines 33-38) with:

```markdown
### 下載預建版本

**macOS** — 透過 [Homebrew](https://brew.sh/) 安裝：

```bash
brew tap josephjsf2/tap
brew install --cask josephjsf2/tap/certificate
```

**Windows** — 至 [Releases](https://github.com/josephjsf2/certificate/releases) 頁面下載 `certificate-windows.zip`，解壓後執行 `CSR工具.exe`。
```

Note: Windows zip filename also changed to `certificate-windows.zip` (ASCII).

- [ ] **Step 2: Verify README renders correctly**

Read the file back and confirm Markdown formatting is correct.

---

### Task 5: Commit all changes

- [ ] **Step 1: Commit**

```bash
git add .github/workflows/build.yml README.md
git commit -m "feat: distribute macOS app via Homebrew Cask

- Add update-tap CI job to auto-update homebrew-tap formula
- Fix zip filenames to ASCII (Chinese chars stripped by GitHub)
- Fix hardcoded version in Info.plist to use git tag
- Update README with Homebrew install instructions for macOS"
```
