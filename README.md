# APPSIGN — APK Verification & Resigning Suite

**APPSIGN** is an offline-first, modular Android application and companion CLI (`appsign`) for verifying Android APK cryptographic signatures (`v1`, `v2`, `v3`, `v3.1`, `v4`), managing portable `.ask` key containers, and batch-resigning APKs with automatic post-sign verification.

---

## 1. Architecture Overview

APPSIGN is structured into three independent Gradle modules sharing a single pure-JVM cryptographic engine:

| Module | Purpose | Key Technologies |
| :--- | :--- | :--- |
| `:appsign-core` | Pure-JVM verification, ZIP alignment, APK signing, ASK v1 key containers, JKS/PKCS#12/PKCS#8/X.509 codecs | Android `apksig`, Bouncy Castle (`bcprov`/`bcpkix`), Java Security API, `kotlinx.serialization` |
| `:app` | Offline Material 3 Jetpack Compose Android app (`com.hephaistos.appsign`) | Navigation Compose, Room + KSP, DataStore, SAF + optional `/sdcard` & `su` Root bridge |
| `:appsign-cli` | Standalone CLI (`appsign`) for Termux, Linux, macOS, and CI/CD pipelines | Picocli, standalone `fatJar` (`appsign-cli-all.jar`), POSIX `scripts/appsign` |

---

## 2. Core Features

### VERIFY APK
- Validates **v1 (JAR)**, **v2**, **v3**, **v3.1**, and **v4** (companion `.idsig`) signatures via `com.android.tools.build:apksig`.
- Inspects X.509 signer certificates (Subject/Issuer DN, serial number, validity period, signature algorithm, public key algorithm and bit length).
- Computes **SHA-256**, **SHA-1**, and **MD5** fingerprints.
- Detects multiple signers and v3 `SigningCertificateLineage` key rotations.
- Exports structured **JSON** and **Text** reports.

### RESIGN APK
- Signs or re-signs one or multiple APKs in batch mode while **always preserving original files**.
- Pure-JVM ZIP entry aligner (`PureJvmZipAligner`, 4-byte / 4096-byte for `.so`) runs prior to signing.
- Selectable signature schemes (`v1`, `v2`, `v3`, `v3.1`, `v4`) and selectable output folder (`/sdcard` or Android SAF folder).
- **Mandatory automatic post-sign verification** runs `ApkVerifierEngine` on every output APK immediately after signing.

### RESIGNPRO
- Deeply profiles a target APK's cryptographic configuration (`v1`/`v2`/`v3`/`v3.1`/`v4`, `minSdkVersion`, zipalign state, RSA/EC/DSA key sizes and curves, signature algorithms, validity periods, multi-signers, and v3 key rotation lineage).
- User supplies only the new X.509 cryptographic identity (with optional `ASK-LOCKED` passphrase; defaults to `ASK-OPEN`).
- Automatically generates matching `.ask` container(s), signs while preserving original APKs, and runs automatic post-sign verification.

### OS Sign (Unpacked GSI / Partition Signer)
- Dynamic filesystem verification and in-place resigning for unpacked Android partitions/GSIs (`.apk`, `.apex`, `.capex`, signed `.jar`) with optional full-device Root (`su`) folder browser (`/`, `/data/local`, `/data/data`, `/sdcard`).
- **Strict symlink safety**: never follows, modifies, backs up, or deletes symbolic links.
- Groups signed artifacts by shared SHA-256 certificate, maps certificate references dynamically across XML/permission/config files (`mac_permissions.xml`, hex DER, PEM, DER, SHA-256/SHA-1), preserves unsigned JARs (such as `framework.jar`), and supports `.appsign.bak` backups with 1-click **Restore** and **Delete .bak**.

---

## 3. APPSIGN Key Format (`.ask` v1)

The `.ask` format is a portable, versioned UTF-8 JSON container built strictly on standard cryptographic primitives (no custom crypto algorithms):

- **Public Header & Certificate Section** *(always inspectable without password)*:
  - `containerType`: `"APPSIGN-KEY-CONTAINER"`
  - `formatVersion`: `1`
  - `keyId`: UUID
  - `mode`: `"ASK_OPEN"` or `"ASK_LOCKED"`
  - `metadata`: alias, timestamps, algorithm, key size, DN, serial, SHA-256/SHA-1/MD5 fingerprints, notes
  - `x509CertificatePem`, `certificateChainPem`, `publicKeyPem`
- **Private Key Payload**:
  - **`ASK-OPEN`**: Unencrypted Base64 PKCS#8 DER for passwordless automation.
  - **`ASK-LOCKED`**: Authenticated encryption using **PBKDF2WithHmacSHA256** (600,000 iterations, 16-byte random salt) + **AES-256-GCM** (12-byte random IV, 128-bit auth tag, AAD bound to `APPSIGN|v1|<keyId>|<mode>`).
- **Interoperability**: Import and export **PKCS#8 + X.509 PEM/DER**, **PKCS#12 (`.p12`/`.pfx`)**, and **JKS (`.jks`)** (including a pure-JVM JKS v2 codec so `.jks` works natively on Android ART).

> **Security Notice**: Private keys exported without encryption (`ASK-OPEN` or raw PKCS#8) can be used by anyone who obtains the file. APPSIGN surfaces explicit warnings whenever unencrypted private keys are created or exported.

---

## 4. Android App Permissions & Storage

- **Zero-Permission SAF by default**: Uses Android Storage Access Framework (`ACTION_OPEN_DOCUMENT` / `ACTION_OPEN_DOCUMENT_TREE`) with zero broad storage permissions required.
- **Optional `/sdcard` Explorer**: Opening **Settings -> Full Storage Access** grants `MANAGE_EXTERNAL_STORAGE` (or legacy storage permission on Android <= 10) for direct `/sdcard` browsing and batch output.
- **Optional Root (`su`) Mode**: Can be probed and enabled in **Settings** to stage read-only copies of protected `/data/app/.../base.apk` files into app cache for inspection.
- **Bilingual & Themeable**: Runtime **French / English** switch and **System / Light / Dark** Material 3 themes.

---

## 5. `appsign` CLI Usage (Termux & Linux)

### Build the Standalone CLI JAR

```bash
gradle :appsign-cli:fatJar
```

Run directly via `java -jar appsign-cli/build/libs/appsign-cli-all.jar` or using `./scripts/appsign` (in Termux: `pkg install openjdk-17`).

### Command Examples

```bash
# Verify a single APK
appsign verify application.apk

# Batch verify with structured JSON output
appsign verify *.apk --json

# Resign with an .ask container (prompts or takes --pass for ASK-LOCKED)
appsign resign application.apk --key mykey.ask --pass secret

# Batch resign with JKS keystore and custom output directory
appsign resign *.apk --keystore mykey.jks --pass storepass --output signed/

# RESIGNPRO: clone target crypto specs with a new identity and save .ask key
appsign resign-pro target.apk --cn "Custom Dev" --org "Org" --ask-out custom_pro.ask

# OS Sign: inspect unpacked GSI/partition, resign in-place, restore or clean .bak
appsign os-sign verify /path/to/unpacked_partition
appsign os-sign resign /path/to/unpacked_partition --strategy identities --cn "Custom OS"
appsign os-sign restore /path/to/unpacked_partition/appsign-backup-manifest.json
appsign os-sign clean-bak /path/to/unpacked_partition/appsign-backup-manifest.json

# Manage ASK keys
appsign key create --alias release --alg rsa2048 --open --out release.ask
appsign key create --alias prod --alg ec256 --pass strongpass --out prod.ask
appsign key inspect prod.ask --json
appsign key import --from jks --in legacy.jks --store-pass pw --out converted.ask
appsign key export prod.ask --format p12 --pass strongpass --out-pass p12pw --out prod.p12
```

### Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | Success / Signature valid |
| `1` | Signature invalid, unsigned, or verification failure |
| `2` | Invalid CLI arguments or usage |
| `3` | File I/O or permission error |
| `4` | Cryptographic, password, or `.ask` format error |

### Python Automation Example

```python
import json, subprocess

proc = subprocess.run(["./scripts/appsign", "verify", "app.apk", "--json"], capture_output=True, text=True)
report = json.loads(proc.stdout)
print("Verified:", report["verified"], "Status:", report["overallStatus"])
```

---

## 6. Build & Test Commands

```bash
# Run core cryptographic & apksig tests
gradle :appsign-core:test

# Run CLI integration tests
gradle :appsign-cli:test

# Run Android Robolectric UI & unit tests
gradle :app:testDebugUnitTest

# Build Debug APK & standalone CLI JAR
gradle :app:assembleDebug :appsign-cli:fatJar
```

GitHub Actions CI is configured in `.github/workflows/ci.yml` to run all test suites and upload both the Debug APK and `appsign-cli-all.jar`.
