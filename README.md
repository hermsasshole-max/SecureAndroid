# AegisLocal — Privacy-First Android Network & Link Security App

AegisLocal is a non-root, privacy-first Android cybersecurity application and interactive workbench built with **React 19 + TypeScript + Vite + Capacitor 8** and native **Android Kotlin (`minSdk 28`, `compileSdk 36`, AGP 8.13, Java 21)**.

## Core Security Capabilities

1. **Wi-Fi Inspector & Evil Twin Detector**
   - Scans nearby 802.11 beacons via `WifiManager` to flag unencrypted (`OPEN`), `WEP`, and legacy `WPA-TKIP` ciphers.
   - Compares observed hardware BSSIDs and NIC OUIs against trusted baselines stored in hardware-backed `EncryptedSharedPreferences` (`AES256-SIV` + `AES256-GCM`) to detect Evil Twin impersonation and protocol downgrade attacks.
   - Runs an on-device **Local Loopback `VpnService`** (`LocalLoopbackVpnService.kt` on `tun0` `10.215.173.1/30`) to inspect DNS QNAMEs locally in memory with zero external VPN server routing.

2. **Link Safe-Guard & Homograph URL Analyzer**
   - Registers an Android Browser Picker `ACTION_VIEW` (`http`/`https`) `<intent-filter>` so external links clicked in SMS, email, or messaging apps can be inspected before launching the system browser.
   - Expands shortened URLs (`bit.ly`, `tinyurl.com`, `t.co`) via non-rendering `HttpURLConnection` `HEAD` requests (`instanceFollowRedirects = false`) without initializing a `WebView`.
   - Performs RFC 3492 Punycode decoding, Android ICU `SpoofChecker` mixed-script confusable analysis, Damerau-Levenshtein typosquatting checks, `@` userinfo credential spoof detection, and `.apk` binary payload blocking.

3. **Permission & Device Health Auditor**
   - Scans installed user-space APKs via `PackageManager` and `AccessibilityManager` to detect Banking Trojan / Spyware permission triads (`BIND_ACCESSIBILITY_SERVICE` + `SYSTEM_ALERT_WINDOW` + `RECEIVE_SMS` / `READ_SMS`) and hidden-launcher stalkerware.
   - Verifies `KeyguardManager.isDeviceSecure`, `Build.VERSION.SECURITY_PATCH` staleness, Play Protect package verification, USB/Wireless ADB state, and unknown APK install sources.

---

## Building the Android APK on GitHub Actions

This repository includes `.github/workflows/build-android-apk.yml`, which automatically runs unit tests, compiles the Vite production bundle, syncs Capacitor 8 (`npx cap sync android`), and builds the Android APK using **JDK 21 + Gradle 8.14.3 + Android SDK 36**.

### Quick Start (Zero Configuration Required)
1. Push this repository to GitHub (`main` branch).
2. Open the **Actions** tab in your GitHub repository and select **Build Android APK**.
3. Click **Run workflow** (or push any commit to `main`).
4. Once complete, download **`AegisLocal-Debug-APK`** (`AegisLocal-debug.apk`) from the workflow run's **Artifacts** section and install it directly on your Android device.

### Optional: Signed Production Release APK & GitHub Releases
To produce a signed `AegisLocal-release-signed.apk`, add the following secrets under **Settings → Secrets and variables → Actions** in GitHub:
- `ANDROID_KEYSTORE_BASE64`: Base64-encoded `.jks` keystore (`base64 -w 0 release.jks`)
- `ANDROID_KEYSTORE_PASSWORD`: Keystore password
- `ANDROID_KEY_ALIAS`: Key alias
- `ANDROID_KEY_PASSWORD`: Key password

Pushing a version tag (for example `git tag v1.0.0 && git push origin v1.0.0`) automatically publishes a GitHub Release with the compiled `.apk` files attached.

---

## Local Development

```bash
# Install dependencies
npm install

# Run unit tests (node:test)
npm test

# Start local Express + Vite workbench on http://localhost:3000
npm run dev

# Sync web assets into Capacitor Android project
npm run cap:sync
```
