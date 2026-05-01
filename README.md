# Sovereign by Copps

> **Free Password Store — Truly local.**
> No accounts. No servers. No cloud. Your secrets stay on your device, always.

---

## What is Sovereign?

Sovereign is a simple, private password store. You add entries with a **name** and a **value** (single-line or multi-line). Everything is encrypted with AES-256-GCM using a key derived from your master password via PBKDF2 (310,000 iterations). Biometric unlock (fingerprint/face) is supported as an alternative to typing the master password.

---

## Repository structure

```
sovereign/
├── web/               ← Deployable web app (also the PWA)
│   ├── index.html     ← Entire app in one file
│   ├── manifest.json  ← PWA install metadata
│   └── sw.js          ← Service worker (offline support)
│
├── android/           ← Android Studio project
│   ├── app/
│   │   ├── src/main/
│   │   │   ├── java/com/copps/sovereign/
│   │   │   │   └── MainActivity.java   ← WebView + native biometric bridge
│   │   │   ├── assets/www/             ← Web app bundled for offline use
│   │   │   ├── res/                    ← Layouts, themes, strings
│   │   │   └── AndroidManifest.xml
│   │   ├── build.gradle
│   │   └── proguard-rules.pro
│   ├── build.gradle
│   ├── settings.gradle
│   └── gradle.properties
│
├── .gitignore
├── .github/workflows/deploy.yml        ← CI: auto-deploy web to GitHub Pages
└── README.md
```

---

## Security model

| Layer | Detail |
|---|---|
| Cipher | AES-256-GCM |
| Key derivation | PBKDF2-SHA256, 310,000 iterations |
| Salt | 32-byte random, per-device |
| Biometric (web) | WebAuthn / FIDO2 passkey |
| Biometric (Android) | Native BiometricPrompt + Keystore |
| Secure storage (Android) | EncryptedSharedPreferences (AES256-GCM, Keystore-backed) |
| Network | Zero — all data stays on device |

---

## Web — run locally

```bash
cd web
python3 -m http.server 8080
# Open http://localhost:8080
```

> WebAuthn requires HTTPS or localhost. Always use HTTPS in production.

---

## Web — deploy to GitHub Pages

Push to `main`. The included GitHub Actions workflow (`.github/workflows/deploy.yml`)  
auto-deploys the `web/` folder to GitHub Pages on every push.

Live URL: `https://<your-username>.github.io/<repo-name>`

Install on Android via Chrome → ⋮ menu → **Add to Home Screen**.

---

## Android — build & run

### Requirements
- Android Studio Hedgehog (2023.1.1) or newer
- JDK 17
- Android SDK 34

### Steps

```bash
cd android
./gradlew assembleDebug
# APK: android/app/build/outputs/apk/debug/app-debug.apk
```

Or open the `android/` folder in Android Studio and click **Run ▶**.

### Release build

```bash
./gradlew assembleRelease
# Sign with your keystore before distributing
```

---

## How the Android version works

The Android app is a thin **WebView wrapper** around the same `index.html` that powers the web version. It adds:

1. **Native BiometricPrompt** — fingerprint/face unlock using Android Keystore
2. **EncryptedSharedPreferences** — Keystore-backed AES-256 storage bridge exposed to JS via `SovereignAndroid.*`
3. **No internet required** — the web app is bundled in `assets/www/`

The JavaScript bridge (`SovereignAndroid`) exposes:
```javascript
SovereignAndroid.authenticate(title, subtitle)  // triggers native biometric
SovereignAndroid.isBiometricAvailable()          // boolean check
SovereignAndroid.secureStore(key, value)         // Keystore-backed store
SovereignAndroid.secureGet(key)                  // retrieve
SovereignAndroid.secureDelete(key)               // delete
```

---

## Roadmap

- [ ] Auto-lock after inactivity timeout
- [ ] Change master password (re-encrypt vault)
- [ ] Entry tags / folders
- [ ] Built-in TOTP code generator
- [ ] Encrypted iCloud / Google Drive sync (optional, opt-in)
- [ ] iOS version (WKWebView wrapper)

---

## License

MIT © Copps
