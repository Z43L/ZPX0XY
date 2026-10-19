# ZPX0XY

Local bug-bounty workbench with a desktop shell and a separate Android application. Android contains its own proxy engine, TLS inspection CA, SQLite history, scope, interception queue, notes, and findings. It does not connect to or require the desktop app.

## Features

- HTTP/1.1 forward proxy on `127.0.0.1:8080`, request history, search, replay, and interception with forward/drop.
- Optional HTTPS inspection with an on-device generated CA. Certificate-pinned apps can reject inspection, and Android user CAs are not trusted by every app.
- Scope management, regex match/replace, bounded sequential checks, saved automations, notes, and scope-gated passive response-header findings.
- Burp `.jar` / `.bapp` static API inspector on desktop and Android. It identifies probable Montoya/legacy API use without executing the package; it is an analysis aid, not an extension runtime.
- Six switchable native extension equivalents, enabled by default: local JWT decoding (no signature verification), JSON/XML/form conversion, passive response-header auditing, cookie attribute review, captured-response route extraction, and redacted potential-secret detection. The latter three analyze one selected in-scope exchange and do not send requests.
- Optional Ollama AI Lab: enumerate installed models, analyze an in-scope captured HTTP exchange, and draft a bounded automation for human review. AI does not run its drafts automatically.
- Responsive light interface for desktop and mobile.
- Android app runs its engine and database on the phone. Set a browser or Wi-Fi proxy to `127.0.0.1:8080` on that Android device to route supported traffic through it. The Android app does not transparently capture every other app; some applications ignore system proxies.

The proxy supports HTTP/1.1 only. It does not yet support WebSocket inspection, HTTP/2, Burp extension execution, Collaborator/OAST, or full Caido/Burp feature parity. Extension archives can be inspected up to 10 MiB, but are not installed or executed. Forwarding is capped at 32 MiB and history stores at most 1 MiB per body. Saved automations are limited to GET, HEAD, or OPTIONS, require an explicitly scoped host, allow up to 25 values, and enforce at least 250 ms between requests. Redirects are recorded without following them.

## Ollama AI

Run Ollama and pull a model supported by your installation. In **AI Lab**, enter the Ollama server URL and discover the installed models. The integration uses Ollama's [`/api/tags`](https://docs.ollama.com/api/tags) and [`/api/chat`](https://docs.ollama.com/api/chat) endpoints. The default is `http://127.0.0.1:11434`. On Android, that address means the phone itself; to use Ollama running on your Mac, enter its LAN address (for example `http://192.168.1.20:11434`). Ollama binds to loopback by default; on macOS, set `OLLAMA_HOST` with `launchctl setenv OLLAMA_HOST "0.0.0.0:11434"` and restart Ollama to allow LAN access, as described in [Ollama's server configuration guide](https://docs.ollama.com/faq#how-can-i-expose-ollama-on-my-network). Keep that server on a trusted network. Captured HTTP contents selected for analysis are sent to the configured Ollama server. In **Automations**, AI creates a draft limited to scoped read-only checks; review it, save it, then start it manually.

## Desktop

Requires Python 3.9+ and OpenSSL. Run `source env.sh` then `python3 server.py`, and open <http://127.0.0.1:4173>. The proxy uses port 8080 by default and automatically tries through 8100 if that port is busy; use the active port shown in Proxy settings to configure your browser. Install the ZPX0XY CA from Proxy settings if you need to inspect HTTPS.

The Electron shell is configured in `desktop/`. Its native macOS package can be rebuilt with `cd desktop && npm run dist:mac` after installing the declared npm dependencies.

## Android

The Android project uses Gradle 8.13, Android Gradle Plugin 8.13.2, JDK 17, API 36, and Bouncy Castle. Load `env.sh`, then from `android/` run `./gradlew app:assembleDebug`. The APK output path is `android/app/build/outputs/apk/debug/app-debug.apk`.

The current machine has not accepted Google SDK licenses or installed the required API 36 platform and Build Tools 35.0.0. Review and accept them in Android Studio's SDK Manager (or `sdkmanager --licenses`), install the missing packages, then rerun the build. ZPX0XY cannot accept those terms for you.

## Local data and safe use

Desktop data is stored in its local SQLite database and certificate directory; Android stores its database and private CA in the app's private storage. Only inspect systems you are authorized to assess, and remove the inspection CA from test devices when finished.
