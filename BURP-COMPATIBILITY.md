# Burp compatibility audit

## Installed build

- Product: Burp Suite Community Edition 2026.9.2 (`/Applications/Burp Suite.app`).
- The app bundles a Java 26 runtime. Its extension loader offers Java (`.jar`), Python (`.py`) and Ruby (`.rb`) choices.
- Static inspection of the installed `burpsuite.jar` found 282 Montoya `.class` entries and legacy interfaces including `IBurpExtender`, `IBurpExtenderCallbacks`, `IExtensionHelpers`, `IHttpListener`, `IProxyListener` and `ITab`. The Montoya root signature exposes AI, Bambda, BurpSuite, Collaborator, Comparer, Decoder, Extension, HTTP, Intruder, Logging, Organizer, Persistence, Project, Proxy, Repeater, Scanner, Scope, SiteMap, UI, Utilities and WebSockets services. The archive includes dedicated APIs for HTTP (52 classes), Proxy (26), Repeater (3), Intruder (12), Scanner (27), Collaborator (16), UI (44), utilities (36), and WebSockets (15), among others.
- Burp's start-up event log reported that its proxy listener could not bind `127.0.0.1:8080`, because another service already owns that port. ZPX0XY uses 8080 by default.

## Current ZPX0XY compatibility

| Area | Current state | Work needed for compatibility |
| --- | --- | --- |
| Burp Java / Montoya `.jar` | Static package inspector added; not loaded | Java extension host plus implementations/adapters for Montoya service interfaces and lifecycle |
| Legacy Java Extender | Not loaded | `IBurpExtenderCallbacks`, helpers, HTTP listeners, tabs and context-menu adapter |
| Python / Ruby Extender | Not loaded | Jython / JRuby runtimes and legacy Java bridge |
| BApp packages | Static archive inspector added; not loaded | Package metadata, dependency/runtime handling and install lifecycle |
| Built-in extension equivalents | JWT Inspector, Content Type Converter, Passive Scope Auditor, Cookie Inspector, Endpoint Extractor and Secret Detector; enabled by default with persistent toggles | These are native ZPX0XY modules, not the original BApps or general extension execution |
| Proxy / HTTP history | Partial independent implementation | Map Montoya/legacy request-response APIs to ZPX0XY's proxy and history |
| Repeater / Intruder / Decoder / Comparer / Logger / Organizer | Partial independent implementations | Per-tool APIs, callbacks and UI integration remain absent |
| Scanner / Collaborator / Burp AI | Not available in this Community Edition build or ZPX0XY | Separate service implementations; some Burp capabilities are edition-gated |
| Android | Native proxy and web UI only | Desktop Burp extensions cannot be loaded directly; Android would need a separate, mobile-safe plugin interface |

## Constraints and implementation direction

Burp extensions run against Burp's APIs and expect Burp-provided services. Copying the extension loader screen or adding a JAR picker would not make them compatible. PortSwigger recommends Montoya for Java extensions; Python and Ruby use the legacy Extender API. See [Burp extensions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions), [creating extensions](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating), and [manual installation](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/installing/manual-install).

ZPX0XY is a Python/Electron desktop application and an Android app with a Java 17 service and WebView. The Android process does not provide Burp's desktop APIs or a Swing environment. Direct Montoya/Extender compatibility therefore has to start as a desktop-only compatibility host. Android can share selected extension capabilities through a constrained cross-platform plugin interface, but cannot promise binary compatibility with every desktop Burp extension.

Compatibility should be implemented incrementally against named, user-provided extensions, starting with the common HTTP, scope, logging, Repeater and UI APIs. Extensions that request unsupported services must be reported as unsupported rather than silently loaded. Requests initiated by an extension should use ZPX0XY's configured scope and appear in its history.

## Static compatibility inspector

The Extensions view now accepts `.jar` and `.bapp` archives up to 10 MiB on desktop and Android. It scans Java class constant strings for Montoya and legacy API references, counts classes, and reports likely feature areas. It reads archives in memory, does not persist them, and never executes extension code. The signature scan is a triage aid: shading/obfuscation can hide references, and a detected API does not mean an adapter exists or that the extension is loadable. This is an initial evidence-gathering feature, not binary compatibility.

Six native modules are enabled by default and can be toggled in Extensions. They decode JWT headers/claims locally; convert JSON, XML and form data; audit captured response headers; review cookie flags with values hidden; extract relative routes from captured responses without crawling; and detect potential secrets while redacting the matched values. They do not load third-party BApp code or execute active JWT attacks. The converter and token tools were informed by the [BApp Store's Content Type Converter](https://portswigger.net/bappstore/db57ecbe2cb7446292a94aa6181c9278) and [JWT extension listing](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61).

REA's repository describes evidence-oriented app, package, JavaScript/Electron and native analysis workflows. Its published target list does not identify Java `.class` API emulation as a capability. The prior REA output in `rea-app-analysis.json` concerns Caido's Electron bundle, not Burp's Java implementation. For Burp, this audit uses local package contents and the public extension API surface; it does not reproduce proprietary implementation code. The local JAR inventory above gives measurable API scope for prioritizing adapters.

## Proxy coexistence

Burp and ZPX0XY cannot both bind the same loopback address and port. Keep ZPX0XY on `127.0.0.1:8080` and configure Burp's listener on another port (for example `127.0.0.1:8081`), or configure Burp to use ZPX0XY as an upstream proxy. This changes routing, not extension compatibility.
