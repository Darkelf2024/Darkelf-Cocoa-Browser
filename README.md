# 🕶️ Darkelf Cocoa Browser v4.0.7

![License](https://img.shields.io/badge/license-LGPL--3.0-green)
![Python](https://img.shields.io/badge/python-3.11+-blue)
![Platform](https://img.shields.io/badge/platform-macOS%2013%2B-lightgrey)
![Status](https://img.shields.io/badge/status-active-success)

A privacy-focused, ephemeral web browser suite built natively for macOS
using Python, PyObjC, and Apple's Cocoa + WebKit frameworks.

x25519MLKEM768 integrated -- macOS native.

------------------------------------------------------------------------

## 🌟 Overview

Darkelf Cocoa combines high-performance native macOS design with
hardened privacy architecture.\
It delivers zero-persistence browsing, aggressive fingerprint defenses,
and optional research-grade hardening.

Two editions are available:

-   🟢 **General Edition** -- Secure daily browsing
-   🔒 **Hardened Edition** -- Research / high-risk privacy mode

------------------------------------------------------------------------

## 🧩 Editions Comparison

| Feature | 🟢 General | 🔒 Hardened |
|----------|------------|------------|
| Daily Use Optimized | ✅ Yes | ⚠️ Not Primary Focus |
| Non-Persistent Sessions | ✅ Yes | ✅ Enforced (Strict) |
| Declarative Ad Blocking | ✅ Enhanced | ✅ Enhanced |
| Fingerprint Reduction | Aggressive | Aggressive |
| JavaScript Toggle | ✅ Yes | ✅ Yes |
| Tor Support | ❌ None | ✅ Optional |
| SOCKS Proxy | ❌ None | ✅ Yes |
| WebKit Hardening | Advanced | Advanced |
| MiniAI Monitoring | ✅ Enabled | ✅ Enabled |
| Intended Audience | Everyday Users | Researchers / High-Risk |

# 🟢 Darkelf Cocoa -- General Edition v4.0.7 Latest

📄 `Darkelf_Cocoa_Browser_4.0.7.py`

Designed for privacy-conscious daily browsing without Tor complexity.

### Core Features

-   Direct networking (no proxy chain)
-   Safari-style declarative content blocking
-   Non-persistent WKWebView data store
-   JavaScript toggle button
-   DarkelfMiniAI Monitoring/IDS
-   Native macOS AppKit interface
-   Keyboard hotkeys
-   Secure Download Mode - Darkelf Temp Folder/Randomized File Name
-   Lockdown Mode
-   Wipe Nuke on Exit
-   Per Tab Isolation
-   Canvas Signatures change on Boot-up and Per-Tab! Not on Reload.
-   Youtube FullScreen Is Fixed

------------------------------------------------------------------------

# 🔒 Darkelf Cocoa -- Hardened Edition - Still in progress with Upgrades

📄 `Darkelf Cocoa Hardened Browser 3.8.py`

Designed for privacy research, fingerprint testing, and high-risk
environments.

### Hardened Features

-   Strict non-persistent session enforcement
-   Aggressive anti-fingerprinting (Canvas, WebGL, Audio, Fonts)
-   Per-tab entropy seeding
-   Additional timing noise injection
-   Expanded WebRTC suppression
-   Optional Tor integration (Homebrew + torrc required)
-   SOCKS proxy capability
-   JavaScript + Tor toggle buttons
-   Enhanced WebKit restrictions
-   MiniAI monitoring

⚠️ Hardened edition currently undergoing major revision with significant
improvements planned.

------------------------------------------------------------------------

# 🔐 Privacy & Security Architecture

### Ephemeral Design

-   Zero disk persistence
-   Memory-only cookies, cache, IndexedDB
-   Automatic wipe on exit
-   Nuclear wipe hotkey (⌘⇧X)

### Anti-Fingerprinting

-   Canvas pixel noise
-   WebGL spoofing (Intel Iris)
-   Audio context zeroing
-   Font surface limitation (Arial)
-   Battery API spoofing
-   Geolocation blocked
-   Performance API timing noise

------------------------------------------------------------------------

# 🛡️ Darkelf MiniAI Sentinel (Both Editions)

Observation-only threat monitoring system.

Detects:

-   SQL Injection patterns
-   Cross-Site Scripting
-   Path traversal attempts
-   Command injection
-   Redirect abuse
-   Fingerprinting API usage
-   Suspicious domain patterns

Session threat summary generated on exit.

------------------------------------------------------------------------

# 🌐 Web Compatibility

Engine: WKWebView\
JavaScript: Optional toggle\
Media: Inline disabled by default

Tested:

-   DuckDuckGo Lite
-   Wikipedia
-   YouTube (DDG Lite)
-   Cover Your Tracks

------------------------------------------------------------------------

## ⌨️ Keyboard Shortcuts

| Action        | Shortcut |
|---------------|----------|
| New Tab       | ⌘T       |
| Close Tab     | ⌘W       |
| Reload        | ⌘R       |
| Address Bar   | ⌘L       |
| Screenshot    | ⌘S       |
| Instant Exit  | ⌘ShiftX  |


------------------------------------------------------------------------
## 📂 Source Files

- 🟢 [Darkelf Cocoa Browser](https://github.com/Darkelf2024/Darkelf-Cocoa-Browser/blob/main/Darkelf_Cocoa_Browser_4.0.py)  
- 🔒 [Darkelf Hardened Cocoa Browser](https://github.com/Darkelf2024/Darkelf-Cocoa-Browser/blob/main/Darkelf%20Cocoa%20Hardened%20Browser%203.7.py)

------------------------------------------------------------------------

# 🧑‍⚖️ License

GNU Lesser General Public License v3.0 (LGPL-3.0-or-later)

-   Commercial use allowed
-   Modification permitted
-   Must disclose source changes
-   Must include original license

------------------------------------------------------------------------

# 👨‍💻 Developer

Kevin J. Moore\
Email: kjm489@km-consultant.pro

------------------------------------------------------------------------

Built for privacy-conscious macOS users.

"Browse without a trace, secured by design"
