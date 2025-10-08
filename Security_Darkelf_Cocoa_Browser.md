# Darkelf Cocoa Browser — Security & Privacy Features

Darkelf Cocoa is built from the ground up as a privacy-first, ephemeral browser. It’s designed to leave zero trace on disk and actively defend against tracking, fingerprinting, and media-persistence attacks. This document outlines the full set of security and privacy enhancements currently integrated (including your recent patches).

---

## Table of Contents

1. [Core Design Philosophy](#core-design-philosophy)  
2. [Storage & Persistence Controls](#storage--persistence-controls)  
3. [Network & Script-Level Protections](#network--script-level-protections)  
4. [Fingerprinting Hardening](#fingerprinting-hardening)  
5. [Media / Audio / Video Defenses](#media--audio--video-defenses)  
6. [Incident Response & Isolation (MiniAI)](#incident-response--isolation-miniai)  
7. [Lifecycle & Quit-Time Wiping](#lifecycle--quit-time-wiping)  
8. [Optional & Support Utilities](#optional--support-utilities)  
9. [Usage Notes & Limitations](#usage-notes--limitations)

---

## 1. Core Design Philosophy

- **RAM-only operation** — no traces should persist to disk under normal usage.  
- **Aggressive teardown** — closed tabs fully stop, cannot leak audio or requests.  
- **Layered defenses** — multiple overlapping protections ensure resilience even if one fails.  
- **User-gesture media** — media must be triggered by users, not auto-played invisibly.  
- **Minimal trust surface** — no third-party plugins, limited APIs, no storage exposure.

---

## 2. Storage & Persistence Controls

- **Non-persistent WebKit data store**  
  Each `WKWebView` uses `WKWebsiteDataStore.nonPersistentDataStore()`, confining cookies, caches, and local storage to memory.  
- **Startup full wipe**  
  `_wipe_all_site_data()` clears all website data types from the default data store at startup.  
- **Quit-time wipe via AppDelegate**  
  The same wipe runs when the app quits, ensuring no residual data.  
- **(Optional) Cookie scrubber**  
  A timer periodically deletes all cookies in the `httpCookieStore`.  
- **Volatile preferences**  
  `NSUserDefaults` is made volatile-only, preventing persistence to disk.

---

## 3. Network & Script-Level Protections

- **Tracker blocking**  
  Blocks known analytics/tracker URLs by intercepting `fetch`, `XMLHttpRequest`, etc.  
- **Script message handlers**  
  Real-time monitoring of suspicious JS activity via registered handlers (`tracker`, `search`, `panic`).  
- **Content rule lists (JS-off mode)**  
  Blocks all script resources when JavaScript is disabled.  
- **App-bound domain restriction**  
  Optional toggle to limit navigations to trusted domains only.

---

## 4. Fingerprinting Hardening

- **Canvas noise injection**  
  Randomizes pixel buffers in canvas APIs to neutralize fingerprinting.  
- **WebGL vendor/renderer spoofing**  
  Masks GPU identity via constant vendor/renderer overrides.  
- **Navigator / UA / Hardware spoofing**  
  Mimics consistent Firefox-on-Mac profile.  
- **Locale, font, timezone, battery, performance spoofing**  
  Normalizes data for all passive fingerprint vectors.  
- **WebRTC mitigation**  
  Disables or stubs `RTCPeerConnection` and `getUserMedia` unless explicitly whitelisted.

---

## 5. Media / Audio / Video Defenses

- **Hard teardown on tab close**  
  Stops all playback, exits PiP, blanks iframes, and destroys handlers.  
- **Media restrictions**  
  Disables AirPlay, Picture-in-Picture, and enforces user-gesture playback.  
- **JS killswitch (when JS disabled)**  
  Injects a stub that neutralizes dangerous JS functions.  
- **Content rules**  
  Automatically block all `<script>` tags when JS is off.

---

## 6. Incident Response & Isolation (MiniAI)

- **Heuristic monitoring**  
  Detects network, header, or DOM anomalies.  
- **Panic mode**  
  Disables JS, rebuilds WebView, navigates Home, and pauses network/Tor.  
- **Bridge integration**  
  JS can trigger native panic routines through `mini_ai` handler.  
- **Auto recovery**  
  Restores JS or normal mode after lockout or user approval.  
- **Tracker alerts**  
  User notifications on tracker or malware hits.

---

## 7. Lifecycle & Quit-Time Wiping

- **Tab teardown** guarantees zero background activity.  
- **Startup wipe** resets environment every launch.  
- **Quit wipe** removes all persistent data before exit.  
- **Cookie scrubber** prevents long-lived cookies even in-session.

---

## 8. Optional & Support Utilities

- **Per-tab data stores (future)** — Isolate tabs further.  
- **Per-tab Tor proxying (future)** — Route each tab separately.  
- **Live resource monitor** — Show per-tab RAM and CPU usage.  
- **Auto-wipe on last tab close** — Full cleanup when all tabs are gone.

---

## 9. Usage Notes & Limitations

- **App sandbox only** — OS-level persistence or root access can still expose data.  
- **CSP interference** — Some injected protections may not run if page CSP forbids scripts.  
- **Performance tradeoff** — Scrubbing and injection add a small overhead.  
- **Plugin risk** — Avoid legacy WebKit plugins entirely.  
- **Tor caution** — DNS and socket isolation depend on proper OS configuration.

---

### Summary

Darkelf Cocoa Browser is a hardened, ephemeral, memory-only browser that ensures:

- No disk traces (cookies, cache, prefs)  
- Full teardown of closed tabs  
- Strong fingerprinting & WebRTC protection  
- Active AI-driven panic mode  
- Total wipe on startup & quit  

> **Goal:** Absolute user privacy and zero-trace browsing.

---
