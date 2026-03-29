# 🧿 Darkelf Cocoa Browser 4.1.9  [![PyPI Downloads](https://static.pepy.tech/personalized-badge/darkelf-cocoa?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/darkelf-cocoa)
### Ephemeral, Privacy‑First macOS Browser (PyObjC + WebKit)

A hardened, **memory‑only** macOS browser designed for **zero persistence**, **tracker resistance**, **real‑time threat detection**, and **post‑quantum integrity awareness** — installable via `pip` with a full native GUI.

> **Core promise:** Darkelf Cocoa aims to keep browsing state **in RAM only** (cookies, cache, history, local storage, IndexedDB, etc.) and discard it when the process exits, while applying defense‑in‑depth protections against tracking and hostile automation.

---

## Table of Contents
- [Why Darkelf Cocoa](#why-darkelf-cocoa)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Security Model](#security-model)
- [Post‑Quantum Integrity Layer (PQ)](#post-quantum-integrity-layer-pq)
- [MiniAI Sentinel (On‑Device IDS)](#miniai-sentinel-on-device-ids)
- [First‑Party & Tab Isolation](#first-party--tab-isolation)
- [Downloads & File Integrity](#downloads--file-integrity)
- [User Indicators](#user-indicators)
- [Platform Support](#platform-support)
- [License](#license)
- [Author](#author)
- [Disclaimer](#disclaimer)

---

## Why Darkelf Cocoa
Darkelf Cocoa Browser is the macOS edition of the Darkelf‑Mini project, implemented with **PyObjC** bindings to Apple’s **Cocoa** + **WebKit** frameworks.

It’s built for users who want:
- **Ephemeral browsing** (no retained session artifacts)
- **Aggressive tracking resistance**
- **Local-only security monitoring** (no telemetry)
- **Integrity signaling** and session-bound consistency checks

---

## Features

### 🔒 Zero‑Persistence Runtime (RAM‑Only)
- No disk-backed cookies/cache/history/local storage
- Uses **non‑persistent WebKit data stores**
- Designed to discard browsing data automatically when the app exits

### 🚫 Tracker & Telemetry Resistance
- Built‑in content blocking rules (WebKit Content Rule Lists)
- Additional DOM/CSS suppression for common banners/ads and nuisance overlays
- Optional protocol/scheme restrictions (blocks risky schemes like `file:`, `ftp:`, `javascript:`)

### 🧬 Isolation by Design
- **First‑Party Isolation (FPI)**: compartmentalized storage by site
- Optional **tab‑level isolation** for stronger separation
- Reduces cross‑site correlation and session leakage risk

### 🧠 On‑Device Threat Detection (MiniAI Sentinel)
- Local intrusion/abuse heuristics
- Tracks suspicious navigation patterns, scanners, credential stuffing behaviors, and fingerprinting indicators
- Automatic **lockdown mode** when critical threat thresholds are met
- No external reporting or analytics

### 🔗 Post‑Quantum Integrity Awareness (PQ Layer)
- Deterministic, session‑bound request integrity signals using **SHA3**
- Behavioral anomaly checks and entropy scoring
- Trust-change awareness via TLS certificate tracking (TOFU‑style)

---

## Installation

```bash
pip install darkelf-cocoa
```

> If you are packaging for PyPI, ensure your project metadata clearly indicates **macOS-only**, and include PyObjC/WebKit prerequisites in your docs.

---

## Quick Start

```bash
darkelf
```

---

## Security Model

Darkelf Cocoa uses a defense‑in‑depth approach:
1. **Ephemeral storage** (RAM-only browsing state)
2. **Isolation** (site/tab compartmentalization)
3. **Content blocking** (known tracker patterns + nuisance suppression)
4. **On-device monitoring** (MiniAI Sentinel)
5. **Integrity awareness** (PQ layer + TLS trust consistency)

---

## Post‑Quantum Integrity Layer (PQ)

Darkelf implements a **post‑quantum–aware integrity and behavioral verification system** using **SHA3-512/SHA3-256** primitives.  
This layer is designed to provide **tamper‑evident, session‑bound consistency signals** *without modifying network traffic*.

### ✅ What PQ is (in Darkelf)
- **Deterministic request fingerprinting** bound to:
  - URL
  - normalized metadata (where available)
  - session seed (hidden)
  - time bucket (anti‑replay)
- **Per‑tab chaining**:
  - per‑tab seed (`_pq_seed`)
  - monotonic per‑tab counter (`_pq_counter`)
  - request-bound chain output (`darkelf_pq_chain`)

### 🔁 PQ Chaining
- Session/Tab seeded chain progression
- Stable, low‑noise integrity evolution per request
- Counter-based continuity designed not to disrupt rendering

### 🕵️ Minimal Deception Layer (Third‑Party Contexts)
- Applies only in **third‑party** situations
- Very low frequency
- Derived from PQ signals
- Intended to reduce tracker confidence and correlation quality

### 🧠 PQ Behavioral Intelligence
- Sliding window tracking (`_pq_window`)
- Unique fingerprint tracking (`_pq_seen`)
- Entropy-based anomaly scoring for automation/replay-like patterns
- PQ signals contribute to the overall threat score and “PQ risk” indicator

### 🔐 TLS Trust Awareness (TOFU‑Style)
- Tracks server certificate subject summaries per host
- Flags trust changes during a session
- Integrates with UI trust indicators:
  - stable trust → normal PQ indicator
  - changed trust → warning indicator

---

## MiniAI Sentinel (On‑Device IDS)

### Detects (heuristic signals)
- Trackers and third‑party correlation attempts
- Fingerprinting indicators (canvas/webgl/audio keywords & patterns)
- Scraping/bot-like navigation patterns
- Credential stuffing-like bursts against login endpoints
- Scanner-like domain velocity patterns
- Suspicious URL encodings / traversal probes

### Automatic Lockdown Mode
When critical threats exceed threshold:
- Stops loading across tabs
- Opens an internal report console (`darkelf://report`)
- Temporarily disables navigation controls
- Auto-unlocks after a defined duration (configurable)

> MiniAI runs locally. No telemetry, analytics, or network beacons are included.

---

## First‑Party & Tab Isolation
- Storage is separated by an eTLD+1 approximation (with an auth whitelist for common login flows)
- Implemented tab-level compartmentalization for stricter isolation
- Designed to prevent cross-site storage reuse and reduce tracking surface

---

## Downloads & File Integrity

### Safe-by-default behavior
- Download routing can be restricted to avoid persistence
- Temporary download directories can be wiped

### File integrity protection
- Downloads can be hashed with **SHA3** and bound to the session PQ chain
- In-memory hash registry enables within-session integrity checks for downloaded artifacts

---

## User Indicators
- `PQ✓` → TLS secure + PQ integrity active (stable)
- `PQ⚠` → trust anomaly detected (e.g., TLS trust change during session)

---

## Platform Support
- **macOS only** (Cocoa + WebKit via PyObjC)

---

## License
**LGPL-3.0-or-later**

---

## Author
Dr. Kevin Moore (2025)

---

## Disclaimer
This project is security-focused software provided **without warranty**.  
If you distribute binaries or integrate cryptographic components beyond Apple’s platform frameworks, you are responsible for applicable compliance (export controls, local regulations, etc.).
