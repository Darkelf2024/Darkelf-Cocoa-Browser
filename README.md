# 🧿 Darkelf Cocoa Browser 4.1.1
### Ephemeral, Privacy-First macOS Browser (PyObjC + WebKit)

> A hardened, memory-only browser designed for **zero persistence**, **tracker resistance**, **real-time threat detection**, and **post-quantum integrity awareness** — installable via `pip`, launching a full native GUI.

---

## 🚀 Overview

Darkelf Cocoa Browser is a macOS-native browser built using **PyObjC + WebKit**, focused on:

- 🔒 Ephemeral browsing (RAM-only)
- 🧠 On-device AI threat detection (Darkelf MiniAI Sentinel)
- 🚫 Aggressive tracker & telemetry blocking
- 🧬 First-party + tab isolation
- 🧯 Automatic threat lockdown system
- 🔗 Post-quantum request integrity (SHA3-512 chain)

Unlike traditional browsers, Darkelf **never persists browsing data to disk** and operates with a **defense-in-depth security model**.

---

## ⚡ Installation

```bash
pip install darkelf-cocoa
darkelf
```

---

## 🛡️ Security Architecture

### 🔥 Memory-Only Execution
- No cookies, cache, or history stored
- Uses non-persistent WebKit storage
- Data wiped completely on exit

---

### 🧬 First-Party & Tab Isolation
- Domain-level isolation (default)
- Tab isolation (implemented)
- No shared global storage
- Prevents cross-site tracking & session leakage

---

### 🧠 Darkelf MiniAI Sentinel (On-Device IDS)
Detects:
- Trackers & fingerprinting  
- Vulnerability scanners  
- Credential stuffing  
- Automation frameworks  
- Exploit attempts  

Runs locally (no telemetry)

---

### 🔗 Post-Quantum Integrity Layer (Enhanced)

Darkelf implements a **post-quantum–aware integrity system** built on **SHA3-512**, providing **tamper-evident browsing, trust monitoring, and file integrity verification** — all without modifying network traffic.

---

### 🧬 Core Design

- Each navigation request is cryptographically fingerprinted (SHA3-512)  
- Requests are chained into a **session-bound integrity chain**  
- The chain evolves continuously during browsing  
- Resistant to quantum attacks (Grover-limited security model)  

---

### 🛡️ Integrity + Trust Awareness

Darkelf extends beyond request integrity with a **real-time trust consistency layer**:

- TLS certificate identity is tracked per domain (TOFU model)  
- Certificate fingerprints are monitored during the session  
- Unexpected changes trigger a **PQ trust warning**  

Helps identify:
- Man-in-the-middle (MITM) attacks  
- Certificate swapping  
- Suspicious infrastructure or routing changes  

---

### 📦 File Integrity Protection (NEW)

Darkelf now includes **post-quantum file integrity verification**:

- All downloads are hashed using **SHA3-512**  
- Hashes are stored **in-memory only (ephemeral)**  
- Files can be verified for tampering during the session  

Capabilities:
- Detects file modification after download  
- Ensures integrity of blob and standard downloads  
- Enables future enforcement (block/delete tampered files)  

---

### 👁️ User Visibility

PQ state is surfaced directly in the address bar:

- `PQ✓` → Integrity active, trust stable  
- `PQ⚠` → Trust inconsistency detected  

- Integrated alongside HTTPS indicators  
- Passive and non-intrusive (no performance impact)  

---

### 🧠 What This Provides

- Tamper-evident request flow  
- Session-level integrity assurance  
- Detection of silent manipulation or replay patterns  
- Early warning of TLS trust anomalies  
- File integrity validation for downloaded content  

---

### ⚙️ Design Philosophy

> Darkelf’s PQ layer augments — not replaces — TLS.

- TLS → Secures transport  
- PQ Layer → Verifies integrity, trust consistency, and file integrity  

Together providing:

> **Transport security + post-quantum-aware integrity validation**

---

### 🔬 Implementation Notes

- Uses SHA3-512 (NIST-standardized, quantum-resistant hashing)  
- Passive design (no protocol or network changes required)  
- No telemetry or external dependencies  
- Fully memory-resident (ephemeral session scope)  
- Designed for incremental hardening (trust, integrity, enforcement layers)

---

### 🚨 Automatic Lockdown Mode
- Stops all tabs on threat
- Locks UI controls
- Displays threat console
- Auto recovery after cooldown

---

### 🛑 Network Enforcement
- HTTPS upgrade enforcement
- Tracker & ad blocking
- Dangerous protocol blocking

---

### 🔐 TLS + Hybrid PQ Transport (macOS)

- Uses macOS WebKit TLS stack
- Supports **hybrid key exchange (X25519 + ML-KEM768)** when available
- Combined with Darkelf PQ layer for **transport + integrity coverage**

---

## 🔒 Privacy Features

- Zero telemetry
- Ephemeral downloads
- Anti-fingerprinting detection
- Third-party tracker detection
- PQ-safe request integrity (SHA3-512)

---

## 🖥️ GUI Features

- Native macOS UI
- Tabbed browsing
- Download progress UI
- Built-in threat console (`darkelf://report`)
- 🔒 HTTPS + **PQ indicator system**

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|--------|--------|
| Cmd + T | New tab |
| Cmd + W | Close tab |
| Cmd + R | Reload |
| Cmd + S | Snapshot |
| Cmd + L | Focus address bar |
| Cmd + ← / → | Back / Forward |
| Cmd + Shift + L | Threat Console |
| Cmd + + / - | Zoom |

---

## 🗂️ Isolated Darkelf Library

Darkelf uses a dedicated sandboxed directory:

```
~/Desktop/Darkelf Library/
├── Darkelf Snap/
└── Darkelf Temp/
```

### 🔒 Security Design

- Separate from system browser storage
- Randomized filenames for downloads
- No persistent user profile
- Fully disposable data structure

### 🧹 Cleanup

- Temporary files easily wiped
- No long-term artifacts
- Reduced forensic traceability

---

## 🧭 Upcoming Features

### 🧅 Tor Integration *(Planned)*
- IP anonymization
- Circuit isolation

### 📐 Letterboxing *(Planned)*
- Anti-screen fingerprinting

### 🦊 Firefox UA Mode *(Planned)*
- Reduce fingerprint uniqueness

### 🎛️ Privacy Control Panel *(In Development)*
- Toggle security modes
- Manage isolation & anonymity

---

## 🔮 Roadmap Philosophy

> Privacy is not static — it adapts to threat models.

Darkelf focuses on:
- Minimizing fingerprint surface
- Increasing anonymity
- Adding post-quantum resilience
- Giving users full control

---

## ⚠️ Platform
macOS only

---

## 📜 License
LGPL-3.0-or-later

---

## 👨‍💻 Author
Dr. Kevin Moore

---

## ⭐ Highlights
- GUI via pip
- Memory-only architecture
- Built-in IDS
- Lockdown system
- Advanced isolation
