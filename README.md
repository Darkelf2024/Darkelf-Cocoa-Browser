# 🧿 Darkelf Cocoa Browser 4.1.0
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

Darkelf implements a **post-quantum–resilient integrity system** built on **SHA3-512**, designed to provide **tamper-evident session integrity without modifying network traffic**.

---

### 🧬 Core Design

- Each navigation request is cryptographically fingerprinted  
- Requests are chained into a **session-bound integrity chain**  
- The chain evolves continuously during browsing  
- Resistant to quantum attacks (Grover-limited security model)

---

### 🛡️ Integrity + Trust Awareness

Darkelf extends beyond request integrity by adding a **real-time trust consistency layer**:

- TLS certificate identity is tracked per domain (TOFU model)  
- Unexpected certificate changes are detected within the session  
- Helps identify:
  - Man-in-the-middle (MITM) attacks  
  - Certificate swapping  
  - Suspicious infrastructure changes  

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
- Early warning of trust anomalies  

---

### ⚙️ Design Philosophy

> Darkelf’s PQ layer augments — not replaces — TLS.

- TLS → Secures transport  
- PQ Layer → Verifies integrity and behavioral consistency  

Together providing:

> **Transport security + post-quantum-aware integrity validation**

---

### 🔬 Implementation Notes

- Uses SHA3-512 (NIST-standardized, quantum-resistant hashing)  
- Passive design (no protocol changes required)  
- No telemetry or external dependencies  
- Fully memory-resident (ephemeral session scope)

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
