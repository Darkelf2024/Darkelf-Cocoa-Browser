# 🧿 Darkelf Cocoa Browser 4.0.14
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

### 🔗 Post-Quantum Integrity Layer (NEW)

Darkelf includes a **passive post-quantum integrity system** using **SHA3-512**:

- Each request is cryptographically fingerprinted
- Requests are chained together per session
- Forms a **tamper-evident browsing history**
- Resistant to quantum-era attacks (Grover-limited)

#### 🧠 What it does
- Detects silent manipulation of request flow
- Prevents undetected replay or injection attempts
- Adds integrity without modifying traffic

#### 👁️ User Visibility
- Displays **“PQ” indicator** next to HTTPS lock when active
- Fully passive — no performance or behavior impact

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
- Post-quantum integrity layer
