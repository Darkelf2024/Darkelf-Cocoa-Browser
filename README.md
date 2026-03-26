# 🧿 Darkelf Cocoa Browser 4.1.7
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

Darkelf implements a **post-quantum–aware integrity and behavioral verification system** built on  
**SHA3-512**, providing **tamper-evident browsing, trust monitoring, anomaly detection, and file integrity binding** — all without modifying network traffic.

---

### 🧬 Core Design

- Each navigation request is cryptographically fingerprinted (SHA3-512)  
- Fingerprints incorporate URL, headers, session secret, and time bucket  
- Requests are tracked within a **session-bound integrity model**  
- Time-bucketed hashing provides **anti-replay protection**  
- Resistant to quantum attacks (Grover-limited security model)  

---

### 🧠 Behavioral Integrity Layer (New)

Darkelf extends beyond static integrity with a **real-time behavioral PQ system**:

- Sliding window tracking of recent request fingerprints (`_pq_window`)  
- Deduplicated fingerprint tracking (`_pq_seen`) for replay detection  
- Detection of **high-entropy request churn** (automation / injection signals)  
- Adaptive anomaly scoring based on fingerprint uniqueness and frequency  
- PQ signals integrated directly into **MiniAI network inspection pipeline**  

This enables detection of:
- Replay attempts  
- Scripted or automated browsing patterns  
- Silent request injection or manipulation  

---

### 🛡️ Integrity + Trust Awareness

Darkelf includes a **trust consistency layer**:

- TLS certificate identity tracked per domain (TOFU-style model)  
- Certificate fingerprints monitored during the session  
- Unexpected changes trigger a **PQ trust warning (`PQ⚠`)**  

Helps identify:
- Man-in-the-middle (MITM) attacks  
- Certificate swapping  
- Suspicious infrastructure or routing changes  

---

### 📦 File Integrity Protection (Enhanced)

Darkelf provides **post-quantum file integrity verification with session binding**:

- All downloads hashed using **SHA3-512**  
- File hashes are **linked to the active PQ session context**  
- Integrity records are stored **in-memory only (ephemeral)**  

Capabilities:
- Detects file modification during the session  
- **Blob downloads are fully session-bound and verifiable**  
- Standard downloads follow the same integrity model  
- Prevents replay or substitution of downloaded content  

---

### 👁️ User Visibility

PQ state is surfaced directly in the address bar:

- `PQ✓` → Integrity active, trust stable, no anomalies detected  
- `PQ⚠` → Trust anomaly detected (entropy spike, replay pattern, or trust inconsistency)  

- Integrated alongside HTTPS indicators  
- Updates dynamically per navigation/session behavior  
- Passive and non-intrusive (no performance impact)  

---

### 🧠 What This Provides

- Tamper-evident request fingerprinting  
- Session-bound integrity assurance  
- Time-based replay resistance  
- Behavioral anomaly detection (entropy + fingerprint churn)  
- Detection of silent manipulation or injected requests  
- Integration with real-time network inspection (MiniAI)  
- Early warning of TLS trust anomalies  
- **Session-bound integrity tracking for downloaded content**  

---

### ⚙️ Design Philosophy

> Darkelf's PQ layer augments — not replaces — TLS.

- TLS → Secures transport  
- PQ Layer → Verifies:
  - request integrity  
  - session continuity  
  - behavioral consistency  

Together providing:

> **Transport security + post-quantum-aware integrity + behavioral validation**

---

### 🔬 Implementation Notes

- SHA3-512 (NIST-standardized, quantum-resistant hashing)  
- Deterministic request fingerprinting (URL + headers + session secret)  
- Time-bucketed anti-replay model (~10s rolling window)  
- Sliding window PQ tracking (`_pq_window`, `_pq_seen`) for entropy analysis  
- Adaptive anomaly detection based on fingerprint churn and replay signals  
- PQ signals integrated into internal MiniAI inspection pipeline  
- File integrity bound to session context (download hash linkage)  
- Fully memory-resident (ephemeral session scope, no persistence)  
- Passive design (no protocol or network changes required)  
- No telemetry or external dependencies  
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
