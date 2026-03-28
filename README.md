# 🧿 Darkelf Cocoa Browser 4.1.8
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

### 🔗 Post-Quantum Integrity Layer

Darkelf introduces a **post-quantum–aware integrity and behavioral verification system** powered by **SHA3-512**, delivering tamper-evident browsing, anomaly detection, and session-bound trust — without modifying network traffic.

---

### 🧬 Core Design

- Every request is cryptographically fingerprinted (SHA3-512)
- Fingerprints bind:
  - URL
  - headers
  - session secret
  - time bucket (anti-replay)
- **Session-bound integrity model** ensures continuity across requests
- **Time-bucketed hashing** prevents replay attacks
- Designed for **post-quantum resilience** (Grover-limited model)

**PQ Chaining**
- Session-seeded chain (`_pq_seed`)
- Deterministic, counter-based evolution per request
- No per-request randomness → stable, low-noise tracking
- Maintains continuity without breaking web compatibility

---

### 🧠 Behavioral Integrity Layer

Darkelf extends integrity into **real-time behavioral analysis**:

- Sliding window fingerprint tracking (`_pq_window`)
- Deduplicated fingerprint detection (`_pq_seen`)
- Entropy-based anomaly detection
- Adaptive scoring based on request patterns
- Integrated into the **MiniAI inspection engine**

**Detects:**
- Replay attempts
- Automated or scripted browsing
- Silent request injection or manipulation

---

### 🛡️ Trust Awareness

- Tracks TLS certificate identity per domain (TOFU-style)
- Monitors certificate consistency during sessions
- Flags anomalies with **PQ⚠ warnings**

**Detects:**
- MITM attacks
- Certificate changes
- Suspicious infrastructure shifts

---

### 📦 File Integrity Protection

- All downloads hashed with **SHA3-512**
- Bound to active session context
- Stored in-memory only (no persistence)

**Capabilities:**
- Detects in-session file tampering
- Verifies blob and standard downloads
- Prevents replay or substitution attacks

---

### 👁️ User Visibility

- `PQ✓` → Integrity active, no anomalies  
- `PQ⚠` → Anomaly or trust issue detected  

- Integrated with HTTPS indicators  
- Updates dynamically per session  
- Zero performance impact  

---

### 🚀 What This Provides

- Tamper-evident request fingerprinting  
- Session-bound integrity guarantees  
- Replay resistance via time + chaining  
- Behavioral anomaly detection  
- Detection of injected or hidden requests  
- Real-time MiniAI integration  
- Early warning of trust anomalies  
- Secure, session-bound download verification  

---

### ⚙️ Design Philosophy

> Darkelf's PQ layer augments — not replaces — TLS.

* TLS → Secures transport
* PQ Layer → Verifies:

  * request integrity
  * session continuity
  * behavioral consistency

Together providing:

> **Transport security + post-quantum-aware integrity + behavioral validation**

---

### 🔬 Implementation Notes

* SHA3-512 (NIST-standardized, quantum-resistant hashing)
* Deterministic request fingerprinting (URL + headers + session secret)
* Time-bucketed anti-replay model (~10s rolling window)
* **Session-based PQ chaining (stable seed + counter evolution)**
* Sliding window PQ tracking (`_pq_window`, `_pq_seen`) for entropy analysis
* Adaptive anomaly detection based on fingerprint churn and replay signals
* PQ signals integrated into internal MiniAI inspection pipeline
* File integrity bound to session context (download hash linkage)
* Fully memory-resident (ephemeral session scope, no persistence)
* Passive design (no protocol or network changes required)
* No telemetry or external dependencies
* Designed for incremental hardening (trust, integrity, enforcement layers)

### ⚙️ Design Philosophy

> TLS secures transport — PQ validates behavior.

---

### 🔬 Implementation Notes

* SHA3-512 (quantum-resistant hashing)
* Session-seeded PQ chain (stable + evolving)
* Rate-limited injection (no entropy spikes)
* Sliding window analysis (`_pq_window`, `_pq_seen`)
* Asynchronous execution (off UI thread)
* No header/network modification
* Fully in-memory, no telemetry

___
 

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
