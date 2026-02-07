# 🕶️ Darkelf Cocoa

**Darkelf Cocoa** is a **privacy-hardened web browser** built using **Python**, **PyObjC**, and **Apple’s Cocoa + WebKit frameworks** — designed for users who want the speed and elegance of native macOS with the security of Tor and hardened privacy defaults.

![Darkelf Cocoa Home](https://github.com/Darkelf2024/Darkelf-Cocoa-Browser/blob/main/Darkelf%20images/Darkelf%20Cocoa%20HM.png)

x25519MLKEM768 already integrated - MacOS 

> ⚙️ *Built natively for macOS with a minimalist design and privacy-first core.*

---

### 🟢 **Darkelf Cocoa — General Use**
📄 `Darkelf Cocoa Browser General.py`

- Direct (non-proxied) networking  
- Safari-style **declarative ad blocking**  
- Privacy-hardened defaults  
- Non-persistent browsing data  
- JavaScript Toggle, and Tracking/Defense List
- No Tor, no SOCKS, no proxy dependencies  
- Designed for **daily, general browsing**

---

### 🔒 **Darkelf Cocoa — Hardened**
📄 `Darkelf Cocoa Hardened Browser.py`

- Maximum privacy defaults  
- Aggressive fingerprint-reduction techniques  
- Non-persistent sessions enforced  
- Optional Tor / research-only features *(when enabled)*
- JavaScript, CSP toggle  
- Hardened WebKit configuration  
- Designed for **privacy research, testing, and high-risk browsing**
- Setup homebrew and torrc - Then toggle to activate Tor inside the browser

📂 Browser Variants (Source Files)

🟢 General Use Browser
- [Darkelf General Cocoa Browser](https://github.com/Darkelf2024/Darkelf-Cocoa-Browser/blob/main/Darkelf%20Cocoa%20Browser%203.2.9%20General.py)
  
🔒 Darkelf Hardened Browser
- [Darkelf Hardened Cocoa Browser](https://github.com/Darkelf2024/Darkelf-Cocoa-Browser/blob/main/Darkelf%20Cocoa%20Hardened%20Browser%20.py)

---

## 🚀 Features

### 🖥️ Native macOS Interface
- Built entirely on **Cocoa (AppKit)** for smooth, native system integration.
- Supports macOS dark mode, rounded windows, and native buttons.
- Lightweight and highly responsive — no Electron, no Chromium overhead.

---

### 🔒 Privacy & Security
- **Private by default**: No telemetry, analytics, or tracking.
- Built-in **anti-fingerprinting** protections.
- Optional **Tor Mode** with one-click activation - Need to set Tor Proxy Sys-wide first
- Supports both:
  - `https://lite.duckduckgo.com/lite/` *(standard privacy mode)*
  - `http://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/lite/` *(Tor .onion mode)*
- Isolated tab environments (sandbox-style navigation contexts).
- Integrated support for **x25519MLKEM768 cryptography** for secure session key exchanges on macOS.

---

### 🧹 Data Control
- Integrated **Clear All Browsing Data** feature:
  - Wipes cookies, cache, local storage, and all web data.
  - Confirmation and completion dialogs with a modern Cocoa prompt design.
  - Custom animated warning + success messages:
    - ⚠️ *“Clear All Browsing Data?”*
    - ✅ *“All data cleared.”*

---

### 🧭 Tabs & Navigation
- Elegant **custom tab system** with:
  - Close “✕” button on each tab (styled for macOS dark theme).
  - Smooth layout and responsive resizing.
  - Active tab highlighting and hover states.
- Tab state restoration and title sync.
- Quick “New Tab” button for fast session creation.

---

### 🌐 Web Engine
- Powered by **WKWebView** for modern web rendering.
- Hardened **WebKit preferences**:
  - No JavaScript popups.
  - No local file access.
  - Restricted cookie policies.
  - Isolated storage per tab.
- Full address bar navigation with auto-focus and Home button support.

---

### 🎨 Visual Design
- Minimal dark aesthetic inspired by modern privacy browsers.
- Rounded tab buttons and vibrant active highlights.
- Adaptive icons using Apple’s SF Symbols (for sharp, retina rendering).
- Hover effects and button tint colors to match the system accent color.

---

### ⚡ Technical Highlights
- Written in **pure Python 3** using `PyObjC` bindings.
- Utilizes:
  - `AppKit`, `WebKit`, `Foundation`
  - `NSWindow`, `NSView`, `WKWebView`
- Modular structure with clean separation of UI, logic, and security layers.
- Fully compatible with macOS Ventura, Sonoma, and Sequoia.

---

## 🧠 Architecture Overview

```
Darkelf Cocoa
│
├── Browser Class (Main Controller)
│   ├── _add_tab() / _close_tab() / actSwitchTab_()
│   ├── _update_tab_buttons() – dynamic Cocoa tab system
│   ├── _layout() – adaptive window + tab positioning
│   └── _sync_addr() – updates navigation bar + URL field
│
├── Tor Integration
│   ├── Detects Tor mode
│   ├── Switches between DDG Lite and Onion Lite endpoints
│
├── Clear Data Prompts
│   ├── Custom Cocoa alert windows
│   └── System-level secure WebKit data wipe
│
└── Privacy Controls
    ├── Fingerprint randomization
    ├── Per-tab isolation
    └── Cookie policy hardening
```

---

## 🧩 Installation

### Requirements
- macOS **13.0 (Ventura)** or later  
- **Python 3.11+**
- PyObjC packages

### Setup

```bash
pip install pyobjc-framework-Cocoa pyobjc-framework-WebKit pyobjc-framework-Quartz
```

### Run the Browser

```bash
python3 "Darkelf Cocoa.py"
```

---

## 🧠 Keyboard Shortcuts

| Action | Shortcut |
|--------|-----------|
| New Tab | ⌘ + T |
| Close Tab | ⌘ + W |
| Reload | ⌘ + R |
| Clear Data | ⌘ + Shift + Del |
| Focus Address Bar | ⌘ + L |

---

## 🧱 Roadmap
 
- [ ] Updates will be released Weekly

## 👨‍💻 Developer Notes

- Built for research, privacy testing, and macOS app prototyping.
- Designed to be **readable, hackable, and extendable**.
- The UI code uses **native AppKit layout**, not Qt or Tkinter.

- No WebRTC Leaks
- WEBGL All Spoofed
- Client Hints/UA Recognized as Tor Browser/Firefox
- Random Canvas Signature Rotation Per Session
- Validated Tor IP, Canvas Protection, Tor Letterboxing Mimic
- Youtube Works - General Version
- Tracking Monitor Results in Terminal
- Other Goods!


## Bugs Known
- Working on implementing History Dialog Box
- Youtube Fullscreen limitation w/DDG Lite



---

## 🧑‍⚖️ License

This project is licensed under the **GNU Lesser General Public License v3.0 (LGPL-3.0)**.  
You are free to use, modify, and distribute this software under the terms of the LGPL-3 license.  
See the [LICENSE](https://www.gnu.org/licenses/lgpl-3.0.html) file for full details.

© 2025 Dr. Kevin Moore
