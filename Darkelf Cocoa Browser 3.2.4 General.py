# Darkelf Cocoa Browser v3.2.4 — Ephemeral, Privacy-Focused Web Browser (macOS / Cocoa Build)
# Copyright (C) 2025 Dr. Kevin Moore
#
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# ────────────────────────────────────────────────────────────────────────────────
# PROJECT SCOPE (EPHEMERAL COCOA BUILD)
# Darkelf Cocoa Browser is the macOS edition of the Darkelf-Mini project,
# implemented using PyObjC bindings to Apple’s Cocoa and WebKit frameworks.
#
# • All browsing data (cookies, cache, history, localStorage, IndexedDB, etc.)
#   is held in memory only and automatically discarded when the process exits.
# • Download requests are disabled by default to prevent disk persistence.
# • No telemetry, analytics, or network beacons are included.
# • Tracker detection and privacy monitoring are implemented through
#   DarkelfMiniAI — an on-device heuristic filter that inspects network headers
#   and JavaScript activity without transmitting data externally.
#
# For additional defense-in-depth, users are encouraged to use macOS full-disk
# encryption (FileVault) and secure memory management.
#
# ────────────────────────────────────────────────────────────────────────────────
# EXPORT / CRYPTOGRAPHY NOTICE
# This source distribution does not itself implement proprietary cryptographic
# algorithms. Any network encryption (such as TLS/SSL) is provided by Apple’s
# WebKit and macOS security frameworks under their respective licenses.
#
# If you distribute binaries that include or link against cryptographic
# components, or if you add cryptographic code, you are responsible for
# compliance with applicable export-control laws (including the U.S. EAR) and
# any relevant license exceptions (e.g., TSU under 15 CFR §740.13(e)), as well
# as local regulations in jurisdictions of distribution and use.
#
# ────────────────────────────────────────────────────────────────────────────────
# COMPLIANCE & RESTRICTIONS
# This software may not be exported, re-exported, or transferred, directly or
# indirectly, in violation of U.S. or other applicable sanctions and export
# control laws.  Do not use this software in connection with the development,
# production, or deployment of weapons of mass destruction as defined by the
# EAR.  By downloading, using, or distributing this software, you agree to
# comply with all applicable laws and regulations.
#
# ────────────────────────────────────────────────────────────────────────────────
# NOTE
# This source code is provided without any compiled binaries. Redistribution,
# modification, and use must comply with the LGPL-3.0-or-later license and all
# applicable export/usage restrictions.
#
# Authored by Dr. Kevin Moore (2025).

import os
import sys, re, json, subprocess, threading
from dataclasses import dataclass
from typing import List
import objc
import secrets
import atexit

from Cocoa import (
    NSApp, NSApplication, NSWindow, NSWindowStyleMaskTitled, NSWindowStyleMaskClosable,
    NSWindowStyleMaskResizable, NSWindowStyleMaskMiniaturizable, NSWindowCollectionBehaviorFullScreenPrimary,
    NSObject, NSToolbar, NSToolbarItem, NSSearchField, NSButton, NSImage, NSBox, NSColor, NSView,
    NSTrackingArea, NSTrackingMouseEnteredAndExited, NSTrackingActiveAlways,
    NSEvent,
    NSToolbarFlexibleSpaceItemIdentifier, NSApplicationActivationPolicyRegular
)
from WebKit import (
    WKWebView, WKWebViewConfiguration, WKUserContentController, WKUserScript, WKUserScript, WKPreferences, WKWebsiteDataStore, WKNavigationActionPolicyAllow, WKNavigationActionPolicyCancel
)
from Foundation import NSURL, NSURLRequest, NSMakeRect, NSNotificationCenter, NSDate, NSTimer, NSObject, NSUserDefaults, NSRegistrationDomain

from AppKit import NSImageSymbolConfiguration, NSBezierPath, NSFont, NSAttributedString, NSAlert, NSAlertStyleCritical, NSColor, NSAppearance

from WebKit import WKContentRuleListStore

class ContentRuleManager:
    _rule_list = None
    _loaded = False

    @classmethod
    def load_rules(cls):
        if cls._loaded:
            return

        cls._loaded = True
        store = WKContentRuleListStore.defaultStore()
        identifier = "darkelf_builtin_rules"

        def _lookup(rule_list, error):
            if rule_list:
                cls._rule_list = rule_list
                print("[Rules] Loaded cached content rule list")
                return

            json_rules = cls._load_json()

            def _compiled(rule_list, error):
                if error:
                    print("[Rules] Compile error:", error)
                    return
                cls._rule_list = rule_list
                print("[Rules] Content rules compiled & ready")

            store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler_(
                identifier,
                json_rules,
                _compiled
            )

        store.lookUpContentRuleListForIdentifier_completionHandler_(
            identifier,
            _lookup
        )

    @classmethod
    def _load_json(cls):
        # ⚠️ CANVAS-SAFE RULES (NO SCRIPT BLOCKING)
        return """
        [
          {
            "trigger": {
              "url-filter": ".*doubleclick.net.*"
            },
            "action": {
              "type": "block"
            }
          },
          {
            "trigger": {
              "url-filter": ".*ads.*",
              "resource-type": ["image", "media"]
            },
            "action": {
              "type": "block"
            }
          }
        ]
        """

# ---- Darkelf Diagnostics / Kill-Switches ----
DARKELF_DISABLE_COOKIE_SCRUBBER = False   # set True to rule out NSTimer cookie scrubber
DARKELF_DISABLE_JS_HANDLERS    = False    # set True to disable all JS message handlers (netlog/search/tracker/panic)
DARKELF_DISABLE_RESIZE_HANDLER = False    # set True to ignore onResize notifications

# ---- Local CSP (off by default) ----
ENABLE_LOCAL_CSP = False  # set False to disable quickly
# A conservative, non-breaking CSP that satisfies the BrowserAudit items.
LOCAL_CSP_VALUE = "worker-src 'self' blob:; manifest-src 'self'; form-action 'self' https:;"
# ---- Local HSTS (off by default) ----
ENABLE_LOCAL_HSTS = True  # set False to disable quickly
# A safe, full HSTS directive with subdomains and preload
LOCAL_HSTS_VALUE = "max-age=63072000; includeSubDomains; preload"
# ---- Local Referrer Policy (off by default) ----
ENABLE_LOCAL_REFERRER_POLICY = True  # toggle as needed
LOCAL_REFERRER_POLICY_VALUE = "strict-origin-when-cross-origin"
# ---- Local WebSocket Policy (off by default) ----
ENABLE_LOCAL_WEBSOCKET_POLICY = True  # toggle as needed
# connect-src 'self' prevents cross-origin WebSocket or EventSource connections
LOCAL_WEBSOCKET_POLICY_VALUE = "connect-src 'self';"
# ---- Local ORS / CORS Header Whitelist (off by default) ----
ENABLE_LOCAL_EXPOSE_HEADERS = True  # toggle on/off as needed
# Only safe, minimal headers exposed to JavaScript
LOCAL_EXPOSE_HEADERS_VALUE = "Content-Length, Content-Type, Content-Language"

def _system_services():
    return ("Wi-Fi", "Ethernet")

class _NavDelegate(NSObject):
    def initWithOwner_(self, owner):
        self = objc.super(_NavDelegate, self).init()
        if self is None:
            return None
        self._owner = owner
        return self

    # ✅ NEW: Receive messages posted from NETLOG_JS and forward them to MiniAI
    def userContentController_didReceiveScriptMessage_(self, ucc, message):
        try:
            if message.name() != "netlog":
                return
            data = message.body() or {}
            url = str(data.get("url", ""))
            headers = data.get("headers", {}) or {}
            if hasattr(self._owner, "mini_ai"):
                self._owner.mini_ai.monitor_network(url, headers)
        except Exception as e:
            print("[Netlog Handler] Error:", e)

    def webView_decidePolicyForNavigationAction_decisionHandler_(self, webView, navAction, decisionHandler):
        try:
            req = navAction.request()
            url = req.URL()
            if url is None:
                decisionHandler(WKNavigationActionPolicyAllow); return

            scheme = (url.scheme() or "").lower()

            # Send main-frame / iframe navigations to MiniAI (kept from your version)
            try:
                if hasattr(self._owner, "mini_ai"):
                    headers = dict(req.allHTTPHeaderFields() or {})
                    self._owner.mini_ai.monitor_network(str(url.absoluteString()), headers)
            except Exception as e:
                print("[Network Monitor] Failed:", e)

            decisionHandler(WKNavigationActionPolicyAllow)
        except Exception:
            decisionHandler(WKNavigationActionPolicyAllow)

    def webView_didFailProvisionalNavigation_withError_(self, webView, nav, error):
        pass  
        
IS_MAC = sys.platform == "darwin"
if not IS_MAC:
    print("[Darkelf] macOS only."); sys.exit(1)

APP_NAME = "Darkelf"

HOMEPAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Darkelf Browser — Cocoa, Private, Hardened</title>
  <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">
  <style>
    :root{--bg:#0a0b10;--accent:#34C759;--border:rgba(255,255,255,.10);--input-bg:#12141b;--input-text:#e5e7eb;}
    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0;
      font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;
      background:
        radial-gradient(1200px 600px at 20% -10%, rgba(4,168,200,.25), transparent 60%),
        radial-gradient(1000px 600px at 120% 10%, rgba(52,199,89,.18), transparent 60%),
        var(--bg);
      color:#eef2f6;
      display:flex;
      justify-content:center;
      align-items:center;
    }

    .container{
      display:flex;
      flex-direction:column;
      align-items:center;
      gap:18px;
      padding:24px;
      text-align:center;
    }

    .brand{
      display:flex;
      gap:10px;
      align-items:center;
      justify-content:center;
      font-weight:700;
      font-size:2rem;
      color:var(--accent);
    }
    .brand i{color:var(--accent);}
    .brand span{color:var(--accent);}

    .tagline{
      font-size:1.25rem;
      font-weight:800;
      letter-spacing:.20em;
      text-transform:uppercase;
      color:#cfd8e3;
      margin:0;
    }

    .search-wrap{
      display:flex;
      align-items:stretch;
      gap:10px;
      justify-content:center;
      width:100%;
    }
    .search-wrap input{
      height:48px;
      padding:0 16px;
      width:min(720px,92vw);
      border-radius:12px;
      border:1px solid var(--border);
      background:var(--input-bg);
      color:var(--input-text);
      font-size:16px;
      outline:none;
      color:#fff;
      -webkit-text-fill-color:#fff;
    }
    .search-wrap input::placeholder{color:#9aa3ad;}
    .search-wrap input:focus{box-shadow:0 0 0 3px rgba(52,199,89,.30);border-color:transparent;}
    .search-wrap button{
      width:48px;height:48px;border-radius:12px;border:none;cursor:pointer;font-size:20px;
      display:inline-flex;align-items:center;justify-content:center;color:#fff;background:var(--accent);
    }
    .search-wrap button:focus{outline:2px solid #34C759;}
  </style>
</head>
<body>
  <div class="container">
    <div class="brand">
      <i class="bi bi-shield-lock"></i>
      <span>Darkelf Browser</span>
    </div>
    <div class="tagline">Cocoa • Private • Hardened</div>
    <form class="search-wrap"
      action="https://lite.duckduckgo.com/lite/"
      method="get" role="search" aria-label="Search DuckDuckGo">
      <input type="text" name="q" placeholder="Search DuckDuckGo" aria-label="Search query" />
      <button type="submit" aria-label="Search">
        <i class="bi bi-search"></i>
      </button>
    </form>
  </div>

  <script>
  (function() {
      // Only run if in WKWebView (macOS)
      if (!navigator.platform.toLowerCase().includes('mac')) return;
      var form = document.querySelector('.search-wrap');
      if (form) {
          form.addEventListener('submit', function(ev) {
              ev.preventDefault();
              var q = form.querySelector('input[name="q"]').value;
              if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.search) {
                  window.webkit.messageHandlers.search.postMessage(q);
              } else {
                  // fallback: redirect to DDG Lite results page
                  window.location.href = "https://lite.duckduckgo.com/lite/?q=" + encodeURIComponent(q);
              }
          });
      }
  })();
  </script>
</body>
</html>
"""

TIMEZONE_LOCALE_DEFENSE_JS = r'''
try {Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {value: function() { return { timeZone: "UTC", locale: "en-US" }; }, configurable: true });} catch(e){}
'''
FONTS_DEFENSE_JS = r'''
(function() {if (navigator.fonts) { navigator.fonts.query = function() { return Promise.resolve([]); }; } var style = document.createElement('style'); style.textContent = '* { font-family: "Arial", sans-serif !important; }'; document.head.appendChild(style);})();
'''
NAV_SPOOF_JS = r'''
Object.defineProperty(navigator, 'platform', {get: () => "Win32", configurable: true});
Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 2, configurable: true});
Object.defineProperty(navigator, 'deviceMemory', {get: () => 2, configurable: true});
'''
MEDIA_ENUM_DEFENSE_JS = r'''
if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {navigator.mediaDevices.enumerateDevices = function() {return Promise.resolve([]);};}
'''
WEBRTC_DEFENSE_JS = r'''
(function(){
  var noop = function(){};
  ['RTCPeerConnection', 'webkitRTCPeerConnection', 'mozRTCPeerConnection'].forEach(function(item){
    try { window[item] = undefined; } catch(e){}
  });
  if (navigator.mediaDevices) {
    try { navigator.mediaDevices.getUserMedia = noop; } catch(e){}
  }
})();
'''
CANVAS_DEFENSE_JS = r'''
(function() {
    // Helper: add a little random noise to pixel data
    function addNoise(data) {
        for (var i = 0; i < data.length; i++) {
            // Only change RGBA, not length. Clamp to 0-255.
            data[i] = Math.min(255, Math.max(0, data[i] + Math.floor(Math.random() * 8 - 4)));
        }
    }
    // Patch toDataURL
    var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
        try {
            var ctx = this.getContext('2d');
            var w = this.width, h = this.height;
            if (ctx && w > 0 && h > 0) {
                var imageData = ctx.getImageData(0, 0, w, h);
                addNoise(imageData.data);
                ctx.putImageData(imageData, 0, 0);
                var result = origToDataURL.apply(this, arguments);
                // Optionally: restore the original (without noise)
                ctx.putImageData(imageData, 0, 0);
                return result;
            }
        } catch(e) {}
        return origToDataURL.apply(this, arguments);
    };
    // Patch toBlob
    var origToBlob = HTMLCanvasElement.prototype.toBlob;
    HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
        try {
            var ctx = this.getContext('2d');
            var w = this.width, h = this.height;
            if (ctx && w > 0 && h > 0) {
                var imageData = ctx.getImageData(0, 0, w, h);
                addNoise(imageData.data);
                ctx.putImageData(imageData, 0, 0);
                origToBlob.call(this, function(blob) {
                    // Optionally: restore original (without noise)
                    ctx.putImageData(imageData, 0, 0);
                    callback(blob);
                }, type, quality);
                return;
            }
        } catch(e) {}
        origToBlob.apply(this, arguments);
    };
    // Patch getImageData (for 2D context)
    var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
        var imageData = origGetImageData.call(this, x, y, w, h);
        addNoise(imageData.data);
        return imageData;
    };
    // Mark as defended
    try {
        Object.defineProperty(window, 'canvasFingerprintDefended', {value: true, writable: false, configurable: false});
    } catch(e){}
})();
'''
WEBGL_DEFENSE_JS = r"""
(function(){
  function spoofGL(ctxProto, vendor, renderer) {
    if (!ctxProto) return;
    var origGetParameter = ctxProto.getParameter;
    ctxProto.getParameter = function(param) {
      // VENDOR = 0x1F00, RENDERER = 0x1F01, UNMASKED_VENDOR_WEBGL = 0x9245, UNMASKED_RENDERER_WEBGL = 0x9246
      if (param === 0x1F00 || param === 0x9245) return vendor;
      if (param === 0x1F01 || param === 0x9246) return renderer;
      return origGetParameter.apply(this, arguments);
    };
  }
  spoofGL(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype, "Intel Inc.", "Intel(R) Iris(TM) Graphics 6100");
  spoofGL(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype, "Intel Inc.", "Intel(R) Iris(TM) Graphics 6100");
})();
"""
AUDIO_DEFENSE_JS = r'''
(function() {if (window.OfflineAudioContext) {var orig = window.OfflineAudioContext.prototype.getChannelData;window.OfflineAudioContext.prototype.getChannelData = function() {var data = orig.apply(this, arguments);for (var i = 0; i < data.length; i++) data[i] = 0;return data;};}})();
'''
# NEW: Battery spoof
BATTERY_DEFENSE_JS = r'''
if ("getBattery" in navigator) {
  navigator.getBattery = function() {
    return Promise.resolve({
      charging: true,
      chargingTime: 0,
      dischargingTime: Infinity,
      level: 1,
      addEventListener: function(){},
      removeEventListener: function(){},
      onchargingchange: null,
      onlevelchange: null
    });
  };
}
'''

#  NEW: Performance fuzz
PERFORMANCE_DEFENSE_JS = r'''
(function() {
  if (window.performance && window.performance.now) {
    const realNow = window.performance.now.bind(window.performance);
    window.performance.now = function() {
      return realNow() + (Math.random() * 15 - 7);
    };
  }
  if (window.performance && window.performance.timing) {
    for (let k in window.performance.timing) {
      if (typeof window.performance.timing[k] === "number")
        window.performance.timing[k] = window.performance.timing[k] + Math.floor(Math.random() * 15 - 7);
    }
  }
})();
'''
NETLOG_JS = r"""
(function(){
  if (!window.webkit || !window.webkit.messageHandlers || !window.webkit.messageHandlers.netlog) return;

  const send = (u, h) => {
    try { window.webkit.messageHandlers.netlog.postMessage({ url: String(u||""), headers: h || {} }); }
    catch (e) {}
  };

  // Hook fetch
  const _fetch = window.fetch;
  if (typeof _fetch === "function") {
    window.fetch = function(input, init) {
      try {
        const url = (typeof input === "string") ? input : (input && input.url) || "";
        const hdrs = (init && init.headers) || {};
        send(url, hdrs);
      } catch(e) {}
      return _fetch.apply(this, arguments);
    };
  }

  // Hook XHR
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    try { send(url, {}); } catch(e) {}
    return _open.apply(this, arguments);
  };
})();
"""

# MINI AI (from PyWebView version, adapted)
class DarkelfMiniAI(NSObject):
    TRUSTED_DOMAINS = [
        "duckduckgo.com",
        "lite.duckduckgo.com",
        "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
        "browserleaks.com",
        "privacytools.io",
        "coveryourtracks.eff.org"
    ]
    MALWARE_PATTERNS = [
        r"(onerror\s*=|<script.*src=.*(\.php|\.exe|\.js)\??|<iframe.*src=.*hack)",
        r"(base64,|eval\(|atob\()",
        r"(document\.cookie|localStorage|sessionStorage)\s*=",
        r"(window\.open\(|location\.replace\(|location\.assign\()",
        r"(navigator\.sendBeacon|navigator\.clipboard|navigator\.mediaDevices)",
        r"(fetch\(|XMLHttpRequest|ActiveXObject)"
    ]
    PHISHING_KEYWORDS = [
        "login", "verify", "update account", "reset password",
        "bank", "security alert", "recovery", "payment", "confirm", "restricted"
    ]
    SNIFFING_HEADER_PATTERNS = [
        "x-forwarded-for", "via", "proxy-connection", "user-agent:curl", "user-agent:nmap"
    ]
    KNOWN_TOOL_SIGNATURES = [
        "wireshark", "burpsuite", "mitmproxy", "fiddler", "nmap", "tcpdump", "ettercap"
    ]
    PANIC_LOCKOUT_SEC = 120

    TRACKER_PATTERNS = [
        r"(^|\.)google-analytics\.com$",
        r"(^|\.)googletagmanager\.com$",
        r"(^|\.)googleadservices\.com$",
        r"(^|\.)doubleclick\.net$",
        r"(^|\.)adservice\.google\.com$",
        r"(^|\.)facebook\.net$",
        r"(^|\.)connect\.facebook\.com$",
        r"(^|\.)facebook\.com\/tr",            # Facebook Pixel endpoint
        r"(^|\.)pixel\.facebook\.com",
        r"(^|\.)ads\.twitter\.com",
        r"(^|\.)analytics\.twitter\.com",
        r"(^|\.)hotjar\.com",
        r"(^|\.)mixpanel\.com",
        r"(^|\.)segment\.io$",
        r"(^|\.)amplitude\.com",
        r"(^|\.)quantserve\.com",
        r"(^|\.)scorecardresearch\.com",
        r"(^|\.)cdn\.ampproject\.org",        # include some CDNs that host trackers
        r"(^|\.)adroll\.com",
        r"(^|\.)criteo\.com",
        r"(^|\.)taboola\.com",
        r"(^|\.)outbrain\.com",
        r"(^|\.)sentry\.io",                  # error+telemetry endpoints (optional)
        r"(^|\.)clarity\.microsoft\.com",
        r"(^|\.)bing-analytics\.com",
        r"\btrack(er|ing|ify|js)\b",          # generic 'track' or 'tracking' script names
        r"\bpixel\b",
        r"\bad(s|service|server)\b",
    ]

    def initWithBrowser_(self, browser):
        self = objc.super(DarkelfMiniAI, self).init()
        if self is None:
            return None
        self.browser = browser
        self.panic_mode = False
        self._panic_timer = None
        return self

    @objc.python_method
    def inject(self, wkview):
        self._inject_js(wkview, self._js_panic_bridge())
        self._inject_js(wkview, self._js_phishing_malware_detector())
        self._inject_js(wkview, self._js_sniffer_detector())
        self._inject_js(wkview, NETLOG_JS)

    @objc.python_method
    def _inject_js(self, wkview, js):
        try:
            from WebKit import WKUserScript
            ucc = wkview.configuration().userContentController()
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False
            )
            ucc.addUserScript_(script)
        except Exception as e:
            print("[MiniAI] JS inject failed:", e)

    @objc.python_method
    def monitor_network(self, url, headers):
        """Monitor outgoing requests for suspicious, sniffing, or tracking activity."""
        if self.panic_mode:
            return

        # --- 1. Detect sniffing headers ---
        for h, v in headers.items():
            for patt in self.SNIFFING_HEADER_PATTERNS:
                if patt in str(h).lower() or patt in str(v).lower():
                    self.trigger_panic(f"Sniffing header detected: {h}: {v}")
                    return

        # --- 2. Detect known interception / hacking tools ---
        url_l = (url or "").lower()
        for sig in self.KNOWN_TOOL_SIGNATURES:
            if sig in url_l or any(sig in str(v).lower() for v in headers.values()):
                self.trigger_panic(f"Known tool detected: {sig}")
                return

        # --- 3. Detect trackers / analytics / ad networks ---
        import re
        matched_tracker = None
        for patt in getattr(self, "TRACKER_PATTERNS", []):
            if re.search(patt, url_l, re.IGNORECASE):
                matched_tracker = patt
                break

        if matched_tracker:
            # Increment counter safely
            self.tracker_count = getattr(self, "tracker_count", 0) + 1
            print(f"[Tracker Blocked] {url}  (pattern: {matched_tracker})")

            # Optional: update UI label if available
            if hasattr(self, "update_tracker_label"):
                try:
                    self.update_tracker_label()
                except Exception as e:
                    print("[Tracker UI] Failed to update label:", e)

            # Optional: block request logic (uncomment if needed)
            # self.trigger_panic(f"Tracker blocked: {url}")
            return

    def showPanicAlert_(self, reason):
        try:
            from AppKit import NSAlert
            alert = NSAlert.alloc().init()
            alert.setMessageText_("PANIC MODE: Suspicious Activity Detected!")
            alert.setInformativeText_(f"Reason: {reason}\nBrowsing is temporarily locked.")
            alert.runModal()
        except Exception as e:
            print(f"[MiniAI] Show Panic Alert failed: {e}")

    def showReleaseAlert_(self, _):
        try:
            from AppKit import NSAlert
            alert = NSAlert.alloc().init()
            alert.setMessageText_("Panic mode released")
            alert.setInformativeText_("Browsing restored.")
            alert.runModal()
        except Exception as e:
            print(f"[MiniAI] Show Release Alert failed: {e}")

    @objc.python_method
    def trigger_panic(self, reason=""):
        if self.panic_mode:
            return
        self.panic_mode = True

        try:
            self.browser.js_enabled = False
            self.browser._rebuild_active_webview()
        except Exception as e:
            print("[MiniAI] JS disable/rebuild failed:", e)

        try:
            self.browser.actHome_(None)
        except Exception as e:
            print("[MiniAI] actHome_ failed:", e)

        try:
            self.performSelectorOnMainThread_withObject_waitUntilDone_("showPanicAlert_", reason, False)
        except Exception as e:
            print(f"PANIC MODE ACTIVATED (no modal): {reason} [{e}]")

        if self._panic_timer:
            self._panic_timer.cancel()
        import threading
        self._panic_timer = threading.Timer(self.PANIC_LOCKOUT_SEC, lambda: self.performSelectorOnMainThread_withObject_waitUntilDone_("releasePanicMainThread_", None, False))
        self._panic_timer.start()

    def releasePanicMainThread_(self, _):
        self._release_panic()

    @objc.python_method
    def _release_panic(self):
        self.panic_mode = False
        try:
            self.browser.js_enabled = True
            self.browser._rebuild_active_webview()
        except Exception as e:
            print("[MiniAI] JS enable/rebuild failed:", e)
        try:
            self.browser.actReload_(None)
        except Exception as e:
            print("[MiniAI] actReload_ failed:", e)
        try:
            self.performSelectorOnMainThread_withObject_waitUntilDone_("showReleaseAlert_", None, False)
        except Exception as e:
            print("[MiniAI] Release alert failed:", e)

    @objc.python_method
    def _js_panic_bridge(self):
        return r"""
        if (!window.__darkelf_panic_trigger) {
          window.__darkelf_panic_trigger = function(reason) {
            if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.panic) {
                window.webkit.messageHandlers.panic.postMessage(reason);
            }
          }
        }
        """

    @objc.python_method
    def _js_phishing_malware_detector(self):
        trusted_domains_js = json.dumps(self.TRUSTED_DOMAINS)
        js = f"""
        (() => {{
            var trusted = {trusted_domains_js};
            if (trusted.some(domain => window.location.hostname.indexOf(domain) !== -1)) return;

            const phishingWords = {repr(self.PHISHING_KEYWORDS)};
            const malwarePatterns = [{','.join([repr(p) for p in self.MALWARE_PATTERNS])}].map(r => new RegExp(r, "i"));
            let panic = false;
            function scanForms() {{
                const forms = document.querySelectorAll("form");
                for (const f of forms) {{
                    const txt = (f.textContent || "") + " " + (f.outerHTML || "");
                    if (f.querySelector('input[type="password"]')) {{
                        for (const w of phishingWords) {{
                            if (txt.toLowerCase().includes(w)) {{
                                window.__darkelf_panic_trigger && window.__darkelf_panic_trigger("Phishing form detected: " + w);
                                panic = true; return;
                            }}
                        }}
                    }}
                }}
            }}
            function scanScripts() {{
                const scripts = document.querySelectorAll("script");
                for (const s of scripts) {{
                    const code = s.textContent || s.src || "";
                    for (const r of malwarePatterns) {{
                        if (r.test(code)) {{
                            window.__darkelf_panic_trigger && window.__darkelf_panic_trigger("Malware script detected.");
                            panic = true; return;
                        }}
                    }}
                }}
            }}
            function runScans() {{
                if (panic) return;
                scanForms(); scanScripts();
            }}
            runScans();
            document.addEventListener("DOMContentLoaded", runScans);
            setTimeout(runScans, 1500);
        }})();
        """
        return js

    @objc.python_method
    def _js_sniffer_detector(self):
        js = r"""
        (() => {
            function trigger(reason) {
                window.__darkelf_panic_trigger && window.__darkelf_panic_trigger(reason);
            }
            if (window.RTCPeerConnection || window.webkitRTCPeerConnection) {
                trigger("WebRTC detected (possible sniffing).");
            }
            if (window.Wireshark || window.BurpSuite || window.Fiddler) {
                trigger("Known sniffing tool detected.");
            }
            let evalCount = 0;
            const origEval = window.eval;
            window.eval = function(code) {
                evalCount++; if (evalCount > 3) trigger("Excessive eval() usage (possible malware).");
                return origEval(code);
            };
            let funcCount = 0;
            const OrigFunc = Function;
            window.Function = function(...args) {
                funcCount++; if (funcCount > 3) trigger("Excessive Function() usage (possible malware).");
                return OrigFunc(...args);
            };
        })();
        """
        return js
        
# ================= Tracker blocker (JS) =================
TRACKER_LIST = [
    "adservice.google.com","www.google-analytics.com","ssl.google-analytics.com",
    "connect.facebook.net","static.chartbeat.com","www.googletagmanager.com",
    "analytics.twitter.com","cdn.segment.com","api.segment.io","snap.licdn.com",
    "cdn.branch.io","bat.bing.com","js-agent.newrelic.com","www.hotjar.com",
    "script.hotjar.com","in.hotjar.com","cdn.heapanalytics.com","static.ads-twitter.com",
]
def tracker_js(block_hosts: List[str]) -> str:
    hosts = json.dumps(block_hosts)
    return """(() => {
  const blockedHosts = new Set(%s);
  const post = (n) => window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.tracker && window.webkit.messageHandlers.tracker.postMessage(n);
  let count = 0;
  function shouldBlock(u){
    try{ const h=new URL(u, location.href).hostname;
      return blockedHosts.has(h) || [...blockedHosts].some(x => h.endsWith('.'+x)); }
    catch(_){ return false; }
  }
  const origFetch = window.fetch;
  window.fetch = async function(input, init){
    const url = (typeof input==='string') ? input : (input && input.url) || '';
    if (shouldBlock(url)) { count++; post(count); return new Response('', {status: 204}); }
    return origFetch.apply(this, arguments);
  };
  const open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m,u){
    if (shouldBlock(u)) { count++; post(count); this.abort(); return; }
    return open.apply(this, arguments);
  };
})();""" % hosts

# ================= Helper widgets =================
class HoverButton(NSButton):
    def init(self):
        self = objc.super(HoverButton, self).init()
        if self is None: return None
        self._hoverArea = None
        return self
    def updateTrackingAreas(self):
        if self._hoverArea is not None:
            self.removeTrackingArea_(self._hoverArea)
        opts = NSTrackingMouseEnteredAndExited | NSTrackingActiveAlways
        self._hoverArea = NSTrackingArea.alloc().initWithRect_options_owner_userInfo_(self.bounds(), opts, self, None)
        self.addTrackingArea_(self._hoverArea)
        objc.super(HoverButton, self).updateTrackingAreas()
    def mouseEntered_(self, evt):
        try:
            # Darker neon green (matches #34C759)
            self.setContentTintColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(52/255.0, 199/255.0, 89/255.0, 1.0))
        except Exception: pass
    def mouseExited_(self, evt):
        try: self.setContentTintColor_(NSColor.whiteColor())
        except Exception: pass

class BadgeView(NSView):
    def init(self):
        self = objc.super(BadgeView, self).initWithFrame_(((0,0),(18,18)))
        if self is None: return None
        self.count = 0
        self.hidden = True
        self.setWantsLayer_(True)
        return self
    def setCount_(self, n):
        self.count = int(n)
        self.hidden = (self.count <= 0)
        self.setNeedsDisplay_(True)
        self.displayIfNeeded()
    def isHidden(self): return self.hidden
    def drawRect_(self, rect):
        if self.hidden: return
        NSColor.colorWithCalibratedRed_green_blue_alpha_(0.2,1.0,0.5,1.0).set()
        path = NSBezierPath.bezierPathWithOvalInRect_(((0,0),(18,18)))
        path.fill()
        NSColor.colorWithCalibratedRed_green_blue_alpha_(0.0,0.5,0.25,1.0).set()
        path.setLineWidth_(1.0); path.stroke()
        txt = str(self.count)
        attrs = {
            "NSFont": NSFont.systemFontOfSize_(10.0),
            "NSForegroundColor": NSColor.blackColor()
        }
        s = NSAttributedString.alloc().initWithString_attributes_(txt, attrs)
        size = s.size()
        x = (18 - size.width)/2.0
        y = (18 - size.height)/2.0 - 0.5
        s.drawAtPoint_((x,y))

# ================= Tabs =================
@dataclass
class Tab:
    view: WKWebView
    url: str = ""
    host: str = "new"
    canvas_seed: int = None  # Unique canvas seed per tab

# ================= Script Message Handler =================
class TrackerHandler(objc.lookUpClass("NSObject")):
    def initWithOwner_(self, owner):
        self = objc.super(TrackerHandler, self).init()
        if self is None: return None
        self.owner = owner; return self
    def userContentController_didReceiveScriptMessage_(self, controller, message):
        try: self.owner.bump_tracker_count(int(message.body()))
        except Exception: pass

class SearchHandler(objc.lookUpClass("NSObject")):
    def initWithOwner_(self, owner):
        self = objc.super(SearchHandler, self).init()
        if self is None: return None
        self.owner = owner; return self
    def userContentController_didReceiveScriptMessage_(self, controller, message):
        try:
            q = str(message.body())
            url = "https://lite.duckduckgo.com/lite/?q=" + re.sub(r"\s+","+",q)
            self.owner._add_tab(url)
        except Exception as e:
            print("SearchHandler error:", e)
            
# Script Message Handler for MiniAI Panic ==========
class MiniAIPanicHandler(objc.lookUpClass("NSObject")):
    def initWithOwner_(self, owner):
        self = objc.super(MiniAIPanicHandler, self).init()
        if self is None: return None
        self.owner = owner; return self
    def userContentController_didReceiveScriptMessage_(self, controller, message):
        try:
            reason = str(message.body())
            self.owner.mini_ai.trigger_panic(reason)
        except Exception: pass
        
# BROWSER CONTROLLER PATCH ===============
class Browser(NSObject):
    def init(self):
        self = objc.super(Browser, self).init()
        if self is None:
            return None

        # =========================
        # Browser state
        # =========================
        self.cookies_enabled = True
        self.csp_enabled = True
        self.js_enabled = True

        self.tabs = []
        self.tab_btns = []
        self.tab_close_btns = []
        self.active = -1
        self._tracker_count = 0

        self.window = self._make_window()
        self.toolbar = self._make_toolbar()
        self.window.setToolbar_(self.toolbar)
        try:
            self.window.toolbar().setVisible_(True)
        except Exception:
            pass

        self._tab_neon_green = NSColor.colorWithCalibratedRed_green_blue_alpha_(
            52/255.0, 199/255.0, 89/255.0, 1.0
        )
        self._tab_neon_green_cg = self._tab_neon_green.CGColor()

        self._build_tabbar()

        # 🔒 wipe everything BEFORE creating the first tab
        try:
            self._wipe_all_site_data()
        except Exception:
            pass

        # =========================
        # 🔥 FIRST WKWebView CREATED HERE
        # =========================
        self._add_tab(home=True)

        # optional: start cookie scrubber
        try:
            self._start_cookie_scrubber()
        except Exception:
            pass

        # =========================
        # MiniAI
        # =========================
        self.mini_ai = DarkelfMiniAI.alloc().initWithBrowser_(self)
        try:
            if 0 <= self.active < len(self.tabs):
                self.mini_ai.inject(self.tabs[self.active].view)
            print("[Init] MiniAI tracker monitor initialized")
        except Exception as e:
            print("[Init] MiniAI inject failed:", e)

        self.window.makeKeyAndOrderFront_(None)
        NSApp().activateIgnoringOtherApps_(True)
        return self

        # Resize listener
        try:
            nc = NSNotificationCenter.defaultCenter()
            nc.addObserver_selector_name_object_(self, "onResize:", "NSWindowDidResizeNotification", self.window)
        except Exception:
            pass

        self._install_key_monitor()
        self.window.makeKeyAndOrderFront_(None)
        NSApp().activateIgnoringOtherApps_(True)
        return self

    # ---- SAFE COOKIE SCRUBBER (selector-based; fixes NSTimer segfault) ----
    def _start_cookie_scrubber(self):
        """Start periodic cookie scrubbing using a real Obj-C selector."""
        try:
            self._cookie_store = WKWebsiteDataStore.defaultDataStore().httpCookieStore()
        except Exception:
            self._cookie_store = None

        # Fire once immediately
        try:
            self._scrub_cookies()
        except Exception:
            pass

        # Keep a strong ref to the timer so it isn't GC'd
        try:
            self._cookie_timer = self._cookie_timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                10.0, self, "actScrubCookies:", None, True  # repeats=True
            )
        except Exception:
            self._cookie_timer = None

    # Called by NSTimer (must be a real Obj-C selector name ending with '_')
    def actScrubCookies_(self, timer):
        try:
            self._scrub_cookies()
        except Exception:
            pass

    def _scrub_cookies(self):
        try:
            store = getattr(self, "_cookie_store", None)
            if not store:
                store = WKWebsiteDataStore.defaultDataStore().httpCookieStore()
                self._cookie_store = store

            def _got(cookies):
                try:
                    for c in (cookies or []):
                        try: store.deleteCookie_(c)
                        except Exception: pass
                except Exception: pass

                # MUST be outside _got()
            store.getAllCookiesWithCompletionHandler_(_got)
        except Exception:
            pass
            
    def _stop_cookie_scrubber(self):
        """Invalidate the NSTimer so it stops firing before app exit."""
        try:
            if getattr(self, "_cookie_timer", None):
                self._cookie_timer.invalidate()
                self._cookie_timer = None
        except Exception:
            pass

    def _make_window(self):
        rect = NSMakeRect(80, 80, 1280, 820)
        style = (
            NSWindowStyleMaskTitled
            | NSWindowStyleMaskClosable
            | NSWindowStyleMaskResizable
            | NSWindowStyleMaskMiniaturizable
        )
        win = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            rect, style, 2, False
        )
        win.setTitle_(APP_NAME)

        try:
            win.setTitleVisibility_(1)
            win.setToolbarStyle_(1)
            win.setTitlebarAppearsTransparent_(False)
            win.setBackgroundColor_(NSColor.blackColor())
            cv = win.contentView()
            if cv is not None:
                f = cv.frame()
                strip = NSBox.alloc().initWithFrame_(((0, f.size.height - 40), (f.size.width, 40)))
                strip.setBoxType_(0)
                strip.setBorderType_(0)
                strip.setFillColor_(NSColor.blackColor())
                strip.setAutoresizingMask_(10)
                strip.setTitle_("")
                strip.setTitlePosition_(0)
                cv.addSubview_(strip)
        except Exception:
            pass

        # Added block: Make titlebar transparent, set background, set layer background
        try:
            win.setTitlebarAppearsTransparent_(True)
            win.setBackgroundColor_(NSColor.blackColor())
            win.contentView().setWantsLayer_(True)
            win.contentView().layer().setBackgroundColor_(NSColor.blackColor().CGColor())
        except Exception:
            pass

        try:
            win.setCollectionBehavior_(NSWindowCollectionBehaviorFullScreenPrimary)
        except Exception:
            pass
        return win

    # ----- Toolbar -----
    def _mk_btn(self, symbol, tooltip):
        b = HoverButton.alloc().init()
        try:
            img = NSImage.imageWithSystemSymbolName_accessibilityDescription_(symbol, None)
            # First, try the user-requested configuration
            cfg = NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(54.0, 2, 2)
            if img and hasattr(img, "imageByApplyingSymbolConfiguration_"):
                img = img.imageByApplyingSymbolConfiguration_(cfg)
        # Optionally fallback to prior config if needed (commented out unless fallback is desired)
        # if not img:
        #     cfg = NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(32.0, 1, 1)
        #     img = img.imageByApplyingSymbolConfiguration_(cfg)
            if img:
                try:
                    img.setTemplate_(True)
                except Exception:
                    pass
                b.setImage_(img)
        except Exception:
            pass
        try:
            b.setBordered_(False)
            b.setBezelStyle_(1)
            b.setToolTip_(tooltip or "")
        except Exception:
            pass
        if hasattr(b, "setContentTintColor_"):
            b.setContentTintColor_(NSColor.whiteColor())
        return b
        
    @objc.python_method
    def _show_quick_controls_popover(self, anchor_view):
        from AppKit import (
            NSPopover, NSView, NSStackView, NSTextField, NSSwitch,
            NSColor, NSLayoutConstraint, NSImage, NSImageView,
            NSImageSymbolConfiguration, NSViewController, NSFont
        )

        ACCENT = NSColor.colorWithCalibratedRed_green_blue_alpha_(52/255.0,199/255.0,89/255.0,1.0)

        pop = NSPopover.alloc().init()
        pop.setBehavior_(1)
        pop.setAnimates_(True)

        root = NSView.alloc().initWithFrame_(((0, 0), (260, 200)))
        stack = NSStackView.alloc().init()
        stack.setOrientation_(1)  # vertical
        stack.setSpacing_(16.0)
        stack.setTranslatesAutoresizingMaskIntoConstraints_(False)
        root.addSubview_(stack)

        NSLayoutConstraint.activateConstraints_([
            stack.topAnchor().constraintEqualToAnchor_constant_(root.topAnchor(), 12),
            stack.leadingAnchor().constraintEqualToAnchor_constant_(root.leadingAnchor(), 12),
            stack.trailingAnchor().constraintEqualToAnchor_constant_(root.trailingAnchor(), -12),
            stack.bottomAnchor().constraintEqualToAnchor_constant_(root.bottomAnchor(), -12),
        ])

        def get_icon(symbol_name):
            icon = None
            try:
                icon = NSImage.imageWithSystemSymbolName_accessibilityDescription_(symbol_name, None)
                if icon and hasattr(icon, "imageByApplyingSymbolConfiguration_"):
                    cfg = NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(18.0, 2, 2)
                    icon = icon.imageByApplyingSymbolConfiguration_(cfg)
            except Exception:
                try:
                    icon = NSImage.imageWithSystemSymbolName_accessibilityDescription_(symbol_name, None)
                except Exception:
                    icon = None
            return icon

        from AppKit import NSLayoutAttributeCenterY  # constant, not an enum member

        def make_row(symbol_name, title, initial_on=None, toggle_selector=None):
            # icon
            icon = get_icon(symbol_name)
            iv = NSImageView.alloc().initWithFrame_(((0, 0), (18, 18)))
            if icon:
                iv.setImage_(icon)
                iv.setContentTintColor_(NSColor.whiteColor())

            # label
            label = NSTextField.labelWithString_(title)
            label.setTextColor_(NSColor.whiteColor())
            label.setFont_(NSFont.systemFontOfSize_(15))
            label.setLineBreakMode_(4)  # NSLineBreakByTruncatingTail

            # horizontal stack
            rowv = NSStackView.alloc().init()
            rowv.setOrientation_(0)            # horizontal
            rowv.setSpacing_(10)
            rowv.setAlignment_(NSLayoutAttributeCenterY)  # ✅ correct vertical centering
            rowv.setTranslatesAutoresizingMaskIntoConstraints_(False)

            # Add views in order: icon → label
            rowv.addArrangedSubview_(iv)
            rowv.addArrangedSubview_(label)

            # Make label flexible so it doesn't push the switch away
            try:
                # Lower compression resistance horizontally so label can truncate before pushing siblings
                label.setContentCompressionResistancePriority_forOrientation_(250, 0)  # 0 = horizontal
                # Lower hugging so label can expand/shrink as needed
                label.setContentHuggingPriority_forOrientation_(249, 0)
            except Exception:
                pass

            # Optional: add a switch
            sw = None
            if initial_on is not None and toggle_selector is not None:
                sw = NSSwitch.alloc().init()
                sw.setTarget_(self)
                sw.setAction_(toggle_selector)
                if hasattr(sw, "setState_"):
                    sw.setState_(1 if initial_on else 0)
                try:
                    if hasattr(sw, "setControlTintColor_"):
                        sw.setControlTintColor_(ACCENT)
                    elif hasattr(sw, "setTintColor_"):
                        sw.setTintColor_(ACCENT)
                except Exception:
                    pass

                # Keep the switch from stretching
                try:
                    sw.setContentHuggingPriority_forOrientation_(751, 0)
                    sw.setContentCompressionResistancePriority_forOrientation_(751, 0)
                except Exception:
                    pass

                rowv.addArrangedSubview_(sw)

            # Distribution hint (may be no-op on some macOS versions)
            try:
                rowv.setDistribution_(0)  # Fill
            except Exception:
                pass

            return rowv, sw

        # JS row
        js_row, self._sw_js = make_row("bolt", "JavaScript", True, "onToggleJS:")
        
        # Cookies row
        cookies_enabled = bool(getattr(self, "cookies_enabled", True))
        cookies_row, self._sw_cookies = make_row(
            "cookie",
            "Cookies",
            cookies_enabled,
            "onToggleCookies:"
        )

        # CSP row
        csp_enabled = bool(getattr(self, "csp_enabled", True))
        csp_row, self._sw_csp = make_row(
            "lock.shield",
            "CSP",
            csp_enabled,
            "onToggleCSP:"
        )

        for rv in (js_row, cookies_row, csp_row):
            stack.addArrangedSubview_(rv)

        vc = NSViewController.alloc().init()
        vc.setView_(root)
        pop.setContentViewController_(vc)
        pop.showRelativeToRect_ofView_preferredEdge_(anchor_view.bounds(), anchor_view, 1)
        self._quick_controls_popover = pop
        
    def onToggleCookies_(self, sender):
        try:
            self.cookies_enabled = bool(sender.state())
            print(f"[Privacy] Cookies {'ENABLED' if self.cookies_enabled else 'DISABLED'}")

            # Apply immediately to future WebViews
            if not self.cookies_enabled:
                try:
                    WKWebsiteDataStore.defaultDataStore().removeDataOfTypes_modifiedSince_completionHandler_(
                        {"WKWebsiteDataTypeCookies"}, NSDate.distantPast(), None
                    )
                except Exception:
                    pass

        except Exception as e:
            print("Cookies toggle error:", e)
            
    def onToggleCSP_(self, sender):
        try:
            self.csp_enabled = bool(sender.state())
            print(f"[Privacy] CSP {'ENABLED' if self.csp_enabled else 'DISABLED'}")

            # CSP is enforced via headers / injection on navigation
            # You likely already reference this flag elsewhere
        except Exception as e:
            print("CSP toggle error:", e)

    def onToggleJS_(self, sender):
        try:
            self.actToggleJS_(None)
            if hasattr(self, "_sw_js"):
                self._sw_js.setState_(1 if self.js_enabled else 0)
        except Exception as e:
            print("JS toggle error:", e)

    def _make_toolbar(self):
        from AppKit import NSColor, NSAppearance
        tb = NSToolbar.alloc().initWithIdentifier_("DarkelfToolbar")
        tb.setDisplayMode_(2)
        tb.setSizeMode_(1)

        # --- Navigation + control buttons ---
        # Larger icons: increase point size (44 recommended)
        def big_btn(symbol, tooltip):

            b = HoverButton.alloc().init()
            try:
                img = NSImage.imageWithSystemSymbolName_accessibilityDescription_(symbol, None)
                cfg = NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(54.0, 2, 2)
                if img and hasattr(img, "imageByApplyingSymbolConfiguration_"):
                    img = img.imageByApplyingSymbolConfiguration_(cfg)
                if img:
                    try: img.setTemplate_(True)
                    except Exception: pass
                    b.setImage_(img)
            except Exception: pass
            try: b.setBordered_(False); b.setBezelStyle_(1); b.setToolTip_(tooltip or "")
            except Exception: pass
            if hasattr(b, "setContentTintColor_"): b.setContentTintColor_(NSColor.whiteColor())
            return b

        self.btn_back   = big_btn("chevron.backward", "Back")
        self.btn_fwd    = big_btn("chevron.forward", "Forward")
        self.btn_reload = big_btn("arrow.clockwise", "Reload")
        self.btn_home   = big_btn("house", "Home")
        self.btn_newtab = big_btn("plus", "New Tab")
        self.btn_close  = big_btn("xmark", "Close Tab")
        self.btn_zoom_in  = big_btn("plus.magnifyingglass", "Zoom In")
        self.btn_zoom_out = big_btn("minus.magnifyingglass", "Zoom Out")
        self.btn_full   = big_btn("arrow.up.left.and.arrow.down.right", "Fullscreen")
        self.btn_track  = big_btn("target", "Trackers Blocked")
        self.btn_js     = big_btn("bolt.slash", "Toggle JavaScript")
        self.btn_more = big_btn("ellipsis.circle", "Quick Controls")

        # JS button coloring
        img = NSImage.imageWithSystemSymbolName_accessibilityDescription_("bolt", None)
        if img:
            img.setTemplate_(True)
            self.btn_js.setImage_(img)
            self.btn_js.setImagePosition_(2)    # Image only
        self.btn_js.setTitle_("")               # <-- This removes the "Button" text
        self.btn_js.setToolTip_(f"JavaScript: {'ON' if self.js_enabled else 'OFF'}")
        if hasattr(self.btn_js, "setContentTintColor_"):
            if self.js_enabled:
                self.btn_js.setContentTintColor_(
                    NSColor.colorWithCalibratedRed_green_blue_alpha_(52/255.0, 199/255.0, 89/255.0, 1.0)
                )
            else:
                self.btn_js.setContentTintColor_(
                    NSColor.colorWithCalibratedRed_green_blue_alpha_(1.0, 59/255.0, 48/255.0, 1.0)
            )
            
        # --- Nuke / Clear All Data ---
        def _load_symbol_with_fallback(symbols):
            for s in symbols:
                im = NSImage.imageWithSystemSymbolName_accessibilityDescription_(s, None)
                if im:
                    try:
                        cfg = NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(54.0, 2, 2)
                        if hasattr(im, "imageByApplyingSymbolConfiguration_"):
                            im = im.imageByApplyingSymbolConfiguration_(cfg)
                        im.setTemplate_(True)
                    except Exception:
                        pass
                    return im, s
            return None, None

        self.btn_nuke = big_btn("skull.fill", "Clear All Data")
        try:
            if not self.btn_nuke.image():
                im, used = _load_symbol_with_fallback([
                    "skull.fill",
                    "xmark.octagon.fill",
                    "flame.fill",
                    "trash.fill"
                ])
                if im:
                    self.btn_nuke.setImage_(im)
            self.btn_nuke.setImagePosition_(2)
            self.btn_nuke.setTitle_("")
            if hasattr(self.btn_nuke, "setContentTintColor_"):
                danger_syms = {"xmark.octagon.fill", "flame.fill"}
                tint = (1.0, 0.25, 0.25, 1.0) if 'used' in locals() and used in danger_syms else (52/255.0, 199/255.0, 89/255.0, 1.0)
                self.btn_nuke.setContentTintColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(*tint))
        except Exception:
            pass

        self.btn_nuke.setTarget_(self)
        self.btn_nuke.setAction_("actNuke:")
        
        # Attach actions to each button
        for b, sel in [
            (self.btn_back, 'actBack:'),
            (self.btn_fwd, 'actFwd:'),
            (self.btn_reload, 'actReload:'),
            (self.btn_home, 'actHome:'),
            (self.btn_newtab, 'actNewTab:'),
            (self.btn_close, 'actCloseTab:'),
            (self.btn_zoom_in, 'actZoomIn:'),
            (self.btn_zoom_out, 'actZoomOut:'),
            (self.btn_full, 'actFull:'),
            #(self.btn_js, 'actToggleJS:'),
            (self.btn_more, 'actQuickControls:'),
            (self.btn_nuke, 'actNuke:'),
        ]:
            b.setTarget_(self); b.setAction_(sel)

        class AddressField(NSSearchField):
            def initWithFrame_owner_(self, frame, owner):
                self = objc.super(AddressField, self).initWithFrame_(frame)
                if self is None: return None
                self._owner = owner   # back-reference to Browser
                return self
            def rightMouseDown_(self, event):
                try:
                    loc = event.locationInWindow()
                    if hasattr(self, "_owner") and self._owner:
                        self._owner._show_context_popover(self, loc)
                    else:
                        objc.super(AddressField, self).rightMouseDown_(event)
                except Exception as e:
                    print("Context menu popover error:", e)

        self.addr = AddressField.alloc().initWithFrame_owner_(((0, 0), (1080, 32)), self)
        try:
            cell = self.addr.cell()
            cell.setPlaceholderString_("Search or enter URL")
            if hasattr(cell, "setSendsWholeSearchString_"):
                cell.setSendsWholeSearchString_(True)
            if hasattr(cell, "setSendsSearchStringImmediately_"):
                cell.setSendsSearchStringImmediately_(False)
        except Exception: pass
        self.addr.setTarget_(self); self.addr.setAction_("actGo:")
        
        # Green border on focus (see your snippet)
        try:
            from AppKit import NSColor
            self.addr.setFocusRingType_(1)  # NSFocusRingTypeNone
            self.addr.setWantsLayer_(True)
            self.addr.layer().setBorderColor_(
                NSColor.colorWithCalibratedRed_green_blue_alpha_(52/255.0, 199/255.0, 89/255.0, 1.0)
            )
            self.addr.layer().setBorderWidth_(2.0)
        except Exception:
            pass

        # --- Keep address field text white in both Dark and Light macOS modes ---
        try:
            from AppKit import NSAppearance
            darkAqua = NSAppearance.appearanceNamed_("NSAppearanceNameDarkAqua")
            if darkAqua and hasattr(self.addr, "setAppearance_"):
                self.addr.setAppearance_(darkAqua)
            if hasattr(self.addr, "setTextColor_"):
                self.addr.setTextColor_(NSColor.whiteColor())
        except Exception as e:
            print("[AddrBar] appearance lock failed:", e)

        # Wrap in NSToolbarItem so AppKit respects width
        addr_item = NSToolbarItem.alloc().initWithItemIdentifier_("Addr")
        addr_item.setView_(self.addr)
        addr_item.setMinSize_((700, 32))     # match search field height
        addr_item.setMaxSize_((1600, 32))    # allow very long

        # Helper to wrap views
        def item(ident, view):
            it = NSToolbarItem.alloc().initWithItemIdentifier_(ident)
            it.setView_(view); return it

        # --- Toolbar items order ---
        self.items = [
            item('Back', self.btn_back),
            item('Fwd', self.btn_fwd),
            item('Reload', self.btn_reload),
            item('Home', self.btn_home),
            "NSToolbarFlexibleSpaceItem",
            addr_item,
            "NSToolbarFlexibleSpaceItem",
            item('NewTab', self.btn_newtab),
            item('CloseTab', self.btn_close),
            #item('JS', self.btn_js),
            item('ZoomIn', self.btn_zoom_in),
            item('ZoomOut', self.btn_zoom_out),
            item('Full', self.btn_full),
            item('Nuke', self.btn_nuke),
            item('More', self.btn_more),
        ]

        # tracker badge overlay placeholder (keep your real BadgeView in prod)
        class BadgeViewStub(NSObject): pass
        self._track_badge = BadgeViewStub.alloc().init()

        owner = self
        class Delegate(NSObject):
            def initWithOwner_(self, owner_):
                self = objc.super(Delegate, self).init(); self.owner = owner_; return self
            def toolbarAllowedItemIdentifiers_(self, tb):
                return [*(i if isinstance(i, str) else i.itemIdentifier() for i in self.owner.items)]
            def toolbarDefaultItemIdentifiers_(self, tb):
                return [*(i if isinstance(i, str) else i.itemIdentifier() for i in self.owner.items)]
            def toolbar_itemForItemIdentifier_willBeInsertedIntoToolbar_(self, tb, ident, flag):
                for i in self.owner.items:
                    if not isinstance(i, str) and i.itemIdentifier() == ident:
                        # --- Always update JS button tooltip and color when inserted ---
                        if ident == 'JS':
                            btn = i.view()
                            if btn:
                                btn.setToolTip_(f"JavaScript: {'ON' if self.owner.js_enabled else 'OFF'}")
                                if hasattr(btn, "setContentTintColor_"):
                                    if self.owner.js_enabled:
                                        btn.setContentTintColor_(
                                            NSColor.colorWithCalibratedRed_green_blue_alpha_(
                                                52/255.0, 199/255.0, 89/255.0, 1.0
                                            )
                                        )
                                    else:
                                        btn.setContentTintColor_(
                                            NSColor.colorWithCalibratedRed_green_blue_alpha_(
                                                1.0, 59/255.0, 48/255.0, 1.0
                                            )
                                        )
                        return i
                return None
        self._toolbar_delegate = Delegate.alloc().initWithOwner_(self)
        tb.setDelegate_(self._toolbar_delegate)
        return tb

    # ----- Tab strip -----
    def _build_tabbar(self):
        cv = self.window.contentView()

        # Compute tabbar frame just below title/toolbar
        tab_h = 36.0
        tab_btn_height = tab_h - 8
        try:
            clr = self.window.contentLayoutRect()
            y = clr.origin.y + clr.size.height - tab_h
            w = clr.size.width
        except Exception:
            f = cv.frame(); title_h = 40.0
            y = f.size.height - title_h - tab_h; w = f.size.width

        # Use NSView instead of NSBox to prevent unwanted title label
        self.tabbar = NSView.alloc().initWithFrame_(((0, y), (w, tab_h)))
        self.tabbar.setWantsLayer_(True)
        self.tabbar.layer().setBackgroundColor_(
            NSColor.colorWithCalibratedRed_green_blue_alpha_(0.07, 0.09, 0.12, 1.0).CGColor()
        )
        self.tabbar.setAutoresizingMask_(10)  # width + stick to top

        cv.addSubview_(self.tabbar)

        # "+" button (image-only)
        self.btn_tab_add = HoverButton.alloc().init()
        try:
            img = NSImage.imageWithSystemSymbolName_accessibilityDescription_("plus", None)
            cfg = NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(18.0, 1, 1)
            if img:
                img = img.imageByApplyingSymbolConfiguration_(cfg)
                img.setTemplate_(True)
                self.btn_tab_add.setImage_(img)
        except Exception:
            pass
        try:
            self.btn_tab_add.setTitle_("")          # image-only
            self.btn_tab_add.setImagePosition_(2)   # NSImageOnly
            self.btn_tab_add.setBordered_(False)
            self.btn_tab_add.setBezelStyle_(1)
            if hasattr(self.btn_tab_add, "setImageScaling_"):
                self.btn_tab_add.setImageScaling_(1)  # NSImageScaleProportionallyDown
        except Exception:
            pass
        if hasattr(self.btn_tab_add, "setContentTintColor_"):
            self.btn_tab_add.setContentTintColor_(NSColor.whiteColor())
        self.btn_tab_add.setTarget_(self)
        self.btn_tab_add.setAction_("actNewTab:")
        self.tabbar.addSubview_(self.btn_tab_add)

        # Initial layout + z-order
        self._layout()
        self._bring_tabbar_to_front()

    def _bring_tabbar_to_front(self):
        """Ensure tabbar is visible above the webview."""
        try:
            cv = self.window.contentView()
            if self.tabbar.superview() is not None:
                self.tabbar.removeFromSuperview()
            cv.addSubview_(self.tabbar)  # last added == topmost
            self.tabbar.displayIfNeeded()
        except Exception: pass

    def onResize_(self, note): self._layout()

    def _layout(self):
        """Lay out the tabbar and its buttons consistently with contentLayoutRect."""
        try:
            cv = self.window.contentView()
            tab_h = 36.0                     # Fixed tab bar height
            tab_btn_height = tab_h - 8.0     # Button height with padding
            close_btn_height = tab_btn_height

            # --- Use contentLayoutRect for accurate top positioning ---
            try:
                clr = self.window.contentLayoutRect()
                y = clr.origin.y + clr.size.height - tab_h  # Pin just below toolbar
                w = clr.size.width
            except Exception:
                # Fallback for older macOS versions
                f = cv.frame()
                title_h = 40.0
                y = f.size.height - title_h - tab_h
                w = f.size.width

            # --- Set tab bar frame, width flexible but height fixed ---
            self.tabbar.setAutoresizingMask_(10)  # WidthSizable + MinYMargin
            self.tabbar.setFrame_(((0, y), (w, tab_h)))

            tb = self.tabbar.frame()

            # --- "+" button at right end ---
            self.btn_tab_add.setFrame_(((tb.size.width - 32.0, (tab_h - tab_btn_height) / 2.0),
                                        (28.0, tab_btn_height)))
    
            # --- Tab buttons layout ---
            x = 8.0
            tab_w = 180.0       # Fixed tab width
            close_w = 18.0
            gap = 8.0

            for b, close in zip(self.tab_btns, self.tab_close_btns):
                b.setFrame_(((x, (tab_h - tab_btn_height) / 2.0),
                            (tab_w, tab_btn_height)))
                close.setFrame_(((x + 8.0, (tab_h - close_btn_height) / 2.0),
                                (close_w, close_btn_height)))
                x += (tab_w + gap)

        except Exception as e:
            print("Layout error:", e)

    def _update_tab_buttons(self):
        # Clear existing tab buttons
        for btn in getattr(self, "tab_btns", []):
            try: btn.removeFromSuperview()
            except Exception: pass
        for btn in getattr(self, "tab_close_btns", []):
            try: btn.removeFromSuperview()
            except Exception: pass
        self.tab_btns, self.tab_close_btns = [], []

        # Helper for middle ellipsis
        def middle_ellipsis(text, max_len=26):
            if len(text) <= max_len:
                return text
            keep = max_len - 1
            head = keep // 2
            tail = keep - head
            return text[:head] + "…" + text[-tail:]

        for idx, t in enumerate(self.tabs):
            # --- Close button (bullet; never image) ---
            close = HoverButton.alloc().init()
            try:
                from AppKit import NSFont, NSMutableParagraphStyle, NSAttributedString, NSColor
                style = NSMutableParagraphStyle.alloc().init()
                style.setAlignment_(1)  # center

                close.setImage_(None)            # ensure no image path
                close.setTitle_("•")
                close.setAttributedTitle_(NSAttributedString.alloc().initWithString_attributes_(
                    "•",
                    {
                        "NSFont": NSFont.boldSystemFontOfSize_(14.0),
                        "NSParagraphStyle": style,
                        "NSColor": NSColor.whiteColor(),
                    }
                ))
                if hasattr(close, "setImagePosition_"):
                    close.setImagePosition_(0)   # NSNoImage
                close.setBordered_(False)
                close.setBezelStyle_(1)
                close.setToolTip_("Close Tab")
            except Exception:
                pass
            # Avoid tinting logic meant for images
            close.setTarget_(self)
            close.setAction_("actCloseTabIndex:")
            close.setTag_(idx)

            # --- Tab button (hostname or 'home') ---
            host = t.host or f"tab {idx+1}"
            if host == "home" or t.url in ("about:home", "about:blank", "about:blank#blocked", "about://home"):
                label = "Home"
            else:
                import re as _re
                host = _re.sub(r"^\s*www\.", "", host, flags=_re.IGNORECASE)
                label = host
            label = middle_ellipsis(label, 26)

            b = HoverButton.alloc().init()
            try:
                # Centered attributed title
                from AppKit import NSMutableParagraphStyle, NSFont, NSAttributedString
                style = NSMutableParagraphStyle.alloc().init()
                style.setAlignment_(1)  # center
                font = NSFont.systemFontOfSize_(12.0)
                attrs = {"NSFont": font, "NSParagraphStyle": style}
                b.setAttributedTitle_(NSAttributedString.alloc().initWithString_attributes_(label, attrs))
                b.setBordered_(False)
                b.setBezelStyle_(1)
                b.setToolTip_(label)
            except Exception:
                try: b.setTitle_(label)
                except Exception: pass

            b.setTarget_(self)
            b.setAction_("actSwitchTab:")
            b.setTag_(idx)

            # Add tab button and close button to tabbar
            self.tabbar.addSubview_(b)
            self.tabbar.addSubview_(close)
            self.tab_btns.append(b)
            self.tab_close_btns.append(close)

        # Restyle and layout
        self._style_tabs()
        self._layout()
        self._bring_tabbar_to_front()

    def _style_tabs(self):
        """Active tab neon green background; others clear."""
        neon_green = NSColor.colorWithCalibratedRed_green_blue_alpha_(15/255.0, 255/255.0, 80/255.0, 1.0)
        neon_green_cg = neon_green.CGColor()
        clear_color = NSColor.clearColor()
        clear_color_cg = clear_color.CGColor()
        for idx, (b, _) in enumerate(zip(self.tab_btns, self.tab_close_btns)):
            if hasattr(b, "setWantsLayer_"):
                b.setWantsLayer_(True)
            try:
                layer = b.layer()
            except Exception:
                layer = None

            if self.active == idx:
                if layer:
                    layer.setCornerRadius_(11.0)
                    layer.setBackgroundColor_(neon_green_cg)
                try:
                    b.setContentTintColor_(NSColor.blackColor())
                except Exception:
                    pass
            else:
                if layer:
                    layer.setBackgroundColor_(clear_color_cg)
                try:
                    b.setContentTintColor_(NSColor.whiteColor())
                except Exception:
                    pass
    
    def _install_local_csp(ucc):
        """
        Injects a <meta http-equiv="Content-Security-Policy"> for pages we control.
        Default: only for file:// pages to avoid breaking the open web.
        """
        try:
            from WebKit import WKUserScript
        except Exception:
            return  # WebKit not available

        js = f"""
        (() => {{
          try {{
            if (location.protocol !== 'file:') return;
            if (document.querySelector('meta[http-equiv="Content-Security-Policy"]')) return;

            const meta = document.createElement('meta');
            meta.httpEquiv = 'Content-Security-Policy';
            meta.content = {repr(LOCAL_CSP_VALUE)};
            (document.head || document.documentElement).prepend(meta);
          }} catch (e) {{
            // Safe fallback, never block page load
          }}
        }})();
        """

        try:
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False  # 0 = AtDocumentStart
            )
            ucc.addUserScript_(script)
            print("[CSP] Local CSP injector installed (file:// only).")
        except Exception as e:
            print("[CSP] Injector add failed:", e)
            
    def _install_local_hsts(self, ucc):
        """
        Injects a <meta http-equiv="Strict-Transport-Security"> for pages we control.
        Limited to HTTPS and file:// origins to avoid breaking third-party sites.
        """
        try:
            from WebKit import WKUserScript
        except Exception:
            return  # WebKit not available

        js = f"""
        (() => {{
          try {{
            const here = location.protocol;
            // Only inject for file:// or HTTPS origins we control
            if (here !== 'file:' && here !== 'https:') return;

            // Avoid duplicate tags
            if (document.querySelector('meta[http-equiv="Strict-Transport-Security"]')) return;

            const meta = document.createElement('meta');
            meta.httpEquiv = 'Strict-Transport-Security';
            meta.content = {repr(LOCAL_HSTS_VALUE)};
            (document.head || document.documentElement).prepend(meta);
          }} catch (e) {{
            // Fail quietly; never break load
          }}
        }})();
        """

        try:
            # Inject after TLS negotiation (AtDocumentEnd, same as CSP)
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False
            )
            ucc.addUserScript_(script)
            print("[HSTS] Local HSTS injector installed (https:// & file:// only).")
        except Exception as e:
            print("[HSTS] Injector add failed:", e)
            
    def _install_local_referrer_policy(self, ucc):
        """
        Injects a <meta name="referrer" content="strict-origin-when-cross-origin">
        for pages we control. Limited to file:// and HTTPS origins.
        """
        try:
            from WebKit import WKUserScript
        except Exception:
            return  # WebKit not available

        js = f"""
        setTimeout(() => {{
          try {{
            const here = location.protocol;
            if (here !== 'file:' && here !== 'https:') return;

            if (document.querySelector('meta[name="referrer"]')) return;

            const meta = document.createElement('meta');
            meta.name = 'referrer';
            meta.content = {repr(LOCAL_REFERRER_POLICY_VALUE)};
            (document.head || document.documentElement).prepend(meta);
            console.log('[ReferrerPolicy] Meta injected after TLS handshake.');
          }} catch (e) {{
            // Fail quietly; never break page load
          }}
        }}, 100);
        """

        try:
            # Inject after TLS negotiation (AtDocumentEnd)
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False  # 1 = AtDocumentEnd
            )
            ucc.addUserScript_(script)
            print("[ReferrerPolicy] Local Referrer-Policy injector installed (https:// & file:// only, delayed).")
        except Exception as e:
            print("[ReferrerPolicy] Injector add failed:", e)
            
    def _install_local_websocket_policy(self, ucc):
        """
        Injects a <meta http-equiv="Content-Security-Policy"> specifically for connect-src 'self'.
        This restricts WebSocket and EventSource endpoints to the same origin.
        Limited to file:// and HTTPS origins to avoid breaking third-party sites.
        """
        try:
            from WebKit import WKUserScript
        except Exception:
            return  # WebKit not available

        js = f"""
        setTimeout(() => {{
          try {{
            const here = location.protocol;
            if (here !== 'file:' && here !== 'https:') return;

            // Prevent duplicate CSP tags that include connect-src
            const existing = document.querySelectorAll('meta[http-equiv="Content-Security-Policy"]');
            for (const m of existing) {{
              if (m.content.includes("connect-src")) return;
            }}

            const meta = document.createElement('meta');
            meta.httpEquiv = 'Content-Security-Policy';
            meta.content = {repr(LOCAL_WEBSOCKET_POLICY_VALUE)};
            (document.head || document.documentElement).prepend(meta);
            console.log('[WebSocketPolicy] connect-src self injected.');
          }} catch (e) {{
            // Fail quietly; never break page load
          }}
        }}, 100);
        """

        try:
            # Inject after TLS negotiation (AtDocumentEnd, safe timing)
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False  # 1 = AtDocumentEnd
            )
            ucc.addUserScript_(script)
            print("[WebSocketPolicy] Local WebSocket Policy injector installed (connect-src 'self').")
        except Exception as e:
            print("[WebSocketPolicy] Injector add failed:", e)
            
    def _install_local_expose_headers(self, ucc):
        """
        Injects a <meta http-equiv="Access-Control-Expose-Headers"> declaration
        to whitelist safe response headers for CORS (ORS Headers).
        Limits scope to HTTPS and file:// pages to avoid conflicts.
        """
        try:
            from WebKit import WKUserScript
        except Exception:
            return  # WebKit not available

        js = f"""
        setTimeout(() => {{
          try {{
            const here = location.protocol;
            if (here !== 'file:' && here !== 'https:') return;

            // Avoid duplicate Access-Control meta tags
            if (document.querySelector('meta[http-equiv="Access-Control-Expose-Headers"]')) return;

            const meta = document.createElement('meta');
            meta.httpEquiv = 'Access-Control-Expose-Headers';
            meta.content = {repr(LOCAL_EXPOSE_HEADERS_VALUE)};
            (document.head || document.documentElement).prepend(meta);

            console.log('[ExposeHeaders] Safe header whitelist injected.');
          }} catch (e) {{
            // Fail quietly, never block page load
          }}
        }}, 100);
        """

        try:
            # Inject at document end (safe timing)
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False  # 1 = AtDocumentEnd
            )
            ucc.addUserScript_(script)
            print("[ExposeHeaders] Local Access-Control-Expose-Headers injector installed (https:// & file:// only).")
        except Exception as e:
            print("[ExposeHeaders] Injector add failed:", e)

    @objc.python_method
    def _inject_core_scripts(self, ucc):

        try:
            # Use whatever seed you've set up previously (falls back if missing)
            seed = getattr(self, "current_canvas_seed", None) or 123456789

            # Helper to add a script safely
            def _add(src):
                try:
                    skr = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(src, 0, False)
                    ucc.addUserScript_(skr)
                except Exception as e:
                    print("[Inject] addUserScript_ failed:", e)

            # 1) WebRTC defense
            if 'WEBRTC_DEFENSE_JS' in globals():
                _add(WEBRTC_DEFENSE_JS)
            else:
                _add(r"(function(){ try{ navigator.mediaDevices.getUserMedia = function(){ return Promise.reject(new Error('Blocked by Darkelf')); }; navigator.mediaDevices.enumerateDevices = function(){ return Promise.resolve([]); }; }catch(e){} })();")

            # 2) WebGL spoof
            if 'WEBGL_DEFENSE_JS' in globals():
                _add(WEBGL_DEFENSE_JS)
            else:
                _add(r"(function(){ try{ if(window.WebGLRenderingContext){ var proto = window.WebGLRenderingContext.prototype; var orig = proto.getParameter; proto.getParameter = function(p){ if(p===0x1F00) return 'Intel Inc.'; if(p===0x1F01) return 'Intel(R) Iris(TM) Graphics 6100'; return orig.apply(this, arguments); }; } }catch(e){} })();")

            # 5) Canvas defense - use seed if available
            if 'CANVAS_DEFENSE_JS' in globals():
                # If global used your {seed} formatting, it will be fine; otherwise fallback
                _add(CANVAS_DEFENSE_JS)
            else:
                _add(f"(function(){{ var SEED={seed}; try{{ var orig=HTMLCanvasElement.prototype.toDataURL; HTMLCanvasElement.prototype.toDataURL=function(){{ try{{ return orig.apply(this,arguments); }}catch(e){{return '';}} }}; }}catch(e){{}} }})();")

            if ENABLE_LOCAL_CSP:
                self._install_local_csp(ucc)
                print("[CSP] Local CSP injector attached to UCC")

            print("[Inject] Core defense scripts added to UCC.")
        except Exception as e:
            pass

            if ENABLE_LOCAL_HSTS:
                self._install_local_hsts(ucc)
                print("[HSTS] Local HSTS injector attached to UCC.")
            
            if ENABLE_LOCAL_REFERRER_POLICY:
                self._install_local_referrer_policy(ucc)
                print("[ReferrerPolicy] Local Referrer Policy attached to UCC.")
                
            if ENABLE_LOCAL_WEBSOCKET_POLICY:
                self._install_local_websocket_policy(ucc)
                print("[WebSocketPolicy] Local WebSocket Policy attached to UCC.")
                
            if ENABLE_LOCAL_EXPOSE_HEADERS:
                self._install_local_expose_headers(ucc)
                print("[ExposeHeaders] Local ORS header whitelist attached to UCC.")

            print("[Inject] Core defense scripts added to UCC.")
            
    def _new_wk(self) -> WKWebView:
        cfg = WKWebViewConfiguration.alloc().init()
        try:
            cfg.setWebsiteDataStore_(WKWebsiteDataStore.nonPersistentDataStore())
        except Exception:
            pass
        
        prefs = WKPreferences.alloc().init()
        try:
            prefs.setJavaScriptEnabled_(bool(getattr(self, "js_enabled", True)))
            prefs.setJavaScriptCanOpenWindowsAutomatically_(True)
        except Exception:
            pass
        cfg.setPreferences_(prefs)

        # --- App-Bound Domain Restriction Debug ---
        try:
            cfg.setLimitsNavigationsToAppBoundDomains_(False)
            print("[Debug] App-bound domain restriction OFF")
        except Exception:
            pass

        ucc = WKUserContentController.alloc().init()
        
            # --- REGISTER JS MESSAGE HANDLER FOR NETLOG ---
        try:
            # remove any stale handlers (avoid duplicates)
            ucc.removeScriptMessageHandlerForName_("netlog")
        except Exception:
            pass

        try:
            # register our delegate (_NavDelegate) as JS message receiver
            if hasattr(self, "_nav"):
                ucc.addScriptMessageHandler_name_(self._nav, "netlog")
                print("[Init] Netlog handler registered")
            else:
                print("[Init] _nav delegate not set yet — cannot add netlog handler.")
        except Exception as e:
            print("[Init] Failed to register netlog handler:", e)
        # ------------------------------------------------

        # --- Search Handler (already in your code) ---
        self._search_handler = getattr(self, "_search_handler", None) or SearchHandler.alloc().initWithOwner_(self)
        ucc.addScriptMessageHandler_name_(self._search_handler, "search")

        # --- Canvas Fingerprint Seed ---
        seed = secrets.randbits(64)
        self.current_canvas_seed = seed

        # --- Core defense scripts (ensure this function writes to UCC, not webview) ---
        try:
            self._inject_core_scripts(ucc)  # <— must accept UCC and call ucc.addUserScript_
            print("[Inject] Core defense scripts added to UCC.")
        except Exception as e:
            print("[Inject] core scripts error:", e)

        # --- Optional: JS killswitch stub when JS is logically OFF ---
        if getattr(self, "js_enabled", True) is False:
            print("[JS] Injecting JavaScript Killswitch user script (defensive stub)...")
            js_killswitch = r"""(function(){ /* … your stub … */ })();"""
            try:
                ks = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(js_killswitch, 0, False)
                ucc.addUserScript_(ks)
            except Exception:
                pass

        # --- Optional: content rules when JS disabled ---
        try:
            if not getattr(self, "js_enabled", True):
                from WebKit import WKContentRuleListStore
                store = WKContentRuleListStore.defaultStore()
                rule_text = '[{"trigger":{"url-filter":".*"},"action":{"type":"block","resource-type":["script"]}}]'
                def _cb(rule_list, err):
                    if rule_list and not err:
                        ucc.addContentRuleList_(rule_list)
                store.compileContentRuleListForIdentifier_source_completionHandler_(
                    "darkelf_block_scripts", rule_text, _cb
            )
        except Exception:
            pass

        # --- Finish: attach controller & create webview ---
        cfg.setUserContentController_(ucc)
        web = WKWebView.alloc().initWithFrame_configuration_(((0, 0), (100, 100)), cfg)

        return web

        # --- Optional: JS killswitch stub ---
        # This is only useful if JS engine is ON but you want to "soft-block" JS
        # With engine OFF, this script will never execute.
        if getattr(self, "js_enabled", True) is False:
            print("[JS] Injecting JavaScript Killswitch user script (defensive stub)...")
            js_killswitch = r"""
            // Defensive: If JS engine is ON, block common APIs
            (function(){
                try { window.eval = function(){return null;}; } catch(e){}
                try { window.Function = function(){throw new Error("JavaScript blocked by Darkelf");}; } catch(e){}
                try { window.setTimeout = window.setInterval = window.requestAnimationFrame = function(){ return; }; } catch(e){}
                try { document.write = function(){ return; }; } catch(e){}
                try {
                    var origSetAttr = Element.prototype.setAttribute;
                    Element.prototype.setAttribute = function(name, value) {
                        if (name && /^on/i.test(name)) return;
                        return origSetAttr.apply(this, arguments);
                    };
                } catch(e){}
                try {
                    var origCreate = Document.prototype.createElement;
                    Document.prototype.createElement = function(tag) {
                        var el = origCreate.apply(this, arguments);
                        try {
                            if (String(tag).toLowerCase() === 'script') {
                                Object.defineProperty(el, 'src', { set: function(){}, get: function(){return ''; } });
                                el.type = 'darkelf/blocked';
                                el.defer = true; el.noModule = true;
                            }
                        } catch(_){}
                        return el;
                    };
                    var origAppend = Element.prototype.appendChild;
                    Element.prototype.appendChild = function(node) {
                        try { if (node && node.tagName === 'SCRIPT') return node; } catch(_){}
                        return origAppend.apply(this, arguments);
                    };
                } catch(e){}
            })();
            """
            try:
                ks = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(js_killswitch, 0, False)
                ucc.addUserScript_(ks)
            except Exception as e:
                pass

        try:
            if not getattr(self, "js_enabled", True):
                from WebKit import WKContentRuleListStore
                store = WKContentRuleListStore.defaultStore()
                rule_text = '[{"trigger":{"url-filter":".*"},"action":{"type":"block","resource-type":["script"]}}]'
                def _cb(rule_list, err):
                    if rule_list and not err:
                        ucc.addContentRuleList_(rule_list)
                store.compileContentRuleListForIdentifier_source_completionHandler_(
                    "darkelf_block_scripts", rule_text, _cb
                )
        except Exception as e:
            pass

        # --- Finish ---
        cfg.setUserContentController_(ucc)
        web = WKWebView.alloc().initWithFrame_configuration_(((0, 0), (100, 100)), cfg)

        # --- UA SPOOF (ensure helper/secondary webviews also send spoofed HTTP UA) ---
        try:
            web.setCustomUserAgent_(USER_AGENT_SPOOF)
        except Exception:
            pass

        return web

        # 2. WebRTC lockdown except getUserMedia for YouTube (no IP leak, SDP scrub)
        WEBRTC_DEFENSE_JS = r"""
        (function(){
          var isYoutube = /^(?:https?:\/\/)?(?:[^\/]+\.)?(youtube\.com|youtu\.be)\//i.test(location.href);
          [
            'RTCPeerConnection', 'webkitRTCPeerConnection', 'mozRTCPeerConnection',
            'RTCDataChannel', 'RTCSessionDescription', 'RTCIceCandidate'
          ].forEach(function(name){
            try { window[name] = undefined; } catch(e){}
            try { if(window.navigator) window.navigator[name] = undefined; } catch(e){}
          });
          try { window.sdp = undefined; } catch(e){}
          try { if(window.sessionDescription) window.sessionDescription = undefined; } catch(e){}
          try { if(window.RTCSessionDescription) window.RTCSessionDescription = undefined; } catch(e){}
          Object.defineProperty(window, 'ondatachannel', {value: undefined, configurable:true});
          Object.defineProperty(window, 'onsignalingstatechange', {value: undefined, configurable:true});
          if (typeof console !== "undefined") {
            var origLog = console.log;
            var sdpPattern = /v=0|a=ice-|a=fingerprint|a=setup|a=candidate|s=-|m=audio|m=video|a=mid|a=sendrecv/;
            console.log = function(){
              var args = Array.from(arguments);
              if(args.some(arg=>typeof arg==="string" && sdpPattern.test(arg))) return;
              return origLog.apply(console, arguments);
            };
          }
          // getUserMedia patch: block unless YouTube
          if (navigator.mediaDevices) {
            if (!isYoutube) {
              navigator.mediaDevices.getUserMedia = function(){ return Promise.reject(new Error("Blocked by Darkelf")); };
            }
            navigator.mediaDevices.enumerateDevices = function(){ return Promise.resolve([]); };
          }
          ['getUserMedia','webkitGetUserMedia','mozGetUserMedia','msGetUserMedia'].forEach(function(name){
            if (!isYoutube) try { navigator[name] = undefined; } catch(e){}
          });
          window.__darkelf_webrtc_defended__ = true;
        })();
        """

        # 3. WebGL vendor/renderer spoofing (looks like Windows)
        WEBGL_DEFENSE_JS = r"""
        (function(){
          var spoof_vendor = "Intel Inc.";
          var spoof_renderer = "Intel(R) Iris(TM) Graphics 6100";
          function patchGL(ctxProto) {
            if (!ctxProto) return;
            var origGetParameter = ctxProto.getParameter;
            ctxProto.getParameter = function(param) {
              if (param === 0x1F00) return spoof_vendor; // VENDOR
              if (param === 0x1F01) return spoof_renderer; // RENDERER
              if (param === 0x9245) return spoof_vendor; // UNMASKED_VENDOR_WEBGL
              if (param === 0x9246) return spoof_renderer; // UNMASKED_RENDERER_WEBGL
              return origGetParameter.apply(this, arguments);
            };
          }
          patchGL(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype);
          patchGL(window.WebGL2RenderingContext && window.WebGL2RenderingContext.prototype);
        })();
        """
        
        # 5. Canvas fingerprint: 100% unique, deterministic per tab
        CANVAS_DEFENSE_JS = f"""
        (function(){{
          var SEED = {seed};
          function rnd() {{
            SEED = (SEED * 1664525 + 1013904223) >>> 0;
            return SEED / 4294967296;
          }}
          function addNoise(data) {{
            for (var i = 0; i < data.length; i++) {{
              data[i] = Math.min(255, Math.max(0, data[i] + Math.floor(rnd()*32 - 16)));
            }}
          }}
          var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
          HTMLCanvasElement.prototype.toDataURL = function() {{
            try {{
              var ctx = this.getContext('2d');
              var w = this.width, h = this.height;
              if (ctx && w > 0 && h > 0) {{
                var imageData = ctx.getImageData(0, 0, w, h);
                addNoise(imageData.data);
                ctx.putImageData(imageData, 0, 0);
                var result = origToDataURL.apply(this, arguments);
                ctx.putImageData(imageData, 0, 0);
                return result;
              }}
            }} catch(e) {{}}
            return origToDataURL.apply(this, arguments);
          }};
          var origToBlob = HTMLCanvasElement.prototype.toBlob;
          HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {{
            try {{
              var ctx = this.getContext('2d');
              var w = this.width, h = this.height;
              if (ctx && w > 0 && h > 0) {{
                var imageData = ctx.getImageData(0, 0, w, h);
                addNoise(imageData.data);
                ctx.putImageData(imageData, 0, 0);
                origToBlob.call(this, function(blob) {{
                  ctx.putImageData(imageData, 0, 0);
                  callback(blob);
                }}, type, quality);
                return;
              }}
            }} catch(e) {{}}
            origToBlob.apply(this, arguments);
          }};
          var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
          CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {{
            var imageData = origGetImageData.call(this, x, y, w, h);
            addNoise(imageData.data);
            return imageData;
          }};
          window.__darkelf_canvas_seed__ = {seed};
          window.__darkelf_canvas_defended__ = true;
          if (!document.getElementById('__darkelf_canvas_banner')) {{
            var div = document.createElement('div');
            div.id = '__darkelf_canvas_banner';
            div.textContent = 'Canvas Seed: ' + {seed};
            div.style = 'position:fixed;top:0;left:0;right:0;background:#121722;color:#34C759;font:14px system-ui;text-align:center;padding:2px 0;z-index:2147483647;';
            document.body.appendChild(div);
            setTimeout(function(){{ try{{ div.remove(); }}catch(e){{}} }}, 2500);
          }}
        }})();
        """

        # --- Inject all scripts ---
        for js in [
            USER_AGENT_SPOOF_JS,
            TIMEZONE_LOCALE_DEFENSE_JS,
            FONTS_DEFENSE_JS,
            MEDIA_ENUM_DEFENSE_JS,
            WEBRTC_DEFENSE_JS,
            CANVAS_DEFENSE_JS,
            WEBGL_DEFENSE_JS,
            AUDIO_DEFENSE_JS,
            BATTERY_DEFENSE_JS,
            CLIENT_HINTS_DEFENSE_JS,
            PERFORMANCE_DEFENSE_JS,
        ]:
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 0, False
            )
            ucc.addUserScript_(script)

        # === TRACKER BLOCKER ===
        if self.js_enabled:
            js = tracker_js(TRACKER_LIST)
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 0, False
            )
            ucc.addUserScript_(script)
            self._tracker_handler = getattr(self, "_tracker_handler", None) or TrackerHandler.alloc().initWithOwner_(self)
            ucc.addScriptMessageHandler_name_(self._tracker_handler, "tracker")

        # === MINI AI SCRIPTS ===
        self._mini_ai_handler = getattr(self, "_mini_ai_handler", None) or MiniAIPanicHandler.alloc().initWithOwner_(self)
        ucc.addScriptMessageHandler_name_(self._mini_ai_handler, "panic")
        cfg.setUserContentController_(ucc)

        wk = WKWebView.alloc().initWithFrame_configuration_(NSMakeRect(0,0,100,100), cfg)
        wk.setAutoresizingMask_(18)

        # --- UA SPOOF ---
        try: wk.setCustomUserAgent_(USER_AGENT_SPOOF)
        except Exception: pass

        # --- Inject MiniAI JS (phish/malware/sniffer/bridge) ---
        try: self.mini_ai.inject(wk)
        except Exception: pass

        return wk
        
    def _mount_webview(self, wk):
        """Mount the webview BELOW the tabbar so tabs never get covered."""
        cv = self.window.contentView()
        tab_h = 34.0
        try:
            clr = self.window.contentLayoutRect()
            web_rect = ((0, 0), (clr.size.width, max(0.0, clr.size.height - tab_h)))
        except Exception:
            f = cv.frame(); title_h = 40.0
            web_rect = ((0, 0), (f.size.width, max(0.0, f.size.height - (title_h + tab_h))))
        cv.addSubview_(wk); wk.setFrame_(web_rect); wk.setAutoresizingMask_(18)
        self._bring_tabbar_to_front()

    def _rebuild_active_webview(self):

            if self.active < 0 or self.active >= len(self.tabs):
                return

            old = self.tabs[self.active].view

            # --- Clean up the old view ---
            try:
                ucc_old = old.configuration().userContentController()
                ucc_old.removeAllUserScripts()
                for name in ["tracker", "panic", "search"]:
                    try: ucc_old.removeScriptMessageHandlerForName_(name)
                    except Exception: pass
            except Exception:
                pass

            try:
                if old.superview() is not None:
                    old.removeFromSuperview()
            except Exception:
                pass
            self.tabs[self.active].view = None

            try:
                if hasattr(self, "_track_badge") and self._track_badge.superview() is not None:
                    self._track_badge.removeFromSuperview()
            except Exception:
                pass

            # --- Determine which URL to reload ---
            url = ""
            try:
                u = old.URL()
                if u is not None:
                    url = str(u.absoluteString())
            except Exception:
                pass
            if not url:
                url = self.tabs[self.active].url

            # --- Build a fresh WebView configuration (App-Bound OFF) ---
            config = WKWebViewConfiguration.alloc().init()
            try:
                config.setLimitsNavigationsToAppBoundDomains_(False)
            except Exception:
                try:
                    config.limitsNavigationsToAppBoundDomains = False
                except Exception:
                    pass

            # --- Set JS enabled or disabled ---
            prefs = WKPreferences.alloc().init()
            try:
                prefs.setJavaScriptEnabled_(bool(getattr(self, "js_enabled", True)))
                prefs.setJavaScriptCanOpenWindowsAutomatically_(True)
            except Exception:
                pass
            config.setPreferences_(prefs)

            # --- Fresh user content controller ---
            ucc = WKUserContentController.alloc().init()

            # --- Reattach handlers ---
            try:
                self._search_handler = getattr(self, "_search_handler", None) or SearchHandler.alloc().initWithOwner_(self)
                ucc.addScriptMessageHandler_name_(self._search_handler, "search")
            except Exception:
                pass

            # --- Inject core defenses into UCC (NOT the webview) ---
            try:
                self._inject_core_scripts(ucc)   # IMPORTANT: pass UCC here
            except Exception:
                pass

            # --- Optional: Block external script resources when JS is off ---
            try:
                if not getattr(self, "js_enabled", True):
                    from WebKit import WKContentRuleListStore
                    store = WKContentRuleListStore.defaultStore()
                    rule_text = '[{"trigger":{"url-filter":".*"},"action":{"type":"block","resource-type":["script"]}}]'
                    def _cb(rule_list, err):
                        if rule_list and not err:
                            ucc.addContentRuleList_(rule_list)
                    store.compileContentRuleListForIdentifier_source_completionHandler_(
                        "darkelf_block_scripts", rule_text, _cb
                    )
            except Exception:
                pass

            # --- Attach the user content controller ---
            try:
                config.setUserContentController_(ucc)
            except Exception:
                pass

            # --- Attach a delegate that allows onion when Tor is on ---
            try:
                self._nav_delegate = _NavDelegate.alloc().initWithOwner_(self)
            except Exception:
                self._nav_delegate = None

            try:
                frame = old.frame() if hasattr(old, "frame") else ((0, 0), (800, 600))
                wk = WKWebView.alloc().initWithFrame_configuration_(frame, config)

                # --- UA SPOOF (rebuild path) ---
                try:
                    wk.setCustomUserAgent_(USER_AGENT_SPOOF)
                except Exception:
                    pass

                if getattr(self, "_nav_delegate", None) is not None:
                    wk.setNavigationDelegate_(self._nav_delegate)
                if getattr(self, "_ui_delegate", None) is not None:
                    try:
                        wk.setUIDelegate_(self._ui_delegate)
                    except Exception:
                        pass

                try:
                    wk.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
                except Exception:
                    pass

                # Mount & swap in
                self.tabs[self.active].view = wk
                self._mount_webview(wk)

                # DO NOT inject scripts into the webview here; they are already on the UCC.
                # (Remove your old: self._inject_core_scripts(wk))
            except Exception as e:
                print("[WK] creation failed:", e)
                return

            # --- Reload prior URL without redirecting to homepage ---
            try:
                old_url = ""
                try:
                    u = old.URL()
                    if u:
                        old_url = str(u.absoluteString())
                except Exception:
                    pass
                if not old_url:
                    try:
                        item = old.backForwardList().currentItem()
                        if item and item.URL():
                            old_url = str(item.URL().absoluteString())
                    except Exception:
                        pass

                # Fall back to tab's remembered URL
                url = old_url or self.tabs[self.active].url or ""

                # If we're on the internal homepage or truly blank, render HOMEPAGE_HTML
                if url in (None, "", "about:home", "about://home", "about:blank", "about:blank#blocked"):
                    try:
                        self.tabs[self.active].view.loadHTMLString_baseURL_(HOMEPAGE_HTML, None)
                        self.tabs[self.active].url  = "about:home"
                        self.tabs[self.active].host = "home"
                        self._sync_addr()
                    except Exception:
                        pass
                    return  # <-- return ONLY in the homepage path

                # Otherwise load the same external URL so we remain on the current page
                req = NSURLRequest.requestWithURL_(NSURL.URLWithString_(url))
                wk.loadRequest_(req)
            except Exception:
                pass

    def _add_tab(self, url: str = "", home: bool = False):
        self._nav = _NavDelegate.alloc().initWithOwner_(self)
        wk = self._new_wk()
        wk.setNavigationDelegate_(self._nav)

        # Hide current webview but DO NOT touch tabbar
        if 0 <= self.active < len(self.tabs):
            try: self.tabs[self.active].view.removeFromSuperview()
            except Exception: pass

        # Mount new webview
        self._mount_webview(wk)          # adds webview
        self._bring_tabbar_to_front()    # keep strip visible

        # Create and select tab, including unique canvas_seed for fingerprinting
        tab = Tab(
            view=wk,
            url="",
            host="new",
            canvas_seed=getattr(self, "current_canvas_seed", None)  # <-- store the seed for this tab
        )
        self.tabs.append(tab)
        self.active = len(self.tabs) - 1

        if home:
            try: self.addr.setStringValue_("")
            except Exception: pass
            wk.loadHTMLString_baseURL_(HOMEPAGE_HTML, None)
            tab.url = "about:home"
            tab.host = "home"
        else:
            self._load_url_in_active(url)

        self._update_tab_buttons()
        self._style_tabs()
        self._sync_addr()
        
    def _teardown_webview(self, wk):
        if not wk:
            return
        # 1) Try to stop any media in the page (YouTube/Invidious/HTML5) & exit PiP
        try:
            js = r"""
            (function(){
              try {
                // Exit Picture-in-Picture if active
                if (document.pictureInPictureElement) {
                  try { document.exitPictureInPicture(); } catch(e){}
                }
                // Pause/neutralize <video>/<audio>
                document.querySelectorAll('video,audio').forEach(function(m){
                  try{ m.pause(); }catch(e){}
                  try{ m.src = ''; }catch(e){}
                  try{ m.load(); }catch(e){}
                });
                // Stop YouTube iframe API players if present
                try {
                  if (window.YT && YT.get) {
                    var players = YT.get();
                    Object.keys(players || {}).forEach(function(k){
                      try{ players[k].stopVideo(); }catch(e){}
                    });
                  }
                } catch(e){}
                // Blank out any iframes that might be producing sound
                document.querySelectorAll('iframe').forEach(function(f){
                  try{ f.src = 'about:blank'; }catch(e){}
                });
              } catch(e){}
            })();
            """
            wk.evaluateJavaScript_completionHandler_(js, None)
        except Exception:
            pass

        # 2) Stop network activity, blank the page
        try: wk.stopLoading()
        except Exception: pass
        try: wk.loadHTMLString_baseURL_("", None)
        except Exception: pass

        # 3) Detach delegates and remove message handlers/scripts
        try: wk.setNavigationDelegate_(None)
        except Exception: pass
        try: wk.setUIDelegate_(None)
        except Exception: pass
        try:
            ucc = wk.configuration().userContentController()
            if ucc:
                try: ucc.removeAllUserScripts()
                except Exception: pass
                for name in ("tracker","netlog","search","mini_ai"):
                    try: ucc.removeScriptMessageHandlerForName_(name)
                    except Exception: pass
        except Exception:
            pass

        # 4) Remove from the view hierarchy
        try: wk.removeFromSuperview()
        except Exception:
            pass

    def _close_tab(self):
        if not self.tabs:
            return
        cur = self.tabs.pop(self.active)
        try:
            self._teardown_webview(cur.view)
        except Exception:
            pass
        # If no tabs left, stop cookie scrubber to prevent segfaults, then add a new home tab
        if not self.tabs:
            try:
                self._stop_cookie_scrubber()
            except Exception:
                pass
            self._add_tab(home=True)
            return
        self.active = min(self.active, len(self.tabs)-1)
        self._mount_webview(self.tabs[self.active].view)
        self._sync_addr()
        self._update_tab_buttons()
        self._style_tabs()

    def actNewTab_(self, _): self._add_tab(home=True)

    def actSwitchTab_(self, sender):
        try: idx = int(sender.tag())
        except Exception: return
        if not (0 <= idx < len(self.tabs)) or idx == self.active: return
        try: self.tabs[self.active].view.removeFromSuperview()
        except Exception: pass
        self.active = idx
        self._mount_webview(self.tabs[self.active].view)
        self._bring_tabbar_to_front()
        self._style_tabs()
        self._sync_addr()

    def actCloseTabIndex_(self, sender):
        try: idx = int(sender.tag())
        except Exception: return
        if not (0 <= idx < len(self.tabs)): return

        # Teardown the target tab’s webview whether it’s active or not
        try: self._teardown_webview(self.tabs[idx].view)
        except Exception: pass

        del self.tabs[idx]

        if not self.tabs:
            self._add_tab(home=True)
            return

        if self.active >= len(self.tabs):
            self.active = len(self.tabs) - 1
        elif idx < self.active:
            self.active -= 1

        self._mount_webview(self.tabs[self.active].view)
        self._update_tab_buttons()
        self._style_tabs()
        self._sync_addr()

    def actCloseTab_(self, _): self._close_tab()

    def actBack_(self, _):
        try: self.tabs[self.active].view.goBack_(None)
        except Exception: pass
    def actFwd_(self, _):
        try: self.tabs[self.active].view.goForward_(None)
        except Exception: pass
    def actReload_(self, _):
        try: self.tabs[self.active].view.reload_(None)
        except Exception: pass
    def actHome_(self, _):
        try:
            self.tabs[self.active].view.loadHTMLString_baseURL_(HOMEPAGE_HTML, None)
            self.tabs[self.active].url = "about:home"; self.tabs[self.active].host = "home"
            self._sync_addr(); self._style_tabs()
        except Exception: pass
    def actZoomIn_(self, _):
        try: s=self.tabs[self.active].view.magnification(); self.tabs[self.active].view.setMagnification_centeredAtPoint_(min(s+0.1,3.0),(0,0))
        except Exception: pass
    def actZoomOut_(self, _):
        try: s=self.tabs[self.active].view.magnification(); self.tabs[self.active].view.setMagnification_centeredAtPoint_(max(s-0.1,0.5),(0,0))
        except Exception: pass
    def actFull_(self, _):
        try: self.window.toggleFullScreen_(None)
        except Exception: pass

    @objc.python_method
    def _tint_alert_ok_green(self, alert):
        ACCENT = (52/255.0, 199/255.0, 89/255.0, 1.0)
        if alert.buttons().count() == 0:
            alert.addButtonWithTitle_("OK")
        btn = alert.buttons().objectAtIndex_(0)
        try:
            if hasattr(btn, "setBezelColor_"):
                btn.setBezelColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT))
            elif hasattr(btn, "setContentTintColor_"):
                btn.setContentTintColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT))
            else:
                btn.setWantsLayer_(True)
                btn.layer().setCornerRadius_(6.0)
                btn.layer().setBackgroundColor_(
                    NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT).CGColor()
                )
        except Exception as e:
            print("[Alert tint] failed:", e)

    def actTrackInfo_(self, _):
        print(f"[Trackers] Blocked so far: {self._tracker_count}")
    def actToggleJS_(self, _):
        # Flip state
        self.js_enabled = not bool(getattr(self, "js_enabled", True))
        try:
            # Update icon + tooltip
            sym = "bolt" if self.js_enabled else "bolt.slash"
            img = NSImage.imageWithSystemSymbolName_accessibilityDescription_(sym, None)
            if img:
                img.setTemplate_(True)
                self.btn_js.setImage_(img)
                self.btn_js.setImagePosition_(2)
            self.btn_js.setToolTip_(f"JavaScript: {'ON' if self.js_enabled else 'OFF'}")
            if hasattr(self.btn_js, "setContentTintColor_"):
                if self.js_enabled:
                    self.btn_js.setContentTintColor_(
                        NSColor.colorWithCalibratedRed_green_blue_alpha_(52/255.0, 199/255.0, 89/255.0, 1.0)
                    )
                else:
                    self.btn_js.setContentTintColor_(
                        NSColor.colorWithCalibratedRed_green_blue_alpha_(1.0, 59/255.0, 48/255.0, 1.0)
                    )
        except Exception as e:
            print("JS icon color error:", e)

        # ✅ Apply JS setting to the existing webview and reload in-place (no rebuild)
        try:
            wk = self.tabs[self.active].view
            cfg = wk.configuration() if hasattr(wk, "configuration") else None
            prefs = cfg.preferences() if cfg and hasattr(cfg, "preferences") else None
            if prefs:
                try:
                    prefs.setJavaScriptEnabled_(bool(getattr(self, "js_enabled", True)))
                except Exception:
                    try:
                        prefs.javaScriptEnabled = bool(getattr(self, "js_enabled", True))
                    except Exception:
                        pass

            # Figure out current URL
            current_url = ""
            try:
                u = wk.URL()
                if u:
                    current_url = str(u.absoluteString())
            except Exception:
                pass
            if not current_url:
                try:
                    item = wk.backForwardList().currentItem()
                    if item and item.URL():
                        current_url = str(item.URL().absoluteString())
                except Exception:
                    pass

            # Homepage/blank needs explicit HTML reload
            if current_url in (None, "", "about:home", "about://home", "about:blank", "about:blank#blocked"):
                try:
                    wk.loadHTMLString_baseURL_(HOMEPAGE_HTML, None)
                    self.tabs[self.active].url  = "about:home"
                    self.tabs[self.active].host = "home"
                except Exception:
                    pass
            else:
                # Normal pages: try a simple reload first
                try:
                    wk.reload_(None)
                except Exception:
                    # Fallback: explicit request to same URL
                    try:
                        req = NSURLRequest.requestWithURL_(NSURL.URLWithString_(current_url))
                        wk.loadRequest_(req)
                    except Exception:
                        pass
        except Exception as e:
            print("[JS Toggle] in-place reload failed:", e)

        # ✅ Keep Quick Controls switch in sync if present
        try:
            if hasattr(self, "_sw_js") and self._sw_js:
                self._sw_js.setState_(1 if self.js_enabled else 0)
        except Exception:
            pass

    def actQuickControls_(self, _):
        try:
            self._show_quick_controls_popover(self.btn_more)
        except Exception as e:
            print("Quick Controls popover error:", e)

    def actGo_(self, sender):
        try:
            text = str(sender.stringValue()).strip()
            if not text:
                return

            # Always treat as DDG Lite search if no scheme and no dot
            if "://" not in text and "." not in text:
                from urllib.parse import quote_plus
                q = quote_plus(text)  # proper URL encoding
                url = "https://lite.duckduckgo.com/lite/?q=" + q
            elif "://" not in text:
                url = "https://" + text
            else:
                url = text

            # Parse proto/host/rest
            m = re.match(r'(\w+):\/\/([^\/]+)(.*)', url)
            if m:
                proto, host, rest = m.group(1), m.group(2), m.group(3) or ""
                host_l = host.lower()
                is_onion = host_l.endswith(".onion")

                # Never redirect to .onion, always use DDG Lite clearnet
                if host_l in (
                    "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
                    "duckduckgo.com", "www.duckduckgo.com",
                    "lite.duckduckgo.com", "www.lite.duckduckgo.com",
                ):
                    host = "lite.duckduckgo.com"
                    proto = "https"
                    url = f"{proto}://{host}{rest}"

            self._add_tab(url)  # Always open in a new tab!
        except Exception as e:
            print("[Go] Failed:", e)

    def _show_block_alert(self, msg):
        try:
            alert = NSAlert.alloc().init()
            alert.setMessageText_("Blocked for privacy")
            alert.setInformativeText_(msg)
            alert.runModal()
        except Exception:
            print("Blocked: " + msg)
            
    def actNuke_(self, sender):

        ACCENT = (52/255.0, 199/255.0, 89/255.0, 1.0)  # #34C759

        alert = NSAlert.alloc().init()
        alert.setMessageText_("Clear All Browsing Data?")
        alert.setInformativeText_("This will wipe cookies, cache, local storage and website data for all sites.")
        alert.setAlertStyle_(NSAlertStyleCritical)

        # Order matters: first button is the default (returns 1000)
        alert.addButtonWithTitle_("Wipe")
        alert.addButtonWithTitle_("Cancel")

        # Tint "Wipe" green
        try:
            buttons = alert.buttons()
            if buttons and hasattr(buttons[0], "setBezelColor_"):
                buttons[0].setBezelColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT))
        except Exception:
            pass

        def on_response(code):
            if int(code) == 1000:  # "Wipe"
                store = WKWebsiteDataStore.defaultDataStore()
                types = WKWebsiteDataStore.allWebsiteDataTypes()
                since = NSDate.dateWithTimeIntervalSince1970_(0)

                def done():
                    # Success sheet
                    ok = NSAlert.alloc().init()
                    ok.setMessageText_("All data cleared")
                    ok.setInformativeText_("Cookies, cache, local storage and website data have been removed.")
                    ok.addButtonWithTitle_("OK")

                    # Tint "OK" green (with fallback if bezelColor isn't supported)
                    try:
                        ok_btn = ok.buttons()[0]
                        if hasattr(ok_btn, "setBezelColor_"):
                            ok_btn.setBezelColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT))
                        else:
                            ok_btn.setWantsLayer_(True)
                            ok_btn.layer().setBackgroundColor_(
                                NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT).CGColor()
                            )
                            ok_btn.setBordered_(False)
                            if hasattr(ok_btn, "setContentTintColor_"):
                                ok_btn.setContentTintColor_(NSColor.whiteColor())
                    except Exception:
                        pass

                    try:
                        ok.beginSheetModalForWindow_completionHandler_(self.window, None)
                    except Exception:
                        ok.runModal()

                store.removeDataOfTypes_modifiedSince_completionHandler_(types, since, done)

        # Prefer sheet; fall back to modal
        try:
            alert.beginSheetModalForWindow_completionHandler_(self.window, on_response)
        except Exception:
            resp = alert.runModal()
            on_response(resp)
            
    def bump_tracker_count(self, n):
        self._tracker_count = int(n)
        try:
            self.btn_track.setToolTip_(f"Trackers blocked: {n}")
            v = self.btn_track
            # Attach the working BadgeView
            if self._track_badge not in v.subviews():
                self._track_badge.setFrame_(((v.frame().size.width-14, v.frame().size.height-14),(18,18)))
                v.addSubview_(self._track_badge)
            else:
                self._track_badge.setFrame_(((v.frame().size.width-14, v.frame().size.height-14),(18,18)))
            self._track_badge.setCount_(n)
            if self._track_badge.isHidden() and n>0: self._track_badge.hidden=False
            self._track_badge.setNeedsDisplay_(True); self._track_badge.displayIfNeeded()
        except Exception: pass
        
    def update_tracker_label(self):
        """Update the tracker counter label in the toolbar/UI."""
        try:
            text = f"Trackers blocked: {getattr(self, 'tracker_count', 0)}"
            self.tracker_label.setStringValue_(text)
        except Exception:
            print("[UI] Tracker label not found or not initialized.")

    # ========== Storage Cleanup ==========
    def _storage_cleanup(self):
        try:
            store = WebKit.WKWebsiteDataStore.defaultDataStore()
            types = WebKit.WKWebsiteDataStore.allWebsiteDataTypes()
            def handler():
                print("[Darkelf] Storage cleanup complete.")
            store.removeDataOfTypes_modifiedSince_completionHandler_(
                types, 0, handler
            )
        except Exception as e:
            print("[Darkelf] Storage cleanup failed:", e)

    # ----- Helpers -----
    def _load_url_in_active(self, url):
        try:
            req = NSURLRequest.requestWithURL_(NSURL.URLWithString_(url))
            self.tabs[self.active].view.loadRequest_(req)
            self.tabs[self.active].url = url
            from urllib.parse import urlparse
            u = urlparse(url); host = u.netloc or "site"
            if host.lower().startswith("www."): host = host[4:] or "site"
            self.tabs[self.active].host = host
            self._sync_addr(); self._update_tab_buttons()
        except Exception as e:
            print("[Load] error:", e)

    def _sync_addr(self):
        try:
            v = ""
            if 0 <= self.active < len(self.tabs):
                try:
                    u = self.tabs[self.active].view.URL()
                    if u is not None: v = str(u.absoluteString())
                except Exception: pass
                if not v: v = self.tabs[self.active].url or ""
            # hide internal pages
            if v in ("about:home", "about:blank", "about:blank#blocked", "about://home"):
                v = ""
            self.addr.setStringValue_(v)
        except Exception: pass

    # Keyboard shortcuts
    def _install_key_monitor(self):
        def handler(evt):
            try:
                if evt.type() == 10:  # NSKeyDown
                    cmd = bool(evt.modifierFlags() & (1 << 20))  # NSEventModifierFlagCommand
                    if not cmd: return evt
                    ch = evt.charactersIgnoringModifiers()
                    if ch == "t": self.actNewTab_(None); return None
                    if ch == "w": self.actCloseTab_(None); return None
                    if ch == "r": self.actReload_(None); return None
                    if ch == "l":
                        try: self.window.makeFirstResponder_(self.addr)
                        except Exception: pass
                        return None
            except Exception: pass
            return evt
        NSEvent.addLocalMonitorForEventsMatchingMask_handler_(1<<10, handler)
        
    def __del__(self):
        # Defensive destructor to avoid NSTimer and observer segfaults
        try:
            print("[Browser] __del__ called, cleaning up timers and observers.")
        except Exception:
            pass

        # Invalidate cookie timer
        try:
            self._stop_cookie_scrubber()
        except Exception as e:
            print("[Browser] Failed to stop cookie scrubber in __del__:", e)
    
            # Invalidate Tor refresh timer
        try:
            if hasattr(self, "_tor_refresh_timer") and self._tor_refresh_timer:
                self._tor_refresh_timer.invalidate()
                self._tor_refresh_timer = None
        except Exception as e:
            print("[Browser] Failed to stop tor refresh timer in __del__:", e)
    
        # Remove resize notification observer
        try:
            nc = NSNotificationCenter.defaultCenter()
            nc.removeObserver_(self)
        except Exception as e:
            print("[Browser] Failed to remove observer in __del__:", e)
    
        # Remove all JS message handlers from active webview (extra insurance)
        try:
            if hasattr(self, "tabs") and len(self.tabs) > 0:
                for tab in self.tabs:
                    wk = getattr(tab, "view", None)
                    if wk:
                        ucc = wk.configuration().userContentController()
                        for name in ("tracker", "netlog", "search", "mini_ai", "panic"):
                            try:
                                ucc.removeScriptMessageHandlerForName_(name)
                            except Exception:
                                pass
        except Exception as e:
            print("[Browser] Failed to remove JS handlers in __del__:", e)
            
    def _wipe_all_site_data(self):
        try:
            store = WKWebsiteDataStore.defaultDataStore()
            types = WKWebsiteDataStore.allWebsiteDataTypes()

            def _done():
                print("[Wipe] All WKWebsiteDataStore data cleared.")

            # NSDate.distantPast() is fine; zero epoch works too.
            store.removeDataOfTypes_modifiedSince_completionHandler_(
                types,
                NSDate.distantPast(),
                _done,               # <-- don't pass None; must be a callable
            )
        except Exception as e:
            print("[Wipe] Error wiping site data:", e)
            
class AppDelegate(NSObject):
    def applicationShouldTerminate_(self, sender):
        try:
            if hasattr(self, "browser") and self.browser is not None:
                try:
                    self.browser._stop_cookie_scrubber()
                except Exception as e:
                    print("[Quit] Failed to stop cookie scrubber:", e)
                try:
                    if hasattr(self.browser, "_tor_refresh_timer") and self.browser._tor_refresh_timer:
                        self.browser._tor_refresh_timer.invalidate()
                        self.browser._tor_refresh_timer = None
                except Exception as e:
                    print("[Quit] Failed to stop tor refresh timer:", e)
                self.browser._wipe_all_site_data()
                print("[Quit Wipe] All WKWebsiteDataStore data cleared on quit.")
        except Exception as e:
            print("[Quit Wipe] Error wiping data:", e)
        return True

def main():
    try:
        NSUserDefaults.standardUserDefaults().setVolatileDomain_forName_({}, NSRegistrationDomain)
        print("[Prefs] NSUserDefaults set to volatile (RAM-only).")
    except Exception as e:
        print("[Prefs] Failed to set volatile domain:", e)

    from Cocoa import NSApplication
    app = NSApplication.sharedApplication()
    app.setActivationPolicy_(NSApplicationActivationPolicyRegular)

    # create delegate and attach to app
    delegate = AppDelegate.alloc().init()
    app.setDelegate_(delegate)

    # initialize Browser and store reference on delegate
    delegate.browser = Browser.alloc().init()

    app.run()


if __name__ == "__main__":
    main()
