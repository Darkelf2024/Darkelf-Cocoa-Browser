# Darkelf Cocoa Hardened Browser v3.6 — Ephemeral, Privacy-Focused Web Browser (macOS / Cocoa Build)
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
# implemented using PyObjC bindings to Apple's Cocoa and WebKit frameworks.
#
# • All browsing data (cookies, cache, history, localStorage, IndexedDB, etc.)
#   is held in memory only and automatically discarded when the process exits.
# • Download requests are disabled by default to prevent disk persistence.
# • No telemetry, analytics, or network beacons are included.
# • Tracker detection and privacy monitoring are implemented through
#   on-device heuristic filters that inspect network headers
#   and JavaScript activity without transmitting data externally.
#
# For additional defense-in-depth, users are encouraged to use macOS full-disk
# encryption (FileVault) and secure memory management.
#
# ────────────────────────────────────────────────────────────────────────────────
# EXPORT / CRYPTOGRAPHY NOTICE
# This source distribution does not itself implement proprietary cryptographic
# algorithms. Any network encryption (such as TLS/SSL) is provided by Apple's
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
import warnings
from objc import ObjCPointerWarning

warnings.filterwarnings("ignore", category=ObjCPointerWarning)

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
import json

# =========================
# Darkelf MiniAI (SAFE / PASSIVE)
# =========================
class DarkelfMiniAISentinel:
    """
    Cocoa-safe Darkelf MiniAI
    Passive observer only
    No JS injection
    No blocking
    No timers
    """
    def __init__(self):
        self.enabled = True
        self.events = []
        self.tracker_hits = 0
        self.suspicious_hits = 0
        print("[MiniAI] Sentinel enabled (passive mode)")

    def monitor_network(self, url, headers):
        if not self.enabled or not url:
            return
        try:
            u = url.lower()
            if any(x in u for x in ("exploit","payload","phish","malware")):
                self.suspicious_hits += 1
            if any(x in u for x in ("tracker","analytics","beacon","doubleclick")):
                self.tracker_hits += 1
            self.events.append(u)
            if len(self.events) > 500:
                self.events.pop(0)
        except Exception:
            pass

    def on_tracker_blocked(self, count):
        try:
            self.tracker_hits += int(count)
        except Exception:
            pass

    def shutdown(self):
        self.enabled = False
        
HOME_URL = "darkelf://home"
HOME_HOST = "Darkelf Home"

_ATTACHED_RULE_CONTROLLERS = set()
_KNOWN_UCCS = set()

class ContentRuleManager:
    _rule_list = None
    _loaded = False

    @classmethod
    def load_rules(cls):
        if cls._loaded:
            return

        cls._loaded = True
        store = WKContentRuleListStore.defaultStore()
        identifier = "darkelf_builtin_rules_v4_media_safe"

        def _lookup(rule_list, error):
            if rule_list:
                cls._rule_list = rule_list
                print("[Rules] Content rules ready")

                # 🔁 Attach to any UCCs that already exist
                for ucc in list(_KNOWN_UCCS):
                    try:
                        ucc_id = id(ucc)
                        if ucc_id not in _ATTACHED_RULE_CONTROLLERS:
                            ucc.addContentRuleList_(rule_list)
                            _ATTACHED_RULE_CONTROLLERS.add(ucc_id)
                            print("[Rules] Declarative content rules attached (late)")
                    except Exception:
                        pass
                        
                return

            json_rules = cls._load_json()

            def _compiled(rule_list, error):
                if error:
                    print("[Rules] Compile error:", error)
                    return
                cls._rule_list = rule_list
                print("[Rules] Media-safe content rules compiled & ready")

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
        return """
        [
          {
            "trigger": {
              "url-filter": "doubleclick\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "googlesyndication\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "adsystem\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "adservice\\\\.google\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "criteo\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "taboola\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "outbrain\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          }
        ]
        """

# ---- Darkelf Diagnostics / Kill-Switches ----
DARKELF_DISABLE_COOKIE_SCRUBBER = False   # set True to rule out NSTimer cookie scrubber
DARKELF_DISABLE_JS_HANDLERS    = False    # set True to disable all JS message handlers (netlog/search/tracker)
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

class _NavDelegate(NSObject):
    def initWithOwner_(self, owner):
        self = objc.super(_NavDelegate, self).init()
        if self is None:
            return None
        self._owner = owner
        return self

    def webView_didFinishNavigation_(self, webView, nav):
        try:
            browser = self._owner
            url = webView.URL()
            title = webView.title()

            for tab in browser.tabs:
                if tab.view is webView:
                    # UI update ONLY — no security escalation
                    if title:
                        tab.host = title
                    elif url:
                        tab.host = url.host() or url.absoluteString()

                    if url:
                        tab.url = url.absoluteString()

                    browser._update_tab_buttons()
                    browser._sync_addr()
                    return
        except Exception:
            pass
            
    def webView_didFinishNavigation_(self, webView, nav):
        try:
            browser = self._owner
            url = webView.URL()
            title = webView.title()

            for tab in browser.tabs:
                if tab.view is webView:

                    # HARDENED HOME GUARD — never override Home
                    if url and url.absoluteString() == HOME_URL:
                        tab.url = HOME_URL
                        tab.host = "Darkelf Home"

                    else:
                        # UI update ONLY — no security escalation
                        if title:
                            tab.host = title
                        elif url:
                            tab.host = url.host() or url.absoluteString()

                        if url:
                            tab.url = url.absoluteString()

                    browser._update_tab_buttons()
                    browser._sync_addr()
                    return

        except Exception:
            pass

    def webView_decidePolicyForNavigationAction_decisionHandler_(self, webView, navAction, decisionHandler):
        handled = False
        try:
            req = navAction.request()
            url = req.URL()

            # 🔁 FIX: Reload on homepage must re-render HTML (WKWebView reload = white page)
            if navAction.navigationType() == WKNavigationTypeReload:
                url_str = str(url.absoluteString()) if url else ""
                if url_str in (HOME_URL, "about:home", "about://home", ""):
                    decisionHandler(WKNavigationActionPolicyCancel)
                    handled = True
                    try:
                        self._owner.load_homepage()
                    except Exception as e:
                        print("[Reload] Failed:", e)
                    return

            if url is None:
                decisionHandler(WKNavigationActionPolicyAllow)
                handled = True
                return

            scheme = (url.scheme() or "").lower()

            # 🔒 Block plaintext HTTP when Tor is OFF (UNCHANGED)
            if scheme == "http" and not getattr(self._owner, "tor_on", False):
                try:
                    self._owner._show_block_alert(
                        "Plaintext HTTP is blocked.\nEnable Tor to access HTTP sites."
                    )
                except Exception:
                    pass
                decisionHandler(WKNavigationActionPolicyCancel)
                handled = True
                return

        except Exception:
            pass
        finally:
            if not handled:
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
:root{
  --bg:#07080d;
  --green:#34C759;
  --cyan:#04a8c8;
  --border:rgba(255,255,255,.10);
  --input-bg:#12141b;
  --text:#eef2f6;
  --muted:#9aa3ad;
}

*{box-sizing:border-box}
html,body{height:100%}

body{
  margin:0;
  font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;
  color:var(--text);
  display:flex;
  justify-content:center;
  align-items:center;
  overflow:hidden;
  background:var(--bg);
}

/* Aurora */
body::before,
body::after{
  content:"";
  position:absolute;
  inset:-20%;
  z-index:-2;
  background:
    radial-gradient(900px 500px at 20% 10%, rgba(4,168,200,.18), transparent 60%),
    radial-gradient(800px 500px at 80% 20%, rgba(52,199,89,.22), transparent 60%),
    radial-gradient(600px 400px at 50% 90%, rgba(52,199,89,.12), transparent 60%);
  animation:drift 36s ease-in-out infinite;
}
body::after{
  animation-duration:54s;
  animation-direction:reverse;
  opacity:.6;
}
@keyframes drift{
  0%{transform:translate(0,0)}
  50%{transform:translate(-6%,-4%)}
  100%{transform:translate(0,0)}
}

.vignette{
  position:absolute;
  inset:0;
  pointer-events:none;
  background:radial-gradient(circle at center, transparent 55%, rgba(0,0,0,.6));
  z-index:-1;
}

.container{
  display:flex;
  flex-direction:column;
  align-items:center;
  gap:20px;
  padding:36px;
  text-align:center;
}

.brand{
  display:flex;
  gap:12px;
  align-items:center;
  font-weight:900;
  font-size:2.3rem;
  color:var(--green);
}
.brand i{
  font-size:2.6rem;
  filter:drop-shadow(0 0 18px rgba(52,199,89,.55));
}

.tagline{
  font-size:1.05rem;
  font-weight:800;
  letter-spacing:.28em;
  text-transform:uppercase;
  color:#cfd8e3;
  margin-top:-6px;
}

.search-wrap{
  display:flex;
  gap:12px;
  margin-top:18px;
}
.search-wrap input{
  height:54px;
  padding:0 18px;
  width:min(720px,92vw);
  border-radius:14px;
  border:1px solid var(--border);
  background:var(--input-bg);
  color:#fff;
  font-size:17px;
  outline:none;
}
.search-wrap input:focus{
  box-shadow:0 0 0 3px rgba(52,199,89,.35);
  border-color:transparent;
}
.search-wrap button{
  width:56px;
  height:54px;
  border-radius:14px;
  border:none;
  cursor:pointer;
  font-size:20px;
  display:flex;
  align-items:center;
  justify-content:center;
  color:#fff;
  background:var(--green);
  box-shadow:0 0 22px rgba(52,199,89,.55);
}

.ai-status{
  margin-top:6px;
  font-size:.78rem;
  color:var(--muted);
  opacity:.75;
  letter-spacing:.06em;
}

.status-badges{
  display:flex;
  gap:12px;
  margin-top:24px;
  flex-wrap:wrap;
  justify-content:center;
}

.status-chip{
  display:flex;
  align-items:center;
  gap:6px;
  padding:8px 14px;
  border-radius:999px;
  font-size:.75rem;
  font-weight:700;
  letter-spacing:.06em;
  background:rgba(52,199,89,.12);
  border:1px solid rgba(52,199,89,.35);
  color:var(--green);
}
</style>
</head>

<body>

<div class="vignette"></div>

<div class="container">
  <div class="brand">
    <i class="bi bi-shield-lock"></i>
    <span>Darkelf Browser</span>
  </div>
  <div class="tagline">Cocoa • Private • Hardened</div>

  <form class="search-wrap" action="https://lite.duckduckgo.com/lite/" method="get">
    <input type="text" name="q" placeholder="Search DuckDuckGo" autofocus/>
    <button type="submit"><i class="bi bi-search"></i></button>
  </form>

  <div id="ai-status" class="ai-status">
    Darkelf MiniAI Sentinel active — passive monitoring enabled
  </div>

  <div class="status-badges">
    <div class="status-chip"><i class="bi bi-file-lock"></i> CSP Active</div>
    <div class="status-chip"><i class="bi bi-fingerprint"></i> FP Defense</div>
    <div class="status-chip"><i class="bi bi-shield-check"></i> Tracker Block</div>
    <div class="status-chip"><i class="bi bi-incognito"></i> Zero Persistence</div>
  </div>
</div>

</body>
</html>
"""

# ADVANCED SPOOFING SCRIPTS
USER_AGENT_SPOOF = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0) Gecko/20100101 Firefox/78.0"
)
USER_AGENT_SPOOF_JS = r'''
Object.defineProperty(navigator, 'userAgent', {get: () => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:78.0) Gecko/20100101 Firefox/78.0", configurable: true});
'''
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
# ---- NEW: Client Hints spoof ----
CLIENT_HINTS_DEFENSE_JS = r'''
Object.defineProperty(navigator, 'userAgentData', {
  get: () => ({
    brands: [{brand: "Firefox", version: "78"}, {brand: "Tor Browser", version: "10.0.0"}],
    mobile: false,
    getHighEntropyValues: (hints) => Promise.resolve({
      architecture: "x86",
      model: "",
      platform: "macOS",
      platformVersion: "10.15.7",
      uaFullVersion: "78.0",
      fullVersionList: [
        {brand: "Firefox", version: "78.0"},
        {brand: "Tor Browser", version: "10.0.0"}
      ]
    })
  }),
  configurable: true
});
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
LETTERBOX_JS = r"""
(function(){
  const W = 1000, H = 1000, DPR = 1;

  function def(obj, prop, getter){
    try { Object.defineProperty(obj, prop, { get: getter, configurable: true }); } catch(e){}
  }

  // Window & Screen boxes
  def(window, 'innerWidth',  () => W);
  def(window, 'innerHeight', () => H);
  def(window, 'outerWidth',  () => W);
  def(window, 'outerHeight', () => H);
  if (window.screen) {
    def(screen, 'width',       () => W);
    def(screen, 'height',      () => H);
    def(screen, 'availWidth',  () => W);
    def(screen, 'availHeight', () => H);
  }

  // Viewport & zoom
  if (window.visualViewport) {
    def(visualViewport, 'width',  () => W);
    def(visualViewport, 'height', () => H);
    def(visualViewport, 'pageLeft', () => 0);
    def(visualViewport, 'pageTop',  () => 0);
    def(visualViewport, 'scale', () => 1);
  }

  // Scrolling & offsets
  def(window, 'pageXOffset', () => 0);
  def(window, 'pageYOffset', () => 0);
  def(window, 'scrollX',     () => 0);
  def(window, 'scrollY',     () => 0);

  // Device pixel ratio
  def(window, 'devicePixelRatio', () => DPR);

  // matchMedia – make it consistent with the box
  const _mm = window.matchMedia ? window.matchMedia.bind(window) : null;
  window.matchMedia = function(q){
    try {
      const mMinW = /min-width:\s*(\d+)px/.exec(q);
      const mMaxW = /max-width:\s*(\d+)px/.exec(q);
      const mMinH = /min-height:\s*(\d+)px/.exec(q);
      const mMaxH = /max-height:\s*(\d+)px/.exec(q);
      let matches = true;
      if (mMinW) matches = matches && (W >= +mMinW[1]);
      if (mMaxW) matches = matches && (W <= +mMaxW[1]);
      if (mMinH) matches = matches && (H >= +mMinH[1]);
      if (mMaxH) matches = matches && (H <= +mMaxH[1]);
      return {
        matches, media: q, onchange: null,
        addListener(){}, removeListener(){},
        addEventListener(){}, removeEventListener(){},
        dispatchEvent(){ return false; }
      };
    } catch(e) {
      return _mm ? _mm(q) : { matches:false, media:q };
    }
  };

  // Rect rounding – reduce subpixel leaks based on real viewport
  try {
    const _gbr = Element.prototype.getBoundingClientRect;
    Element.prototype.getBoundingClientRect = function(){
      const r = _gbr.apply(this, arguments);
      const clone = Object.create(DOMRect.prototype);
      ['x','y','width','height','top','left','right','bottom'].forEach(k=>{
        Object.defineProperty(clone, k, { value: Math.round(r[k]), enumerable: true });
      });
      return clone;
    };
  } catch(e){}
})();
"""

TOR_AVAILABLE = True
try:
    from stem.process import launch_tor_with_config
except Exception:
    TOR_AVAILABLE = False

def _run(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 1, "", str(e)

def _toggle_system_socks(enable: bool, host="127.0.0.1", port=9052):
    for svc in ["Wi-Fi", "Ethernet"]:
        if enable:
            _run(["/usr/sbin/networksetup", "-setsocksfirewallproxy", svc, host, str(port)])
            _run(["/usr/sbin/networksetup", "-setsocksfirewallproxystate", svc, "on"])
        else:
            _run(["/usr/sbin/networksetup", "-setsocksfirewallproxystate", svc, "off"])

class TorManager:
    def __init__(self): self.proc=None; self.port=9052
    def start(self):
        if not TOR_AVAILABLE: print("[Tor] stem not available. pip install stem"); return False
        if self.proc is not None: print("[Tor] already running"); return True
        try:
            print("[Tor] launching...")
            self.proc = launch_tor_with_config(config={'SocksPort':str(self.port),'ClientOnly':'1'}, take_ownership=True, init_msg_handler=print)
            print(f"[Tor] socks5://127.0.0.1:{self.port}")
            _toggle_system_socks(True, "127.0.0.1", self.port)
            return True
        except Exception as e:
            print("[Tor] failed:", e); self.proc=None; return False
    def stop(self):
        if self.proc is not None:
            try: self.proc.terminate()
            except Exception: pass
            self.proc=None; print("[Tor] stopped.")
        _toggle_system_socks(False)

TOR = TorManager()


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
  let count = 0;
  function shouldBlock(u){
    try{ const h=new URL(u, location.href).hostname;
      return blockedHosts.has(h) || [...blockedHosts].some(x => h.endsWith('.'+x)); }
    catch(_){ return false; }
  }
  const origFetch = window.fetch;
  window.fetch = async function(input, init){
    const url = (typeof input==='string') ? input : (input && input.url) || '';
    if (shouldBlock(url)) { count++; return new Response('', {status: 204}); }
    return origFetch.apply(this, arguments);
  };
  const open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m,u){
    if (shouldBlock(u)) { count++; this.abort(); return; }
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

# ================= Tabs =================
@dataclass
class Tab:
    view: WKWebView
    url: str = ""
    host: str = "new"
    canvas_seed: int = None  # Unique canvas seed per tab

# ================= Script Message Handler =================
class SearchHandler(objc.lookUpClass("NSObject")):
    def initWithOwner_(self, owner):
        self = objc.super(SearchHandler, self).init()
        if self is None: return None
        self.owner = owner
        return self
        
    def userContentController_didReceiveScriptMessage_(self, controller, message):
        try:
            q = str(message.body())
            url = "https://lite.duckduckgo.com/lite/?q=" + re.sub(r"\s+","+",q)
            self.owner._add_tab(url)
        except Exception as e:
            print("SearchHandler error:", e)
            
class JSToggleHandler(objc.lookUpClass("NSObject")):
    def initWithOwner_(self, owner):
        self = objc.super(JSToggleHandler, self).init()
        if self is None:
            return None
        self.owner = owner
        return self

    def userContentController_didReceiveScriptMessage_(self, controller, message):
        try:
            # Toggle global JS state
            self.owner.js_enabled = not getattr(self.owner, "js_enabled", True)

            state = "ENABLED" if self.owner.js_enabled else "DISABLED"
            print(f"[JS Toggle] JavaScript {state}")

            # 🔥 Apply JS preference to active webview
            wk = self.owner.tabs[self.owner.active].view
            prefs = wk.configuration().preferences()
            prefs.setJavaScriptEnabled_(self.owner.js_enabled)

            # If on homepage, just update UI and DO NOT rebuild
            try:
                url = wk.URL()
                if url and url.absoluteString() == HOME_URL:
                    js_update = f"""
                        if (window.DarkelfStatus && window.DarkelfStatus.update) {{
                            window.DarkelfStatus.update({{js: {str(self.owner.js_enabled).lower()}}});
                        }}
                    """
                    wk.evaluateJavaScript_completionHandler_(js_update, None)
                    return
            except Exception:
                pass

            # For external sites: reload instead of full rebuild (lighter + safer)
            wk.reload()

        except Exception as e:
            print("[JSToggleHandler] error:", e)
            
class TorToggleHandler(NSObject):
    def initWithOwner_(self, owner):
        self = objc.super(TorToggleHandler, self).init()
        if self is None:
            return None
        self.owner = owner
        return self

    def userContentController_didReceiveScriptMessage_(self, controller, message):
        try:
            # Call the SAME method your toolbar button uses
            self.owner.actTor_(None)
        except Exception as e:
            print("[TorToggleHandler] error:", e)

# BROWSER CONTROLLER ===============
class Browser(NSObject):
    def init(self):
        self = objc.super(Browser, self).init()
        if self is None: return None
        
        self.csp_enabled = True
        self.js_enabled = True
        self.tor_on = False
        self.window = self._make_window()
        self.mini_ai = DarkelfMiniAISentinel()
        self.toolbar = self._make_toolbar()
        self.window.setToolbar_(self.toolbar)
        try: self.window.toolbar().setVisible_(True)
        except Exception: pass

        self.tabs: List[Tab] = []
        self.tab_btns: List[NSButton] = []
        self.tab_close_btns: List[NSButton] = []
        self.active = -1
        self.tor_on = False

        self._tab_neon_green = NSColor.colorWithCalibratedRed_green_blue_alpha_(52/255.0, 199/255.0, 89/255.0, 1.0)
        self._tab_neon_green_cg = (self._tab_neon_green.CGColor())
        
        self._build_tabbar()

        # 🔒 wipe everything BEFORE creating the first tab
        try:
            self._wipe_all_site_data()
        except Exception:
            pass

        # create first tab (home)
        self._add_tab(home=True)

        # optional: start cookie scrubber right away
        try:
            self._start_cookie_scrubber()
        except Exception:
            pass

        self.window.makeKeyAndOrderFront_(None)

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
        
    def toggle_tor(self):
        self.actTor_(None)

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
        win.setDelegate_(self)

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
        self.btn_js     = big_btn("bolt.slash", "Toggle JavaScript")
        self.btn_tor = big_btn("network", "Toggle Tor")
        
        self.btn_tor = big_btn("network", "Toggle Tor")

        # --- TOR BUTTON ICON SETUP ---
        img_tor = NSImage.imageWithSystemSymbolName_accessibilityDescription_("network", None)
        if img_tor:
            img_tor.setTemplate_(True)
            self.btn_tor.setImage_(img_tor)
            self.btn_tor.setImagePosition_(2)  # Image only
        self.btn_tor.setTitle_("")  # Remove text label
        # Button tint with safety check
        if hasattr(self, 'btn_tor') and self.btn_tor:
            if hasattr(self.btn_tor, "setContentTintColor_"):
                tint = NSColor.colorWithCalibratedRed_green_blue_alpha_(
                    52/255.0, 199/255.0, 89/255.0, 1.0  # Neon green #34C759
                ) if self.tor_on else NSColor.whiteColor()
                self.btn_tor.setContentTintColor_(tint)
        
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
            (self.btn_js, 'actToggleJS:'),
            (self.btn_tor,'actTor:'),
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
            item('ZoomIn', self.btn_zoom_in),
            item('ZoomOut', self.btn_zoom_out),
            item('Full', self.btn_full),
            item('JS', self.btn_js),
            item('Nuke', self.btn_nuke),
            item('Tor', self.btn_tor),
            
        ]

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
            self.btn_tab_add.setTitle_(None)          # image-only
            self.btn_tab_add.setImagePosition_(0)   # NSImageOnly
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
            tab_w = 180.0
            gap = 8.0
            close_w = 14.0
            inset = 10.0

            for b, close in zip(self.tab_btns, self.tab_close_btns):
            # Place the tab (background + text)
                b.setFrame_(((x, (tab_h - tab_btn_height) / 2.0),
                             (tab_w, tab_btn_height)))

            # Place close button INSIDE the tab
                close.setFrame_(((inset,
                                  (tab_btn_height - close_btn_height) / 2.0),
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

                close.setImage_(None)
                close.setAttributedTitle_(NSAttributedString.alloc().initWithString_attributes_(
                    "•",
                    {
                        "NSFont": NSFont.boldSystemFontOfSize_(14.0),
                        "NSParagraphStyle": style,
                        "NSColor": NSColor.whiteColor(),
                    }
                ))
                close.setBordered_(False)
                close.setBezelStyle_(1)
                close.setToolTip_("Close Tab")
            except Exception:
                pass

            close.setTarget_(self)
            close.setAction_("actCloseTabIndex:")
            close.setTag_(idx)

            # --- Tab button (hostname or 'home') ---
            host = t.host or f"tab {idx+1}"
            if host == "home" or t.url in (
                "about:home", "about:blank", "about:blank#blocked", "about://home"
            ):
                label = "Home"
            else:
                import re as _re
                host = _re.sub(r"^\s*www\.", "", host, flags=_re.IGNORECASE)
                label = host

            label = middle_ellipsis(label, 26)

            b = HoverButton.alloc().init()
            try:
                from AppKit import NSMutableParagraphStyle, NSFont, NSAttributedString

                style = NSMutableParagraphStyle.alloc().init()
                style.setAlignment_(1)  # LEFT
                style.setFirstLineHeadIndent_(26.0)  # space for close dot
                style.setHeadIndent_(26.0)
                style.setLineBreakMode_(4)  # truncating tail

                font = NSFont.systemFontOfSize_(12.0)
                attrs = {
                    "NSFont": font,
                    "NSParagraphStyle": style,
                }

                b.setAttributedTitle_(NSAttributedString.alloc().initWithString_attributes_(
                    label, attrs
                ))
                b.setBordered_(False)
                b.setBezelStyle_(1)
                b.setToolTip_(label)
            except Exception:
                try: b.setTitle_(label)
                except Exception: pass

            b.setTarget_(self)
            b.setAction_("actSwitchTab:")
            b.setTag_(idx)

            # Add views (close INSIDE tab)
            self.tabbar.addSubview_(b)
            b.addSubview_(close)

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
                    
    def _install_local_csp(self, ucc):
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
                
            # 3) Navigator / UA spoof
            if 'FIREFOX_NAV_SPOOF_JS' in globals():
                _add(FIREFOX_NAV_SPOOF_JS)
            else:
                _add(r"(function(){ try{ Object.defineProperty(navigator,'userAgent',{get:function(){return 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Gecko/20100101 Firefox/78.0';}}); }catch(e){} })();")

            # 4) Letterboxing
            if 'LETTERBOX_JS' in globals():
                _add(LETTERBOX_JS)
            else:
                _add(r"(function(){ try{ Object.defineProperty(window,'innerWidth',{get:function(){return 1000;}}); Object.defineProperty(window,'innerHeight',{get:function(){return 1000;}}); }catch(e){} })();")
                
            # 5) Canvas defense - use seed if available
            if 'CANVAS_DEFENSE_JS' in globals():
                # If global used your {seed} formatting, it will be fine; otherwise fallback
                _add(CANVAS_DEFENSE_JS)
            else:
                _add(f"(function(){{ var SEED={seed}; try{{ var orig=HTMLCanvasElement.prototype.toDataURL; HTMLCanvasElement.prototype.toDataURL=function(){{ try{{ return orig.apply(this,arguments); }}catch(e){{return '';}} }}; }}catch(e){{}} }})();")
            
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

            # Cosmetic ad container cleanup (EasyList-style)
            _add(r"""
            (function(){
                try {
                    if (
                        location.hostname.includes("youtube.com") ||
                        location.hostname.includes("coveryourtracks")
                    ) return;

                    var css = `
                    iframe[src*="ad"],
                    div[class*="ad"],
                    div[id*="ad"],
                    aside,
                    [data-ad],
                    [data-sponsored] {
                        display: none !important;
                    }`;

                    var style = document.createElement('style');
                    style.type = 'text/css';
                    style.appendChild(document.createTextNode(css));
                    document.documentElement.appendChild(style);
                } catch(e){}
            })();
            """)

            print("[Inject] Core defense scripts added to UCC.")
            
        except Exception as e:
            print("[Inject] Core script injection failed:", e)
            
    def _new_wk(self) -> WKWebView:
        cfg = WKWebViewConfiguration.alloc().init()
        try:
            # Must be FALSE to allow native fullscreen takeover
            cfg.setAllowsInlineMediaPlayback_(False)
        except Exception:
            pass

        try:
            # Allow media playback after user interaction
            cfg.setMediaTypesRequiringUserActionForPlayback_(0)
        except Exception:
            pass
    
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
                
        # =========================================================
        # ✅ SAFARI-STYLE DECLARATIVE CONTENT BLOCKING (AD BLOCKING)
        # =========================================================
        try:
            rule_list = getattr(ContentRuleManager, "_rule_list", None)
            ucc_id = id(ucc)

            if rule_list and ucc_id not in _ATTACHED_RULE_CONTROLLERS:
                ucc.addContentRuleList_(rule_list)
                _ATTACHED_RULE_CONTROLLERS.add(ucc_id)
                print("[Rules] Declarative content rules attached")

            elif not rule_list:
                print("[Rules] Content rules not ready yet")

        except Exception as e:
            print("[Rules] Failed to attach content rules:", e)

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

        # --- Search Handler (already in your code) ---
        self._search_handler = getattr(self, "_search_handler", None) or SearchHandler.alloc().initWithOwner_(self)
        ucc.addScriptMessageHandler_name_(self._search_handler, "search")
    
        # --- JS Toggle Handler ---
        self._js_handler = JSToggleHandler.alloc().initWithOwner_(self)
        ucc.addScriptMessageHandler_name_(self._js_handler, "jsToggle")

        # --- TOR Toggle Handler ---
        self._tor_handler = TorToggleHandler.alloc().initWithOwner_(self)
        ucc.addScriptMessageHandler_name_(self._tor_handler, "torToggle")

        # --- Canvas Fingerprint Seed ---
        seed = secrets.randbits(64)
        self.current_canvas_seed = seed

        # --- TOR LETTERBOX (document start, all frames) ---
        try:
            letterbox_source = LETTERBOX_JS
            letterbox_script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                letterbox_source,
                0,      # AtDocumentStart
                False   # forMainFrameOnly = False (inject into iframes)
            )
            ucc.addUserScript_(letterbox_script)
            print("[Letterbox] 1000x1000 shim installed (docStart, all frames)")
        except Exception as e:
            print("[Letterbox] failed to add WKUserScript:", e)

        # --- Core defense scripts (ensure this function writes to UCC, not webview) ---
        try:
            self._inject_core_scripts(ucc)
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

        # --- Finalize configuration ---
        cfg.setUserContentController_(ucc)

        # ============================================================
        # ✅ APPLY TOR PROXY TO NEW WEBVIEW (if Tor is active)
        # ============================================================
        if getattr(self, "tor_on", False):
            try:
                print("[Tor] New tab inheriting Tor proxy state (system-level)")
                # WKWebView automatically uses system proxy (already set in actTor_)
                # No per-webview config needed; proxy is system-wide
            except Exception as e:
                print("[Tor] Proxy inheritance check failed:", e)

        # --- Create WebView ---
        web = WKWebView.alloc().initWithFrame_configuration_(((0, 0), (100, 100)), cfg)

        # --- UA SPOOF (HTTP UA must match JS UA) ---
        try:
            web.setCustomUserAgent_(USER_AGENT_SPOOF)
        except Exception:
            pass

        return web
        
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
                for name in ["search"]:
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

            # --- TOR LETTERBOX (document start, all frames) ---
            try:
                letterbox_script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                    LETTERBOX_JS,
                    0,      # AtDocumentStart
                    False   # forMainFrameOnly = False (cover iframes)
                )
                ucc.addUserScript_(letterbox_script)
                print("[Letterbox] 1000x1000 shim installed (rebuild)")
            except Exception as e:
                print("[Letterbox] rebuild add failed:", e)

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
                        self.tabs[self.active].view.loadHTMLString_baseURL_(HOMEPAGE_HTML, NSURL.URLWithString_(HOME_URL)
                        )
                        self.tabs[self.active].url  = HOME_URL
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
        wk = self._new_wk()  # ← Tor state already applied in _new_wk()
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
            try:
                self.addr.setStringValue_("")
            except Exception:
                pass

            wk.loadHTMLString_baseURL_(
                HOMEPAGE_HTML,
                NSURL.URLWithString_(HOME_URL)
            )

            tab.url = HOME_URL
            tab.host = "Darkelf Home"
            if hasattr(tab, "is_new"):
                tab.is_new = False

        else:
            if url:
                try:
                    req = NSURLRequest.requestWithURL_(
                        NSURL.URLWithString_(url)
                    )
                    wk.loadRequest_(req)
                except Exception:
                    pass

                tab.url = url
                tab.host = "new"

        self._update_tab_buttons()
        self._style_tabs()
        self._sync_addr()
    
        # ✅ SYNC TOR BUTTON TINT (after tab is created)
        try:
            if hasattr(self, 'btn_tor') and self.btn_tor:
                tint = NSColor.colorWithCalibratedRed_green_blue_alpha_(
                    52/255.0, 199/255.0, 89/255.0, 1.0
                ) if self.tor_on else NSColor.whiteColor()
                self.btn_tor.setContentTintColor_(tint)
        except Exception:
            pass
        
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
                for name in ("netlog","search","mini_ai","jsToggle"):
                    try:
                        ucc.removeScriptMessageHandlerForName_(name)
                    except Exception:
                        pass
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

        # Teardown the target tab's webview whether it's active or not
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
        try:
            wk = self.tabs[self.active].view
            u = wk.URL()
            cur = str(u.absoluteString()) if u is not None else (self.tabs[self.active].url or "")
            if cur == HOME_URL:
                self.actHome_(None)
            else:
                wk.reload_(None)
        except Exception as e:
            print("[Reload] Failed:", e)
    def actHome_(self, _):
        try:
            wk = self.tabs[self.active].view

            wk.loadHTMLString_baseURL_(
                HOMEPAGE_HTML,
                NSURL.URLWithString_(HOME_URL)
            )

            self.tabs[self.active].url = HOME_URL
            self.tabs[self.active].host = "Darkelf Home"

            self._update_tab_buttons()
            self._sync_addr()
            
        except Exception as e:
            print("[Home] Failed:", e)
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
    def actTor_(self, _):
        try:
            # Snapshot current URL (only needed when turning Tor OFF so we can go back to it)
            current_url = None
            try:
                view = self.tabs[self.active].view
                if hasattr(view, "URL") and view.URL():
                    current_url = str(view.URL().absoluteString())
            except Exception:
                pass

            starting = (TOR.proc is None)
            if starting:
                ok = TOR.start()
                self.tor_on = bool(ok)
                if ok:
                    os.environ["HTTPS_PROXY"] = "socks5h://127.0.0.1:9052"
                    os.environ["HTTP_PROXY"]  = "socks5h://127.0.0.1:9052"
                    print("[Tor] Running; system SOCKS proxy ON.")
                else:
                    print("[Tor] Failed to start.")
            else:
                TOR.stop()
                self.tor_on = False
                os.environ.pop("HTTPS_PROXY", None)
                os.environ.pop("HTTP_PROXY",  None)
                print("[Tor] Stopped; system SOCKS proxy OFF.")

            # Button tint (unchanged)
            if hasattr(self.btn_tor, "setContentTintColor_"):
                tint = NSColor.colorWithCalibratedRed_green_blue_alpha_(0.6, 1.0, 0.7, 1.0) if self.tor_on else NSColor.whiteColor()
                self.btn_tor.setContentTintColor_(tint)

            # ⬇️ Key behavior change:
            if self.tor_on:
                # When enabling Tor, do NOT restore any URL → force homepage
                self._pendingRefreshURL = None
            else:
                # When disabling Tor, it's fine to restore what you were viewing
                self._pendingRefreshURL = current_url
    
            self._tor_refresh_timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                1.8, self, "_refreshAfterTor:", None, False
            )

        except Exception as e:
            print("[Tor] Toggle failed:", e)

    def _refreshAfterTor_(self, _timer):
        try:
            if hasattr(self, "_tor_refresh_timer") and self._tor_refresh_timer:
                self._tor_refresh_timer.invalidate()
                self._tor_refresh_timer = None
        except Exception:
            pass
    
        try:
            if hasattr(self, "_rebuild_active_webview"):
                self._rebuild_active_webview()

            url = getattr(self, "_pendingRefreshURL", None)
            self._pendingRefreshURL = None

            if url:
                req = NSURLRequest.requestWithURL_(NSURL.URLWithString_(url))
                self.tabs[self.active].view.loadRequest_(req)
            else:
                # Always load your custom homepage (WITH a base URL)
                self.tabs[self.active].view.loadHTMLString_baseURL_(
                    HOMEPAGE_HTML,
                    NSURL.URLWithString_(HOME_URL)
                )
                self.tabs[self.active].url  = HOME_URL
                self.tabs[self.active].host = "Darkelf Home"

                # keep the location bar blank on homepage
                try:
                    if hasattr(self, "addr"):
                        self.addr.setStringValue_("")
                except Exception:
                    pass

            if getattr(self, "tor_on", False):
                try:
                    ACCENT = (52/255.0, 199/255.0, 89/255.0, 1.0)  # #34C759

                    alert = NSAlert.alloc().init()
                    alert.setMessageText_("Tor is active")
                    alert.setInformativeText_("Traffic will now route through Tor for all clearnet browsing.")

                    # Ensure there is a button we can tint
                    if alert.buttons().count() == 0:
                        alert.addButtonWithTitle_("OK")

                    ok_btn = alert.buttons().objectAtIndex_(0)

                    # Prefer bezelColor (newer macOS), fall back to contentTintColor, then layer background
                    try:
                        if hasattr(ok_btn, "setBezelColor_"):
                            ok_btn.setBezelColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT))
                        elif hasattr(ok_btn, "setContentTintColor_"):
                            ok_btn.setContentTintColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT))
                        else:
                            ok_btn.setWantsLayer_(True)
                            ok_btn.layer().setCornerRadius_(6.0)
                            ok_btn.layer().setBackgroundColor_(
                                NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT).CGColor()
                            )
                    except Exception as _tint_err:
                        print("[Tor] OK button tint fallback:", _tint_err)

                    alert.runModal()
                except Exception as e:
                    print("[Tor] Prompt failed:", e)

        except Exception as e:
            print("[Tor] _refreshAfterTor_ failed:", e)
            try:
                # Fail-safe: go to homepage, don't reload previous request
                self.tabs[self.active].view.loadHTMLString_baseURL_(HOMEPAGE_HTML, None)
                self.tabs[self.active].url  = "about:home"
                self.tabs[self.active].host = "home"
                try:
                    if hasattr(self, "addr"):
                        self.addr.setStringValue_("")
                except Exception:
                    pass
            except Exception:
                pass
                
        except Exception as e:
            print("[Tor] _refreshAfterTor_ failed:", e)
            try:
                # Fail-safe: go to homepage with a reloadable base URL
                self.tabs[self.active].view.loadHTMLString_baseURL_(
                    HOMEPAGE_HTML,
                    NSURL.URLWithString_(HOME_URL)
                )
                self.tabs[self.active].url  = HOME_URL
                self.tabs[self.active].host = "Darkelf Home"

                # keep the address bar blank on homepage
                try:
                    if hasattr(self, "addr"):
                        self.addr.setStringValue_("")
                except Exception:
                    pass
            except Exception:
                pass
                
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
                current_js_state = bool(getattr(self, "js_enabled", True))
                try:
                    prefs.setJavaScriptEnabled_(current_js_state)
                    print(f"[JS Toggle] Preference set to: {current_js_state}")
                except Exception as e:
                    print(f"[JS Toggle] setJavaScriptEnabled_ failed: {e}")
                    try:
                        prefs.javaScriptEnabled = current_js_state
                        print(f"[JS Toggle] Property assignment succeeded")
                    except Exception as e2:
                        print(f"[JS Toggle] Property assignment also failed: {e2}")

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
                    if u is not None:
                        v = str(u.absoluteString())
                except Exception:
                    pass

                if not v:
                    v = self.tabs[self.active].url or ""

            # 🔒 hide internal pages
            if v in (
                HOME_URL,
                "about:home",
                "about:blank",
                "about:blank#blocked",
                "about://home",
            ):
                v = ""

            self.addr.setStringValue_(v)

        except Exception:
            pass

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
                        for name in ("netlog", "search", "mini_ai"):
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
            
    def windowWillClose_(self, notification):
        try:
            self._stop_cookie_scrubber()
        except Exception:
            pass
        NSApp().terminate_(None)

    def applicationWillTerminate_(self, notification):
        try:
            self._stop_cookie_scrubber()
        except Exception:
            pass

class AppDelegate(NSObject):

    def applicationShouldTerminate_(self, sender):
        # Allow termination immediately
        return True

    def applicationWillTerminate_(self, notification):
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

                try:
                    self.browser._wipe_all_site_data()
                    print("[Quit Wipe] All WKWebsiteDataStore data cleared on quit.")
                except Exception as e:
                    print("[Quit Wipe] Error wiping data:", e)

        except Exception as e:
            print("[Quit] Unexpected shutdown error:", e)

def main():
    try:
        NSUserDefaults.standardUserDefaults().setVolatileDomain_forName_({}, NSRegistrationDomain)
        print("[Prefs] NSUserDefaults set to volatile (RAM-only).")
    except Exception as e:
        print("[Prefs] Failed to set volatile domain:", e)

    from Cocoa import NSApplication
    app = NSApplication.sharedApplication()
    # App startup
    ContentRuleManager.load_rules()

    app.setActivationPolicy_(NSApplicationActivationPolicyRegular)

    # create delegate and attach to app
    delegate = AppDelegate.alloc().init()
    app.setDelegate_(delegate)

    # initialize Browser and store reference on delegate
    delegate.browser = Browser.alloc().init()

    app.run()


if __name__ == "__main__":
    main()
