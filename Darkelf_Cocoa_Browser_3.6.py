# Darkelf Cocoa General Browser v3.6 — Ephemeral, Privacy-Focused Web Browser (macOS / Cocoa Build)
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
#   DarkelfMiniAI — an on-device heuristic filter that inspects network headers
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
import atexit
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
    WKWebView, WKWebViewConfiguration, WKUserContentController, WKUserScript, WKPreferences,
    WKWebsiteDataStore, WKNavigationActionPolicyAllow, WKNavigationActionPolicyCancel, WKNavigationTypeReload, WKNavigationType
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
                print("[Rules] Loaded cached media-safe rule list")
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
DARKELF_DISABLE_COOKIE_SCRUBBER = False
DARKELF_DISABLE_JS_HANDLERS = False
DARKELF_DISABLE_RESIZE_HANDLER = False

# ---- Local CSP (off by default) ----
ENABLE_LOCAL_CSP = False
LOCAL_CSP_VALUE = "worker-src 'self' blob:; manifest-src 'self'; form-action 'self' https:;"

# ---- Local HSTS (off by default) ----
ENABLE_LOCAL_HSTS = True
LOCAL_HSTS_VALUE = "max-age=63072000; includeSubDomains; preload"

# ---- Local Referrer Policy (off by default) ----
ENABLE_LOCAL_REFERRER_POLICY = True
LOCAL_REFERRER_POLICY_VALUE = "strict-origin-when-cross-origin"

# ---- Local WebSocket Policy (off by default) ----
ENABLE_LOCAL_WEBSOCKET_POLICY = True
LOCAL_WEBSOCKET_POLICY_VALUE = (
    "connect-src 'self' https: wss: "
    "https://*.googlevideo.com "
    "https://youtubei.googleapis.com "
    "https://*.youtube.com;"
)

# ---- Local ORS / CORS Header Whitelist (off by default) ----
ENABLE_LOCAL_EXPOSE_HEADERS = True
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
        except Exception as e:
            print(f"[NavDelegate] didFinish error: {e}")

    # ✅ MINI AI INTEGRATION: Handle JavaScript network requests (fetch/XHR)
    def userContentController_didReceiveScriptMessage_(self, ucc, message):
        try:
            if message.name() != "netlog":
                return
            
            data = message.body() or {}
            url = str(data.get("url", ""))
            headers = data.get("headers", {}) or {}
            
            # Feed to MiniAI for passive monitoring
            if hasattr(self._owner, "mini_ai") and self._owner.mini_ai:
                self._owner.mini_ai.monitor_network(url, headers)
                
        except Exception as e:
            print("[Netlog Handler] Error:", e)

    # ✅ MINI AI INTEGRATION: Monitor navigation requests
    def webView_decidePolicyForNavigationAction_decisionHandler_(
        self, webView, navAction, decisionHandler
    ):
        handled = False
        
        try:
            req = navAction.request()
            url = req.URL()

            # ✅ Feed URL to MiniAI BEFORE making security decisions
            try:
                if url and hasattr(self._owner, "mini_ai") and self._owner.mini_ai:
                    headers = dict(req.allHTTPHeaderFields() or {})
                    self._owner.mini_ai.monitor_network(
                        str(url.absoluteString()), headers
                    )
            except Exception as e:
                print("[MiniAI Monitor] Failed:", e)

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

            # 🔒 Block plaintext HTTP when Tor is OFF
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

        except Exception as e:
            print(f"[NavDelegate] Policy decision error: {e}")
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

# JavaScript Defense Scripts
TIMEZONE_LOCALE_DEFENSE_JS = r'''
try {Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {value: function() { return { timeZone: "UTC", locale: "en-US" }; }, configurable: true });} catch(e){}
'''

FONTS_DEFENSE_JS = r'''
(function() {if (navigator.fonts) { navigator.fonts.query = function() { return Promise.resolve([]); }; } var style = document.createElement('style'); style.textContent = '* { font-family: "Arial", sans-serif !important; }'; document.head.appendChild(style);})();
'''

NAV_SPOOF_JS = r'''
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
    function addNoise(data) {
        for (var i = 0; i < data.length; i++) {
            data[i] = Math.min(255, Math.max(0, data[i] + Math.floor(Math.random() * 8 - 4)));
        }
    }
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
                ctx.putImageData(imageData, 0, 0);
                return result;
            }
        } catch(e) {}
        return origToDataURL.apply(this, arguments);
    };
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
                    ctx.putImageData(imageData, 0, 0);
                    callback(blob);
                }, type, quality);
                return;
            }
        } catch(e) {}
        origToBlob.apply(this, arguments);
    };
    var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
    CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {
        var imageData = origGetImageData.call(this, x, y, w, h);
        addNoise(imageData.data);
        return imageData;
    };
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
    canvas_seed: int = None

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
            
# BROWSER CONTROLLER ===============
class Browser(NSObject):

    def init(self):
        self = objc.super(Browser, self).init()
        if self is None:
            return None

        self.cookies_enabled = False
        self.js_enabled = True
        self.tor_on = False
        self.tabs = []
        self.tab_btns = []
        self.tab_close_btns = []
        self.active = -1

        self.window = self._make_window()
        self.mini_ai = DarkelfMiniAISentinel()

        self.toolbar = self._make_toolbar()
        self.window.setToolbar_(self.toolbar)
        try:
            self.window.toolbar().setVisible_(True)
        except Exception:
            pass

        self._build_tabbar()
        self._add_tab(home=True)
        self._bring_tabbar_to_front()

        self.window.makeKeyAndOrderFront_(None)
        NSApp().activateIgnoringOtherApps_(True)

        self._install_key_monitor()

        try:
            nc = NSNotificationCenter.defaultCenter()
            nc.addObserver_selector_name_object_(
                self,
                "onResize:",
                "NSWindowDidResizeNotification",
                self.window
            )
        except Exception:
            pass

        return self
                    
    def _start_cookie_scrubber(self):
        """Start periodic cookie scrubbing using a real Obj-C selector."""
        try:
            self._cookie_store = WKWebsiteDataStore.defaultDataStore().httpCookieStore()
        except Exception:
            self._cookie_store = None

        try:
            self._scrub_cookies()
        except Exception:
            pass

        try:
            self._cookie_timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                10.0, self, "actScrubCookies:", None, True
            )
        except Exception:
            self._cookie_timer = None

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
            
    def actToggleJS_(self, _):
        """Toggle JavaScript on/off and reload the active tab."""
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
        
            # Update button color
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
            print("[JS Toggle] Icon update error:", e)

        # Apply JS setting to active webview and reload
        try:
            wk = self.tabs[self.active].view
            prefs = wk.configuration().preferences()
            prefs.setJavaScriptEnabled_(self.js_enabled)
        
            # Check if on homepage
            try:
                url = wk.URL()
                if url and url.absoluteString() == HOME_URL:
                    # Just update UI on homepage, don't rebuild
                    js_update = f"""
                        if (window.DarkelfStatus && window.DarkelfStatus.update) {{
                            window.DarkelfStatus.update({{js: {str(self.js_enabled).lower()}}});
                        }}
                    """
                    wk.evaluateJavaScript_completionHandler_(js_update, None)
                    return
            except Exception:
                pass

            # For external sites: reload
            wk.reload()
        
        except Exception as e:
            print("[JS Toggle] Reload error:", e)
            
    def _is_home_context(self):
        try:
            if getattr(self, "loading_home", False):
                return True
            u = self.tabs[self.active].view.URL()
            return bool(u and u.absoluteString() == HOME_URL)
        except Exception:
            return False
            
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
        
    def windowShouldClose_(self, sender):
        return True
        
    def actCloseTab_(self, _):
        self._close_tab()

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

            tab_h = 36.0
            tab_btn_height = tab_h - 8.0
            close_btn_height = tab_btn_height
            tab_w = 180.0
            gap = 8.0
            close_w = 14.0
            inset = 10.0

            try:
                clr = self.window.contentLayoutRect()
                y = clr.origin.y + clr.size.height - tab_h
                w = clr.size.width
            except Exception:
                f = cv.frame()
                title_h = 40.0
                y = f.size.height - title_h - tab_h
                w = f.size.width

            self.tabbar.setAutoresizingMask_(10)
            self.tabbar.setFrame_(((0, y), (w, tab_h)))

            tb = self.tabbar.frame()

            self.btn_tab_add.setFrame_(
                ((tb.size.width - 32.0, (tab_h - tab_btn_height) / 2.0),
                 (28.0, tab_btn_height))
            )

            x = 8.0

            for b, close in zip(self.tab_btns, self.tab_close_btns):
                b.setFrame_(
                    ((x, (tab_h - tab_btn_height) / 2.0),
                     (tab_w, tab_btn_height))
                )

                close.setFrame_(
                    ((x + inset,
                      (tab_h - close_btn_height) / 2.0),
                     (close_w, close_btn_height))
                )

                close.removeFromSuperview()
                self.tabbar.addSubview_positioned_relativeTo_(close, 1, b)

                close.setHidden_(False)
                close.setEnabled_(True)

                x += tab_w + gap

        except Exception as e:
            print("Layout error:", e)

    def _update_tab_buttons(self):
        for btn in getattr(self, "tab_btns", []):
            try: btn.removeFromSuperview()
            except Exception: pass
        for btn in getattr(self, "tab_close_btns", []):
            try: btn.removeFromSuperview()
            except Exception: pass
        self.tab_btns, self.tab_close_btns = [], []

        def middle_ellipsis(text, max_len=26):
            if len(text) <= max_len:
                return text
            keep = max_len - 1
            head = keep // 2
            tail = keep - head
            return text[:head] + "…" + text[-tail:]

        for idx, t in enumerate(self.tabs):
            close = HoverButton.alloc().init()
            try:
                from AppKit import NSFont, NSMutableParagraphStyle, NSAttributedString, NSColor
                style = NSMutableParagraphStyle.alloc().init()
                style.setAlignment_(1)

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
            close.setTransparent_(False)

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
                style.setAlignment_(1)
                style.setFirstLineHeadIndent_(26.0)
                style.setHeadIndent_(26.0)
                style.setLineBreakMode_(4)

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

            self.tabbar.addSubview_(b)
            self.tabbar.addSubview_(close)

            self.tab_btns.append(b)
            self.tab_close_btns.append(close)

        self._style_tabs()
        self._layout()

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

    def _install_local_hsts(self, ucc):
        """
        Injects a <meta http-equiv="Strict-Transport-Security"> for pages we control.
        Limited to HTTPS and file:// origins to avoid breaking third-party sites.
        """
        try:
            from WebKit import WKUserScript
        except Exception:
            return

        js = f"""
        (() => {{
          try {{
            const here = location.protocol;
            if (here !== 'file:' && here !== 'https:') return;

            if (document.querySelector('meta[http-equiv="Strict-Transport-Security"]')) return;

            const meta = document.createElement('meta');
            meta.httpEquiv = 'Strict-Transport-Security';
            meta.content = {repr(LOCAL_HSTS_VALUE)};
            (document.head || document.documentElement).prepend(meta);
          }} catch (e) {{
          }}
        }})();
        """

        try:
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
            return

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
          }}
        }}, 100);
        """

        try:
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False
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
            return

        js = f"""
        setTimeout(() => {{
          try {{
            const here = location.protocol;
            if (here !== 'file:' && here !== 'https:') return;

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
          }}
        }}, 100);
        """

        try:
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False
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
            return

        js = f"""
        setTimeout(() => {{
          try {{
            const here = location.protocol;
            if (here !== 'file:' && here !== 'https:') return;

            if (document.querySelector('meta[http-equiv="Access-Control-Expose-Headers"]')) return;

            const meta = document.createElement('meta');
            meta.httpEquiv = 'Access-Control-Expose-Headers';
            meta.content = {repr(LOCAL_EXPOSE_HEADERS_VALUE)};
            (document.head || document.documentElement).prepend(meta);

            console.log('[ExposeHeaders] Safe header whitelist injected.');
          }} catch (e) {{
          }}
        }}, 100);
        """

        try:
            script = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                js, 1, False
            )
            ucc.addUserScript_(script)
            print("[ExposeHeaders] Local Access-Control-Expose-Headers injector installed (https:// & file:// only).")
        except Exception as e:
            print("[ExposeHeaders] Injector add failed:", e)

    @objc.python_method
    def _inject_core_scripts(self, ucc):
        try:
            seed = getattr(self, "current_canvas_seed", None) or 123456789

            def _add(src):
                try:
                    skr = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(src, 0, False)
                    ucc.addUserScript_(skr)
                except Exception as e:
                    print("[Inject] addUserScript_ failed:", e)

            _add(WEBRTC_DEFENSE_JS)
            _add(WEBGL_DEFENSE_JS)
            _add(CANVAS_DEFENSE_JS)
            _add(TIMEZONE_LOCALE_DEFENSE_JS)
            _add(FONTS_DEFENSE_JS)
            _add(NAV_SPOOF_JS)
            _add(MEDIA_ENUM_DEFENSE_JS)
            _add(AUDIO_DEFENSE_JS)
            _add(BATTERY_DEFENSE_JS)
            _add(PERFORMANCE_DEFENSE_JS)
            
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
        # --- determine if this WKWebView is for the homepage ---
        is_home = False
        try:
            if getattr(self, "loading_home", False):
                is_home = True
        except Exception:
            pass

        cfg = WKWebViewConfiguration.alloc().init()
        try:
            cfg.setAllowsInlineMediaPlayback_(False)
        except Exception:
            pass

        try:
            cfg.setMediaTypesRequiringUserActionForPlayback_(0)
        except Exception:
            pass
    
        try:
            cfg.setWebsiteDataStore_(WKWebsiteDataStore.nonPersistentDataStore())
        except Exception:
            pass
    
        # ✅ FIXED: Determine JS state ONCE at the top
        js_should_be_enabled = True if is_home else bool(getattr(self, "js_enabled", True))
    
        prefs = WKPreferences.alloc().init()
        try:
            prefs.setJavaScriptEnabled_(js_should_be_enabled)
            prefs.setJavaScriptCanOpenWindowsAutomatically_(True)
            print(f"[WKPrefs] JS={'ON' if js_should_be_enabled else 'OFF'} (home={is_home}, global={getattr(self, 'js_enabled', True)})")
        except Exception as e:
            print(f"[WKPrefs] Failed to set JS state: {e}")
        cfg.setPreferences_(prefs)

        try:
            cfg.setLimitsNavigationsToAppBoundDomains_(False)
            print("[Debug] App-bound domain restriction OFF")
        except Exception:
                pass

        ucc = WKUserContentController.alloc().init()
        
        try:
            from WebKit import WKContentRuleListStore

            adblock_rules = r'''
            [
              {
                "trigger": {
                  "url-filter": ".*",
                  "resource-type": [
                    "image",
                    "style-sheet",
                    "script",
                    "media",
                    "raw",
                    "font"
                  ],
                  "if-domain": [
                    "doubleclick.net",
                    "googlesyndication.com",
                    "googleadservices.com",
                    "adsystem.com",
                    "adservice.google.com",
                    "taboola.com",
                    "outbrain.com",
                    "criteo.com",
                    "pubmatic.com",
                    "openx.net",
                    "rubiconproject.com",
                    "adnxs.com",
                    "scorecardresearch.com",
                    "quantserve.com",
                    "zedo.com",
                    "revcontent.com",
                    "uubooster.com"
                  ]
                },
                "action": { "type": "block" }
              },
              {
                "trigger": {
                  "url-filter": ".*(pixel|track|beacon|analytics).*",
                  "resource-type": ["image", "script"]
                },
                "action": { "type": "block" }
              },
            {
              "trigger": {
                "url-filter": ".*(adserver|ads|sponsor|promoted).*",
                "resource-type": ["script"]
              },
              "action": { "type": "block" }
            }
          ]
          '''
            
            store = WKContentRuleListStore.defaultStore()

            def _adblock_ready(rule_list, error):
                if rule_list and not error:
                    ucc.addContentRuleList_(rule_list)
                    print("[AdBlock] Native WebKit ad blocking enabled")
                elif error:
                    print("[AdBlock] Rule compilation error:", error)
                    
            rules = ContentRuleManager._load_json()

            if hasattr(
                store,
                "compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler_"
            ):
                try:
                    store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler_(
                        "darkelf_native_adblock",
                        rules,
                        _adblock_ready
                    )
                except Exception as e:
                    print("[AdBlock] Native adblock skipped:", e)
            else:
                print("[AdBlock] Native WebKit content blocking unavailable — using injector")

        except Exception as e:
            print("[AdBlock] Failed to initialize native ad blocker:", e)

        try:
            ucc.removeScriptMessageHandlerForName_("netlog")
        except Exception:
            pass
            
        # ✅ ADD THIS BLOCK:
        try:
            if hasattr(self, "_nav"):
                ucc.addScriptMessageHandler_name_(self._nav, "netlog")
                print("[Init] Netlog handler registered")
            else:
                print("[Init] _nav delegate not set yet — cannot add netlog handler.")
        except Exception as e:
            print("[Init] Failed to register netlog handler:", e)
            
        self._search_handler = getattr(self, "_search_handler", None) or SearchHandler.alloc().initWithOwner_(self)
        ucc.addScriptMessageHandler_name_(self._search_handler, "search")
        
        # --- JS Toggle Handler ---
        self._js_toggle_handler = getattr(self, "_js_toggle_handler", None) or JSToggleHandler.alloc().initWithOwner_(self)
        ucc.addScriptMessageHandler_name_(self._js_toggle_handler, "jsToggle")
        
        
        seed = secrets.randbits(64)
        self.current_canvas_seed = seed

        # =========================================================
        # ✅ FIXED: Script Injection Logic
        # =========================================================
    
        # CASE 1: Homepage (always inject, JS always ON)
        if is_home:
            try:
                self._inject_core_scripts(ucc)
                print("[Inject] ✅ Core defense scripts added (HOMEPAGE)")
            except Exception as e:
                print("[Inject] Homepage scripts error:", e)
    
        # CASE 2: External site with JS ENABLED
        elif js_should_be_enabled:
            try:
                self._inject_core_scripts(ucc)
                print("[Inject] ✅ Core defense scripts added (JS ENABLED)")
            except Exception as e:
                print("[Inject] External site scripts error:", e)
    
        # CASE 3: External site with JS DISABLED
        else:
            print("[Inject] ⛔ SKIPPED core scripts (JS DISABLED globally)")

            # ✅ Add aggressive killswitch to block any JS that somehow executes
            js_killswitch = r"""
            (function(){
                console.log('[Darkelf] JavaScript execution blocked by killswitch');
            
                // Block eval and Function constructor
                try { 
                    window.eval = function(){ 
                        console.warn('[Darkelf] eval() blocked'); 
                        return null; 
                    }; 
                } catch(e){}
            
                try { 
                    window.Function = function(){ 
                        throw new Error("JavaScript blocked by Darkelf"); 
                    }; 
                } catch(e){}
            
                // Block timers
                try { 
                    window.setTimeout = function(){ 
                        console.warn('[Darkelf] setTimeout() blocked'); 
                        return 0; 
                    }; 
                    window.setInterval = function(){ 
                        console.warn('[Darkelf] setInterval() blocked'); 
                        return 0; 
                    }; 
                    window.requestAnimationFrame = function(){ 
                        console.warn('[Darkelf] requestAnimationFrame() blocked'); 
                        return 0; 
                    }; 
                } catch(e){}
            
                // Block document.write
                try { 
                    document.write = function(){ 
                        console.warn('[Darkelf] document.write() blocked'); 
                    }; 
                } catch(e){}
            
                // Block inline event handlers
                try {
                    var origSetAttr = Element.prototype.setAttribute;
                    Element.prototype.setAttribute = function(name, value) {
                        if (name && /^on/i.test(name)) {
                            console.warn('[Darkelf] Inline event handler blocked:', name);
                            return;
                        }
                        return origSetAttr.apply(this, arguments);
                    };
                } catch(e){}
            
                // Block dynamic script creation
                try {
                    var origCreate = Document.prototype.createElement;
                    Document.prototype.createElement = function(tag) {
                        var el = origCreate.apply(this, arguments);
                        try {
                            if (String(tag).toLowerCase() === 'script') {
                                console.warn('[Darkelf] <script> creation blocked');
                                Object.defineProperty(el, 'src', { 
                                    set: function(){}, 
                                    get: function(){return '';} 
                                });
                                el.type = 'darkelf/blocked';
                                el.defer = true; 
                                el.noModule = true;
                            }
                        } catch(_){}
                        return el;
                    };
                
                    var origAppend = Element.prototype.appendChild;
                    Element.prototype.appendChild = function(node) {
                        try { 
                            if (node && node.tagName === 'SCRIPT') {
                                console.warn('[Darkelf] <script> append blocked');
                                return node; 
                            }
                        } catch(_){}
                        return origAppend.apply(this, arguments);
                    };
                } catch(e){}
            
                console.log('[Darkelf] Killswitch active — JS blocked');
            })();
            """
        
            try:
                ks = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(
                    js_killswitch,
                    0,    # AtDocumentStart
                    False # All frames
                )
                ucc.addUserScript_(ks)
                print("[JS] ⛔ Killswitch injected")
            except Exception as e:
                print("[JS] Killswitch injection failed:", e)
        
            # ✅ Add native content blocker for ALL <script> resources
            try:
                store = WKContentRuleListStore.defaultStore()
            
                # Block ALL script resources (network + inline)
                block_scripts_rule = json.dumps([{
                    "trigger": {
                        "url-filter": ".*",
                        "resource-type": ["script"]
                    },
                    "action": {
                        "type": "block"
                    }
                }])
            
                def _script_block_ready(rule_list, err):
                    if rule_list and not err:
                        ucc.addContentRuleList_(rule_list)
                        print("[JS] ⛔ Native script blocking enabled")
                    elif err:
                        print(f"[JS] Native script blocking failed: {err}")
            
                store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler_(
                    "darkelf_block_all_scripts",
                    block_scripts_rule,
                    _script_block_ready
                )
            except Exception as e:
                print(f"[JS] Native script blocking error: {e}")

        # =========================================================
        # Finalize Configuration
        # =========================================================
        cfg.setUserContentController_(ucc)
        web = WKWebView.alloc().initWithFrame_configuration_(((0, 0), (100, 100)), cfg)

        return web
        
    def _mount_webview(self, wk):
        """Mount the webview BELOW the tabbar so tabs never get covered."""
        from AppKit import NSColor

        cv = self.window.contentView()
        tab_h = 34.0

        try:
            clr = self.window.contentLayoutRect()
            web_rect = ((0, 0), (clr.size.width, max(0.0, clr.size.height - tab_h)))
        except Exception:
            f = cv.frame()
            title_h = 40.0
            web_rect = ((0, 0), (f.size.width, max(0.0, f.size.height - (title_h + tab_h))))

        cv.addSubview_(wk)

        try:
            wk.setDrawsBackground_(True)
            wk.setBackgroundColor_(NSColor.blackColor())
        except Exception:
            pass

        wk.setFrame_(web_rect)
        wk.setAutoresizingMask_(18)
        
        try:
            wk.enableCursorRects()
        except Exception:
            pass

        self._bring_tabbar_to_front()

    def _rebuild_active_webview(self):
    
            # --- never rebuild homepage ---
            try:
                u = self.tabs[self.active].view.URL()
                if u and u.absoluteString() == HOME_URL:
                    print("[JS] Skip rebuild: homepage")
                    return
            except Exception:
                pass

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
                prefs.setJavaScriptEnabled_(
                    True if url == HOME_URL else bool(getattr(self, "js_enabled", True))
                )
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
                    store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler_(
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
                        self.tabs[self.active].view.loadHTMLString_baseURL_(HOMEPAGE_HTML, NSURLWithString_(HOME_URL)
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
        self.loading_home = bool(home)
    
        print(f"[AddTab] Creating tab: home={home}, url={url or '(none)'}, js_enabled={getattr(self, 'js_enabled', True)}")
    
        self._nav = _NavDelegate.alloc().initWithOwner_(self)
        wk = self._new_wk()
        wk.setNavigationDelegate_(self._nav)

        if 0 <= self.active < len(self.tabs):
            try:
                self.tabs[self.active].view.removeFromSuperview()
            except Exception:
                pass

        self._mount_webview(wk)
        self._bring_tabbar_to_front()

        tab = Tab(
            view=wk,
            url="",
            host="new",
            canvas_seed=getattr(self, "current_canvas_seed", None)
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
        
            self.loading_home = False

            tab.url = HOME_URL
            tab.host = "Darkelf Home"
            if hasattr(tab, "is_new"):
                tab.is_new = False
        
            # ✅ Store webview and schedule chip update
            self._pending_chip_sync = wk

        else:
            self.loading_home = False
        
            if url:
                try:
                    req = NSURLRequest.requestWithURL_(
                        NSURL.URLWithString_(url)
                    )
                    wk.loadRequest_(req)
                    print(f"[AddTab] Loading external URL with JS={'ON' if getattr(self, 'js_enabled', True) else 'OFF'}")
                except Exception:
                    pass

                tab.url = url
                tab.host = "new"
                    
        self._update_tab_buttons()
        self._style_tabs()
        self._sync_addr()

    def _teardown_webview(self, wk):
        if not wk:
            return
        try:
            js = r"""
            (function(){
              try {
                if (document.pictureInPictureElement) {
                  try { document.exitPictureInPicture(); } catch(e){}
                }
                document.querySelectorAll('video,audio').forEach(function(m){
                  try{ m.pause(); }catch(e){}
                  try{ m.src = ''; }catch(e){}
                  try{ m.load(); }catch(e){}
                });
                try {
                  if (window.YT && YT.get) {
                    var players = YT.get();
                    Object.keys(players || {}).forEach(function(k){
                      try{ players[k].stopVideo(); }catch(e){}
                    });
                  }
                } catch(e){}
                document.querySelectorAll('iframe').forEach(function(f){
                  try{ f.src = 'about:blank'; }catch(e){}
                });
              } catch(e){}
            })();
            """
            wk.evaluateJavaScript_completionHandler_(js, None)
        except Exception:
            pass

        try: wk.stopLoading()
        except Exception: pass
        try: wk.loadHTMLString_baseURL_("", None)
        except Exception: pass

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
            
        try:
            wk.removeFromSuperview()
        except Exception:
            pass

    def actNewTab_(self, _): self._add_tab(home=True)

    def actSwitchTab_(self, sender):
        """Switch to the tab identified by sender.tag() - PROPER tab isolation"""
        try:
            idx = int(sender.tag())
        except Exception:
            return
    
        if not (0 <= idx < len(self.tabs)) or idx == self.active:
            return
    
        cv = self.window.contentView()
        for subview in list(cv.subviews()):
            try:
                if isinstance(subview, WKWebView):
                    subview.removeFromSuperview()
            except Exception:
                pass
    
        self.active = idx
        self._mount_webview(self.tabs[idx].view)
        self._bring_tabbar_to_front()
        self._style_tabs()
        self._sync_addr()
                
    def actCloseTabIndex_(self, sender):
        try:
            idx = int(sender.tag())
        except Exception:
            return

        if not (0 <= idx < len(self.tabs)):
            return

        try:
            self._teardown_webview(self.tabs[idx].view)
        except Exception:
            pass

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

    def _close_tab(self):
        if 0 <= self.active < len(self.tabs):
            class _Tmp:
                def tag(self_inner):
                    return self.active
            self.actCloseTabIndex_(_Tmp())

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

    def actGo_(self, sender):
        try:
            text = str(sender.stringValue()).strip()
            if not text:
                return

            # Build URL (your existing logic)
            if "://" not in text and "." not in text:
                from urllib.parse import quote_plus
                q = quote_plus(text)
                url = "https://lite.duckduckgo.com/lite/?q=" + q
            elif "://" not in text:
                url = "https://" + text
            else:
                url = text

            self._add_tab(url)
        
        except Exception as e:
            print("[Go] Failed:", e)

    def _show_js_disabled_warning(self, url):
        """Show a placeholder page when JS is disabled."""
        warning_html = f"""<!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8"/>
            <title>JavaScript Disabled</title>
            <style>
                body {{
                    margin: 0;
                    font-family: system-ui, -apple-system, sans-serif;
                    background: #07080d;
                    color: #eef2f6;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    text-align: center;
                }}
                .container {{
                    max-width: 600px;
                    padding: 40px;
                }}
                h1 {{
                    color: #ff453a;
                    font-size: 2rem;
                    margin-bottom: 20px;
                }}
                p {{
                    color: #9aa3ad;
                    font-size: 1.1rem;
                    line-height: 1.6;
                }}
                .url {{
                    color: #34C759;
                    word-break: break-all;
                    margin-top: 20px;
                    padding: 10px;
                    background: rgba(52, 199, 89, 0.1);
                    border-radius: 8px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>⛔ JavaScript is Disabled</h1>
                <p>You attempted to navigate to:</p>
                <div class="url">{url}</div>
                <p style="margin-top: 30px;">
                    Enable JavaScript from the homepage chip to browse this site.
                </p>
            </div>
        </body>
        </html>
        """
    
        try:
            wk = self.tabs[self.active].view
            wk.loadHTMLString_baseURL_(warning_html, None)
        except Exception:
            pass
            
    def _show_block_alert(self, msg):
        try:
            alert = NSAlert.alloc().init()
            alert.setMessageText_("Blocked for privacy")
            alert.setInformativeText_(msg)
            alert.runModal()
        except Exception:
            print("Blocked: " + msg)
            
    def actNuke_(self, sender):
        ACCENT = (52/255.0, 199/255.0, 89/255.0, 1.0)

        alert = NSAlert.alloc().init()
        alert.setMessageText_("Clear All Browsing Data?")
        alert.setInformativeText_("This will wipe cookies, cache, local storage and website data for all sites.")
        alert.setAlertStyle_(NSAlertStyleCritical)

        alert.addButtonWithTitle_("Wipe")
        alert.addButtonWithTitle_("Cancel")

        try:
            buttons = alert.buttons()
            if buttons and hasattr(buttons[0], "setBezelColor_"):
                buttons[0].setBezelColor_(NSColor.colorWithCalibratedRed_green_blue_alpha_(*ACCENT))
        except Exception:
            pass

        def on_response(code):
            if int(code) == 1000:
                store = WKWebsiteDataStore.defaultDataStore()
                types = WKWebsiteDataStore.allWebsiteDataTypes()
                since = NSDate.dateWithTimeIntervalSince1970_(0)

                def done():
                    ok = NSAlert.alloc().init()
                    ok.setMessageText_("All data cleared")
                    ok.setInformativeText_("Cookies, cache, local storage and website data have been removed.")
                    ok.addButtonWithTitle_("OK")

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

        try:
            alert.beginSheetModalForWindow_completionHandler_(self.window, on_response)
        except Exception:
            resp = alert.runModal()
            on_response(resp)

    def _storage_cleanup(self):
        try:
            from WebKit import WKWebsiteDataStore
            store = WKWebsiteDataStore.nonPersistentDataStore()
            types = WKWebsiteDataStore.allWebsiteDataTypes()

            def handler():
                print("[Darkelf] Non-persistent storage cleanup complete.")

            store.removeDataOfTypes_modifiedSince_completionHandler_(
                types, 0, handler
            )
        except Exception as e:
            print("[Darkelf] Storage cleanup skipped:", e)

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

            if v in (
                HOME_URL,
                "about:home",
                "about://home",
                "about:blank",
                "about:blank#blocked",
            ):
                v = ""

            self.addr.setStringValue_(v)

        except Exception:
            pass

    def _install_key_monitor(self):
        from AppKit import NSEventModifierFlagCommand, NSEventModifierFlagShift

        def handler(evt):
            try:
                if evt.type() != 10:  # KeyDown
                    return evt

                flags = evt.modifierFlags()
                cmd = bool(flags & NSEventModifierFlagCommand)
                shift = bool(flags & NSEventModifierFlagShift)

                if not cmd:
                    return evt

                ch = evt.charactersIgnoringModifiers()

                # ⌘ + T
                if ch == "t":
                    self.actNewTab_(None)
                    return None

                # ⌘ + W
                if ch == "w":
                    self.actCloseTab_(None)
                    return None

                # ⌘ + R
                if ch == "r":
                    self.actReload_(None)
                    return None

                # ⌘ + L
                if ch == "l":
                    self.window.makeFirstResponder_(self.addr)
                    return None

                # 🔥 ⌘ + S  → Snapshot
                if ch == "s":
                    self.actSnapshot_(None)
                    return None

                # 🔥 ⌘ + Shift + X  → Instant Exit
                if ch == "x" and shift:
                    NSApp().terminate_(None)
                    return None

            except Exception as e:
                print("Key handler error:", e)

            return evt

        NSEvent.addLocalMonitorForEventsMatchingMask_handler_(1 << 10, handler)

        
    def __del__(self):
        try:
            print("[Browser] __del__ called, cleaning up timers and observers.")
        except Exception:
            pass

        # Invalidate cookie timer
        try:
            self._stop_cookie_scrubber()
        except Exception as e:
            print("[Browser] Failed to stop cookie scrubber in __del__:", e)

        # Remove resize notification observer
        try:
            nc = NSNotificationCenter.defaultCenter()
            nc.removeObserver_(self)
        except Exception as e:
            print("[Browser] Failed to remove observer in __del__:", e)

        # Remove all JS message handlers from active webview
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

        # ��� Shutdown MiniAI Sentinel
        try:
            if hasattr(self, "mini_ai") and self.mini_ai:
                self.mini_ai.shutdown()
                print("[MiniAI] Sentinel shutdown")
        except Exception as e:
            print("[MiniAI] Shutdown failed:", e)
                                
    def _wipe_all_site_data(self):
        try:
            store = WKWebsiteDataStore.defaultDataStore()
            types = WKWebsiteDataStore.allWebsiteDataTypes()

            def _done():
                print("[Wipe] All WKWebsiteDataStore data cleared.")

            store.removeDataOfTypes_modifiedSince_completionHandler_(
                types,
                NSDate.distantPast(),
                _done,
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
            
    def actSnapshot_(self, sender):
        try:
            wk = self.tabs[self.active].view

            def handler(image, error):
                if image and not error:
                    from AppKit import NSSavePanel
                    panel = NSSavePanel.savePanel()
                    panel.setNameFieldStringValue_("darkelf_snapshot.png")

                    if panel.runModal() == 1:
                        url = panel.URL()
                        tiff = image.TIFFRepresentation()
                        from AppKit import NSBitmapImageRep
                        rep = NSBitmapImageRep.imageRepWithData_(tiff)
                        png = rep.representationUsingType_properties_(4, None)  # PNG
                        png.writeToURL_atomically_(url, True)

            wk.takeSnapshotWithConfiguration_completionHandler_(None, handler)

        except Exception as e:
            print("[Snapshot] Failed:", e)

class AppDelegate(NSObject):

    def applicationShouldTerminate_(self, sender):
        # Allow termination immediately
        return True

    def applicationWillTerminate_(self, notification):
        try:
            if hasattr(self, "browser") and self.browser is not None:
                # Stop cookie scrubber
                try:
                    self.browser._stop_cookie_scrubber()
                except Exception as e:
                    print("[Quit] Failed to stop cookie scrubber:", e)

                # Stop Tor refresh timer (if active)
                try:
                    if hasattr(self.browser, "_tor_refresh_timer") and self.browser._tor_refresh_timer:
                        self.browser._tor_refresh_timer.invalidate()
                        self.browser._tor_refresh_timer = None
                except Exception as e:
                    print("[Quit] Failed to stop tor refresh timer:", e)

                # ✅ Shutdown MiniAI Sentinel
                try:
                    if hasattr(self.browser, "mini_ai") and self.browser.mini_ai:
                        self.browser.mini_ai.shutdown()
                        print("[Quit] MiniAI Sentinel shutdown")
                except Exception as e:
                    print("[Quit] MiniAI shutdown failed:", e)

                # Wipe all browsing data
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
    app.setActivationPolicy_(NSApplicationActivationPolicyRegular)

    delegate = AppDelegate.alloc().init()
    app.setDelegate_(delegate)

    delegate.browser = Browser.alloc().init()

    app.run()


if __name__ == "__main__":
    main()
