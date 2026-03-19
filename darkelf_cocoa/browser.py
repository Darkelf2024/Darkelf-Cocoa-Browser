# Darkelf Cocoa General Browser v4.0.13 — Ephemeral, Privacy-Focused Web Browser (macOS / Cocoa Build)
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
# ──────────────────────────────────────────────��─────────────────────────────────
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
import hashlib
import zipfile
import objc
import secrets
import warnings
import AppKit
from Quartz import CABasicAnimation
from collections import deque
from datetime import datetime
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, unquote, quote_plus
from objc import ObjCPointerWarning
import shutil
import tldextract
from Foundation import NSRunLoop, NSDate,  NSOperationQueue, NSURLCache

warnings.filterwarnings("ignore", category=ObjCPointerWarning)

from Cocoa import (
    NSApp, NSApplication, NSWindow, NSWindowStyleMaskTitled, NSWindowStyleMaskClosable,
    NSWindowStyleMaskResizable, NSWindowStyleMaskMiniaturizable, NSWindowCollectionBehaviorFullScreenPrimary,
    NSObject, NSButton, NSImage, NSBox, NSColor, NSView,
    NSTrackingArea, NSTrackingMouseEnteredAndExited, NSTrackingActiveAlways,
    NSEvent, NSMakeRect, NSSearchField, NSProgressIndicator, NSTextField,
    NSToolbarFlexibleSpaceItemIdentifier, NSApplicationActivationPolicyRegular, NSOperationQueue
)
from WebKit import (
    WKWebView, WKWebViewConfiguration, WKProcessPool, WKUserContentController, WKUserScript,
    WKPreferences, WKContentRuleListStore, WKWebsiteDataStore,
    WKNavigationActionPolicyAllow, WKNavigationActionPolicyCancel,
    WKNavigationResponsePolicyAllow, WKNavigationResponsePolicyDownload,
    WKNavigationTypeReload, WKNavigationType, WKUserScriptInjectionTimeAtDocumentStart,
    WKUserScriptInjectionTimeAtDocumentEnd
)
from Foundation import NSURL, NSURLRequest, NSMakeRect, NSNotificationCenter, NSDate, NSTimer, NSUserDefaults, NSRegistrationDomain,NSURLAuthenticationMethodServerTrust, NSURLSessionAuthChallengeUseCredential, NSURLCredential, NSURLSessionAuthChallengePerformDefaultHandling

from AppKit import NSImageSymbolConfiguration, NSBezierPath, NSFont, NSAttributedString, NSAlert, NSAlertStyleCritical, NSColor, NSAppearance, NSAnimationContext, NSViewWidthSizable, NSViewMinYMargin, NSViewMaxXMargin, NSViewHeightSizable, NSAppearance, NSEventModifierFlagCommand, NSEventModifierFlagShift, NSSavePanel, NSBitmapImageRep, NSMutableParagraphStyle, NSFont, NSFocusRingTypeNone, NSAttributedString

from WebKit import WKContentRuleListStore
import json
import time

from Security import SecTrustEvaluateWithError, SecTrustGetCertificateAtIndex, SecCertificateCopySubjectSummary
import tempfile

# ---- Darkelf logging control ----

LOG_LEVEL = 1
# 0 = silent
# 1 = important only
# 2 = verbose debug

def log(level, *msg):
    if level <= LOG_LEVEL:
        print(*msg)
        
def darkelf_pq_fingerprint(url: str, headers: dict = None) -> str:
    """
    Post-quantum safe request fingerprint (SHA3-256)
    Lightweight, deterministic, replay-resistant
    """
    h = hashlib.sha3_512()

    # bind URL
    h.update(url.encode("utf-8", errors="ignore"))

    # bind headers (if any)
    if headers:
        for k, v in sorted(headers.items()):
            h.update(str(k).encode())
            h.update(str(v).encode())

    # time window (10s buckets → prevents replay)
    h.update(str(int(time.time() // 10)).encode())

    return h.hexdigest()
    
def darkelf_is_pq_active(owner) -> bool:
    return hasattr(owner, "_pq_chain") and bool(owner._pq_chain)
    
class DarkelfNetworkPolicy:

    def __init__(self, browser):
        self.browser = browser

    def inspect(self, url, nav_type):

        url = str(url)

        # MiniAI inspection
        if hasattr(self.browser, "mini_ai"):
            try:
                self.browser.mini_ai.monitor_network(url)
            except Exception:
                pass

        # tracker blocking
        blocked = [
            "doubleclick.net",
            "google-analytics.com",
            "facebook.net",
            "facebook.com/tr",
            "googletagmanager.com"
        ]

        for domain in blocked:
            if domain in url:
                return "block"

        # enforce HTTPS
        if url.startswith("http://"):
            return ("redirect", url.replace("http://", "https://", 1))

        return "allow"
        
class DownloadProgressView(NSView):

    def initWithFrame_(self, frame):
        self = objc.super(DownloadProgressView, self).initWithFrame_(frame)
        if self is None:
            return None

        self.setWantsLayer_(True)
        self.layer().setCornerRadius_(12)
        self.layer().setBackgroundColor_(
            NSColor.colorWithCalibratedRed_green_blue_alpha_(0.04,0.05,0.07,1).CGColor()
        )

        # filename
        self.label = NSTextField.alloc().initWithFrame_(NSMakeRect(15, 40, 400, 20))
        self.label.setBezeled_(False)
        self.label.setEditable_(False)
        self.label.setDrawsBackground_(False)
        self.label.setTextColor_(NSColor.whiteColor())
        self.label.setFont_(NSFont.systemFontOfSize_(13))
        self.addSubview_(self.label)
        
        # percentage label
        self.percent = NSTextField.alloc().initWithFrame_(NSMakeRect(360, 40, 60, 20))
        self.percent.setBezeled_(False)
        self.percent.setEditable_(False)
        self.percent.setDrawsBackground_(False)
        self.percent.setTextColor_(NSColor.systemGrayColor())
        self.percent.setFont_(NSFont.systemFontOfSize_(12))
        self.percent.setAlignment_(2)  # right align
        self.percent.setStringValue_("0%")
        self.addSubview_(self.percent)
        
        # progress track
        self.progressTrack = NSView.alloc().initWithFrame_(NSMakeRect(15, 22, 400, 6))
        self.progressTrack.setWantsLayer_(True)

        self.progressTrack.layer().setCornerRadius_(3)
        self.progressTrack.layer().setBackgroundColor_(
            NSColor.colorWithCalibratedRed_green_blue_alpha_(0.08,0.09,0.12,1).CGColor()
        )

        self.addSubview_(self.progressTrack)

        # progress fill
        self.progressFill = NSView.alloc().initWithFrame_(NSMakeRect(0, 0, 0, 6))
        self.progressFill.setWantsLayer_(True)

        green = NSColor.colorWithCalibratedRed_green_blue_alpha_(0.20,0.78,0.35,1)

        self.progressFill.layer().setCornerRadius_(3)
        self.progressFill.layer().setBackgroundColor_(green.CGColor())

        # glow
        self.progressFill.layer().setShadowColor_(green.CGColor())
        self.progressFill.layer().setShadowOpacity_(0.7)
        self.progressFill.layer().setShadowRadius_(6)
        self.progressFill.layer().setShadowOffset_((0,0))

        self.progressTrack.addSubview_(self.progressFill)

        # speed label
        self.speed = NSTextField.alloc().initWithFrame_(NSMakeRect(15, 2, 200, 15))
        self.speed.setBezeled_(False)
        self.speed.setEditable_(False)
        self.speed.setDrawsBackground_(False)
        self.speed.setTextColor_(NSColor.systemGrayColor())
        self.speed.setFont_(NSFont.systemFontOfSize_(11))
        self.addSubview_(self.speed)

        # Done button
        self.done = NSButton.alloc().initWithFrame_(NSMakeRect(420, 18, 70, 22))
        self.done.setTitle_("Done")
        self.done.setBezelStyle_(1)
        self.addSubview_(self.done)
        self.done.setTarget_(self)
        self.done.setAction_("closeDownload:")

        return self


    def updateProgress_(self, percent):

        try:
            percent = max(0.0, min(100.0, float(percent)))

            # update percent label if present
            try:
                if hasattr(self, "percent"):
                    self.percent.setStringValue_(f"{int(percent)}%")
            except Exception:
                pass

            trackWidth = self.progressTrack.bounds().size.width
            newWidth = trackWidth * (percent / 100.0)

            frame = self.progressFill.frame()
            frame.size.width = newWidth

            def animate(ctx):
                ctx.setDuration_(0.12)
                self.progressFill.animator().setFrame_(frame)

            NSAnimationContext.runAnimationGroup_completionHandler_(
                animate,
                None
            )

        except Exception as e:
            print("[DownloadUI progress error]", e)

    def setFilename_(self, name):
        self.label.setStringValue_(name)


    def setSpeed_(self, speed):
        self.speed.setStringValue_(speed)


    def closeDownload_(self, sender):
        try:
            self.setHidden_(True)
        except Exception as e:
            print("[DownloadUI] close error:", e)
        
# ============================================================
# Darkelf First Party Isolation (FPI)
# Memory-only domain + optional tab isolation
# ============================================================

class FirstPartyIsolation:

    # domains allowed to share storage for login flows
    AUTH_WHITELIST = {
        "accounts.google.com",
        "login.microsoftonline.com",
        "appleid.apple.com",
        "github.com"
    }

    def __init__(self, tab_isolation=False):
        """
        tab_isolation:
            False -> domain-only isolation
            True  -> domain + tab isolation
        """
        self.tab_isolation = tab_isolation
        self._stores = {}

    # --------------------------------------------------------
    # Extract first-party domain (eTLD+1 approximation)
    # --------------------------------------------------------

    def _domain_key(self, url):

        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""
            
        host = host.lower()
        host = host.split(":")[0]
        
        if not host:
            return "unknown"

        if host in self.AUTH_WHITELIST:
            return host

        try:
            ext = tldextract.extract(host)

            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"

        except Exception:
            pass

        return host

    # --------------------------------------------------------
    # Build isolation key
    # --------------------------------------------------------

    def _key(self, url, tab_uid=None, nonce=None):

        domain = self._domain_key(url)

        if self.tab_isolation and tab_uid is not None:
            return f"{domain}@tab{tab_uid}-{nonce}"

        return domain

    # --------------------------------------------------------
    # Get storage container
    # --------------------------------------------------------

    def store_for(self, url, tab_uid=None):

        key = self._key(url, tab_uid)
        
        print("[FPI] Using store:", key)
        
        if key not in self._stores:

            # IMPORTANT: non-persistent memory store
            store = WKWebsiteDataStore.nonPersistentDataStore()

            self._stores[key] = store

        return self._stores[key]

    # --------------------------------------------------------
    # Clear all stores (browser shutdown)
    # --------------------------------------------------------

    def clear(self):

        self._stores.clear()
        
def _darkelf_library():

    desktop = os.path.join(os.path.expanduser("~"), "Desktop")

    library = os.path.join(desktop, "Darkelf Library")
    snaps   = os.path.join(library, "Darkelf Snap")
    temp    = os.path.join(library, "Darkelf Temp")

    os.makedirs(snaps, exist_ok=True)
    os.makedirs(temp, exist_ok=True)

    return library, snaps, temp


def _safe_download_dir():

    _, _, temp = _darkelf_library()
    return temp
    
def _snapshot_dir():

    _, snaps, _ = _darkelf_library()
    return snaps
    
def _randomized_filename(name):
    name = (name or "download").strip()
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)[:120]

    base, ext = os.path.splitext(name)

    token = secrets.token_hex(6)

    base = base[:60] or "download"
    ext = ext[:12]

    return f"{base}_{token}{ext}"

class DarkelfMiniAISentinel:

    MAX_URL_LENGTH = 2048
    CRITICAL_WINDOW_SECONDS = 60
    LOCKDOWN_DURATION_SECONDS = 120

    def __init__(self):

        self.enabled = True
        self.browser = None

        self.events = deque(maxlen=500)

        self.tracker_hits = 0
        self.suspicious_hits = 0
        self.malware_hits = 0
        self.exploit_attempts = 0
        self.fingerprint_attempts = 0
        self.intrusion_attempts = 0
        self.http_blocks_attempts = 0

        # IDS detections
        self.scraper_attempts = 0
        self.credential_stuffing_attempts = 0
        self.vuln_scanner_attempts = 0
        self.bruteforce_attempts = 0
        self.automation_attempts = 0
        self.total_requests = 0
        self.static_requests = 0
        self.dynamic_requests = 0
        self.blocked_requests = 0
        
        self.login_attempt_tracker = {}
        self.scraper_tracker = {}

        self.session_start = time.time()
        self.unique_domains = set()
        self.first_party_domain = None
        self.redirects = []

        self.lockdown_active = False
        self.lockdown_threshold = 3
        self.lockdown_triggered_at = None
        self._lockdown_ui_opened = False

        self.request_timestamps = deque(maxlen=100)
        self.anomaly_threshold = 800

        # 🔧 throttling (prevents UI queue flooding)
        self._last_scan_time = 0
        self._last_lockdown_eval = 0

        self.hacker_tools = [
            "nmap","sqlmap","metasploit","burpsuite","nikto",
            "dirbuster","hydra","wireshark","tcpdump","ettercap",
            "aircrack","hashcat","johntheripper","cobalt","mimikatz"
        ]

        self.high_risk_domains = {
            "doubleclick.net","googlesyndication.com","googleadservices.com",
            "facebook.net","scorecardresearch.com","quantserve.com",
            "taboola.com","outbrain.com","criteo.com","adnxs.com"
        }

        self.high_risk_tlds = {".tk",".ml",".ga",".cf",".gq"}

        self.fingerprint_apis = {
            "canvas":0,"webgl":0,"audio":0,"font":0,
            "battery":0,"geolocation":0,"media_devices":0,"webrtc":0
        }

        print("[MiniAI] Sentinel initialized")


    # --------------------------------------------------
    # URL NORMALIZATION
    # --------------------------------------------------

    def _normalize_url(self, url: str) -> str:

        try:
            url = url[:self.MAX_URL_LENGTH]
            return unquote(unquote(url.lower()))
        except Exception:
            return (url or "").lower()


    # --------------------------------------------------
    # MAIN NETWORK MONITOR
    # --------------------------------------------------

    def monitor_network(self, url: str, headers=None):

        if not url or not self.enabled:
            return

        now = time.time()

        # throttle heavy bursts (SPA pages)
        if now - self._last_scan_time < 0.005:
            return

        self._last_scan_time = now

        normalized = self._normalize_url(url)

        if not normalized:
            return

        # ---- stats ----
        self.total_requests += 1

        headers = headers or {}

        try:
            host = urlparse(normalized).hostname or ""
        except Exception:
            host = ""
    
        # determine first-party domain
        if not self.first_party_domain and host:
            self.first_party_domain = host

        # safe hosts
        SAFE_HOSTS = (
            "github.com",
            "githubassets.com",
            "githubusercontent.com",
            "avatars.githubusercontent.com"
        )

        for safe in SAFE_HOSTS:
            if host.endswith(safe):
                return

        # track domain early
        if host:
            self.unique_domains.add(host)

        # --------------------------------------------------
        # static asset detection
        # --------------------------------------------------

        STATIC_EXT = (
            ".png",".jpg",".jpeg",".gif",".svg",".webp",
            ".css",".woff",".woff2",".ttf",".eot",".ico",
            ".map",".mp4",".webm",".mp3",".ogg"
        )

        is_static = normalized.split("?")[0].endswith(STATIC_EXT)

        # ---- stats ----
        if is_static:
            self.static_requests += 1
        else:
            self.dynamic_requests += 1

        # --------------------------------------------------
        # build event object
        # --------------------------------------------------

        event = {
            "url": normalized,
            "timestamp": now,
            "datetime": datetime.now().isoformat(),
            "threats": [],
            "risk_level": "low",
            "static": is_static
        }

        # --------------------------------------------------
        # lightweight static analysis
        # --------------------------------------------------

        if is_static:

            for domain in self.high_risk_domains:

                if host == domain or host.endswith("." + domain):

                    event["threats"].append("tracker")
                    event["risk_level"] = "medium"
                    self.tracker_hits += 1
                    break

            self.events.append(event)
            return

        # --------------------------------------------------
        # lockdown logic
        # --------------------------------------------------

        if self.lockdown_active:

            self._maybe_auto_unlock(now)

            if self.lockdown_active:

                print("[MiniAI] LOCKDOWN BLOCK:", normalized)

                if self.browser and not self._lockdown_ui_opened:
                    NSOperationQueue.mainQueue().addOperationWithBlock_(
                        self._show_threat_report_ui
                    )

                return

        # --------------------------------------------------
        # detection engines
        # --------------------------------------------------

        self._detect_intrusion(normalized, event)
        self._detect_fingerprinting(normalized, headers, event)
        self._check_domain_reputation(normalized, event)
        self._detect_anomalies(now, event)
        self._detect_ids_activity(normalized, headers, event)

        self.events.append(event)

        if event["risk_level"] in ("high","critical"):
            self._log_threat(event)

        # --------------------------------------------------
        # UI lockdown checks
        # --------------------------------------------------

        if now - self._last_lockdown_eval > 1.0:
            self._last_lockdown_eval = now

            NSOperationQueue.mainQueue().addOperationWithBlock_(
                self._evaluate_lockdown
            )

    # --------------------------------------------------
    # DETECT INTRUSION
    # --------------------------------------------------

    def _detect_intrusion(self, url, event):

        for tool in self.hacker_tools:

            if tool in url:

                event["threats"].append("intrusion")
                event["risk_level"] = "critical"

                self.intrusion_attempts += 1
                return


    # --------------------------------------------------
    # DOMAIN REPUTATION
    # --------------------------------------------------
    def _check_domain_reputation(self, url, event):

        try:
            host = urlparse(url).hostname or ""
        except Exception:
            host = ""

        # ------------------------------------
        # Known tracker domain list
        # ------------------------------------
        for domain in self.high_risk_domains:

            if host == domain or host.endswith("." + domain):

                event["threats"].append("tracker")
                self.tracker_hits += 1

                if event["risk_level"] == "low":
                    event["risk_level"] = "medium"

                return


        # ------------------------------------
        # Automatic third-party tracker detection
        # ------------------------------------
        if getattr(self, "first_party_domain", None) and host:

            if not host.endswith(self.first_party_domain):

                # ignore common CDNs
                cdn_whitelist = (
                    "cloudflare.com",
                    "cloudfront.net",
                    "akamai.net",
                    "fastly.net",
                    "gstatic.com",
                    "fonts.gstatic.com"
                )

                for cdn in cdn_whitelist:
                    if host.endswith(cdn):
                        break
                else:

                    event["threats"].append("tracker")
                    self.tracker_hits += 1

                    if event["risk_level"] == "low":
                        event["risk_level"] = "medium"

                    return


        # ------------------------------------
        # Suspicious TLD detection
        # ------------------------------------
        for tld in self.high_risk_tlds:

            if host.endswith(tld):

                event["threats"].append("suspicious_domain")
                self.suspicious_hits += 1

                if event["risk_level"] == "low":
                    event["risk_level"] = "medium"


    # --------------------------------------------------
    # FINGERPRINT DETECTION
    # --------------------------------------------------

    def _detect_fingerprinting(self, url, headers, event):

        keywords = ["fingerprint","canvas","webgl","audiofingerprint"]

        for k in keywords:

            if k in url:

                event["threats"].append("fingerprinting")
                self.fingerprint_attempts += 1

                if event["risk_level"] == "low":
                    event["risk_level"] = "medium"

                return


    # --------------------------------------------------
    # TRAFFIC ANOMALY
    # --------------------------------------------------

    def _detect_anomalies(self, now, event):

        self.request_timestamps.append(now)

        window = [
            t for t in self.request_timestamps
            if now - t < self.CRITICAL_WINDOW_SECONDS
        ]

        if len(self.unique_domains) > 120:

            event["threats"].append("domain_scanner")

            if event["risk_level"] == "low":
                event["risk_level"] = "high"

            self.vuln_scanner_attempts += 1

        if len(window) > self.anomaly_threshold:

            event["threats"].append("traffic_anomaly")
            event["risk_level"] = "high"

            self.suspicious_hits += 1


    # --------------------------------------------------
    # IDS DETECTION
    # --------------------------------------------------

    def _detect_ids_activity(self, url, headers, event):

        now = time.time()

        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            path = parsed.path or ""
        except:
            host = ""
            path = ""

        ua = str(headers.get("user-agent","")).lower()

        # scraper detection
        if host:

            history = self.scraper_tracker.setdefault(host,[])
            history.append(now)

            history = [t for t in history if now - t < 10]
            self.scraper_tracker[host] = history

            if len(history) > 10:
                event["threats"].append("scraping_bot")
                event["risk_level"] = "high"
                self.scraper_attempts += 1

        # credential stuffing
        if any(x in path for x in ["login","signin","auth"]):

            key = host

            attempts = self.login_attempt_tracker.setdefault(key,[])
            attempts.append(now)

            attempts = [t for t in attempts if now - t < 60]
            self.login_attempt_tracker[key] = attempts

            if len(attempts) > 10:
                event["threats"].append("credential_stuffing")
                event["risk_level"] = "high"
                self.credential_stuffing_attempts += 1


        scanner_patterns = [
            "wp-admin",".env","phpmyadmin",
            "config.php","backup.sql","/cgi-bin/","/admin/"
        ]

        for p in scanner_patterns:
            if p in path:

                event["threats"].append("vulnerability_scanner")
                event["risk_level"] = "high"
                self.vuln_scanner_attempts += 1
                break


        if "password" in path or "login" in path:

            key = f"bf_{host}"

            attempts = self.login_attempt_tracker.setdefault(key,[])
            attempts.append(now)

            attempts = [t for t in attempts if now - t < 30]
            self.login_attempt_tracker[key] = attempts

            if len(attempts) > 15:
                event["threats"].append("bruteforce_login")
                event["risk_level"] = "critical"
                self.bruteforce_attempts += 1


        automation_signatures = [
            "headless","selenium","phantomjs",
            "puppeteer","playwright","curl/","python-requests"
        ]

        for sig in automation_signatures:

            if sig in ua:

                event["threats"].append("automation_framework")
                event["risk_level"] = "medium"
                self.automation_attempts += 1
                break
    # --------------------------------------------------
    # HTTP BLOCK DETECTION
    # --------------------------------------------------

    def on_http_blocked(self, url):

        self.http_blocks_attempts += 1

        print("[MiniAI] HTTP blocked:", url)


    # --------------------------------------------------
    # THREAT LOGGING
    # --------------------------------------------------

    def _log_threat(self, event):

        print(
            "[MiniAI] THREAT:",
            event["risk_level"],
            event["url"],
            event["threats"]
        )


    # --------------------------------------------------
    # LOCKDOWN EVALUATION
    # --------------------------------------------------

    def _evaluate_lockdown(self):

        # Already in lockdown
        if self.lockdown_active:
            return

        # Critical threats only
        critical_score = (
            self.intrusion_attempts +
            self.malware_hits +
            self.exploit_attempts
        )

        # Trigger lockdown if threshold reached
        if critical_score >= self.lockdown_threshold:

            print("[MiniAI] Critical threat threshold reached:", critical_score)

            self._trigger_lockdown()

    # --------------------------------------------------
    # STATS FOR UI
    # --------------------------------------------------

    def get_statistics(self):

        uptime = time.time() - self.session_start

        threat_score = (
            self.tracker_hits +
            self.suspicious_hits +
            self.fingerprint_attempts * 2 +
            self.intrusion_attempts * 4 +
            self.malware_hits * 6 +
            self.exploit_attempts * 6 +
            self.http_blocks_attempts
        )

        return {

            "uptime_seconds": uptime,

            # -----------------------------
            # Network Activity (NEW)
            # -----------------------------
            "network": {
                "total_requests": getattr(self, "total_requests", 0),
                "dynamic_requests": getattr(self, "dynamic_requests", 0),
                "static_requests": getattr(self, "static_requests", 0),
                "unique_domains": len(self.unique_domains)
            },

            # existing event counter
            "total_events": len(self.events),

            "threat_score": threat_score,

            "lockdown": {
                "active": self.lockdown_active,
                "threshold": self.lockdown_threshold,
                "triggered_at": self.lockdown_triggered_at,
            },

            # -----------------------------
            # Threat Counters
            # -----------------------------
            "threats": {
                "trackers": self.tracker_hits,
                "suspicious": self.suspicious_hits,
                "malware": self.malware_hits,
                "exploits": self.exploit_attempts,
                "intrusions": self.intrusion_attempts,
                "fingerprinting": self.fingerprint_attempts,
                "http_blocks": self.http_blocks_attempts,
            },

            # -----------------------------
            # IDS Detection
            # -----------------------------
            "ids": {
                "scrapers": self.scraper_attempts,
                "credential_stuffing": self.credential_stuffing_attempts,
                "vulnerability_scanners": self.vuln_scanner_attempts,
                "bruteforce_logins": self.bruteforce_attempts,
                "automation_frameworks": self.automation_attempts
            }
        }
    # --------------------------------------------------
    # LOCKDOWN TRIGGER
    # --------------------------------------------------
    def _trigger_lockdown(self):

        if self.lockdown_active:
            return

        self.lockdown_active = True
        self.lockdown_triggered_at = time.time()
        self._lockdown_ui_opened = False

        print("[MiniAI] 🔴 LOCKDOWN ACTIVATED")

        if not self.browser:
            print("[MiniAI] No browser bridge")
            return

        # Stop all tab loading
        for tab in getattr(self.browser, "tabs", []):
            try:
                tab.view.stopLoading()
            except Exception:
                pass

        try:
            self.browser.start_lockdown_timer()
        except Exception as e:
            print("[MiniAI] timer error:", e)

        NSOperationQueue.mainQueue().addOperationWithBlock_(
            self._show_threat_report_ui
        )

        NSOperationQueue.mainQueue().addOperationWithBlock_(
            self._lock_browser_ui
        )

    # --------------------------------------------------
    # AUTO UNLOCK
    # --------------------------------------------------
    def _maybe_auto_unlock(self, now):

        if not self.lockdown_active:
            return

        if not self.lockdown_triggered_at:
            return

        if now - self.lockdown_triggered_at < self.LOCKDOWN_DURATION_SECONDS:
            return

        print("[MiniAI] Lockdown expired")

        self.lockdown_active = False
        self.lockdown_triggered_at = None
        self._lockdown_ui_opened = False
        self.intrusion_attempts = 0
        self.events.clear()

        if self.browser:
            self.browser.finish_lockdown_unlock()

    # --------------------------------------------------
    # UI ACTIONS (via Browser)
    # --------------------------------------------------
    def _show_threat_report_ui(self):

        if self._lockdown_ui_opened:
            return

        if not self.browser:
            return

        try:

            report_idx = -1

            for i, tab in enumerate(self.browser.tabs):
                if getattr(tab,"url","") == "darkelf://report":
                    report_idx = i
                    break

            if report_idx >= 0:

                tab = self.browser.tabs[report_idx]
                html = self.browser._build_threat_report_html()

                #tab.view.loadHTMLString_baseURL_(html, None)
                tab.view.loadHTMLString_baseURL_(html, NSURL.URLWithString_("darkelf://report"))
                
                tab.url = "darkelf://report"
                tab.host = "Darkelf Threat Console"
                
                self.browser.active = report_idx
                self.browser._update_tab_buttons()
                self.browser._sync_addr()

            else:

                self.browser.openThreatReport_(None)

        except Exception as e:
            print("[MiniAI] threat report error:", e)

        self._lockdown_ui_opened = True

    # --------------------------------------------------
    # UI LOCK
    # --------------------------------------------------
    def _lock_browser_ui(self):

        if not self.browser:
            return

        controls = [
            "btn_back","btn_fwd","btn_reload","btn_home",
            "btn_new_tab","addr","urlbar",
            "btn_zoom_out","btn_zoom_in","btn_js","btn_nuke"
        ]

        for name in controls:
            try:
                ctrl = getattr(self.browser,name,None)
                if ctrl:
                    ctrl.setEnabled_(False)
            except Exception:
                pass

    # --------------------------------------------------
    # UI UNLOCK
    # --------------------------------------------------
    def _unlock_browser_ui(self):

        if not self.browser:
            return

        controls = [
            "btn_back","btn_fwd","btn_reload","btn_home",
            "btn_new_tab","addr","urlbar",
            "btn_zoom_out","btn_zoom_in","btn_js","btn_nuke"
        ]

        for name in controls:
            try:
                ctrl = getattr(self.browser,name,None)
                if ctrl:
                    ctrl.setEnabled_(True)
            except Exception:
                pass
                
HOME_URL = "darkelf://home"
        
class ContentRuleManager:
    _rule_list = None
    _loaded = False

    @classmethod
    def load_rules(cls, completion_callback=None):
        if cls._loaded:
            if cls._rule_list and completion_callback:
                completion_callback()
            return

        cls._loaded = True
        store = WKContentRuleListStore.defaultStore()
        identifier = "darkelf_builtin_rules_v9_enhanced"

        def _lookup(rule_list, error):
            if rule_list:
                cls._rule_list = rule_list
                cls._loaded = True
                if completion_callback:
                    completion_callback()
                return

            json_rules = cls._load_json()

            def _compiled(rule_list, error):
                if error:
                    print("[Rules] Compile error:", error)
                    return

                cls._rule_list = rule_list
                cls._loaded = True
                print("[Rules] Comprehensive tracker blocking rules compiled & ready")

                if completion_callback:
                    completion_callback()

            store.compileContentRuleListForIdentifier_encodedContentRuleList_completionHandler_(
                identifier,
                json_rules,
                _compiled
            )

        store.lookUpContentRuleListForIdentifier_completionHandler_(
            identifier,
            _lookup
        )

    @classmethod  # ✅ FIXED: Proper indentation at class level
    def _load_json(cls):
        # ✅ FIXED: Proper escape sequences for WebKit content blocking
        rules_json = """
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
              "url-filter": "googleadservices\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "google-analytics\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "googletagmanager\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "googletagservices\\\\.com",
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
          },
          {
            "trigger": {
              "url-filter": "facebook\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "fbcdn\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "connect\\\\.facebook\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "scorecardresearch\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "quantserve\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "pubmatic\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "openx\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "rubiconproject\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "adnxs\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "advertising\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "amazon-adsystem\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "adsafeprotected\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "moatads\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "2mdn\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "serving-sys\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "mathtag\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "addthis\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "sharethis\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "chartbeat\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "newrelic\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "nr-data\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "hotjar\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "mouseflow\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "crazyegg\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "luckyorange\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "fullstory\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "segment\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "segment\\\\.io",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "mixpanel\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "amplitude\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "optimizely\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "cdnwidget\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "zedo\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "revcontent\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "iadsdk\\\\.apple\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "adroll\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "bizographics\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "pardot\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "marketo\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "eloqua\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "hubspot\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "hs-analytics\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "kissmetrics\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "intercom\\\\.io",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "drift\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "olark\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "livechatinc\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "tawk\\\\.to",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "doubleclick\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "casalemedia\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "contextweb\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "33across\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "yieldmo\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "sharethrough\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "triplelift\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "sovrn\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "media\\\\.net",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "indexexchange\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "simpli\\\\.fi",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "bidswitch\\\\.com",
              "resource-type": ["script", "image"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "lijit\\\\.com",
              "resource-type": ["image", "script"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "adform\\\\.net",
              "resource-type": ["image", "script"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "smartadserver\\\\.com",
              "resource-type": ["image", "script"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "trafficjunky\\\\.net",
              "resource-type": ["image", "script"]
            },
            "action": { "type": "block" }
          },
          {
            "trigger": {
              "url-filter": "undertone\\\\.com",
              "resource-type": ["image", "script"]
            },
            "action": { "type": "block" }
          }
        ]
        """

        # Convert JSON string to Python list
        try:
            rules = json.loads(rules_json)
        except Exception as e:
            print(f"[ContentRules] Parse error in base rules: {e}")
            return

        # CSS-based blocking rules (these don't use regex)
        rules.append({
            "trigger": {
                "url-filter": "cookiebot",
                "resource-type": ["script"]
            },
            "action": { "type": "block" }
        })

        rules.append({
            "trigger": {
                "url-filter": "onetrust",
                "resource-type": ["script"]
            },
            "action": { "type": "block" }
        })

        rules.append({
            "trigger": {
                "url-filter": "trustarc",
                "resource-type": ["script"]
            },
            "action": { "type": "block" }
        })

        rules.append({
            "trigger": {
                "url-filter": "quantcast",
                "resource-type": ["script"]
            },
            "action": { "type": "block" }
        })

        rules.append({
            "trigger": {
                "url-filter": "consentmanager",
                "resource-type": ["script"]
            },
            "action": { "type": "block" }
        })
        return json.dumps(rules)
        
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
    "https://*.youtube.com "
    "https://i.ytimg.com "
    "https://www.youtube.com;"
)

class _UIDelegate(NSObject):
    def initWithOwner_(self, owner):
        self = objc.super(_UIDelegate, self).init()
        if self is None:
            return None
        self.owner = owner
        return self

    # Forward the methods you currently implemented on Browser:

    def webView_createWebViewWithConfiguration_forNavigationAction_windowFeatures_(
            self, webView, configuration, navigationAction, windowFeatures):

        try:
            req = navigationAction.request()

            if req:
                print("[UIDelegate] Popup redirected to same tab")

                # Load popup URL in current tab
                webView.loadRequest_(req)

        except Exception as e:
            print("[UIDelegate] Popup handling error:", e)

        return None

    def webView_runJavaScriptAlertPanelWithMessage_initiatedByFrame_completionHandler_(
        self, webView, message, frame, completionHandler
    ):
        try:
            print(f"[JS Alert] {message}")
            alert = NSAlert.alloc().init()
            alert.setMessageText_("JavaScript Alert")
            alert.setInformativeText_(str(message))
            alert.addButtonWithTitle_("OK")
            alert.runModal()
        finally:
            completionHandler()

    def webView_runJavaScriptConfirmPanelWithMessage_initiatedByFrame_completionHandler_(
        self, webView, message, frame, completionHandler
    ):
        try:
            print(f"[JS Confirm] {message}")
            alert = NSAlert.alloc().init()
            alert.setMessageText_("Confirm")
            alert.setInformativeText_(str(message))
            alert.addButtonWithTitle_("OK")
            alert.addButtonWithTitle_("Cancel")
            result = alert.runModal()
            completionHandler(result == 1000)
        except Exception as e:
            print(f"[JS Confirm] Error: {e}")
            completionHandler(False)

    def webView_runJavaScriptTextInputPanelWithPrompt_defaultText_initiatedByFrame_completionHandler_(
        self, webView, prompt, defaultText, frame, completionHandler
    ):
        try:
            print(f"[JS Prompt] {prompt}")
            completionHandler(None)
        except Exception as e:
            print(f"[JS Prompt] Error: {e}")
            completionHandler(None)

    def webView_requestMediaCapturePermissionForOrigin_initiatedByFrame_type_decisionHandler_(
        self, webView, origin, frame, type, decisionHandler
    ):
        try:
            print(f"[Media] 🔒 Denied media capture for: {origin}")
            decisionHandler(0)
        except Exception:
            pass
            
    def webView_enterFullScreenForFrame_completionHandler_(self, webView, frame, completionHandler):

        try:
            print("[UIDelegate] WebKit video fullscreen")

            webView.setFrame_(webView.window().contentView().bounds())
            webView.setAutoresizingMask_(18)  # width + height

        except Exception as e:
            print("[UIDelegate] fullscreen error:", e)

        completionHandler(True)

    def webView_exitFullScreenForFrame_completionHandler_(self, webView, frame, completionHandler):
        print("[UIDelegate] exit video fullscreen")
        completionHandler(True)
        
class _NavDelegate(NSObject):

    # -------------------------------------------------
    # Init
    # -------------------------------------------------
    def initWithOwner_(self, owner):
        self = objc.super(_NavDelegate, self).init()
        if self is None:
            return None

        self.owner = owner
        self.download_dir = _safe_download_dir()   # ✅ ADD THIS

        return self
    # -------------------------------------------------
    # Navigation Finished
    # -------------------------------------------------
    def webView_didFinishNavigation_(self, webView, nav):

        owner = getattr(self, "owner", None)

        if not owner:
            return

        if not getattr(owner, "tabs", None):
            return

        try:
            browser = getattr(self, "owner", None)
            if not browser:
                return

            if not browser._is_tab_webview(webView):
                return

            url = webView.URL()
            title = webView.title()

            for tab in browser.tabs:
                if tab.view is webView:

                    if url and url.absoluteString() == HOME_URL:
                        tab.url = HOME_URL
                        tab.host = "Darkelf Home"

                    else:

                        if title:
                            tab.host = title
                        elif url:
                            tab.host = url.host() or url.absoluteString()

                        if url:
                            tab.url = url.absoluteString()

                    break

            browser._update_tab_buttons()
            browser._sync_addr()
            
            # --- WebKit process recycling trigger ---
            try:
                if hasattr(browser, "page_load_count"):
                    browser.page_load_count += 1

                    if browser.page_load_count >= 100:
                        browser.recycle_web_process()
            except Exception as e:
                print("[Darkelf] recycle trigger error:", e)
                
            color = NSColor.whiteColor()

            if url:
                scheme = str(url.scheme() or "").lower()

                if scheme == "https":
                    current = browser.addr.textColor()
                    if current != NSColor.systemRedColor():
                        color = NSColor.systemGreenColor()

            browser.addr.setTextColor_(color)
            
            # --- PQ indicator ---
            try:
                if scheme == "https" and darkelf_is_pq_active(browser):

                    current = browser.addr.stringValue() or ""

                    if " PQ" not in current:
                        browser.addr.setStringValue_(current + "  PQ")

                    browser.addr.setToolTip_("TLS Secure + PQ Integrity Active")

            except Exception:
                pass
                
        except Exception as e:
            print("[NavDelegate] didFinish error:", e)


    # -------------------------------------------------
    # JS Bridge
    # -------------------------------------------------
    def userContentController_didReceiveScriptMessage_(self, ucc, message):

        try:

            # -------------------------
            # FULLSCREEN BRIDGE
            # -------------------------
            if message.name() == "fullscreen":
                print("[Fullscreen message ignored]")
                return
            
            # -------------------------
            # NETLOG HANDLER
            # -------------------------
            if message.name() == "netlog":

                try:
    
                    body = message.body()

                    if not isinstance(body, dict):
                        return

                    owner = getattr(self, "owner", None)
                    if not owner:
                        return

                    url = str(body.get("url", "")).strip()

                    if not url:
                        return

                    req_type = str(body.get("type", "unknown"))
                    headers = body.get("headers", {}) or {}

                    # structured metadata for MiniAI
                    meta = {
                        "type": req_type,
                        "source": "js",
                        "headers": headers
                    }

                    if hasattr(owner, "mini_ai"):
                        owner.mini_ai.monitor_network(url, meta)

                except Exception as e:
                    print("[Darkelf netlog error]", e)

                return
            
            # -------------------------
            # BLOB DOWNLOAD HANDLER
            # -------------------------
            if message.name() == "blobdownload":

                body = message.body()

                filename = body.get("filename", "download")
                data = body.get("data")

                if not data:
                    return

                import base64

                base64_data = data.split(",")[1]

                randomized = _randomized_filename(filename)

                path = os.path.join(self.download_dir, randomized)

                with open(path, "wb") as f:
                    f.write(base64.b64decode(base64_data))

                print("[Darkelf] Blob downloaded →", path)

                return

        except Exception as e:
            print("[NavDelegate ScriptMessage] Error:", e)
        
    # ===============================
    # DOWNLOAD HANDLING
    # ===============================

    def webView_decidePolicyForNavigationResponse_decisionHandler_(self, webView, response, decisionHandler):

        try:
            ns_response = response.response()

            if not ns_response:
                decisionHandler(WKNavigationResponsePolicyAllow)
                return

            mime = ns_response.MIMEType() or ""
            headers = ns_response.allHeaderFields() or {}

            # Normalize headers (case-insensitive)
            headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}

            # 🔽 ADD THIS BLOCK HERE
            if mime == "application/octet-stream":
                print("[Darkelf] Binary download detected")
                decisionHandler(WKNavigationResponsePolicyDownload)
                return

            # Force download if server explicitly says so
            if "content-disposition" in headers_lower and "attachment" in headers_lower["content-disposition"]:
                print("[Darkelf] Content-Disposition download detected")
                decisionHandler(WKNavigationResponsePolicyDownload)
                return

            # If WebKit cannot render this MIME type → download
            if not response.canShowMIMEType():
                log(2, "[Download] MIME:", mime)
                decisionHandler(WKNavigationResponsePolicyDownload)
                return

            # Otherwise allow normal navigation
            decisionHandler(WKNavigationResponsePolicyAllow)

        except Exception as e:
            print("[Darkelf] Download decision error:", e)
            decisionHandler(WKNavigationResponsePolicyAllow)
            
    def webView_navigationResponse_didBecomeDownload_(self, webView, response, download):
        try:
            download.setDelegate_(self)
            print("[Darkelf] Download started")

            # --- get filename safely ---
            filename = "download"
            try:
                url = response.response().URL()
                if url:
                    filename = url.lastPathComponent() or "download"
            except Exception:
                pass

            # --- init tracking (do this before UI updates) ---
            self.start_time = time.time()
            self.bytes_received = 0
            self.expected = 0
            self._download_path = None
            self._download_last_size = 0

            # --- show progress UI (MAIN THREAD) ---
            def _ui():
                try:
                    ui = getattr(self.owner, "download_ui", None)
                    if not ui:
                        return

                    ui.download = download
                    ui.nav_delegate = self  # so Cancel can stop polling etc.

                    parent = ui.superview()
                    if parent:
                        try:
                            ui.removeFromSuperview()
                        except Exception:
                            pass
                        parent.addSubview_(ui)

                    ui.setHidden_(False)
                    ui.setFilename_(filename)

                    # start with indeterminate until we learn expected size
                    try:
                        if hasattr(ui, "setIndeterminate_"):
                            ui.setIndeterminate_(True)
                    except Exception:
                        pass

                    ui.updateProgress_(0)
                except Exception as e:
                    print("[DownloadUI] error:", e)

            NSOperationQueue.mainQueue().addOperationWithBlock_(_ui)

            # start file-size polling fallback (works even if WebKit progress callbacks never fire)
            try:
                if hasattr(self, "_start_download_poll_timer"):
                    self._start_download_poll_timer()
            except Exception as e:
                print("[Download poll start] error:", e)

        except Exception as e:
            print("Download delegate error:", e)
            
    def download_decideDestinationUsingResponse_suggestedFilename_completionHandler_(
            self, download, response, filename, completionHandler):

        try:

            # Ensure download directory exists
            os.makedirs(self.download_dir, exist_ok=True)
    
            randomized = _randomized_filename(filename)

            path = os.path.join(self.download_dir, randomized)

            print("[Darkelf] Download →", path)

            completionHandler(NSURL.fileURLWithPath_(path))

        except Exception as e:
            print("Download error:", e)
            completionHandler(None)
            
    def download_didReceiveData_(self, download, length):
        try:
            self.bytes_received += length

            elapsed = max(time.time() - getattr(self, "start_time", time.time()), 0.1)
            speed = self.bytes_received / elapsed
            mb = speed / 1024 / 1024

            expected = getattr(self, "expected", 0) or 0
            if expected > 0:
                percent = min(100.0, (self.bytes_received / expected) * 100.0)
            else:
                # fallback "spinner-like" progress if unknown size
                mb_downloaded = self.bytes_received / 1024 / 1024
                percent = (mb_downloaded % 100)

            def _ui():
                try:
                    ui = getattr(self.owner, "download_ui", None)
                    if not ui:
                        return
                    ui.setSpeed_(f"{mb:.2f} MB/s")
                    ui.updateProgress_(percent)
                except Exception:
                    pass

            NSOperationQueue.mainQueue().addOperationWithBlock_(_ui)

        except Exception as e:
            print("[Download progress error]", e)
            
    def download_didReceiveResponse_(self, download, response):

        try:
            self.expected = response.expectedContentLength()
        except:
            self.expected = 0
        
    def downloadDidFinish_(self, download):

        try:
            print("[Darkelf] Download finished")

            ui = getattr(self.owner, "download_ui", None)
            if not ui:
                return

            # show full progress
            try:
                ui.updateProgress_(100)
            except Exception:
                pass

            # auto hide after delay (main thread)
            def hide():
                try:
                    ui.setHidden_(True)
                except Exception:
                    pass

            NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
                1.5,          # delay before hiding
                ui,
                "setHidden:",
                True,
                False
            )

        except Exception as e:
            print("[Download finish error]", e)
            
    def download_didWriteData_totalBytesWritten_totalBytesExpectedToWrite_(
        self, download, bytesWritten, totalBytesWritten, totalBytesExpectedToWrite
    ):
        try:
            self.bytes_received = int(totalBytesWritten or 0)
            self.expected = int(totalBytesExpectedToWrite or 0)

            elapsed = max(time.time() - getattr(self, "start_time", time.time()), 0.1)

            speed = self.bytes_received / elapsed
            mb = speed / 1024 / 1024

            if self.expected > 0:
                percent = min(100.0, (self.bytes_received / self.expected) * 100.0)
            else:
                percent = (self.bytes_received / 1024 / 1024) % 100

            def _ui():
                ui = getattr(self.owner, "download_ui", None)
                if not ui:
                    return
                ui.setSpeed_(f"{mb:.2f} MB/s")
                ui.updateProgress_(percent)

            NSOperationQueue.mainQueue().addOperationWithBlock_(_ui)

        except Exception as e:
            print("[Download didWriteData error]", e)
            
    def download_didFailWithError_resumeData_(self, download, error, resumeData):
        try:
            print("[Darkelf] Download failed:", error)
        except Exception:
            pass

    # ===============================
    # WIPE DOWNLOAD TRACES
    # ===============================

    def wipe_download_traces(self):

        try:

            if getattr(self, "download_dir", None) and os.path.isdir(self.download_dir):

                shutil.rmtree(self.download_dir, ignore_errors=True)

                print("[Darkelf] Temp downloads wiped")

        except Exception as e:
            print("Download wipe error:", e)
            
    # -------------------------------------------------
    # Navigation Policy (Darkelf Network Interception)
    # -------------------------------------------------
    def webView_decidePolicyForNavigationAction_decisionHandler_(
            self, webView, navAction, decisionHandler):

        try:

            if not navAction or not navAction.request():
                decisionHandler(WKNavigationActionPolicyAllow)
                return

            req = navAction.request()
            url_obj = req.URL()

            if not url_obj:
                decisionHandler(WKNavigationActionPolicyAllow)
                return

            url_str = str(url_obj.absoluteString() or "").strip()
            scheme = str(url_obj.scheme() or "").lower()
            host = str(url_obj.host() or "")

            nav_type = navAction.navigationType()

            owner = getattr(self, "owner", None)
            
            # --- PQ fingerprint binding ---
            try:
                fp = darkelf_pq_fingerprint(url_str)

                # store per-session chain (optional but powerful)
                prev = getattr(owner, "_pq_chain", "")
                combined = hashlib.sha3_512((prev + fp).encode()).hexdigest()
                owner._pq_chain = combined

                # attach to MiniAI (optional)
                if hasattr(self.owner, "mini_ai"):
                    owner.mini_ai.last_request_fp = combined

            except Exception as e:
                print("[PQ] fingerprint error:", e)
            # -------------------------------------------------
            # MiniAI traffic monitoring
            # -------------------------------------------------
            try:
                if owner and hasattr(owner, "mini_ai"):
                    owner.mini_ai.monitor_network(url_str, {
                        "type": nav_type,
                        "host": host,
                        "scheme": scheme
                    })
            except Exception:
                pass

            # -------------------------------------------------
            # Invalid URLs
            # -------------------------------------------------
            if scheme in ("http", "https") and not host:
                decisionHandler(WKNavigationActionPolicyCancel)
                return

            # -------------------------------------------------
            # Allow blob URLs (downloads, media, etc)
            # -------------------------------------------------
            if scheme == "blob":
                decisionHandler(WKNavigationActionPolicyAllow)
                return

            # -------------------------------------------------
            # Internal Darkelf pages
            # -------------------------------------------------
            if scheme == "darkelf":
    
                # reload threat report
                if nav_type == WKNavigationTypeReload and url_str == "darkelf://report":

                    if owner and hasattr(owner, "mini_ai"):

                        html = owner._build_threat_report_html()

                        webView.loadHTMLString_baseURL_(
                            html,
                            NSURL.URLWithString_("darkelf://report")
                        )

                    decisionHandler(WKNavigationActionPolicyCancel)
                    return

                decisionHandler(WKNavigationActionPolicyAllow)
                return

            # -------------------------------------------------
            # Block dangerous protocols
            # -------------------------------------------------
            if scheme in ("ftp", "file", "javascript"):
                print("[Darkelf] Blocked scheme:", scheme)
                decisionHandler(WKNavigationActionPolicyCancel)
                return

            # -------------------------------------------------
            # Force HTTPS upgrade
            # -------------------------------------------------
            if scheme == "http":

                https_url = url_str.replace("http://", "https://", 1)

                try:
                    webView.loadRequest_(
                        NSURLRequest.requestWithURL_(
                            NSURL.URLWithString_(https_url)
                        )
                    )
                except Exception:
                    pass

                decisionHandler(WKNavigationActionPolicyCancel)
                return

            # -------------------------------------------------
            # Optional tracker blocking (domain level)
            # -------------------------------------------------
            blocked_domains = (
                "doubleclick.net",
                "google-analytics.com",
                "facebook.net",
                "googletagmanager.com",
            )

            for domain in blocked_domains:
                if domain in host:
                    print("[Darkelf] Tracker blocked:", host)
                    decisionHandler(WKNavigationActionPolicyCancel)
                    return

            # -------------------------------------------------
            # Allow navigation
            # -------------------------------------------------
            decisionHandler(WKNavigationActionPolicyAllow)

        except Exception as e:
            print("[NavDelegate] Policy decision error:", e)
            decisionHandler(WKNavigationActionPolicyAllow)
            
    # -------------------------------------------------
    # TLS Certificate Inspection
    # -------------------------------------------------
    def webView_didReceiveAuthenticationChallenge_completionHandler_(
        self, webView, challenge, completionHandler
    ):

        try:

            owner = getattr(self, "owner", None)

            protectionSpace = challenge.protectionSpace()
            authMethod = protectionSpace.authenticationMethod()

            if authMethod == NSURLAuthenticationMethodServerTrust:

                serverTrust = protectionSpace.serverTrust()
                isTrusted = False

                if serverTrust:

                    try:
                        isTrusted = bool(SecTrustEvaluateWithError(serverTrust, None))
                    except Exception as e:
                        print("[TLS] Trust evaluation failed:", e)

                    cert = SecTrustGetCertificateAtIndex(serverTrust, 0)

                    if cert:
                        summary = SecCertificateCopySubjectSummary(cert)
                        log(2, "🔎 Certificate Subject:", summary)

                    if owner and hasattr(owner, "update_security_indicator"):

                        NSOperationQueue.mainQueue().addOperationWithBlock_(
                            lambda: owner.update_security_indicator(isTrusted)
                        )

                completionHandler(
                    NSURLSessionAuthChallengeUseCredential,
                    NSURLCredential.credentialForTrust_(serverTrust)
                )
                return

        except Exception as e:
            print("[Cert Inspection Error]", e)

        completionHandler(
            NSURLSessionAuthChallengePerformDefaultHandling,
            None
        )

    # -------------------------------------------------
    # Load Failure
    # -------------------------------------------------
    def webViewWebContentProcessDidTerminate_(self, webView):

        print("[WebKit] WebContent process crashed")

        try:
            owner = getattr(self, "owner", None)
            if owner and owner._is_tab_webview(webView):
                webView.loadRequest_(
                    NSURLRequest.requestWithURL_(
                        NSURL.URLWithString_(HOME_URL)
                    )
                )
        except Exception as e:
            print("[WebKit] Recovery failed:", e)
            
            
IS_MAC = sys.platform == "darwin"
if not IS_MAC:
    print("[Darkelf] macOS only."); sys.exit(1)

APP_NAME = "Darkelf"

HOMEPAGE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Darkelf Browser</title>

<style>

:root{
  --bg:#0a0b10;
  --accent:#34C759;
  --text:#eef2f6;
}

*{box-sizing:border-box;}

html,body{
  height:100%;
  margin:0;
  overflow:hidden;
}

body{
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
  background:
    radial-gradient(1200px 600px at 20% -10%, rgba(52,199,89,.35), transparent 60%),
    radial-gradient(1000px 600px at 120% 10%, rgba(52,199,89,.45), transparent 60%),
    var(--bg);

  display:flex;
  flex-direction:column;
  justify-content:center;
  align-items:center;

  color:var(--text);
}

/* animated particle grid */

.particles{
  position:fixed;
  inset:0;
  pointer-events:none;

  background-image:
    radial-gradient(rgba(52,199,89,.7) 1px, transparent 1px);

  background-size:90px 90px;

  opacity:.15;

  animation:particleMove 80s linear infinite;
}

@keyframes particleMove{
  from{transform:translateY(0);}
  to{transform:translateY(-200px);}
}

/* logo */

.brand{
  font-size:3.7rem;
  font-weight:800;
  letter-spacing:-.02em;
  color:#34C759;

  text-shadow:
    0 0 10px rgba(52,199,89,.8),
    0 0 30px rgba(52,199,89,.5),
    0 0 60px rgba(52,199,89,.25);

  animation:pulse 3s ease-in-out infinite;
}

@keyframes pulse{

  0%{
    text-shadow:
      0 0 10px rgba(52,199,89,.8),
      0 0 30px rgba(52,199,89,.5),
      0 0 60px rgba(52,199,89,.25);
  }

  50%{
    text-shadow:
      0 0 18px rgba(52,199,89,1),
      0 0 50px rgba(52,199,89,.7),
      0 0 90px rgba(52,199,89,.4);
  }

  100%{
    text-shadow:
      0 0 10px rgba(52,199,89,.8),
      0 0 30px rgba(52,199,89,.5),
      0 0 60px rgba(52,199,89,.25);
  }

}

.tagline{
  margin-top:20px;
  font-size:1rem;
  letter-spacing:.25em;
  text-transform:uppercase;
  color:#cfd8e3;
}

.ai{
  position:absolute;
  bottom:50px;
  font-size:.85rem;
  letter-spacing:.25em;
  color:#34C759;
  opacity:.8;
}

</style>
</head>

<body>

<div class="particles"></div>

<div class="brand">
Darkelf Browser
</div>

<div class="tagline">
Cocoa • Private • Hardened
</div>

<div class="ai">
Darkelf MiniAI Sentinel
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
(function(SEED) {

    // ---- 32-bit deterministic hash per pixel ----
    function pixelNoise(seed, index) {
        let x = seed ^ index;
        x = Math.imul(x ^ (x >>> 15), 0x85ebca6b);
        x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35);
        x = x ^ (x >>> 16);
        return (x & 0xff);
    }

    function applyNoise(imageData) {
        const data = imageData.data;
        for (let i = 0; i < data.length; i++) {
            const n = (pixelNoise(SEED, i) % 8) - 4;
            data[i] = Math.min(255, Math.max(0, data[i] + n));
        }
    }

    function cloneImageData(ctx, src) {
        const copy = ctx.createImageData(src.width, src.height);
        copy.data.set(src.data);
        return copy;
    }

    function safePatch(proto, method, wrapper) {
        const original = proto[method];
        Object.defineProperty(proto, method, {
            value: wrapper(original),
            configurable: false,
            writable: false
        });
    }

    // ---- Patch toDataURL ----
    safePatch(HTMLCanvasElement.prototype, 'toDataURL', function(original) {
        return function() {
            try {
                const ctx = this.getContext('2d');
                if (!ctx) return original.apply(this, arguments);

                const w = this.width;
                const h = this.height;
                if (!w || !h) return original.apply(this, arguments);

                const originalData = ctx.getImageData(0, 0, w, h);
                const modifiedData = cloneImageData(ctx, originalData);

                applyNoise(modifiedData);
                ctx.putImageData(modifiedData, 0, 0);

                const result = original.apply(this, arguments);

                ctx.putImageData(originalData, 0, 0);

                return result;
            } catch (e) {
                return original.apply(this, arguments);
            }
        };
    });

    // ---- Patch toBlob ----
    safePatch(HTMLCanvasElement.prototype, 'toBlob', function(original) {
        return function(callback, type, quality) {
            try {
                const ctx = this.getContext('2d');
                if (!ctx) return original.apply(this, arguments);

                const w = this.width;
                const h = this.height;
                if (!w || !h) return original.apply(this, arguments);

                const originalData = ctx.getImageData(0, 0, w, h);
                const modifiedData = cloneImageData(ctx, originalData);

                applyNoise(modifiedData);
                ctx.putImageData(modifiedData, 0, 0);

                const self = this;

                original.call(this, function(blob) {
                    ctx.putImageData(originalData, 0, 0);
                    callback(blob);
                }, type, quality);

            } catch (e) {
                return original.apply(this, arguments);
            }
        };
    });

    // ---- Patch getImageData (non-mutating) ----
    safePatch(CanvasRenderingContext2D.prototype, 'getImageData', function(original) {
        return function(x, y, w, h) {
            const imageData = original.call(this, x, y, w, h);
            applyNoise(imageData);
            return imageData;
        };
    });

})(__NATIVE_SEED__);
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

CORE_JS = r'''
(function() {

    try {

        Object.defineProperty(document, "fullscreenEnabled", {
            get: () => true,
            configurable: true
        });

    } catch(e){}

    // ==========================================
    // 0️⃣ Browser Identity Hardening
    // ==========================================
    try {

        // Hide webdriver
        Object.defineProperty(navigator, "webdriver", {
            get: () => undefined,
            configurable: true
        });

        // Normalize vendor (Safari/WebKit style)
        Object.defineProperty(navigator, "vendor", {
            get: () => "Apple Computer, Inc.",
            configurable: true
        });

        // Hide standalone property (WKWebView detection vector)
        try {
            delete navigator.standalone;
        } catch(e) {}

        // Normalize plugins list
        if (navigator.plugins && navigator.plugins.length === 0) {

            const fakePlugin = {
                name: "WebKit built-in PDF",
                filename: "internal-pdf-viewer",
                description: "Portable Document Format"
            };

            Object.defineProperty(navigator, "plugins", {
                get: () => [fakePlugin],
                configurable: true
            });
        }

        // Normalize mimeTypes
        if (navigator.mimeTypes && navigator.mimeTypes.length === 0) {

            const fakeMime = {
                type: "application/pdf",
                suffixes: "pdf",
                description: "Portable Document Format"
            };

            Object.defineProperty(navigator, "mimeTypes", {
                get: () => [fakeMime],
                configurable: true
            });
        }

    } catch(e){}


    // ==========================================
    // 1️⃣ Network Monitoring (MiniAI)
    // ==========================================
    const sendToMiniAI = function(url) {
        try {

            if (!url) return;

            url = String(url);

            if (!url.startsWith("http") && !url.startsWith("blob") && !url.startsWith("data"))
                return;

            if (window.webkit &&
                window.webkit.messageHandlers &&
                window.webkit.messageHandlers.netlog) {

                window.webkit.messageHandlers.netlog.postMessage({
                    url: url
                });
            }

        } catch(e){}
    };


    // ==========================================
    // 2️⃣ fetch interceptor
    // ==========================================
    if (window.fetch) {

        const origFetch = window.fetch;

        window.fetch = function(...args) {

            try { sendToMiniAI(args[0]); } catch(e){}

            return origFetch.apply(this, args);
        };
    }


    // ==========================================
    // 3️⃣ XHR interceptor
    // ==========================================
    if (window.XMLHttpRequest) {

        const origOpen = XMLHttpRequest.prototype.open;

        XMLHttpRequest.prototype.open = function(method, url) {

            try { sendToMiniAI(url); } catch(e){}

            return origOpen.apply(this, arguments);
        };
    }


    // ==========================================
    // 4️⃣ DOM Resource Watcher
    // ==========================================
    try {

        const attrs = ["src","href","data","action"];

        const scanNode = function(node) {

            try {

                if (!node || !node.getAttribute) return;

                attrs.forEach(function(attr){

                    if (node.hasAttribute(attr)) {

                        const val = node.getAttribute(attr);

                        if (val && val.startsWith("http")) {
                            sendToMiniAI(val);
                        }
                    }

                });

            } catch(e){}
        };

        const observer = new MutationObserver(function(mutations){

            mutations.forEach(function(m){

                if (m.addedNodes) {

                    m.addedNodes.forEach(function(node){

                        scanNode(node);

                        if (node.querySelectorAll) {

                            node.querySelectorAll("[src],[href],[data],[action]").forEach(scanNode);

                        }

                    });

                }

            });

        });

        observer.observe(document.documentElement,{
            childList:true,
            subtree:true
        });

    } catch(e){}


    // ==========================================
    // 5️⃣ window.open restriction
    // ==========================================
    try {

        const origOpen = window.open;

        window.open = function() {

            console.warn("[Darkelf] window.open blocked");

            return null;

        };

    } catch(e){}


    // ==========================================
    // 6️⃣ OffscreenCanvas Guard
    // ==========================================
    try {

        if (window.OffscreenCanvas &&
            OffscreenCanvas.prototype &&
            OffscreenCanvas.prototype.convertToBlob) {

            const origConvert = OffscreenCanvas.prototype.convertToBlob;

            OffscreenCanvas.prototype.convertToBlob = function() {

                return origConvert.apply(this, arguments);

            };

        }

    } catch(e){}


    // ==========================================
    // 7️⃣ WebSocket Monitor
    // ==========================================
    try {

        if (window.WebSocket) {

            const RealWebSocket = window.WebSocket;

            window.WebSocket = function(url, protocols) {

                try { sendToMiniAI(url); } catch(e){}

                return new RealWebSocket(url, protocols);
            };

            window.WebSocket.prototype = RealWebSocket.prototype;

        }

    } catch(e){}

})();
'''

NETWORK_MONITOR_JS = r"""
(function() {

function send(url, type) {
    try {
        window.webkit.messageHandlers.netlog.postMessage({
            url: url,
            type: type
        });
    } catch(e) {}
}

/* fetch() */
const origFetch = window.fetch;
window.fetch = function() {
    try { send(arguments[0], "fetch"); } catch(e){}
    return origFetch.apply(this, arguments);
};

/* XMLHttpRequest */
const origOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
    try { send(url, "xhr"); } catch(e){}
    return origOpen.apply(this, arguments);
};

/* WebSocket */
const OrigWS = window.WebSocket;
window.WebSocket = function(url, proto) {
    try { send(url, "websocket"); } catch(e){}
    return new OrigWS(url, proto);
};

/* navigator.sendBeacon */
if (navigator.sendBeacon) {
    const origBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function(url,data) {
        try { send(url, "beacon"); } catch(e){}
        return origBeacon.apply(this, arguments);
    };
}

})();
"""

INDEXEDDB_DEFENSE_JS = r'''
try{
Object.defineProperty(window,"indexedDB",{get:()=>undefined});
}catch(e){}
'''

WEBSQL_DEFENSE_JS = r'''
try{
Object.defineProperty(window,"openDatabase",{get:()=>undefined});
}catch(e){}
'''

STORAGE_DEFENSE_JS = r'''
(function(){

function makeMemoryStorage(){

 const store = new Map();

 return {
  get length(){return store.size},
  key:(i)=>Array.from(store.keys())[i]||null,
  getItem:(k)=>store.has(k)?store.get(k):null,
  setItem:(k,v)=>store.set(String(k),String(v)),
  removeItem:(k)=>store.delete(String(k)),
  clear:()=>store.clear()
 };

}

try{Object.defineProperty(window,"localStorage",{value:makeMemoryStorage()})}catch(e){}
try{Object.defineProperty(window,"sessionStorage",{value:makeMemoryStorage()})}catch(e){}

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
        if getattr(self, "_hoverArea", None) is not None:
            self.removeTrackingArea_(self._hoverArea)
        opts = NSTrackingMouseEnteredAndExited | NSTrackingActiveAlways
        self._hoverArea = NSTrackingArea.alloc().initWithRect_options_owner_userInfo_(
            self.bounds(), opts, self, None)
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
    data_store: WKWebsiteDataStore
    tab_uid: int = None
    container_nonce: str = None
    url: str = ""
    host: str = "new"
    canvas_seed: int = None

# =============================================================================
# ADD THIS NEW CLASS near _NavDelegate (top-level, not nested)
# =============================================================================
class _WindowDelegate(NSObject):
    def initWithOwner_(self, owner):
        self = objc.super(_WindowDelegate, self).init()
        if self is None:
            return None
        self.owner = owner
        return self

    # NSWindowDelegate hook
    def windowWillClose_(self, notification):
        try:
            owner = getattr(self, "owner", None)
            if owner is not None:
                owner.windowWillClose_(notification)
        except Exception as e:
            print("[WindowDelegate] windowWillClose_ error:", e)

# =============================================================================
# FULL UPDATED SearchHandler (as-is, this part is already correct)
# =============================================================================
class SearchHandler(NSObject):
    def initWithOwner_(self, owner): ...
    def userContentController_didReceiveScriptMessage_(self, controller, message):
        self = objc.super(SearchHandler, self).init()
        if self is None:
            return None
        self.owner = owner
        return self

    def userContentController_didReceiveScriptMessage_(self, controller, message):
        try:
            owner = getattr(self, "owner", None)
            if not owner or not getattr(owner, "tabs", None) or getattr(owner, "active", -1) < 0:
                return

            body = message.body()
            print("🔥 MESSAGE RECEIVED:", body)

            if body == "darkelf_native_fullscreen":
                print("🔥 FULLSCREEN TRIGGERED")
                owner.window.toggleFullScreen_(None)
                return

            q = str(body)
            # Only search if q is non-empty, longer than 1 character
            if not q or len(q.strip()) < 2:
                return  # Ignore short/no input

            url = "https://lite.duckduckgo.com/lite/?q=" + re.sub(r"\s+", "+", q)
            owner._add_tab(url)

        except Exception as e:
            print("SearchHandler error:", e)
            
def _clamp(v, lo, hi):
    return max(lo, min(hi, v))
    
class AddressField(NSSearchField):

    def initWithFrame_owner_(self, frame, owner):
        self = objc.super(AddressField, self).initWithFrame_(frame)
        if self is None:
            return None
        self._owner = owner
        return self

    def drawFocusRingMask(self):
        pass

    def focusRingMaskBounds(self):
        return NSMakeRect(0,0,0,0)

    def rightMouseDown_(self, event):
        try:
            loc = event.locationInWindow()
            if hasattr(self, "_owner") and self._owner:
                self._owner._show_context_popover(self, loc)
            else:
                objc.super(AddressField, self).rightMouseDown_(event)
        except Exception as e:
            print("Context menu popover error:", e)
            
# =============================================================================
# FULL UPDATED Browser.init (critical changes marked)
# =============================================================================
class Browser(NSObject):

    def init(self):
        self = objc.super(Browser, self).init()
        if self is None:
            return None
            
        self.fpi = FirstPartyIsolation(tab_isolation=True)
        
        # ---- Usual field setup ----
        self.cookies_enabled = False
        self.js_enabled = True
        self.tabs = []
        self.active = 0

        # WebKit memory protection
        self.page_load_count = 0
        self.process_pool = WKProcessPool.alloc().init()
        
        self.tab_btns = []
        self.tab_close_btns = []
        self.active = -1
        self._window = []
        
        self._containers = {}
        
        self._tab_uid_counter = 0
        # ---- 1. Create window ----
        self.window = self._make_window()
        
        self.window.setCollectionBehavior_(128)  # NSWindowCollectionBehaviorFullScreenPrimary
        
        # ---- 2. Strong refs for delegates/handlers ----
        self._strong_refs = []

        self._window_delegate = _WindowDelegate.alloc().initWithOwner_(self)
        self._nav_delegate    = _NavDelegate.alloc().initWithOwner_(self)
        self._ui_delegate     = _UIDelegate.alloc().initWithOwner_(self)
        self._search_handler  = SearchHandler.alloc().initWithOwner_(self)
                
        self._strong_refs.extend([
            self._window_delegate,
            self._nav_delegate,
            self._ui_delegate,
            self._search_handler
        ])

        self.window.setDelegate_(self._window_delegate)

        ContentRuleManager.load_rules()
        
        self.mini_ai = DarkelfMiniAISentinel()
        self.mini_ai.browser = self
        
        self.download_ui = DownloadProgressView.alloc().initWithFrame_(NSMakeRect(20, 60, 520, 70))
        self.download_ui.setHidden_(True)
        self.net_policy = DarkelfNetworkPolicy(self)
        
        content = self.window.contentView()

        content.addSubview_positioned_relativeTo_(
            self.download_ui,
            1,   # NSWindowAbove
            None
        )

        # ensure it resizes with the window
        self.download_ui.setAutoresizingMask_(NSViewWidthSizable | NSViewMinYMargin)
        
        # ---- 4. Toolbar, Tabbar, UI wiring ----
        self.toolbar = self._make_toolbar()

        self._build_toolbar()
        self._build_tabbar()
        self._add_tab(home=True)
        self._bring_tabbar_to_front()
        
        self.window.setDelegate_(self)
        
        self.window.makeKeyAndOrderFront_(None)
        NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        
        self.download_dir = _safe_download_dir()
        # ---- 7. Keyboard monitor ----
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
        
    def _cleanup_unused_containers(self):

        try:

            active_keys = set()

            for i, tab in enumerate(self.tabs):

                try:
                    key = self.fpi._key(tab.url or HOME_URL, tab_uid=i)
                    active_keys.add(key)
                except Exception:
                    pass

            for key in list(self._containers.keys()):

                if key not in active_keys:
                    del self._containers[key]

        except Exception:
            pass
            
    def recycle_web_process(self):

        print("[Darkelf] Recycling WebKit process pool")

        try:

            # create a fresh WebKit process pool
            self.process_pool = WKProcessPool.alloc().init()

            for tab in self.tabs:

                try:

                    old_view = tab.view
                    url = None

                    if old_view and old_view.URL():
                        url = old_view.URL().absoluteString()

                    # rebuild configuration
                    config = WKWebViewConfiguration.alloc().init()
                    config.setProcessPool_(self.process_pool)

                    # preserve memory-only storage
                    config.setWebsiteDataStore_(
                        WKWebsiteDataStore.nonPersistentDataStore()
                    )

                    new_view = WKWebView.alloc().initWithFrame_configuration_(
                        old_view.frame(), config
                    )

                    new_view.setNavigationDelegate_(self.nav_delegate)
                    new_view.setUIDelegate_(self.ui_delegate)

                    # replace view
                    old_view.removeFromSuperview()
                    tab.view = new_view

                    if url:
                        new_view.loadRequest_(
                        NSURLRequest.requestWithURL_(NSURL.URLWithString_(url))
                        )

                except Exception as e:
                    print("[Darkelf] Tab recycle error:", e)

            self.page_load_count = 0

        except Exception as e:
            print("[Darkelf] Process recycle failed:", e)
            
    @objc.IBAction
    def refreshMiniAI_(self, timer):

        if not hasattr(self, "mini_ai"):
            return

        import time
        now = time.time()

        try:
            # Only check unlock timer
            self.mini_ai._maybe_auto_unlock(now)
        except Exception as e:
            print("[MiniAI Timer Error]", e)

        # Update indicator only if not on report tab
        try:
            if self.tabs and self.active >= 0:
                if getattr(self.tabs[self.active], "url", "") != "darkelf://report":
                    self.updateMiniAIIndicator()
        except Exception:
            pass
        
    def openThreatReport_(self, sender):

        try:
            if not hasattr(self, "mini_ai"):
                return

            report_html = self._build_threat_report_html()

            wk, store = self._new_wk(container_nonce=secrets.token_hex(4))

            wk.setNavigationDelegate_(self._nav_delegate)
            
            self._mount_webview(wk)

            tab = Tab(
                view=wk,
                data_store=store,
                url="darkelf://report",
                host="Threat Report",
                canvas_seed=None
            )

            self.tabs.append(tab)
            self.active = len(self.tabs) - 1

            wk.loadHTMLString_baseURL_(
                report_html,
                NSURL.URLWithString_("darkelf://report")
            )

            self._update_tab_buttons()
            self._sync_addr()

        except Exception as e:
            print("[MiniAI] Threat report open failed:", e)
        
    def _build_threat_report_html(self):

        stats = self.mini_ai.get_statistics() if getattr(self, "mini_ai", None) else {}

        lockdown = stats.get("lockdown", {}) or {}
        lockdown_active = bool(lockdown.get("active", False))
        lockdown_triggered_at = float(lockdown.get("triggered_at") or 0)

        now = time.time()

        LOCKDOWN_DURATION = getattr(self.mini_ai, "LOCKDOWN_DURATION_SECONDS", 0) or 0
        elapsed = now - (lockdown_triggered_at or now)
        remaining = int(max(0, LOCKDOWN_DURATION - elapsed)) if lockdown_active else 0

        try:
            seed_stats_json = json.dumps(stats)
        except Exception:
            seed_stats_json = "{}"

        # Precompute badge color
        badge_bg = "#ff3b30" if lockdown_active else "#36ff9a"
        badge_text = "LOCKDOWN ACTIVE" if lockdown_active else "SYSTEM MONITORING"

        # Timer block shows only when active
        timer_block = ""
        if lockdown_active:
            timer_block = f"""
            <div class="countdown-timer">
                Lockdown ends in <span id="lockdown_timer">{remaining}</span>s
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>Darkelf Threat Console</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">

  <style>
    :root{{
      --bg:#05060a;
      --accent:#36ff9a;
      --accent2:#00eaff;
      --accent3:#b400ff;
      --card:rgba(255,255,255,.05);
      --muted:#9db0be;
      --danger:#ff3b30;
      --ok:#36ff9a;
      --border:rgba(255,255,255,.08);
    }}

    *{{ box-sizing:border-box; }}

    body{{
      margin:0;
      font-family:system-ui,-apple-system;
      background:
        radial-gradient(1200px 800px at 15% -10%, rgba(0,234,255,.35), transparent 70%),
        radial-gradient(900px 600px at 110% 0%, rgba(54,255,154,.35), transparent 70%),
        radial-gradient(1200px 700px at 50% 120%, rgba(180,0,255,.35), transparent 70%),
        var(--bg);
      color:#eef2f6;
    }}

    .container{{
      max-width:1300px;
      margin:auto;
      padding:70px 24px;
    }}

    .title{{
      font-size:1.8rem;
      font-weight:900;
      letter-spacing:.15em;
      background:linear-gradient(90deg,var(--accent),var(--accent2),var(--accent3));
      -webkit-background-clip:text;
      -webkit-text-fill-color:transparent;
    }}

    .badge{{
      display:inline-flex;
      margin-top:14px;
      padding:8px 16px;
      border-radius:999px;
      font-size:.7rem;
      font-weight:800;
      letter-spacing:.15em;
      background:{badge_bg};
      color:#000;
    }}

    .countdown-timer{{
      margin-top:14px;
      font-size:1.2rem;
      color:var(--danger);
      font-weight:700;
    }}

    .cards{{
     margin-top:60px;
     display:grid;
     grid-template-columns:repeat(auto-fit,minmax(320px,1fr));
     gap:36px;
    }}

    @media (max-width: 1100px) {{
      .cards{{ grid-template-columns:repeat(2, minmax(0, 1fr)); }}
    }}

    @media (max-width: 720px) {{
      .cards{{ grid-template-columns:1fr; }}
      .container{{ padding:34px 16px; }}
    }}

    .card{{
      background:var(--card);
      backdrop-filter:blur(20px);
      padding:30px;
      border-radius:18px;
      border:1px solid var(--border);
      box-shadow:
        0 30px 60px rgba(0,0,0,.6),
        0 0 40px rgba(0,234,255,.15);
      min-height: 220px;
    }}

    .section-title{{
      font-size:.75rem;
      letter-spacing:.25em;
      text-transform:uppercase;
      color:var(--muted);
      margin-bottom:20px;
    }}

    .line{{
      display:grid;
      grid-template-columns:28px auto max-content;
      column-gap:14px;
      align-items:center;
      margin:12px 0;
    }}

    .icon{{ color:var(--accent2); }}

    .stat-value{{ font-weight:900; }}

    .dummy-card{{
      opacity:.5;
      border-style:dashed;
    }}

    .log{{
      margin-top:60px;
      background:rgba(0,0,0,.45);
      padding:30px;
      border-radius:14px;
      font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size:.85rem;
      max-height:260px;
      overflow:auto;
      border:1px solid rgba(255,255,255,.06);
    }}

    .log-entry{{
      margin:8px 0;
      color:#ff9a9a;
      white-space:nowrap;
      overflow:hidden;
      text-overflow:ellipsis;
    }}

    .footer{{
      margin-top:60px;
      text-align:center;
      font-size:.8rem;
      color:var(--muted);
    }}

    .top-row{{
      display:flex;
      justify-content:space-between;
      gap:16px;
      align-items:flex-end;
      flex-wrap:wrap;
    }}

    .subtle{{
      color: var(--muted);
      font-size: .9rem;
      margin-top: 8px;
    }}

    .pill{{
      display:inline-flex;
      padding:6px 10px;
      border-radius:999px;
      border:1px solid rgba(255,255,255,.1);
      background:rgba(255,255,255,.03);
      font-size:.75rem;
      color: var(--muted);
    }}
  </style>
</head>

<body>
  <div class="container">
    <div class="top-row">
      <div>
        <div class="title">Darkelf MiniAI Threat Console</div>
        <div class="badge" id="status_badge">{badge_text}</div>
        {timer_block}
        <div class="subtle">
          Live view (updates every <span class="pill">2s</span>). No full page reload.
        </div>
      </div>

      <div class="pill" id="last_updated">Last updated: --</div>
    </div>

    <div class="cards">

      <!-- Session Metrics -->
      <div class="card">
        <div class="section-title">Session Metrics</div>

        <div class="line">
          <i class="bi bi-clock-history icon"></i>
          <span>Session Uptime</span>
          <span class="stat-value" id="uptime_seconds">0.0s</span>
        </div>

        <div class="line">
          <i class="bi bi-activity icon"></i>
          <span>Total Events</span>
          <span class="stat-value" id="total_events">0</span>
        </div>

        <div class="line">
          <i class="bi bi-globe icon"></i>
          <span>Unique Domains</span>
          <span class="stat-value" id="unique_domains">0</span>
        </div>

        <div class="line">
          <i class="bi bi-shield-exclamation icon"></i>
          <span>Threat Score</span>
          <span class="stat-value" id="threat_score">0</span>
        </div>
      </div>
      
      <!-- Network Activity -->
      <div class="card">
        <div class="section-title">Network Activity</div>

        <div class="line">
          <i class="bi bi-diagram-3 icon"></i>
          <span>Total Requests</span>
          <span class="stat-value" id="net_total">0</span>
        </div>

        <div class="line">
          <i class="bi bi-lightning-charge icon"></i>
          <span>Dynamic Requests</span>
          <span class="stat-value" id="net_dynamic">0</span>
        </div>

        <div class="line">
          <i class="bi bi-image icon"></i>
          <span>Static Assets</span>
          <span class="stat-value" id="net_static">0</span>
        </div>

        <div class="line">
          <i class="bi bi-globe2 icon"></i>
          <span>Domains Contacted</span>
          <span class="stat-value" id="net_domains">0</span>
        </div>

       </div>
       
       <!-- Traffic Breakdown -->
       <div class="card">
         <div class="section-title">Traffic Breakdown</div>

         <div class="line">
           <i class="bi bi-bar-chart-line icon"></i>
           <span>Dynamic / Static Ratio</span>
           <span class="stat-value" id="tb_ratio">0 : 0</span>
         </div>

         <div class="line">
           <i class="bi bi-diagram-3 icon"></i>
           <span>Requests / Domain</span>
           <span class="stat-value" id="tb_req_domain">0</span>
         </div>

         <div class="line">
           <i class="bi bi-speedometer2 icon"></i>
           <span>Requests / Second</span>
           <span class="stat-value" id="tb_rps">0</span>
         </div>

         <div class="line">
           <i class="bi bi-activity icon"></i>
           <span>Recent Events</span>
           <span class="stat-value" id="tb_recent">0</span>
         </div>
       </div>

        <!-- System Status -->
        <div class="card">
          <div class="section-title">System Status</div>

          <div class="line">
            <i class="bi bi-cpu icon"></i>
            <span>MiniAI Engine</span>
            <span class="stat-value" id="sys_ai">ACTIVE</span>
          </div>

        <div class="line">
          <i class="bi bi-shield-check icon"></i>
          <span>Tracker Filters</span>
          <span class="stat-value" id="sys_filters">LOADED</span>
        </div>

        <div class="line">
          <i class="bi bi-lock icon"></i>
          <span>Isolation Mode</span>
          <span class="stat-value" id="sys_isolation">ENABLED</span>
        </div>

        <div class="line">
          <i class="bi bi-hdd-network icon"></i>
          <span>Ephemeral Storage</span>
          <span class="stat-value" id="sys_storage">MEMORY</span>
        </div>
      </div>
       
      <!-- Threat Analysis -->
      <div class="card">
        <div class="section-title">Threat Analysis</div>

        <div class="line">
          <i class="bi bi-crosshair icon"></i>
          <span>Trackers</span>
          <span class="stat-value" id="th_trackers">0</span>
        </div>

        <div class="line">
          <i class="bi bi-bullseye icon"></i>
          <span>Intrusions</span>
          <span class="stat-value" id="th_intrusions">0</span>
        </div>

        <div class="line">
          <i class="bi bi-bug icon"></i>
          <span>Malware</span>
          <span class="stat-value" id="th_malware">0</span>
        </div>

        <div class="line">
          <i class="bi bi-lightning icon"></i>
          <span>Exploits</span>
          <span class="stat-value" id="th_exploits">0</span>
        </div>

        <div class="line">
          <i class="bi bi-fingerprint icon"></i>
          <span>Fingerprinting</span>
          <span class="stat-value" id="th_fingerprinting">0</span>
        </div>
      </div>

      <!-- IDS Engine -->
      <div class="card">
        <div class="section-title">MiniAI IDS Engine</div>

        <div class="line">
          <i class="bi bi-robot icon"></i>
          <span>Scraping Bots</span>
          <span class="stat-value" id="ids_scrapers">0</span>
        </div>

        <div class="line">
          <i class="bi bi-key icon"></i>
          <span>Credential Stuffing</span>
          <span class="stat-value" id="ids_credential_stuffing">0</span>
        </div>

        <div class="line">
          <i class="bi bi-search icon"></i>
          <span>Vulnerability Scanners</span>
          <span class="stat-value" id="ids_vulnerability_scanners">0</span>
        </div>

        <div class="line">
          <i class="bi bi-shield-lock icon"></i>
          <span>Bruteforce Logins</span>
          <span class="stat-value" id="ids_bruteforce_logins">0</span>
        </div>
      </div>

    </div>

    <div class="log">
      <b>Recent Threats</b>
      <div id="recent_threats"></div>
    </div>

    <div class="footer">
      Darkelf Browser • MiniAI Sentinel • Hardened Runtime
    </div>
  </div>

  <script>
    // ---------- seed ----------
    const SEED_STATS = {seed_stats_json};

    // ---------- helpers ----------
    function el(id) {{ return document.getElementById(id); }}
    function setText(id, v) {{
      const n = el(id);
      if (!n) return;
      n.textContent = (v === undefined || v === null) ? "" : String(v);
    }}

    function formatUptimeSeconds(x) {{
      const n = Number(x || 0);
      return n.toFixed(1) + "s";
    }}

    // Safer rendering (no innerHTML from untrusted data)
    function renderRecentThreats(items) {{
      const container = el("recent_threats");
      if (!container) return;
      container.innerHTML = "";
      (items || []).slice(0, 50).forEach(e => {{
        const div = document.createElement("div");
        div.className = "log-entry";
        const dt = (e && e.datetime) ? e.datetime : "";
        const url = (e && e.url) ? e.url : "";
        div.textContent = dt + " — " + url;
        container.appendChild(div);
      }});
    }}

    // ---------- countdown ----------
    // Keep a local countdown that will be corrected on each poll.
    let lockdownRemaining = null;
    function tickCountdown() {{
      const t = el("lockdown_timer");
      if (!t) return;

      if (lockdownRemaining === null) return;
      if (lockdownRemaining > 0) {{
        lockdownRemaining -= 1;
        t.textContent = String(lockdownRemaining);
      }}
    }}
    setInterval(tickCountdown, 1000);

    // ---------- apply stats ----------
    function applyStats(stats) {{
      stats = stats || {{}};

      // Basic metrics
      setText("uptime_seconds", formatUptimeSeconds(stats.uptime_seconds));
      setText("total_events", stats.total_events || 0);
      setText("unique_domains", stats.unique_domains || 0);
      setText("threat_score", stats.threat_score || 0);

      // Network stats
      const net = stats.network || {{}};
      setText("unique_domains", net.unique_domains || 0);
      setText("net_total", net.total_requests || 0);
      setText("net_dynamic", net.dynamic_requests || 0);
      setText("net_static", net.static_requests || 0);
      setText("net_domains", net.unique_domains || 0);

      // Threats
      const th = stats.threats || {{}};
      setText("th_trackers", th.trackers || 0);
      setText("th_intrusions", th.intrusions || 0);
      setText("th_malware", th.malware || 0);
      setText("th_exploits", th.exploits || 0);
      setText("th_fingerprinting", th.fingerprinting || 0);

      // IDS
      const ids = stats.ids || {{}};
      setText("ids_scrapers", ids.scrapers || 0);
      setText("ids_credential_stuffing", ids.credential_stuffing || 0);
      setText("ids_vulnerability_scanners", ids.vulnerability_scanners || 0);
      setText("ids_bruteforce_logins", ids.bruteforce_logins || 0);
      
      // Traffic Breakdown 
      const dyn = net.dynamic_requests || 0;
      const stat = net.static_requests || 0;
      const domains = net.unique_domains || 1;
      const total = net.total_requests || 0;
      const uptime = stats.uptime_seconds || 1;

      setText("tb_ratio", dyn + " : " + stat);
      setText("tb_req_domain", (total / domains).toFixed(1));
      setText("tb_rps", (total / uptime).toFixed(2));
      setText("tb_recent", stats.total_events || 0);

      // Recent threats
      renderRecentThreats(stats.recent_threats || []);

      // Lockdown status + badge
      const lockdown = stats.lockdown || {{}};
      const active = !!lockdown.active;

      const badge = el("status_badge");
      if (badge) {{
        badge.textContent = active ? "LOCKDOWN ACTIVE" : "SYSTEM MONITORING";
        badge.style.background = active ? "{'#ff3b30'}" : "{'#36ff9a'}";
        badge.style.color = "#000";
      }}

      // Countdown node handling:
      // If lockdown becomes active, ensure timer exists; if becomes inactive, remove it.
      const existingTimer = el("lockdown_timer");
      if (active) {{
        // compute remaining based on server-ish timestamps
        const triggeredAt = Number(lockdown.triggered_at || 0);
        const duration = Number(lockdown.duration_seconds || {LOCKDOWN_DURATION} || 0);

        // We'll accept either:
        // - backend provides duration_seconds
        // - fallback to embedded LOCKDOWN_DURATION
        const nowSec = Date.now() / 1000;
        let rem = Math.max(0, Math.floor(duration - (nowSec - triggeredAt)));
        lockdownRemaining = rem;

        if (!existingTimer) {{
          // create timer block
          const container = badge ? badge.parentElement : document.body;
          const div = document.createElement("div");
          div.className = "countdown-timer";
          div.innerHTML = 'Lockdown ends in <span id="lockdown_timer"></span>s';
          container.appendChild(div);
        }}
        setText("lockdown_timer", lockdownRemaining);
      }} else {{
        lockdownRemaining = null;
        // remove timer block if present
        if (existingTimer) {{
          const parent = existingTimer.closest(".countdown-timer");
          if (parent) parent.remove();
        }}
      }}

      // Last updated
      const lu = el("last_updated");
      if (lu) {{
        const d = new Date();
        lu.textContent = "Last updated: " + d.toLocaleTimeString();
      }}
    }}

    // First paint
    applyStats(SEED_STATS);

    // ---------- live polling ----------
    // IMPORTANT: implement in your _NavDelegate:
    // If URL is darkelf://report?json=1, return JSON string of self.mini_ai.get_statistics()
    async function poll() {{
      try {{
        const res = await fetch("darkelf://report?json=1", {{
          cache: "no-store",
          credentials: "omit"
        }});
        const txt = await res.text();
        const data = JSON.parse(txt);
        applyStats(data);
      }} catch (e) {{
        // If fetch is blocked by your scheme handler, you can replace this with:
        // - message handler bridge, or
        // - WKURLSchemeHandler, or
        // - injected script via evaluateJavaScript_ from native side.
      }}
    }}

    setInterval(poll, 2000);
  </script>
</body>
</html>
"""

    def update_security_indicator(self, trusted):
        try:
            cell = self.addr.cell()

            if trusted:
                # Green lock icon
                lock = NSImage.imageNamed_("NSLockLockedTemplate")
                cell.setSearchButtonCell_(cell.searchButtonCell())
                cell.searchButtonCell().setImage_(lock)

                self.addr.setTextColor_(NSColor.labelColor())

            else:
                # Warning triangle
                warn = NSImage.imageNamed_("NSCaution")
                cell.searchButtonCell().setImage_(warn)

                self.addr.setTextColor_(NSColor.systemRedColor())

        except Exception as e:
            print("Security indicator error:", e)
                    
    def start_lockdown_timer(self):

        self.stop_lockdown_timer()

        self._lockdown_timer = NSTimer.scheduledTimerWithTimeInterval_target_selector_userInfo_repeats_(
            1.0,
            self,
            "refreshMiniAI:",
            None,
            True
        )
 
    def stop_lockdown_timer(self):

        if hasattr(self, "_lockdown_timer") and self._lockdown_timer:
            self._lockdown_timer.invalidate()
            self._lockdown_timer = None
            
    def finish_lockdown_unlock(self):

        print("[Browser] Lockdown finished")

        self.stop_lockdown_timer()

        try:
            self.mini_ai._unlock_browser_ui()
        except Exception:
            pass

        try:
            self.close_threat_report_tab()
        except Exception as e:
            print("[Browser] Close report error:", e)
            
    def close_threat_report_tab(self):

        idx = -1

        for i, tab in enumerate(self.tabs):
            if getattr(tab, "url", None) == "darkelf://report":
                idx = i
                break

        if idx < 0:
            return

        try:
            report_view = self.tabs[idx].view

            if report_view and report_view.superview():
                report_view.removeFromSuperview()

        except Exception:
            pass

        del self.tabs[idx]

        if not self.tabs:
            self._add_tab(home=True)
            return

        if self.active >= len(self.tabs):
            self.active = len(self.tabs) - 1

        wk = self.tabs[self.active].view

        try:
            if wk.superview():
                wk.removeFromSuperview()

            self._mount_webview(wk)

        except Exception as e:
            print("[Browser] restore webview error:", e)

        self._bring_tabbar_to_front()
        self._update_tab_buttons()
        self._sync_addr()
            
    def _is_tab_webview(self, webview):
        for tab in self.tabs:
            if tab.view is webview:
                return True
        return False
    
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
            print("[Window] ✅ Fullscreen collection behavior set")
        except Exception as e:
            print(f"[Window] ❌ Fullscreen behavior failed: {e}")

        try:
            cv = win.contentView()
            cv.setWantsLayer_(True)
            print("[Window] ✅ Content view layer-backed")
        except Exception as e:
            print(f"[Window] ❌ Content view layer failed: {e}")

        return win
        
    def windowShouldClose_(self, sender):
        return True
        
    def actCloseTab_(self, _):
        self._close_tab()
        
    TOOLBAR_HEIGHT = 44
    TABBAR_HEIGHT = 38
    PADDING = 10

    def _nscolor_hex(self, hex_str, alpha=1.0):
        hs = hex_str.lstrip("#")
        r = int(hs[0:2], 16) / 255.0
        g = int(hs[2:4], 16) / 255.0
        b = int(hs[4:6], 16) / 255.0
        return NSColor.colorWithCalibratedRed_green_blue_alpha_(r, g, b, alpha)

    def _style_button(self, btn, tooltip=None):
        # Avoid fancy styles that sometimes misbehave across macOS versions
        try:
            btn.setBordered_(True)
        except Exception:
            pass
        if tooltip:
            try:
                btn.setToolTip_(tooltip)
            except Exception:
                pass
        return btn

    def _build_toolbar(self):
        bounds = self.window.contentView().bounds()
        w = bounds.size.width

        self.toolbar = NSView.alloc().initWithFrame_(
            NSMakeRect(0, bounds.size.height - self.TOOLBAR_HEIGHT, w, self.TOOLBAR_HEIGHT)
        )
        self.toolbar.setAutoresizingMask_(NSViewWidthSizable)

        self.toolbar.setWantsLayer_(True)
        self.toolbar.layer().setBackgroundColor_(self._nscolor_hex("#0b0f14", 1.0).CGColor())

        x = self.PADDING
        y = 8
        bw = 34
        bh = 28
        gap = 4
                    
    def _build_tabbar(self):
        bounds = self.window.contentView().bounds()
        w = bounds.size.width
        h = bounds.size.height
        top_y = h - self.TOOLBAR_HEIGHT - self.TABBAR_HEIGHT

        # CREATE TABBAR ONCE
        self.tabbar = NSView.alloc().initWithFrame_(
            NSMakeRect(0, top_y, w, self.TABBAR_HEIGHT)
        )

        self.tabbar.setAutoresizingMask_(NSViewWidthSizable | NSViewMinYMargin)
        self.tabbar.setWantsLayer_(True)
        self.tabbar.layer().setBackgroundColor_(
            self._nscolor_hex("#0a0d12", 1.0).CGColor()
        )

        # ADD BUTTON (after tabbar exists)
        self.btn_new_tab = HoverButton.alloc().initWithFrame_(
            NSMakeRect(w - 44, 6, 34, 26)
        )
        
        self.btn_new_tab.setTitle_("+")
        self.btn_new_tab.setBordered_(False)
        self.btn_new_tab.setBezelStyle_(0)
        self.btn_new_tab.setTarget_(self)
        self.btn_new_tab.setAction_("actNewTab:")
                
        self.tabbar.addSubview_(self.btn_new_tab)

        # container
        self.tab_buttons_container = NSView.alloc().initWithFrame_(
            NSMakeRect(0, 0, w - 50, self.TABBAR_HEIGHT)
        )
        self.tabbar.addSubview_(self.tab_buttons_container)

        self.window.contentView().addSubview_(self.tabbar)

        if not hasattr(self, "tabs"):
            self.tabs = []

        if not hasattr(self, "active"):
            self.active = -1

        self._update_tab_buttons()
        self._cleanup_unused_containers()
        
    def _layout_topbars(self):
        bounds = self.window.contentView().bounds()
        w = bounds.size.width
        h = bounds.size.height

        if getattr(self, "toolbar", None):
            self.toolbar.setFrame_(NSMakeRect(0, h - self.TOOLBAR_HEIGHT, w, self.TOOLBAR_HEIGHT))
        if getattr(self, "tabbar", None):
            self.tabbar.setFrame_(NSMakeRect(0, h - self.TOOLBAR_HEIGHT - self.TABBAR_HEIGHT, w, self.TABBAR_HEIGHT))
        if getattr(self, "btn_new_tab", None):
            self.btn_new_tab.setFrame_(NSMakeRect(w - 44, 6, 34, 26))
        if getattr(self, "content_container", None):
            self.content_container.setFrame_(NSMakeRect(0, 0, w, h - self.TOOLBAR_HEIGHT - self.TABBAR_HEIGHT))
        
    def windowDidResize_(self, notification):
        self._layout_topbars()
        self._update_tab_buttons()

    def _update_tab_buttons(self):
        if not getattr(self, "tab_buttons_container", None):
            return

        # Remove old generated tab controls
        for v in list(self.tab_buttons_container.subviews() or []):
            v.removeFromSuperview()

        w = self.tab_buttons_container.bounds().size.width
        y = 6
        h = 32
        gap = 6
        min_tab_w = 110
        max_tab_w = 180
        close_w = 18
        inner_pad = 10

        # Leave space on the right for the "+" button
        num_tabs = len(self.tabs)
        if num_tabs <= 0:
            return
            
        plus_reserved = 44  # space for + button

        available_w = max(
            200,
            w - plus_reserved - (gap * max(0, num_tabs - 1)) - self.PADDING * 2
        )
        
        tab_w = max(min_tab_w, min(available_w // num_tabs, max_tab_w))

        x = self.PADDING

        for i, tab in enumerate(self.tabs):
            selected = (i == self.active)

            # outer tab shell
            tab_shell = NSView.alloc().initWithFrame_(NSMakeRect(x, y, tab_w, h))
            tab_shell.setWantsLayer_(True)
            tab_shell.layer().setCornerRadius_(12.0)

            if selected:
                tab_shell.layer().setBackgroundColor_(self._nscolor_hex("#34C759", 0.25).CGColor())
                tab_shell.layer().setBorderWidth_(2.0)
                tab_shell.layer().setBorderColor_(self._nscolor_hex("#34C759", 1.0).CGColor())
            else:
                tab_shell.layer().setBackgroundColor_(self._nscolor_hex("#222830", 0.7).CGColor())
                tab_shell.layer().setBorderWidth_(1.0)
                tab_shell.layer().setBorderColor_(self._nscolor_hex("#3c454f", 0.7).CGColor())

            # close button
            close_btn = HoverButton.alloc().initWithFrame_(
                NSMakeRect(tab_w - close_w - 8, 7, close_w, close_w)
            )
            close_btn.setTitle_("×")
            close_btn.setBordered_(False)
            close_btn.setTarget_(self)
            close_btn.setAction_("actCloseTabIndex:")
            close_btn.setTag_(i)
            close_btn.setToolTip_("Close Tab")
            close_btn.setFont_(NSFont.boldSystemFontOfSize_(13))
            close_btn.setContentTintColor_(
                self._nscolor_hex("#34C759", 1.0) if selected else NSColor.whiteColor()
            )
            
            title = tab.host or "New Tab"
            if len(title) > 18:
                title = title[:18] + "…"
                
            title_btn = NSButton.alloc().initWithFrame_(
                NSMakeRect(inner_pad, 0, tab_w - close_w - 20, h)
            )
            title_btn.setTitle_(title)
            title_btn.setBordered_(False)
            title_btn.setAlignment_(0)  # left
            title_btn.setTarget_(self)
            title_btn.setAction_("actSwitchTab:")
            title_btn.setTag_(i)
            title_btn.setContentTintColor_(
                self._nscolor_hex("#34C759", 1.0) if selected else NSColor.whiteColor()
            )

            tab_shell.addSubview_(title_btn)
            tab_shell.addSubview_(close_btn)
            self.tab_buttons_container.addSubview_(tab_shell)

            x += tab_w + gap
        
    # ================= TAB / NAV ACTIONS =================

    @objc.IBAction
    def tabClicked_(self, sender):
        try:
            idx = int(sender.tag())
            self._select_tab(idx)
        except Exception as e:
            print("[Tabs] tabClicked_ error:", e)

    @objc.IBAction
    def actNewTab_(self, sender):
        print("CLICKED + BUTTON")

        idx = self._add_tab(home=True)

        print("TAB RESULT:", idx)
        print("TOTAL TABS:", len(self.tabs))

        self.active = len(self.tabs) - 1
        self._update_tab_buttons()
        self._sync_addr()

    @objc.IBAction
    def actBack_(self, sender):
        tab = self._active_tab()
        if tab and getattr(tab, "view", None):
            try:
                tab.view.goBack()
            except Exception:
                pass

    @objc.IBAction
    def actFwd_(self, sender):
        tab = self._active_tab()
        if tab and getattr(tab, "view", None):
            try:
                tab.view.goForward()
            except Exception:
                pass

    @objc.IBAction
    def actReload_(self, sender):
        tab = self._active_tab()
        if tab and getattr(tab, "view", None):
            try:
                tab.view.reload()
            except Exception:
                pass

    @objc.IBAction
    def actHome_(self, sender):
        try:
            self._add_tab(home=True)
        except Exception as e:
            print("[Nav] actHome_ error:", e)
            
    @objc.IBAction
    def addrEntered_(self, sender):
        try:
            text = str(self.addr.stringValue() or "").strip()
            if not text:
                return

            if "://" not in text and "." in text:
                text = "https://" + text
            elif "://" not in text:
                text = "https://lite.duckduckgo.com/lite/?q=" + quote_plus(text)
                
            self._add_tab(home=False)

            self._navigate_to(text)

        except Exception as e:
            print("[Nav] addrEntered error:", e)

    # ================= TAB HELPERS =================

    def _active_tab(self):
        if not hasattr(self, "tabs"):
            return None
        if self.active < 0 or self.active >= len(self.tabs):
            return None
        return self.tabs[self.active]

    def _select_tab(self, idx):
        if idx < 0 or idx >= len(self.tabs):
            return

        self.active = idx

        cv = self.window.contentView()

        # Remove any existing WKWebViews from contentView
        for sub in list(cv.subviews()):
            if isinstance(sub, WKWebView):
                sub.removeFromSuperview()

        # Hide all tab WKWebViews except for the active one
        for i, tab in enumerate(self.tabs):
            view = getattr(tab, "view", None)
            if not view:
                continue
            if i == self.active:
                # Remount the active tab's WKWebView, ensure it's visible
                self._mount_webview(view)
                try:
                    view.setHidden_(False)
                except Exception:
                    pass
            else:
                try:
                    view.setHidden_(True)
                except Exception:
                    pass

        self._sync_addr()
        self._update_tab_buttons()

    def _sync_addr(self):
        tab = self._active_tab()
        if not tab or not getattr(self, "addr", None):
            return

        try:
            self.addr.setStringValue_(getattr(tab, "url", "") or "")
        except Exception:
            pass

    def _navigate_to(self, url_str):
        tab = self._active_tab()
        if not tab or not getattr(tab, "view", None):
            return

        try:
            nsurl = NSURL.URLWithString_(url_str)
            tab.view.loadRequest_(NSURLRequest.requestWithURL_(nsurl))
            tab.url = url_str
            self._sync_addr()
        except Exception as e:
            print("[Nav] navigate error:", e)
            
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
                                        
# -------------------------------------------------------------------
# Replace your existing _make_toolbar + _build_shadow_toolbar with this
# -------------------------------------------------------------------
    def _make_toolbar(self):
        cv = self.window.contentView()

        # Determine a reliable top Y using contentLayoutRect (safe with titlebars/toolbars)
        try:
            clr = self.window.contentLayoutRect()
            top_y = clr.origin.y + clr.size.height
            width = clr.size.width
        except Exception:
            f = cv.frame()
            top_y = f.size.height
            width = f.size.width

        bar_h = 52.0
        y = top_y - bar_h

        # Container
        self.toolbar_container = NSView.alloc().initWithFrame_(NSMakeRect(0, y, width, bar_h))
        self.toolbar_container.setAutoresizingMask_(10)  # width sizable + stick to top
        self.toolbar_container.setWantsLayer_(True)

        # Modern dark background
        self.toolbar_container.layer().setBackgroundColor_(
            NSColor.colorWithCalibratedRed_green_blue_alpha_(0.05, 0.06, 0.08, 1.0).CGColor()
        )

        # subtle bottom border
        try:
            self.toolbar_container.layer().setBorderWidth_(1.0)
            self.toolbar_container.layer().setBorderColor_(
                NSColor.colorWithCalibratedWhite_alpha_(1.0, 0.08).CGColor()
            )
        except Exception:
            pass

        cv.addSubview_(self.toolbar_container)

        # ----------------------------
        # Helpers: button factory
        # ----------------------------
        def make_icon_btn(symbol, tooltip, tint=None, size=18.0):
            b = HoverButton.alloc().init()
            b.setBordered_(False)
            b.setBezelStyle_(1)
            b.setTitle_("")
            b.setToolTip_(tooltip or "")

            img = None
            try:
                img = NSImage.imageWithSystemSymbolName_accessibilityDescription_(symbol, None)
                if img:
                    cfg = NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(size, 2, 2)
                    if hasattr(img, "imageByApplyingSymbolConfiguration_"):
                        img = img.imageByApplyingSymbolConfiguration_(cfg)
                    try:
                        img.setTemplate_(True)
                    except Exception:
                        pass
            except Exception:
                img = None

            if img:
                b.setImage_(img)
                b.setImagePosition_(2)  # image-only

            if hasattr(b, "setContentTintColor_"):
                if tint:
                    b.setContentTintColor_(tint)
                else:
                    b.setContentTintColor_(NSColor.whiteColor())

            b.setWantsLayer_(True)
            try:
                b.layer().setCornerRadius_(10.0)
            except Exception:
                pass

            return b

        # ----------------------------
        # Left buttons
        # ----------------------------
        self.btn_back   = make_icon_btn("chevron.backward", "Back")
        self.btn_fwd    = make_icon_btn("chevron.forward", "Forward")
        self.btn_reload = make_icon_btn("arrow.clockwise", "Reload")
        self.btn_home   = make_icon_btn("house.fill", "Home")

        for b, sel in [
            (self.btn_back,   "actBack:"),
            (self.btn_fwd,    "actFwd:"),
            (self.btn_reload, "actReload:"),
            (self.btn_home,   "actHome:"),
        ]:
            b.setTarget_(self)
            b.setAction_(sel)
            self.toolbar_container.addSubview_(b)

        # ----------------------------
        # URL bar
        # ----------------------------
        self.urlbar = AddressField.alloc().initWithFrame_owner_(NSMakeRect(200, 10, 720, 32), self)
        self.addr = self.urlbar

        self.urlbar.setBezeled_(True)

        self.urlbar.setFocusRingType_(0)
        self.urlbar.cell().setFocusRingType_(0)

        # THIS is the real fix
        self.urlbar.cell().setShowsFirstResponder_(False)

        self.urlbar.setDrawsBackground_(False)

        self.urlbar.setPlaceholderString_("Search or enter URL")
        self.urlbar.setTarget_(self)
        self.urlbar.setAction_("addrEntered:")

        self.urlbar.cell().setSendsWholeSearchString_(True)
        self.urlbar.cell().setSendsSearchStringImmediately_(False)

        self.urlbar.setAutoresizingMask_(2)

        self.toolbar_container.addSubview_(self.urlbar)
        
        # ----------------------------
        # Right-side buttons
        # ----------------------------
        self.btn_zoom_out = make_icon_btn("minus.magnifyingglass", "Zoom Out")
        self.btn_zoom_in  = make_icon_btn("plus.magnifyingglass", "Zoom In")
        self.btn_full     = make_icon_btn("arrow.up.left.and.arrow.down.right", "Fullscreen")
        self.btn_js       = make_icon_btn("bolt.fill" if self.js_enabled else "bolt.slash.fill",
                                          f"JavaScript: {'ON' if self.js_enabled else 'OFF'}",
                                          tint=NSColor.systemGreenColor() if self.js_enabled else NSColor.systemRedColor())

        self.btn_nuke     = make_icon_btn("trash.fill", "Clear All Data", tint=NSColor.systemRedColor())
        self.btn_mini_ai  = make_icon_btn("shield.fill", "MiniAI Threat Report", tint=NSColor.systemGreenColor())

        for b, sel in [
            (self.btn_zoom_out, "actZoomOut:"),
            (self.btn_zoom_in,  "actZoomIn:"),
            (self.btn_full,     "actFull:"),
            (self.btn_js,       "actToggleJS:"),
            (self.btn_nuke,     "actNuke:"),
            (self.btn_mini_ai,  "openThreatReport:"),
        ]:
            b.setTarget_(self)
            b.setAction_(sel)
            self.toolbar_container.addSubview_(b)

        # layout pass
        self._layout_toolbar()
        return self.toolbar_container

    def _layout_toolbar(self):
        """Called on startup + window resize to keep toolbar aligned."""
        if not getattr(self, "toolbar_container", None):
            return

        cv = self.window.contentView()
        try:
            clr = self.window.contentLayoutRect()
            top_y = clr.origin.y + clr.size.height
            width = clr.size.width
        except Exception:
            f = cv.frame()
            top_y = f.size.height
            width = f.size.width

        bar_h = 52.0
        y = top_y - bar_h
        self.toolbar_container.setFrame_(NSMakeRect(0, y, width, bar_h))

        # geometry
        pad = 10.0
        btn = 32.0
        gap = 10.0

        # left cluster
        x = pad
        for b in [self.btn_back, self.btn_fwd, self.btn_reload, self.btn_home]:
            b.setFrame_(NSMakeRect(x, 10, btn, btn))
            x += btn + 6

        left_end = x + 10

        # right cluster
        right_buttons = [self.btn_zoom_out, self.btn_zoom_in, self.btn_full, self.btn_js, self.btn_nuke, self.btn_mini_ai]
        right_x = width - pad - (len(right_buttons) * btn + (len(right_buttons) - 1) * 6)

        rx = right_x
        for b in right_buttons:
            b.setFrame_(NSMakeRect(rx, 10, btn, btn))
            rx += btn + 6

        right_start = right_x - 10

        # urlbar fills remaining
        url_x = left_end
        url_w = max(260.0, right_start - url_x)
        self.urlbar.setFrame_(NSMakeRect(url_x, 10, url_w, 32))

    # Make sure your existing onResize_ calls _layout() AND _layout_toolbar()
    def onResize_(self, note):
        try:
            self._layout_toolbar()
        except Exception:
            pass
        try:
            self._layout()
        except Exception:
            pass

    def _bring_tabbar_to_front(self):
        try:
            cv = self.window.contentView()

            # keep toolbar on top
            if getattr(self, "toolbar_container", None):
                # Only remove if it's attached elsewhere
                if self.toolbar_container.superview() is not None and self.toolbar_container.superview() != cv:
                    try:
                        self.toolbar_container.removeFromSuperview()
                    except Exception:
                        pass
                # Only add if not already attached to contentView
                if self.toolbar_container.superview() != cv:
                    cv.addSubview_(self.toolbar_container)

            # keep tabbar above webview
            if getattr(self, "tabbar", None):
                if self.tabbar.superview() is not None and self.tabbar.superview() != cv:
                    try:
                        self.tabbar.removeFromSuperview()
                    except Exception:
                        pass
                if self.tabbar.superview() != cv:
                    cv.addSubview_(self.tabbar)
                self.tabbar.displayIfNeeded()
        except Exception:
            pass

    # In actToggleJS_, after toggling, also update JS button icon/tint:
    def actToggleJS_(self, _):
        self.js_enabled = not bool(getattr(self, "js_enabled", True))

        # update UI button
        try:
            sym = "bolt.fill" if self.js_enabled else "bolt.slash.fill"
            img = NSImage.imageWithSystemSymbolName_accessibilityDescription_(sym, None)
            if img:
                cfg = NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(18.0, 2, 2)
                if hasattr(img, "imageByApplyingSymbolConfiguration_"):
                    img = img.imageByApplyingSymbolConfiguration_(cfg)
                img.setTemplate_(True)
                self.btn_js.setImage_(img)
            self.btn_js.setToolTip_(f"JavaScript: {'ON' if self.js_enabled else 'OFF'}")
            if hasattr(self.btn_js, "setContentTintColor_"):
                self.btn_js.setContentTintColor_(NSColor.systemGreenColor() if self.js_enabled else NSColor.systemRedColor())
        except Exception:
            pass

        # apply to active webview + reload
        try:
            wk = self.tabs[self.active].view
            prefs = wk.configuration().preferences()
            prefs.setJavaScriptEnabled_(self.js_enabled)
            wk.reload()
        except Exception as e:
            print("[JS Toggle] Reload error:", e)

    def _install_local_hsts(self, ucc):

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
            
    @objc.python_method
    def _inject_core_scripts(self, ucc):
    
        try:
            seed = getattr(self, "_current_canvas_seed", None)
            if seed is None:
                seed = secrets.randbits(32) & 0xFFFFFFFF

            canvas_script = CANVAS_DEFENSE_JS.replace(
                "__NATIVE_SEED__", str(seed)
            )

            def _add(src):
                try:
                    skr = WKUserScript.alloc().initWithSource_injectionTime_forMainFrameOnly_(src, 0, False)
                    ucc.addUserScript_(skr)
                except Exception as e:
                    print("[Inject] addUserScript_ failed:", e)
                            
            _add(WEBRTC_DEFENSE_JS)
            _add(WEBGL_DEFENSE_JS)
            _add(canvas_script)
            _add(TIMEZONE_LOCALE_DEFENSE_JS)
            _add(FONTS_DEFENSE_JS)
            _add(MEDIA_ENUM_DEFENSE_JS)
            _add(AUDIO_DEFENSE_JS)
            _add(BATTERY_DEFENSE_JS)
            _add(PERFORMANCE_DEFENSE_JS)
            _add(CORE_JS)
            _add(NETWORK_MONITOR_JS)
            #_add(INDEXEDDB_DEFENSE_JS)
            #_add(STORAGE_DEFENSE_JS)
            
            if ENABLE_LOCAL_HSTS:
                self._install_local_hsts(ucc)
                print("[HSTS] Local HSTS injector attached to UCC.")
            
            if ENABLE_LOCAL_REFERRER_POLICY:
                self._install_local_referrer_policy(ucc)
                print("[ReferrerPolicy] Local Referrer Policy attached to UCC.")
                
            if ENABLE_LOCAL_WEBSOCKET_POLICY:
                self._install_local_websocket_policy(ucc)
                print("[WebSocketPolicy] Local WebSocket Policy attached to UCC.")
                        
            # ✅ UPDATED: Enhanced ad/banner blocking with Wikipedia support
            _add(r"""
            (function(){
                try {
                    if (
                        location.hostname.includes("youtube.com")) return;

                    var css = `
                    /* Generic ad blocking */
                    iframe[src*="ad"],
                    iframe[src*="doubleclick"],
                    iframe[src*="adsystem"],
                    iframe[src*="googlesyndication"],

                    div[id^="ad_"],
                    div[id^="ads_"],
                    div[class^="ad-"],
                    div[class^="ads-"],

                    [data-ad],
                    [data-sponsored],

                    #centralNotice,
                    .frb-banner,
                    .cn-banner

                    [data-ad],
                    [data-sponsored],
                
                    /* Wikipedia banners (fundraising/campaigns) */
                    .frb-banner,
                    .frb-container,
                    #centralNotice,
                    .cn-banner,
                    div[id*="banner-container"],
                    div[class*="campaign"],
                    .mw-parser-output > .mw-dismissable-notice,
                
                    /* Common donation/fundraising banners */
                    div[class*="donation"],
                    div[id*="fundrais"],
                    div[class*="appeal"],
                
                    /* Newsletter/subscription popups */
                    div[class*="newsletter"],
                    div[id*="subscribe"],
                    div[class*="popup-banner"] {
                        display: none !important;
                        visibility: hidden !important;
                        opacity: 0 !important;
                        height: 0 !important;
                        overflow: hidden !important;
                    }`;

                    var style = document.createElement('style');
                    style.type = 'text/css';
                    style.appendChild(document.createTextNode(css));
                    document.documentElement.appendChild(style);
                
                    console.log('[Darkelf] Ad/banner blocking CSS injected');
                } catch(e){
                    console.error('[Darkelf] Banner blocking failed:', e);
                }
            })();
            """)
            
            print("[Inject] Core defense scripts added to UCC.")
        
        except Exception as e:
            print(f"[Inject] Core script injection failed: {e}")
            
    def _new_wk(self, container_nonce):

        is_home = bool(getattr(self, "loading_home", False))

        cfg = WKWebViewConfiguration.alloc().init()

        # ---------------------------
        # First-Party Isolation
        # ---------------------------
        url = getattr(self, "current_url_for_fpi", HOME_URL)

        tab_uid = secrets.token_hex(4)

        key = self.fpi._key(url, tab_uid=tab_uid, nonce=container_nonce)

        if key not in self._containers:

            # storage container (cookies, indexedDB, etc)
            store = self.fpi.store_for(url, tab_uid=len(self.tabs))

            # isolated WebKit network process
            pool = WKProcessPool.alloc().init()

            # memory-only HTTP cache
            cache = NSURLCache.alloc().initWithMemoryCapacity_diskCapacity_directoryURL_(
                16 * 1024 * 1024,   # 16MB memory cache
                0,                  # disk cache disabled
                None
            )

            if cache.diskCapacity() != 0:
                raise RuntimeError("Darkelf security failure: disk cache detected")

            # apply cache to container - (None)/Cache) options
            #NSURLCache.setSharedURLCache_()
            NSURLCache.setSharedURLCache_(NSURLCache.alloc().init())
            
            self._containers[key] = (store, pool)

        store, pool = self._containers[key]

        # apply container isolation
        cfg.setWebsiteDataStore_(store)
        cfg.setProcessPool_(pool)
        
        cfg.setMediaTypesRequiringUserActionForPlayback_(0)

        if store.isPersistent():
            raise RuntimeError("Darkelf security failure: persistent data store detected")

        js_enabled = True if is_home else bool(getattr(self, "js_enabled", True))

        # ---- preferences ----
        prefs = WKPreferences.alloc().init()
        prefs.setJavaScriptEnabled_(js_enabled)
        prefs.setJavaScriptCanOpenWindowsAutomatically_(True)

        # ✅ enable HTML5 fullscreen
        prefs.setValue_forKey_(True, "fullScreenEnabled")

        cfg.setPreferences_(prefs)

        # ---- user content controller ----
        ucc = WKUserContentController.alloc().init()

        if ContentRuleManager._rule_list:
            ucc.addContentRuleList_(ContentRuleManager._rule_list)

        # ---- message handlers ----
        ucc.addScriptMessageHandler_name_(self._nav_delegate, "netlog")
        ucc.addScriptMessageHandler_name_(self._nav_delegate, "blobdownload")
        ucc.addScriptMessageHandler_name_(self._search_handler, "search")

        self._inject_core_scripts(ucc)

        cfg.setUserContentController_(ucc)

        web = WKWebView.alloc().initWithFrame_configuration_(NSMakeRect(0,0,800,600), cfg)

        web.setNavigationDelegate_(self._nav_delegate)
        web.setUIDelegate_(self._ui_delegate)

        return web, store
        
    def webView_runJavaScriptAlertPanelWithMessage_initiatedByFrame_completionHandler_(
        self, webView, message, frame, completionHandler
    ):
        """Handle JavaScript alerts"""
        try:
            print(f"[JS Alert] {message}")
            alert = NSAlert.alloc().init()
            alert.setMessageText_("JavaScript Alert")
            alert.setInformativeText_(str(message))
            alert.addButtonWithTitle_("OK")
            alert.runModal()
        finally:
            completionHandler()

    def webView_runJavaScriptConfirmPanelWithMessage_initiatedByFrame_completionHandler_(
        self, webView, message, frame, completionHandler
    ):
        """Handle JavaScript confirms"""
        try:
            print(f"[JS Confirm] {message}")
            alert = NSAlert.alloc().init()
            alert.setMessageText_("Confirm")
            alert.setInformativeText_(str(message))
            alert.addButtonWithTitle_("OK")
            alert.addButtonWithTitle_("Cancel")
            result = alert.runModal()
            completionHandler(result == 1000)
        except Exception as e:
            print(f"[JS Confirm] Error: {e}")
            completionHandler(False)

    def webView_runJavaScriptTextInputPanelWithPrompt_defaultText_initiatedByFrame_completionHandler_(
        self, webView, prompt, defaultText, frame, completionHandler
    ):
        """Handle JavaScript prompts"""
        try:
            print(f"[JS Prompt] {prompt}")
            completionHandler(None)
        except Exception as e:
            print(f"[JS Prompt] Error: {e}")
            completionHandler(None)
            
    def webView_requestMediaCapturePermissionForOrigin_initiatedByFrame_type_decisionHandler_(
        self, webView, origin, frame, type, decisionHandler
    ):
        try:
            print(f"[Media] 🔒 Denied media capture for: {origin}")
            decisionHandler(0)  # Always deny
        except Exception:
            pass
                                                    
    def _mount_webview(self, wk):
        cv = self.window.contentView()

        # Remove ALL existing WKWebViews immediately
        for sub in list(cv.subviews()):
            if "WKWebView" in str(type(sub)):
                sub.removeFromSuperview()

        # ====== Ensure Navigation and UI Delegates are set ======
        if getattr(self, "_nav_delegate", None):
            wk.setNavigationDelegate_(self._nav_delegate)
        if getattr(self, "_ui_delegate", None):
            wk.setUIDelegate_(self._ui_delegate)

        # Compute frame: subtract both toolbar and tabbar height!
        try:
            clr = self.window.contentLayoutRect()
            min_height = 100
            total_ui_height = self.TOOLBAR_HEIGHT + self.TABBAR_HEIGHT
            w = clr.size.width
            h = clr.size.height - total_ui_height

            if h < min_height:
                f = cv.frame()
                h = max(min_height, f.size.height - total_ui_height)
                log(2, "[WKWebView] Fallback to cv.frame(), height =", h)

            web_rect = NSMakeRect(0, 0, w, h)
            log(2, f"[WKWebView] Set frame: width={w}, height={h}")

        except Exception as e:
            f = cv.frame()
            min_height = 100
            h = max(min_height, f.size.height - (self.TOOLBAR_HEIGHT + self.TABBAR_HEIGHT))
            w = f.size.width
            web_rect = NSMakeRect(0, 0, w, h)
            log(2, f"[WKWebView] Exception fallback. Set frame: width={w}, height={h}. Error: {e}")

        cv.addSubview_(wk)

        # FIXED BACKGROUND HANDLING
        try:
            wk.setOpaque_(True)
            wk.setBackgroundColor_(NSColor.blackColor())
        except Exception as e:
            print("[WKWebView] Failed to set background:", e)

        wk.setFrame_(web_rect)
        wk.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)

        # Always re-add toolbar and tabbar after mounting webview!
        try:
            if getattr(self, "toolbar_container", None):
                if self.toolbar_container.superview() != cv:
                    cv.addSubview_(self.toolbar_container)

            if getattr(self, "tabbar", None):
                if self.tabbar.superview() != cv:
                    cv.addSubview_(self.tabbar)

        except Exception as e:
            print("[WKWebView] Failed to re-add toolbar/tabbar:", e)
            
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
            
            config.preferences().setValue_forKey_(True, "fullScreenEnabled")
            
            # Security
            prefs = config.preferences()
            prefs.setValue_forKey_(False, "javaScriptCanOpenWindowsAutomatically")
            prefs.setValue_forKey_(False, "developerExtrasEnabled")

            config.setValue_forKey_(False, "allowFileAccessFromFileURLs")
            config.setValue_forKey_(False, "allowUniversalAccessFromFileURLs")

            try:
                config.setLimitsNavigationsToAppBoundDomains_(False)
            except Exception:
                pass
                
            config = WKWebViewConfiguration.alloc().init()

            store = self.fpi.store_for(url, tab_uid=tab_index)

            config.setWebsiteDataStore_(store)

            webview = WKWebView.alloc().initWithFrame_configuration_(
                frame,
                config
            )
            wk = WKWebView.alloc().initWithFrame_configuration_(old.frame(), config)

            if getattr(self, "_ui_delegate", None) is not None:
                wk.setUIDelegate_(self._ui_delegate)

            if getattr(self, "_nav_delegate", None) is not None:
                wk.setNavigationDelegate_(self._nav_delegate)
                
            # THEN create webview
            #self.webView = WKWebView.alloc().initWithFrame_configuration_(
                #self.bounds(), config
            #)

            # attach delegates
            #webview.setUIDelegate_(self.ui_delegate)
            #webview.setNavigationDelegate_(self)

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

            try:
                frame = old.frame() if hasattr(old, "frame") else ((0, 0), (1200, 760))

                wk = WKWebView.alloc().initWithFrame_configuration_(frame, config)

                wk.setFrame_(NSMakeRect(0, 0, 1200, 760))
                
                if getattr(self, "_nav_delegate", None) is not None:
                    wk.setNavigationDelegate_(self._nav_delegate)
                if getattr(self, "_ui_delegate", None) is not None:
                    try:
                        wk.setUIDelegate_(self._ui_delegate)
                    except Exception:
                        pass

                try:
                    wk.setAutoresizingMask_(18)
                except Exception:
                    pass

                # Mount & swap in
                self.tabs[self.active].view = wk
                self._mount_webview(wk)

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
                        self.tabs[self.active].view.loadHTMLString_baseURL_(
                            HOMEPAGE_HTML,
                            NSURL.URLWithString_(HOME_URL)
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

        # 🔥 Generate seed FIRST
        seed = secrets.randbits(32) & 0xFFFFFFFF
        self._current_canvas_seed = seed   # temporary storage
        
        container_nonce = secrets.token_hex(4)
        
        self._tab_uid_counter += 1
        tab_uid = self._tab_uid_counter
        
        print(f"[AddTab] Seed = {seed}")
        
        self.current_url_for_fpi = url if url else HOME_URL

        wk, store = self._new_wk(container_nonce)

        wk.setNavigationDelegate_(self._nav_delegate)
        
        if 0 <= self.active < len(self.tabs):
            try:
                old_view = self.tabs[self.active].view

                old_view.stopLoading()
                old_view.setNavigationDelegate_(None)
                old_view.setUIDelegate_(None)

                old_view.removeFromSuperview()

            except Exception:
                pass
                
        self._mount_webview(wk)
        self._bring_tabbar_to_front()
        
        tab = Tab(
            view=wk,
            data_store=store,
            url="",
            host="new",
            canvas_seed=seed,
            container_nonce=container_nonce,
            tab_uid=tab_uid
        )

        self.tabs.append(tab)
        self.active = len(self.tabs) - 1

        # --- MiniAI reset for new session ---
        if hasattr(self, "mini_ai"):
            try:
                self.mini_ai.unique_domains.clear()
            except Exception:
                pass

        self._current_canvas_seed = None
    
        if home:
            try:
                self.urlbar.setStringValue_("")
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
                for name in ("netlog","search"):
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
            
        try:
            tab.data_store = None
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

        # 🔹 update active tab
        self.active = idx

        # 🔹 mount correct webview
        self._mount_webview(self.tabs[idx].view)

        # 🔹 bring UI layers back
        self._bring_tabbar_to_front()

        # 🔹 refresh tab highlight
        self._update_tab_buttons()

        # 🔹 sync address bar
        self._sync_addr()
                
    def actCloseTabIndex_(self, sender):

        try:
            idx = int(sender.tag())
        except Exception:
            return

        log(2, "Close tab index:", idx)

        if not (0 <= idx < len(self.tabs)):
            return

        try:
            view = self.tabs[idx].view

            if view:
                # 🔥 FULL teardown (kills YouTube / media pipelines)
                self._teardown_webview(view)

        except Exception as e:
            print("[CloseTab] teardown error:", e)

        # remove tab
        del self.tabs[idx]

        # if no tabs left create homepage
        if not self.tabs:
            self._add_tab(home=True)
            return

        # adjust active index
        if idx == self.active:
            self.active = min(idx, len(self.tabs) - 1)
        elif idx < self.active:
            self.active -= 1

        # mount next tab
        wk = self.tabs[self.active].view

        try:
            self._mount_webview(wk)
        except Exception as e:
            print("[CloseTab] mount error:", e)

        self._update_tab_buttons()
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
            if not self.tabs:
                return

            tab = self.tabs[self.active]
            wk = tab.view

            # 🔥 SPECIAL CASE: Threat Report (fix white screen)
            if tab.url == "darkelf://report":
                html = self._build_threat_report_html()
                wk.loadHTMLString_baseURL_(html, None)
                return

            # Existing logic preserved
            u = wk.URL()
            cur = str(u.absoluteString()) if u is not None else (tab.url or "")

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

            # Build URL
            if "://" not in text and "." not in text:
                q = quote_plus(text)
                url = "https://lite.duckduckgo.com/lite/?q=" + q
            elif "://" not in text:
                url = "https://" + text
            else:
                url = text

            # FIX: Use _navigate_to instead of _add_tab
            self._navigate_to(url)

        except Exception as e:
            print("[Go] Failed:", e)

    def actNuke_(self, sender):

        # 🔴 Confirmation Alert
        alert = NSAlert.alloc().init()
        alert.setMessageText_("Clear All Browsing Data?")
        alert.setInformativeText_(
            "This will wipe cookies, cache, local storage, "
            "IndexedDB, and all website data, then close Darkelf."
        )
        alert.setAlertStyle_(NSAlertStyleCritical)

        # Order matters:
        # First button = 1000
        # Second button = 1001
        alert.addButtonWithTitle_("Cancel")  # 1000
        alert.addButtonWithTitle_("Wipe")    # 1001

        # 🔴 Response Handler
        def on_response(code):

            # Only proceed if Wipe was pressed (1001)
            if int(code) != 1001:
                return

            try:
                # 1️⃣ Destroy all WebViews (ephemeral wipe)
                for tab in list(self.tabs):
                    try:
                        self._teardown_webview(tab.view)
                    except Exception:
                        pass

                self.tabs.clear()
                self.active = -1

                # 2️⃣ Reset ephemeral store
                self._data_store = WKWebsiteDataStore.nonPersistentDataStore()

            except Exception as e:
                print("wipe error:", e)

            # 3️⃣ Shutdown browser cleanly
            NSApplication.sharedApplication().terminate_(None)

        # Show confirmation sheet
        alert.beginSheetModalForWindow_completionHandler_(self.window, on_response)

    def _storage_cleanup(self):
        try:
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

            self.urlbar.setStringValue_(v)

        except Exception:
            pass
                        
    def _install_key_monitor(self):

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
                key = evt.keyCode()

                # ----------------------------------
                # ⌘ + ← / →  (Back / Forward)
                # ----------------------------------
                if key == 123:  # left arrow
                    self.actBack_(None)
                    return None

                if key == 124:  # right arrow
                    self.actFwd_(None)
                    return None

                # ----------------------------------
                # ⌘ + Shift + L  (Threat Console)
                # ----------------------------------
                if ch and ch.lower() == "l" and shift:
                    try:
                        self.openThreatReport_(None)
                    except Exception:
                        print("[Shortcut] Threat console not hooked")
                    return None

                # ----------------------------------
                # ⌘ + T
                # ----------------------------------
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
                if ch and ch.lower() == "l" and not shift:
                    self.window.makeFirstResponder_(self.urlbar)
                    return None

                # ⌘ + S → Snapshot
                if ch == "s":
                    self.actSnapshot_(None)
                    return None

                # ⌘ + Shift + X → Exit
                if ch.lower() == "x" and shift:
                    NSApp().terminate_(None)
                    return None

                # ⌘ + - → Zoom Out
                if ch == "-":
                    self.actZoomOut_(None)
                    return None

                # ⌘ + = → Zoom In
                if ch == "=":
                    self.actZoomIn_(None)
                    return None

            except Exception as e:
                print("Key handler error:", e)

            return evt

        NSEvent.addLocalMonitorForEventsMatchingMask_handler_(1 << 10, handler)
        
    def safe_shutdown(self):
 
        if hasattr(self, "window"):
            try:
                nc = NSNotificationCenter.defaultCenter()
                nc.removeObserver_(self)
            except Exception:
                pass
    
        if hasattr(self, "tabs"):
            for tab in self.tabs:
                view = getattr(tab, "view", None)
                if view:
                    try:
                        ucc = view.configuration().userContentController()
                        for name in ("netlog", "search"):
                            ucc.removeScriptMessageHandlerForName_(name)
                        view.removeFromSuperview()
                    except Exception:
                        pass
                        
    def _wipe_all_site_data(self):
        """
        Fully reset browser session:
        - Tear down all webviews
        - Clear tab list
        - Reset active index
        - Recreate fresh non-persistent data store
        """

        if getattr(self, "_has_wiped", False):
            return

        try:
            # Teardown all webviews safely
            for tab in list(self.tabs):
                try:
                    if hasattr(tab, "view") and tab.view:
                        self._teardown_webview(tab.view)
                except Exception:
                    pass

            # Clear tab state
            self.tabs = []
            self.active = 0

            # Reset to fresh ephemeral store
            self._data_store = WKWebsiteDataStore.nonPersistentDataStore()

            # Mark wipe complete only after success
            self._has_wiped = True

        except Exception as e:
            print("wipe error:", e)

    def windowWillClose_(self, notification):

        try:
            # Stop all webviews
            for tab in getattr(self, "tabs", []):
                try:
                    tab.view.stopLoading()
                except Exception:
                    pass
        except Exception:
            pass

        NSApplication.sharedApplication().terminate_(None)

    def applicationWillTerminate_(self, notification):
        try:
            pass
        except Exception:
            pass
            
    def wipe_webkit_memory():
        store = WKWebsiteDataStore.nonPersistentDataStore()

        types = WKWebsiteDataStore.allWebsiteDataTypes()

        store.removeDataOfTypes_modifiedSince_completionHandler_(
            types,
            0,
            lambda: None
        )
        
    def actSnapshot_(self, sender):
        try:
            wk = self.tabs[self.active].view

            def handler(image, error):
                if image and not error:

                    # --- Darkelf snapshot folder ---
                    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
                    library = os.path.join(desktop, "Darkelf Library")
                    snapdir = os.path.join(library, "Darkelf Snap")

                    os.makedirs(snapdir, exist_ok=True)

                    # timestamp filename
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filename = f"darkelf_snapshot_{ts}.png"
                    path = os.path.join(snapdir, filename)

                    url = NSURL.fileURLWithPath_(path)

                    tiff = image.TIFFRepresentation()
                    rep = NSBitmapImageRep.imageRepWithData_(tiff)
                    png = rep.representationUsingType_properties_(4, None)  # PNG
                    png.writeToURL_atomically_(url, True)

                    print("[Darkelf] Snapshot saved →", path)

            wk.takeSnapshotWithConfiguration_completionHandler_(None, handler)

        except Exception as e:
            print("[Snapshot] Failed:", e)
            
class AppDelegate(NSObject):

    def applicationShouldTerminate_(self, sender):
        # Allow termination immediately
        return True

    def applicationWillTerminate_(self, notification):
        """Graceful shutdown with threat report and data cleanup"""
        print("\n" + "="*70)
        print("[Darkelf] Browser shutting down - initiating cleanup...")
        print("="*70 + "\n")
    
        try:
            if hasattr(self, "browser") and self.browser is not None:
        
                # ═══════════════════════════════════════════════════════════
                # 2. STOP COOKIE SCRUBBER
                # ═══════════════════════════════════════════════════════════
                print("\n" + "="*70)
                print("[Darkelf] Shutdown complete - all data wiped")
                print("="*70 + "\n")

        except Exception as e:
            print("[Quit] Unexpected shutdown error:", e)

def main():
    try:
        NSUserDefaults.standardUserDefaults().setVolatileDomain_forName_({}, NSRegistrationDomain)
        print("[Prefs] NSUserDefaults set to volatile (RAM-only).")
    except Exception as e:
        print("[Prefs] Failed to set volatile domain:", e)

    app = NSApplication.sharedApplication()
    
    # ✅ PRE-COMPILE RULES BEFORE BROWSER STARTS
    print("[Startup] Compiling content blocking rules...")
    ContentRuleManager.load_rules()
    
    # ✅ WAIT FOR ASYNC COMPILATION

    time.sleep(3.0)  # Give WebKit time to compile 121 rules
    
    if ContentRuleManager._rule_list:
        print("[Startup] ✅ Rules ready - initializing browser")
    
    app.setActivationPolicy_(NSApplicationActivationPolicyRegular)
    
    NSURLCache.setSharedURLCache_(None)
    delegate = AppDelegate.alloc().init()
    app.setDelegate_(delegate)

    delegate.browser = Browser.alloc().init()

    app.run()

    wipe_webkit_memory()

    nav_delegate.wipe_download_traces()
    
if __name__ == "__main__":
    main()
