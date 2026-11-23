"""Turns raw scan data into understanding: what each device is, what is risky, and a score."""

import re

from .knowledge import (F, HTTP_PORTS, HTTPS_PORTS, PORT_FINDINGS, SEVERITY_ORDER,
                        SEVERITY_WEIGHT, UPNP_PORTS)

DEVICE_TYPES = {
    "router":      ("📡", {"en": "Router", "el": "Router"}),
    "this_pc":     ("🖥️", {"en": "This computer", "el": "Αυτός ο υπολογιστής"}),
    "samsung_tv":  ("📺", {"en": "Samsung Smart TV", "el": "Samsung Smart TV"}),
    "smart_tv":    ("📺", {"en": "Smart TV", "el": "Smart TV"}),
    "cast":        ("📦", {"en": "TV / TV box (Google Cast)", "el": "TV / TV box (Google Cast)"}),
    "camera":      ("📷", {"en": "Camera", "el": "Κάμερα"}),
    "iphone":      ("📱", {"en": "iPhone / iPad", "el": "iPhone / iPad"}),
    "android":     ("📱", {"en": "Android phone", "el": "Κινητό Android"}),
    "phone":       ("📱", {"en": "Phone (probably)", "el": "Κινητό (πιθανότατα)"}),
    "ac":          ("❄️", {"en": "Air conditioner", "el": "Κλιματιστικό"}),
    "printer":     ("🖨️", {"en": "Printer", "el": "Εκτυπωτής"}),
    "windows_pc":  ("💻", {"en": "Windows computer", "el": "Υπολογιστής Windows"}),
    "apple":       ("💻", {"en": "Apple device", "el": "Συσκευή Apple"}),
    "speaker":     ("🔊", {"en": "Smart speaker", "el": "Έξυπνο ηχείο"}),
    "console":     ("🎮", {"en": "Game console", "el": "Κονσόλα"}),
    "iot":         ("💡", {"en": "Smart home device", "el": "Έξυπνη συσκευή σπιτιού"}),
    "unknown":     ("❔", {"en": "Unknown device", "el": "Άγνωστη συσκευή"}),
}

# Words in the manufacturer name -> device type
VENDOR_HINTS = [
    (("ewpe", "gree", "midea", "daikin", "haier"), "ac"),
    (("imilab", "chuangmi", "hikvision", "dahua", "reolink", "ezviz", "wyze", "arlo"), "camera"),
    (("hewlett", "epson", "canon", "brother", "kyocera", "lexmark", "xerox"), "printer"),
    (("sonos", "bose"), "speaker"),
    (("nintendo", "sony interactive", "microsoft"), "console"),
    (("espressif", "tuya", "shelly", "sonoff", "itead", "philips lighting", "signify", "tp-link"), "iot"),
    (("apple",), "apple"),
]

HOST_HINTS = [
    (("camera", "cam_", "ipcam"), "camera"),
    (("iphone", "ipad"), "iphone"),
    (("galaxy", "sm-", "redmi", "poco", "pixel", "oneplus", "android", "huawei", "honor", "oppo", "realme"), "android"),
    (("macbook", "imac", "mac-"), "apple"),
    (("tv-box", "tvbox", "chromecast", "shield"), "cast"),
    (("printer", "hp-", "npi", "brw", "epson", "canon"), "printer"),
    (("echo", "alexa", "homepod", "nest"), "speaker"),
    (("playstation", "ps4", "ps5", "xbox", "switch"), "console"),
    (("esp_", "esp-", "shelly", "tasmota", "sonoff"), "iot"),
    (("desktop-", "laptop-"), "windows_pc"),
]


def guess_type(dev):
    ports = set(dev.get("open_ports", []))
    vendor = (dev.get("vendor") or "").lower()
    host = (dev.get("hostname") or "").lower()
    banners = " ".join((b or {}).get("text", "") for b in dev.get("banners", {}).values()).lower()

    if dev.get("is_me"):
        return "this_pc"
    if dev.get("is_gateway"):
        return "router"
    if 554 in ports:
        return "camera"
    if {8001, 8002} & ports or "allshare" in banners or ("samsung" in vendor and "tv" in host):
        return "samsung_tv"
    if {8008, 8009, 6466, 6467} & ports:
        return "cast"
    if 62078 in ports:
        return "iphone"
    if {9100, 631, 515} & ports:
        return "printer"
    for words, kind in HOST_HINTS:
        if any(w in host for w in words):
            return kind
    if re.match(r"^m\d{4}", host):          # Xiaomi model codes like M2101K6G
        return "android"
    for words, kind in VENDOR_HINTS:
        if any(w in vendor for w in words):
            return kind
    if {445, 135, 3389} & ports:
        return "windows_pc"
    if "samsung" in vendor or "lg electronics" in vendor or "tcl" in vendor:
        return "smart_tv"
    if dev.get("random_mac"):
        return "phone"
    return "unknown"


VERSION_RE = re.compile(r"server:\s*(.+)", re.I)


def _version_leak(banner):
    """Return the 'Server:' value if it contains a version number, e.g. 'ExampleServer/1.2.3'."""
    m = VERSION_RE.search(banner or "")
    if m and re.search(r"\d+\.\d+", m.group(1)):
        return m.group(1).strip()
    return ""


def device_findings(dev):
    out = []
    ports = set(dev.get("open_ports", []))
    banners = dev.get("banners", {})

    def add(key, port=None, detail=""):
        out.append({"key": key, "port": port, "detail": detail})

    for p in sorted(ports):
        if p == 6379:
            add("redis_noauth" if dev.get("probes", {}).get("6379") else "redis", p)
        elif p in PORT_FINDINGS:
            add(PORT_FINDINGS[p], p)

    http = sorted(HTTP_PORTS & ports)
    if http and not (HTTPS_PORTS & ports) and not dev.get("is_me"):
        add("http_admin", http[0])

    if dev.get("is_gateway") and UPNP_PORTS & ports:
        add("router_upnp", sorted(UPNP_PORTS & ports)[0])

    all_banners = " ".join((b or {}).get("text", "") for b in banners.values()).lower()
    if ("airtunes" in all_banners or 7000 in ports) and "apple" not in (dev.get("vendor") or "").lower() \
            and dev.get("type") not in ("iphone", "apple", "this_pc"):
        add("airplay")

    seen = set()
    for p, b in sorted(banners.items(), key=lambda x: int(x[0])):
        leak = _version_leak((b or {}).get("text", ""))
        if leak and leak not in seen:
            seen.add(leak)
            add("version_leak", int(p), leak)

    if dev.get("type") == "unknown" and not dev.get("hostname") and not dev.get("random_mac"):
        add("unknown_device")
    return out


def analyze(scan, ever_seen=None):
    """Return findings for the whole network, plus a 0-100 score and a grade.

    ever_seen: MAC addresses seen in earlier scans (to flag brand-new devices)."""
    findings = []
    for dev in scan["devices"]:
        dev.setdefault("type", guess_type(dev))
        items = device_findings(dev)
        if ever_seen is not None and dev.get("mac") and dev["mac"] not in ever_seen and not dev.get("is_me"):
            items.insert(0, {"key": "new_device", "port": None, "detail": ""})
        for f in items:
            findings.append({
                **f,
                "severity": F[f["key"]]["severity"],
                "ip": dev["ip"], "mac": dev.get("mac", ""),
                "type": dev["type"], "hostname": dev.get("hostname", ""),
                # On this computer we scan from the inside, so the firewall is bypassed:
                # what we see is NOT what other devices see. Don't count it in the score.
                "local_only": bool(dev.get("is_me")),
            })

    findings.sort(key=lambda f: (f["local_only"], SEVERITY_ORDER.index(f["severity"]),
                                 tuple(int(x) for x in f["ip"].split("."))))
    penalty = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings if not f["local_only"])
    score = max(0, 100 - penalty)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    counts = {s: sum(1 for f in findings if f["severity"] == s and not f["local_only"]) for s in SEVERITY_ORDER}
    return {"findings": findings, "score": score, "grade": grade, "counts": counts}
