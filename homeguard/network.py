"""Finding devices on the local network: IP, gateway, ARP/neighbour table, hostnames, vendors.

Works on Windows, Linux and macOS using only the standard library and the
system's own `ping` / `arp` / `route` commands.
"""

import csv
import ipaddress
import platform
import re
import socket
import subprocess
import urllib.request
import uuid
from pathlib import Path

SYSTEM = platform.system()          # "Windows", "Linux", "Darwin" (macOS)
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

OUI_SOURCES = [
    # (url, local file name, format)
    ("https://standards-oui.ieee.org/oui/oui.csv", "oui.csv", "ieee"),
    ("https://www.wireshark.org/download/automated/data/manuf", "manuf.txt", "wireshark"),
]

MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def _run(cmd):
    """Run a system command and return its output ('' if it fails)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              errors="ignore", timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def normalize_mac(mac):
    """'aa:b:cc:...' or 'AA-0B-CC-...' -> 'aa-0b-cc-...'."""
    parts = re.split(r"[:-]", mac.strip().lower())
    return "-".join(p.zfill(2) for p in parts)


# ------------------------------------------------------------------ our own address

def my_ip():
    """Our IP on the LAN. Connecting a UDP socket sends no packets; it just picks a route."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def my_mac():
    n = uuid.getnode()
    return "-".join(f"{(n >> i) & 0xff:02x}" for i in range(40, -1, -8))


def default_network(ip):
    """Assume the common home /24 network (e.g. 192.168.1.0/24)."""
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def parse_network(text):
    """Accept '192.168.1', '192.168.1.0/24' or '10.0.0.0/23'."""
    text = text.strip()
    if text.count(".") == 2 and "/" not in text:
        text += ".0/24"
    net = ipaddress.ip_network(text, strict=False)
    if net.num_addresses > 1024:
        raise ValueError("Network too large (max /22, 1024 addresses) - this tool is meant for home networks.")
    return net


def default_gateway():
    """Find the router's IP from the routing table (language-independent)."""
    if SYSTEM == "Windows":
        out = _run(["route", "print", "0.0.0.0"])
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    if SYSTEM == "Linux":
        try:
            for line in Path("/proc/net/route").read_text().splitlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[1] == "00000000":
                    return socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
        except OSError:
            pass
        m = re.search(r"default via (\S+)", _run(["ip", "route"]))
        return m.group(1) if m else None
    m = re.search(r"gateway:\s*(\S+)", _run(["route", "-n", "get", "default"]))  # macOS
    return m.group(1) if m else None


# ------------------------------------------------------------------ discovery

def ping(ip):
    """One ping. True if the device answered. We look for 'ttl=' which appears in
    every successful reply, in any OS language."""
    if SYSTEM == "Windows":
        cmd = ["ping", "-n", "1", "-w", "600", ip]
    elif SYSTEM == "Darwin":
        cmd = ["ping", "-c", "1", "-t", "1", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    return "ttl=" in _run(cmd).lower()


def neighbours(network):
    """Read the ARP / neighbour table: which IP has which MAC address.
    Devices that ignore ping still show up here, because ARP happens first."""
    text = ""
    if SYSTEM == "Linux":
        try:
            text = Path("/proc/net/arp").read_text()
        except OSError:
            text = _run(["ip", "neigh"])
    if not text:
        text = _run(["arp", "-a"])

    found = {}
    for line in text.splitlines():
        ip_m, mac_m = IP_RE.search(line), MAC_RE.search(line)
        if not (ip_m and mac_m):
            continue
        ip, mac = ip_m.group(1), normalize_mac(mac_m.group(1))
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr not in network or addr in (network.network_address, network.broadcast_address):
            continue
        if mac in ("00-00-00-00-00-00", "ff-ff-ff-ff-ff-ff") or mac.startswith("01-00-5e"):
            continue
        found[ip] = mac
    return found


def hostname(ip):
    """Ask DNS (usually the router) for a name. Phones and TVs often announce their model here."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


# ------------------------------------------------------------------ vendors (OUI)

def is_random_mac(mac):
    """2nd hex digit 2/6/A/E = 'locally administered' = randomized MAC (privacy feature of phones)."""
    return bool(mac) and mac != "-" and int(mac[1], 16) & 2 == 2


def _download(url, dest):
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    if len(data) < 100_000:                       # an error page, not the database
        raise ValueError("download too small")
    dest.write_bytes(data)


def load_vendors(log=print):
    """Load the MAC-prefix -> manufacturer table. Downloads it once into data/."""
    DATA_DIR.mkdir(exist_ok=True)
    if not any((DATA_DIR / name).exists() for _, name, _ in OUI_SOURCES):
        log("Downloading manufacturer database (first run only)...")
        for url, name, _ in OUI_SOURCES:
            try:
                _download(url, DATA_DIR / name)
                break
            except Exception as e:                # noqa: BLE001 - try the next source
                log(f"  {url} failed: {e}")
        else:
            log("  Could not download. Vendors will show as unknown. "
                f"You can download {OUI_SOURCES[1][0]} manually into the data/ folder as manuf.txt")
            return {}

    table = {}
    for _, name, fmt in OUI_SOURCES:
        path = DATA_DIR / name
        if not path.exists():
            continue
        if fmt == "ieee":
            with open(path, newline="", encoding="utf-8", errors="ignore") as f:
                for row in csv.DictReader(f):
                    key = row.get("Assignment", "").upper()
                    if len(key) == 6:
                        table[key] = row.get("Organization Name", "").strip()
        else:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line or line.startswith("#"):
                    continue
                parts = line.split("\t")
                if len(parts) < 2 or "/" in parts[0]:
                    continue
                key = parts[0].replace(":", "").replace("-", "").upper()
                if len(key) == 6:
                    table.setdefault(key, parts[-1].strip())
    return table


def vendor_of(mac, table):
    if not mac or mac == "-":
        return ""
    if is_random_mac(mac):
        return "random"            # translated in the UI
    return table.get(mac.replace("-", "")[:6].upper(), "")
