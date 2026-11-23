"""TCP port scanning, banner grabbing and a few safe, read-only service checks."""

import errno
import socket
import ssl

TIMEOUT = 0.6
REFUSED = {errno.ECONNREFUSED, 10061}        # Linux/macOS, Windows

# Ports checked in a quick scan, with a short service name.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 81: "HTTP",
    110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    515: "LPD (printer)", 548: "AFP", 554: "RTSP (video)", 631: "IPP (printer)",
    873: "rsync", 993: "IMAPS", 1080: "SOCKS proxy", 1433: "MS-SQL", 1883: "MQTT",
    2323: "Telnet (alt)", 2375: "Docker API", 2376: "Docker API (TLS)", 3000: "HTTP (dev)",
    3306: "MySQL", 3389: "RDP", 5000: "UPnP / HTTP", 5432: "PostgreSQL", 5555: "ADB",
    5900: "VNC", 5901: "VNC", 6379: "Redis", 6466: "Android TV Remote",
    6467: "Android TV Pairing", 7000: "AirPlay", 7100: "AirPlay", 7547: "TR-069 (ISP)",
    7678: "Samsung UPnP", 8000: "HTTP", 8001: "Samsung TV API", 8002: "Samsung TV API",
    8008: "Google Cast", 8009: "Google Cast", 8060: "Roku", 8080: "HTTP", 8081: "HTTP",
    8088: "HTTP", 8443: "HTTPS", 8883: "MQTT (TLS)", 8888: "HTTP", 9000: "HTTP",
    9100: "Printer (RAW)", 9197: "Samsung UPnP", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 49152: "UPnP", 62078: "iPhone sync",
}

TLS_PORTS = {443, 993, 2376, 6466, 6467, 8002, 8009, 8443, 8883}


def service_name(port):
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return ""


def scan_port(ip, port):
    """Return 'open', 'closed' (device said no) or 'filtered' (silence - a firewall)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        code = s.connect_ex((ip, port))
    if code == 0:
        return "open"
    return "closed" if code in REFUSED else "filtered"


def _printable(text):
    return "".join(c for c in text if c.isprintable() or c in "\r\n")


def _grab(ip, port, use_tls):
    try:
        raw = socket.create_connection((ip, port), timeout=2.5)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE      # we only want to talk, not verify
            raw = ctx.wrap_socket(raw)
        with raw as s:
            s.settimeout(2.5)
            try:
                data = s.recv(1024)              # SSH, FTP, SMTP... speak first
            except (socket.timeout, TimeoutError):
                data = b""
            if not data:                         # otherwise ask like a browser would
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: HomeGuard\r\n\r\n".encode())
                data = s.recv(1024)
    except Exception as e:                       # noqa: BLE001
        return None, type(e).__name__
    lines = [l.strip() for l in _printable(data.decode(errors="ignore")).splitlines() if l.strip()]
    if not lines:
        return "", None
    server = next((l for l in lines if l.lower().startswith("server:")), "")
    first = lines[0][:100]
    return (f"{first} | {server}" if server else first), None


def grab_banner(ip, port):
    """Ask the service who it is. Tries plain text first (or TLS for known TLS ports),
    then the other way. Returns (banner_text, used_tls)."""
    first_tls = port in TLS_PORTS
    banner, err = _grab(ip, port, first_tls)
    if banner:
        return banner, first_tls
    banner2, _ = _grab(ip, port, not first_tls)
    if banner2:
        return banner2, not first_tls
    return (banner if banner is not None else f"({err})"), first_tls


# ------------------------------------------------------------------ safe active checks
# Read-only questions that confirm a real problem. They never log in, guess
# passwords or change anything.

def probe_redis_open(ip, port=6379):
    """Redis answers PING with +PONG only if no password is required."""
    try:
        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(b"PING\r\n")
            return s.recv(64).startswith(b"+PONG")
    except OSError:
        return False


PROBES = {6379: probe_redis_open}
