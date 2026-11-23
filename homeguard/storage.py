"""Saving scans to disk and comparing them over time (the 'baseline' of your network)."""

import json
from pathlib import Path

SCANS_DIR = Path(__file__).resolve().parent.parent / "scans"


def save(scan):
    SCANS_DIR.mkdir(exist_ok=True)
    name = "scan_" + scan["time"].replace(":", "-").replace("T", "_") + ".json"
    path = SCANS_DIR / name
    path.write_text(json.dumps(scan, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_all():
    """All valid scans, oldest first."""
    scans = []
    for f in sorted(SCANS_DIR.glob("scan_*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("version") == 1:            # ignore files from older experiments
            data["file"] = f.name
            scans.append(data)
    return scans


def key(dev):
    """Identify a device by MAC (stable) rather than IP (can change)."""
    return dev.get("mac") or dev["ip"]


def ever_seen(scans):
    return {key(d) for s in scans for d in s["devices"]}


def history(scans):
    """Per device: first/last time seen and in how many scans."""
    out = {}
    for s in scans:
        for d in s["devices"]:
            h = out.setdefault(key(d), {"first": s["time"], "count": 0})
            h["last"] = s["time"]
            h["count"] += 1
            h["device"] = d
    return out


def changes(previous, current, earlier):
    """What changed between two scans. 'earlier' = all scans before 'current'."""
    if not previous:
        return []
    seen = ever_seen(earlier)
    old = {key(d): d for d in previous["devices"]}
    new = {key(d): d for d in current["devices"]}
    out = []
    for k, d in new.items():
        if k not in seen:
            out.append({"kind": "new", "device": d})
        elif k not in old:
            out.append({"kind": "back", "device": d})
        else:
            for p in sorted(set(d["open_ports"]) - set(old[k]["open_ports"])):
                out.append({"kind": "port_open", "device": d, "port": p})
            for p in sorted(set(old[k]["open_ports"]) - set(d["open_ports"])):
                out.append({"kind": "port_closed", "device": d, "port": p})
    for k, d in old.items():
        if k not in new:
            out.append({"kind": "gone", "device": d})
    order = ["new", "port_open", "back", "port_closed", "gone"]
    return sorted(out, key=lambda c: order.index(c["kind"]))
