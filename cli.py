"""HomeGuard in the terminal.

    python cli.py                 quick scan, report in English
    python cli.py --lang el       report in Greek
    python cli.py --deep          all 65,535 ports (slow)
    python cli.py --net 10.0.0.0/24
"""

import argparse
import sys

from homeguard import analysis, i18n, knowledge, network, scanner, storage

COLORS = {"critical": "\033[91m", "high": "\033[33m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[95m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def main():
    # Windows consoles may default to an old code page: force UTF-8 so Greek and emoji print.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass
    if sys.platform == "win32":
        import os
        os.system("")                     # enables ANSI colours in the Windows console

    ap = argparse.ArgumentParser(description="HomeGuard - home network security check-up")
    ap.add_argument("--net", help="network to scan, e.g. 192.168.1.0/24 (default: your /24)")
    ap.add_argument("--deep", action="store_true", help="scan all 65,535 ports (slow)")
    ap.add_argument("--lang", choices=i18n.LANGS, default="en")
    ap.add_argument("--yes", action="store_true", help="skip the permission question")
    args = ap.parse_args()
    L = args.lang

    def t(key):
        return i18n.UI[key][L]

    if not args.yes:
        answer = input(f"{t('consent')}? [y/N] ").strip().lower()
        if answer not in ("y", "yes", "ν", "ναι"):
            print(t("consent_needed"))
            return

    net = network.parse_network(args.net) if args.net else None
    last = {"phase": None}

    def progress(phase, done, total):
        if phase != last["phase"]:
            last["phase"] = phase
            print()
        print(f"\r  {t('phase_' + phase)}... {done}/{total}", end="", flush=True)

    earlier = storage.load_all()
    scan = scanner.run_scan(net=net, deep=args.deep, progress=progress)
    path = storage.save(scan)
    report = analysis.analyze(scan, storage.ever_seen(earlier) if earlier else None)

    print(f"\n\n{BOLD}HomeGuard · {scan['network']} · {scan['duration']} {t('sec')}{RESET}")
    print(f"{BOLD}{t('score')}: {report['grade']} ({report['score']}/100){RESET} - {t('grade_' + report['grade'])}\n")

    print(f"{BOLD}{t('devices')} ({len(scan['devices'])}){RESET}")
    for d in scan["devices"]:
        icon, names = analysis.DEVICE_TYPES[d["type"]]
        vendor = t("random_mac") if d["vendor"] == "random" else (d["vendor"] or t("unknown_vendor"))
        ports = ", ".join(str(p) for p in d["open_ports"]) or "-"
        name = f" ({d['hostname']})" if d["hostname"] else ""
        print(f"  {icon} {d['ip']:<15} {names[L]}{name}")
        print(f"     {DIM}{d['mac'] or '-'} · {vendor} · {t('open_ports')}: {ports}{RESET}")

    print(f"\n{BOLD}{t('report')}{RESET}")
    if not report["findings"]:
        print(f"  ✅ {t('no_findings')}")
    for f in report["findings"]:
        kb = knowledge.F[f["key"]]
        color = COLORS[f["severity"]]
        where = f"{f['ip']}" + (f" · {t('port')} {f['port']}" if f["port"] else "")
        print(f"\n  {color}{BOLD}[{t('sev_' + f['severity'])}]{RESET} {BOLD}{kb['title'][L]}{RESET}  {DIM}{where}{RESET}")
        if f["detail"]:
            print(f"     {f['detail']}")
        if f["local_only"]:
            print(f"     {DIM}ℹ {t('local_only')}{RESET}")
        print(f"     {t('why')}: {kb['why'][L]}")
        print(f"     {t('fix')}: {kb['fix'][L]}")

    print(f"\n{DIM}{path}{RESET}")


if __name__ == "__main__":
    main()
