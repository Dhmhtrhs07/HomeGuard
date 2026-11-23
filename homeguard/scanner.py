"""Runs a complete scan of the local network and returns the results as a dict."""

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from . import network, ports
from .analysis import guess_type

PHASES = ["discover", "identify", "ports", "banners"]


def run_scan(net=None, deep=False, progress=None, log=print):
    """Scan the network.

    net:      ipaddress network (default: our /24)
    deep:     scan all 65535 ports instead of the common ones (slow)
    progress: callback(phase, done, total) for progress bars
    """
    def report(phase, done, total):
        if progress:
            progress(phase, done, total)

    vendors = network.load_vendors(log=log)
    me = network.my_ip()
    net = net or network.default_network(me)
    gateway = network.default_gateway()
    start = time.time()

    # 1) Discovery: ping everything in parallel, then read the ARP table
    hosts = [str(h) for h in net.hosts()]
    alive = set()
    with ThreadPoolExecutor(max_workers=64) as ex:
        for i, (ip, ok) in enumerate(zip(hosts, ex.map(network.ping, hosts)), 1):
            if ok:
                alive.add(ip)
            report("discover", i, len(hosts))
    arp = network.neighbours(net)
    ips = alive | set(arp)
    if ipaddress.ip_address(me) in net:
        ips.add(me)
    ips = sorted(ips, key=lambda x: tuple(int(p) for p in x.split(".")))

    # 2) Identify: names and manufacturers
    with ThreadPoolExecutor(max_workers=32) as ex:
        names = {}
        for i, (ip, name) in enumerate(zip(ips, ex.map(network.hostname, ips)), 1):
            names[ip] = name
            report("identify", i, len(ips))

    devices = []
    for ip in ips:
        mac = network.my_mac() if ip == me else arp.get(ip, "")
        devices.append({
            "ip": ip, "mac": mac, "vendor": network.vendor_of(mac, vendors),
            "random_mac": network.is_random_mac(mac), "hostname": names.get(ip, ""),
            "ping": ip in alive, "is_me": ip == me, "is_gateway": ip == gateway,
            "open_ports": [], "banners": {}, "probes": {},
        })

    # 3) Ports
    port_list = list(range(1, 65536)) if deep else sorted(ports.COMMON_PORTS)
    with ThreadPoolExecutor(max_workers=300) as ex:
        if deep:
            for i, dev in enumerate(devices, 1):
                states = ex.map(lambda p, ip=dev["ip"]: ports.scan_port(ip, p), port_list)
                dev["open_ports"] = [p for p, st in zip(port_list, states) if st == "open"]
                report("ports", i, len(devices))
        else:
            jobs = [(d, p) for d in devices for p in port_list]
            states = ex.map(lambda j: ports.scan_port(j[0]["ip"], j[1]), jobs)
            for i, ((dev, p), st) in enumerate(zip(jobs, states), 1):
                if st == "open":
                    dev["open_ports"].append(p)
                if i % 50 == 0 or i == len(jobs):
                    report("ports", i, len(jobs))

    # 4) Banners + safe checks
    jobs = [(d, p) for d in devices for p in d["open_ports"]]
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = ex.map(lambda j: ports.grab_banner(j[0]["ip"], j[1]), jobs)
        for i, ((dev, p), (text, tls)) in enumerate(zip(jobs, results), 1):
            dev["banners"][str(p)] = {"text": text, "tls": tls}
            report("banners", i, len(jobs))
    for dev in devices:
        for p in dev["open_ports"]:
            if p in ports.PROBES:
                dev["probes"][str(p)] = ports.PROBES[p](dev["ip"], p)
        dev["type"] = guess_type(dev)

    now = datetime.now()
    return {
        "version": 1,
        "time": now.isoformat(timespec="seconds"),
        "network": str(net), "my_ip": me, "gateway": gateway,
        "deep": deep, "duration": round(time.time() - start, 1),
        "devices": devices,
    }
