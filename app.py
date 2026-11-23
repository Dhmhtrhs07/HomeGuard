"""HomeGuard web dashboard.

Run:   python app.py      then open http://127.0.0.1:5000
"""

import argparse
import os
import secrets
import threading
import traceback
import webbrowser
from datetime import datetime

from flask import (Flask, Response, abort, jsonify, make_response, redirect,
                   render_template, request, url_for)

from homeguard import __version__, analysis, i18n, knowledge, ports, scanner, storage

app = Flask(__name__)
CSRF_TOKEN = secrets.token_urlsafe(32)        # new random token every time the app starts
ALLOWED_HOSTS = set()                          # filled in main()

state = {"running": False, "phase": "", "done": 0, "total": 0, "error": "", "just_finished": False}

STOP_MSG = ("\n  >> Scan complete. When you are done, press Ctrl+C here (or the 'Stop HomeGuard' button) to stop HomeGuard."
            "\n  >> Το σκανάρισμα ολοκληρώθηκε. Όταν τελειώσεις, πάτα Ctrl+C εδώ (ή το κουμπί «Τερματισμός HomeGuard»).\n")
lock = threading.Lock()


# ------------------------------------------------------------------ security of the dashboard itself

@app.before_request
def protect():
    # 1) Host check: blocks "DNS rebinding", where a malicious website tricks your
    #    browser into talking to this local server under the attacker's domain name.
    if request.host not in ALLOWED_HOSTS:
        abort(400)
    # 2) CSRF check: every form POST must carry the secret token that only our page knows,
    #    so another website can't make your browser start scans behind your back.
    if request.method == "POST" and request.form.get("csrf") != CSRF_TOKEN:
        abort(403)


@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'")
    return resp


# ------------------------------------------------------------------ helpers for templates

def current_lang():
    return i18n.pick_lang(request.args.get("lang"), request.cookies.get("lang"),
                          request.headers.get("Accept-Language"))


@app.context_processor
def helpers():
    lang = current_lang()

    def t(key):
        return i18n.UI.get(key, {}).get(lang, key)

    def tr(d):
        return d.get(lang, d.get("en", "")) if isinstance(d, dict) else d

    def dtype(kind):
        icon, names = analysis.DEVICE_TYPES.get(kind, analysis.DEVICE_TYPES["unknown"])
        return icon, names[lang]

    def when(iso):
        try:
            return datetime.fromisoformat(iso).strftime("%d/%m/%Y %H:%M")
        except (TypeError, ValueError):
            return iso or ""

    def vendor(dev):
        v = dev.get("vendor")
        return t("random_mac") if v == "random" else (v or t("unknown_vendor"))

    return dict(t=t, tr=tr, dtype=dtype, when=when, vendor=vendor, lang=lang,
                KB=knowledge.F, CHECKLIST=knowledge.CHECKLIST, service_names=ports.COMMON_PORTS, csrf=CSRF_TOKEN, version=__version__)


# ------------------------------------------------------------------ scanning in the background

def progress(phase, done, total):
    with lock:
        state.update(phase=phase, done=done, total=total)


def scan_worker(deep):
    try:
        result = scanner.run_scan(deep=deep, progress=progress, log=lambda m: None)
        storage.save(result)
        state["just_finished"] = True
        print(STOP_MSG, flush=True)
    except Exception:                                       # noqa: BLE001
        state["error"] = traceback.format_exc(limit=3)
    finally:
        with lock:
            state["running"] = False


# ------------------------------------------------------------------ pages

@app.route("/")
def index():
    scans = storage.load_all()
    latest = scans[-1] if scans else None
    ctx = {"latest": latest, "scans": scans, "state": state,
           "just_finished": state.get("just_finished") and not state["running"]}
    state["just_finished"] = False          # show the "scan complete" message only once
    if latest:
        earlier = scans[:-1]
        report = analysis.analyze(latest, storage.ever_seen(earlier) if earlier else None)
        hist = storage.history(scans)
        current = {storage.key(d) for d in latest["devices"]}
        by_device = {}
        for f in report["findings"]:
            by_device.setdefault(f["ip"], []).append(f)
        ctx.update(
            report=report,
            by_device=by_device,
            changes=storage.changes(earlier[-1] if earlier else None, latest, earlier),
            hist=hist,
            missing=[h for k, h in hist.items() if k not in current],
            total_ports=sum(len(d["open_ports"]) for d in latest["devices"]),
        )
    resp = make_response(render_template("index.html", **ctx))
    if request.args.get("lang") in i18n.LANGS:
        resp.set_cookie("lang", request.args["lang"], max_age=3600 * 24 * 365, samesite="Strict")
    return resp


@app.route("/scan", methods=["POST"])
def scan():
    if not request.form.get("consent"):
        return redirect(url_for("index", need_consent=1))
    with lock:
        if not state["running"]:
            state.update(running=True, phase="start", done=0, total=0, error="")
            threading.Thread(target=scan_worker, args=(bool(request.form.get("deep")),), daemon=True).start()
    return redirect(url_for("index"))


@app.route("/stop", methods=["POST"])
def stop():
    """Stop the whole program, so nobody forgets it running in the background."""
    print("\n  HomeGuard stopped. / Το HomeGuard σταμάτησε.\n", flush=True)
    threading.Timer(1.5, lambda: os._exit(0)).start()      # give the browser time to load the page
    return render_template("stopped.html")


@app.route("/api/status")
def status():
    with lock:
        return jsonify(state)


@app.route("/api/latest.json")
def latest_json():
    scans = storage.load_all()
    if not scans:
        abort(404)
    body = (storage.SCANS_DIR / scans[-1]["file"]).read_text(encoding="utf-8")
    return Response(body, mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename={scans[-1]['file']}"})


def main():
    parser = argparse.ArgumentParser(description="HomeGuard web dashboard")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    args = parser.parse_args()

    ALLOWED_HOSTS.update({f"127.0.0.1:{args.port}", f"localhost:{args.port}"})
    url = f"http://127.0.0.1:{args.port}"
    print(f"\n  HomeGuard {__version__} is running at {url}")
    print("  Keep this window open while you use HomeGuard. When you are done, press Ctrl+C to stop it.")
    print("  Άφησε αυτό το παράθυρο ανοιχτό όσο χρησιμοποιείς το HomeGuard. Όταν τελειώσεις, πάτα Ctrl+C.\n")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    # 127.0.0.1 = only this computer can open the dashboard. Never use 0.0.0.0 here.
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
