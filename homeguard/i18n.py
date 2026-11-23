"""User-interface text in English and Greek."""

LANGS = ("en", "el")

UI = {
    "tagline": {"en": "Security check-up for your home network",
                "el": "Έλεγχος ασφαλείας για το δίκτυο του σπιτιού σου"},
    "scan_now": {"en": "Scan my network", "el": "Σκανάρισμα δικτύου"},
    "scanning": {"en": "Scanning...", "el": "Σκανάρω..."},
    "deep": {"en": "Deep scan (all 65,535 ports - about 2 min per device)",
             "el": "Βαθύ σκανάρισμα (όλες οι 65.535 πόρτες - περίπου 2 λεπτά ανά συσκευή)"},
    "consent": {"en": "I own this network or have permission to scan it",
                "el": "Το δίκτυο είναι δικό μου ή έχω άδεια να το σκανάρω"},
    "consent_needed": {"en": "Please confirm that you are allowed to scan this network.",
                       "el": "Επιβεβαίωσε ότι έχεις δικαίωμα να σκανάρεις αυτό το δίκτυο."},
    "network": {"en": "Network", "el": "Δίκτυο"},
    "last_scan": {"en": "last scan", "el": "τελευταίο σκανάρισμα"},
    "took": {"en": "took", "el": "διάρκεια"},
    "sec": {"en": "s", "el": "δευτ."},
    "mode_deep": {"en": "deep", "el": "βαθύ"},
    "mode_quick": {"en": "quick", "el": "γρήγορο"},
    "empty_title": {"en": "Let's check your network", "el": "Ας ελέγξουμε το δίκτυό σου"},
    "empty_text": {"en": "HomeGuard finds every device on your Wi-Fi, checks which doors (ports) are open, and tells "
                         "you in plain words what is risky and how to fix it.",
                   "el": "Το HomeGuard βρίσκει κάθε συσκευή στο Wi-Fi σου, ελέγχει ποιες «πόρτες» είναι ανοιχτές και σου "
                         "εξηγεί με απλά λόγια τι έχει ρίσκο και πώς να το διορθώσεις."},
    "score": {"en": "Security score", "el": "Βαθμός ασφαλείας"},
    "grade_A": {"en": "Excellent - nothing serious found.", "el": "Εξαιρετικά - δεν βρέθηκε κάτι σοβαρό."},
    "grade_B": {"en": "Good - a few things worth improving.", "el": "Καλά - λίγα πράγματα αξίζει να βελτιωθούν."},
    "grade_C": {"en": "Needs attention - fix the items below.", "el": "Θέλει προσοχή - διόρθωσε τα παρακάτω."},
    "grade_D": {"en": "Risky - important problems found.", "el": "Ριψοκίνδυνο - βρέθηκαν σημαντικά προβλήματα."},
    "grade_F": {"en": "Critical - act now on the red items.", "el": "Κρίσιμο - διόρθωσε άμεσα τα κόκκινα."},
    "devices": {"en": "Devices", "el": "Συσκευές"},
    "open_ports": {"en": "Open ports", "el": "Ανοιχτές πόρτες"},
    "findings": {"en": "Findings", "el": "Ευρήματα"},
    "scans": {"en": "Scans", "el": "Σκαναρίσματα"},
    "report": {"en": "Security report", "el": "Αναφορά ασφαλείας"},
    "report_hint": {"en": "Click a finding to see why it matters and how to fix it.",
                    "el": "Πάτα ένα εύρημα για να δεις γιατί έχει σημασία και πώς διορθώνεται."},
    "no_findings": {"en": "No risky services found. Well done!", "el": "Δεν βρέθηκαν επικίνδυνες υπηρεσίες. Μπράβο!"},
    "why": {"en": "Why it matters", "el": "Γιατί έχει σημασία"},
    "fix": {"en": "How to fix it", "el": "Πώς το διορθώνεις"},
    "learn": {"en": "Learn more", "el": "Μάθε περισσότερα"},
    "search_cve": {"en": "Search known vulnerabilities (NVD)", "el": "Αναζήτηση γνωστών ευπαθειών (NVD)"},
    "port": {"en": "port", "el": "πόρτα"},
    "local_only": {"en": "Seen from inside this computer - the firewall was bypassed, so other devices may not see "
                         "this. Not counted in the score. To verify, scan this PC from another device.",
                   "el": "Φαίνεται από μέσα, από αυτόν τον υπολογιστή - το firewall παρακάμπτεται, οπότε οι άλλες συσκευές "
                         "μπορεί να μην το βλέπουν. Δεν μετράει στη βαθμολογία. Για επιβεβαίωση, σκάναρε αυτόν τον "
                         "υπολογιστή από άλλη συσκευή."},
    "changes": {"en": "What changed since the previous scan", "el": "Τι άλλαξε από το προηγούμενο σκανάρισμα"},
    "no_changes": {"en": "No changes.", "el": "Καμία αλλαγή."},
    "ch_new": {"en": "NEW device - never seen before", "el": "ΝΕΑ συσκευή - πρώτη φορά"},
    "ch_back": {"en": "Came back", "el": "Επέστρεψε"},
    "ch_port_open": {"en": "opened port", "el": "άνοιξε την πόρτα"},
    "ch_port_closed": {"en": "closed port", "el": "έκλεισε την πόρτα"},
    "ch_gone": {"en": "Not found now", "el": "Δεν βρέθηκε τώρα"},
    "first_seen": {"en": "first seen", "el": "πρώτη φορά"},
    "seen_in": {"en": "seen in", "el": "σε"},
    "of_scans": {"en": "scans", "el": "σκαναρίσματα"},
    "random_mac": {"en": "Private (random) MAC", "el": "Ιδιωτική (τυχαία) MAC"},
    "unknown_vendor": {"en": "Unknown manufacturer", "el": "Άγνωστος κατασκευαστής"},
    "no_ports": {"en": "No open ports among those checked", "el": "Καμία ανοιχτή πόρτα από όσες ελέγχθηκαν"},
    "no_answer": {"en": "no reply", "el": "καμία απάντηση"},
    "missing": {"en": "Seen before, not found now", "el": "Τις είδαμε παλιότερα, όχι τώρα"},
    "last_seen": {"en": "last seen", "el": "τελευταία φορά"},
    "checklist": {"en": "Things a scan can't check - do them once", "el": "Όσα δεν ελέγχει ένα σκανάρισμα - κάν' τα μία φορά"},
    "print": {"en": "Print / save PDF", "el": "Εκτύπωση / PDF"},
    "json": {"en": "Download data (JSON)", "el": "Λήψη δεδομένων (JSON)"},
    "phase_discover": {"en": "Finding devices", "el": "Βρίσκω συσκευές"},
    "phase_identify": {"en": "Identifying devices", "el": "Αναγνωρίζω συσκευές"},
    "phase_ports": {"en": "Checking ports", "el": "Ελέγχω πόρτες"},
    "phase_banners": {"en": "Asking services who they are", "el": "Ρωτάω τις υπηρεσίες ποιες είναι"},
    "phase_start": {"en": "Starting", "el": "Ξεκινάω"},
    "error": {"en": "The last scan failed", "el": "Το τελευταίο σκανάρισμα απέτυχε"},
    "footer": {"en": "HomeGuard only scans your local network and sends nothing to the internet (except a one-time "
                     "download of the public manufacturer list). Scan only networks you own or are allowed to test.",
               "el": "Το HomeGuard σκανάρει μόνο το τοπικό σου δίκτυο και δεν στέλνει τίποτα στο internet (εκτός από μια "
                     "εφάπαξ λήψη της δημόσιας λίστας κατασκευαστών). Σκάναρε μόνο δίκτυα που σου ανήκουν ή έχεις άδεια."},
    "done_title": {"en": "Scan complete!", "el": "Το σκανάρισμα ολοκληρώθηκε!"},
    "done_text": {"en": "When you are finished, stop HomeGuard: press the 'Stop HomeGuard' button at the bottom of the "
                        "page, or press Ctrl+C in the black window. Don't leave it running in the background.",
                  "el": "Όταν τελειώσεις, σταμάτησε το HomeGuard: πάτα το κουμπί «Τερματισμός HomeGuard» στο κάτω μέρος "
                        "της σελίδας ή πάτα Ctrl+C στο μαύρο παράθυρο. Μην το αφήνεις να τρέχει στο παρασκήνιο."},
    "stop": {"en": "Stop HomeGuard", "el": "Τερματισμός HomeGuard"},
    "stop_hint": {"en": "HomeGuard keeps running until you stop it (button below, or Ctrl+C in the black window).",
                  "el": "Το HomeGuard τρέχει μέχρι να το σταματήσεις (κουμπί παρακάτω ή Ctrl+C στο μαύρο παράθυρο)."},
    "stopped_title": {"en": "HomeGuard has stopped", "el": "Το HomeGuard σταμάτησε"},
    "stopped_text": {"en": "You can close this tab and the black window. To use it again, run app.py (or run.bat).",
                     "el": "Μπορείς να κλείσεις αυτή την καρτέλα και το μαύρο παράθυρο. Για να το ξαναχρησιμοποιήσεις, "
                           "τρέξε το app.py (ή το run.bat)."},
    "sev_critical": {"en": "Critical", "el": "Κρίσιμο"},
    "sev_high": {"en": "High", "el": "Υψηλό"},
    "sev_medium": {"en": "Medium", "el": "Μέτριο"},
    "sev_low": {"en": "Low", "el": "Χαμηλό"},
    "sev_info": {"en": "Info", "el": "Πληροφορία"},
}


def pick_lang(requested, cookie, accept_header):
    for candidate in (requested, cookie):
        if candidate in LANGS:
            return candidate
    return "el" if "el" in (accept_header or "").lower()[:20] else "en"
