"""The security knowledge base: what each finding means and how to fix it (English + Greek).

Each finding has:
  severity: critical / high / medium / low / info
  title, why, fix: {"en": ..., "el": ...}
  learn: optional link for further reading
"""

F = {}


def finding(key, severity, title, why, fix, learn=""):
    F[key] = {"severity": severity, "title": title, "why": why, "fix": fix, "learn": learn}


# ------------------------------------------------------------------ dangerous services

finding("telnet", "critical",
        {"en": "Telnet is open", "el": "Ανοιχτό Telnet"},
        {"en": "Telnet is a remote-control protocol from 1969. Everything, including the password, travels as plain "
               "text, so anyone listening on the network can read it. Many cheap cameras and routers ship with "
               "Telnet enabled and a default password (admin/admin). In 2016 the Mirai botnet took over hundreds of "
               "thousands of such devices exactly this way.",
         "el": "Το Telnet είναι πρωτόκολλο απομακρυσμένου ελέγχου από το 1969. Όλα ταξιδεύουν ως απλό κείμενο, μαζί "
               "και ο κωδικός, οπότε όποιος «ακούει» το δίκτυο τα διαβάζει. Πολλές φθηνές κάμερες και router έρχονται "
               "με ανοιχτό Telnet και εργοστασιακό κωδικό (admin/admin). Το 2016 το botnet Mirai κατέλαβε εκατοντάδες "
               "χιλιάδες τέτοιες συσκευές ακριβώς έτσι."},
        {"en": "Disable Telnet in the device's settings. If that is not possible, change the default password, update "
               "the firmware and move the device to a guest Wi-Fi network. Consider replacing it.",
         "el": "Απενεργοποίησε το Telnet από τις ρυθμίσεις της συσκευής. Αν δεν γίνεται, άλλαξε τον εργοστασιακό κωδικό, "
               "κάνε ενημέρωση firmware και βάλε τη συσκευή στο Wi-Fi επισκεπτών. Σκέψου να την αντικαταστήσεις."},
        "https://en.wikipedia.org/wiki/Mirai_(malware)")

finding("adb", "critical",
        {"en": "Android Debug Bridge (ADB) is open", "el": "Ανοιχτό ADB (Android Debug Bridge)"},
        {"en": "ADB is a developer tool. When it is reachable over the network, anyone on your Wi-Fi can install apps, "
               "read files and run commands on the device, usually without any password. Many cheap Android TV boxes "
               "ship like this and have been infected with crypto-miners and botnets.",
         "el": "Το ADB είναι εργαλείο για προγραμματιστές. Όταν είναι ανοιχτό στο δίκτυο, οποιοσδήποτε στο Wi-Fi σου "
               "μπορεί να εγκαταστήσει εφαρμογές, να διαβάσει αρχεία και να τρέξει εντολές στη συσκευή, συνήθως χωρίς "
               "κωδικό. Πολλά φθηνά Android TV box έρχονται έτσι και έχουν μολυνθεί με crypto-miners και botnets."},
        {"en": "On the device: Settings → Developer options → turn off USB debugging and Wireless debugging. If the port "
               "stays open and there is no such option, treat the device as suspicious and isolate it.",
         "el": "Στη συσκευή: Ρυθμίσεις → Developer options → κλείσε το USB debugging και το Wireless debugging. Αν η πόρτα "
               "μένει ανοιχτή και δεν υπάρχει τέτοια επιλογή, θεώρησε τη συσκευή ύποπτη και απομόνωσέ την."})

finding("docker", "critical",
        {"en": "Docker API exposed", "el": "Εκτεθειμένο Docker API"},
        {"en": "An open Docker API gives full control of the machine: anyone can start containers with access to the "
               "host's files. Attackers scan for it constantly to install crypto-miners.",
         "el": "Ένα ανοιχτό Docker API δίνει πλήρη έλεγχο του μηχανήματος: οποιοσδήποτε μπορεί να ξεκινήσει containers "
               "με πρόσβαση στα αρχεία του host. Οι επιτιθέμενοι το ψάχνουν συνεχώς για να βάλουν crypto-miners."},
        {"en": "Never expose the Docker daemon on TCP without TLS client certificates. Use the local socket instead.",
         "el": "Μην εκθέτεις ποτέ το Docker daemon σε TCP χωρίς TLS πιστοποιητικά. Χρησιμοποίησε το τοπικό socket."})

finding("redis_noauth", "critical",
        {"en": "Redis database with no password", "el": "Βάση Redis χωρίς κωδικό"},
        {"en": "HomeGuard asked this Redis server 'PING' and it answered without asking for a password. Anyone on the "
               "network can read or delete all its data, and in some setups take over the machine.",
         "el": "Το HomeGuard ρώτησε αυτόν τον Redis server «PING» και απάντησε χωρίς να ζητήσει κωδικό. Οποιοσδήποτε στο "
               "δίκτυο μπορεί να διαβάσει ή να σβήσει όλα του τα δεδομένα, και σε κάποιες ρυθμίσεις να πάρει τον έλεγχο του "
               "μηχανήματος."},
        {"en": "Set 'requirepass' (or ACL users) in redis.conf and bind Redis to 127.0.0.1 if only local apps use it.",
         "el": "Βάλε 'requirepass' (ή ACL χρήστες) στο redis.conf και δέσε το Redis στο 127.0.0.1 αν το χρησιμοποιούν μόνο "
               "τοπικές εφαρμογές."})

finding("ftp", "high",
        {"en": "FTP server is open", "el": "Ανοιχτός FTP server"},
        {"en": "FTP sends usernames, passwords and files without encryption, and often allows 'anonymous' login.",
         "el": "Το FTP στέλνει ονόματα χρηστών, κωδικούς και αρχεία χωρίς κρυπτογράφηση, και συχνά επιτρέπει «anonymous» "
               "σύνδεση χωρίς κωδικό."},
        {"en": "Turn FTP off. If you need file transfer, use SFTP (over SSH) or an encrypted sharing method.",
         "el": "Κλείσε το FTP. Αν χρειάζεσαι μεταφορά αρχείων, χρησιμοποίησε SFTP (μέσω SSH) ή κάποιον κρυπτογραφημένο τρόπο."})

finding("vnc", "high",
        {"en": "VNC remote screen is open", "el": "Ανοιχτό VNC (απομακρυσμένη οθόνη)"},
        {"en": "VNC shows and controls a computer's screen remotely. Many setups use weak or no passwords and the "
               "traffic is often unencrypted.",
         "el": "Το VNC δείχνει και ελέγχει την οθόνη ενός υπολογιστή από μακριά. Πολλές εγκαταστάσεις έχουν αδύναμο ή "
               "καθόλου κωδικό και η κίνηση συχνά δεν είναι κρυπτογραφημένη."},
        {"en": "Uninstall it if unused. Otherwise use a strong password and reach it only through a VPN.",
         "el": "Απεγκατέστησέ το αν δεν το χρησιμοποιείς. Αλλιώς βάλε δυνατό κωδικό και χρησιμοποίησέ το μόνο μέσω VPN."})

finding("database", "high",
        {"en": "Database server reachable on the network", "el": "Βάση δεδομένων προσβάσιμη από το δίκτυο"},
        {"en": "Database servers (MySQL, PostgreSQL, MS-SQL, MongoDB, Elasticsearch, Memcached) hold valuable data and "
               "are a favourite target. Thousands of databases have been wiped or held for ransom because they were "
               "reachable with default or no credentials.",
         "el": "Οι βάσεις δεδομένων (MySQL, PostgreSQL, MS-SQL, MongoDB, Elasticsearch, Memcached) έχουν πολύτιμα δεδομένα "
               "και είναι αγαπημένος στόχος. Χιλιάδες βάσεις έχουν σβηστεί ή κρατηθεί για λύτρα επειδή ήταν προσβάσιμες "
               "με εργοστασιακό ή καθόλου κωδικό."},
        {"en": "If only programs on the same computer use it, bind it to 127.0.0.1. Always require a strong password "
               "and never forward its port on the router.",
         "el": "Αν τη χρησιμοποιούν μόνο προγράμματα στον ίδιο υπολογιστή, δέσ' τη στο 127.0.0.1. Βάλε πάντα δυνατό κωδικό "
               "και μην ανοίγεις ποτέ την πόρτα της στο router."})

finding("rdp", "medium",
        {"en": "Remote Desktop (RDP) is open", "el": "Ανοιχτό Remote Desktop (RDP)"},
        {"en": "RDP lets someone log in to this Windows computer remotely. It is one of the most common entry points "
               "for ransomware, through password guessing (brute-force) and past flaws such as BlueKeep (2019).",
         "el": "Το RDP επιτρέπει σύνδεση σε αυτόν τον υπολογιστή Windows από μακριά. Είναι από τους πιο συχνούς τρόπους "
               "εισόδου για ransomware, μέσω μαντέματος κωδικών (brute-force) και παλιότερων κενών όπως το BlueKeep (2019)."},
        {"en": "If you don't use it: Settings → System → Remote Desktop → Off. Never forward port 3389 on your router.",
         "el": "Αν δεν το χρησιμοποιείς: Ρυθμίσεις → Σύστημα → Απομακρυσμένη επιφάνεια εργασίας → Off. Μην ανοίγεις ποτέ "
               "την πόρτα 3389 στο router."})

finding("smb", "medium",
        {"en": "Windows file sharing (SMB) is open", "el": "Ανοιχτή κοινή χρήση αρχείων Windows (SMB)"},
        {"en": "SMB shares folders and printers. It is one of the most attacked ports in history: in 2017 the WannaCry "
               "ransomware used a flaw in old SMBv1 (EternalBlue) to spread on its own from computer to computer. At "
               "home it can be acceptable, but it must never be reachable from the internet.",
         "el": "Μέσω SMB μοιράζονται φάκελοι και εκτυπωτές. Είναι από τις πιο «χτυπημένες» πόρτες στην ιστορία: το 2017 το "
               "ransomware WannaCry χρησιμοποίησε ένα κενό στο παλιό SMBv1 (EternalBlue) και εξαπλωνόταν μόνο του από "
               "υπολογιστή σε υπολογιστή. Στο σπίτι μπορεί να είναι αποδεκτό, αλλά ποτέ προσβάσιμο από το internet."},
        {"en": "1) Keep Windows updated. 2) Make sure SMB 1.0/CIFS is unchecked in 'Turn Windows features on or off'. "
               "3) If you don't share folders, turn off 'File and printer sharing' (Settings → Network & internet → "
               "Advanced network settings → Advanced sharing settings). Printing from this PC does not need it.",
         "el": "1) Κράτα τα Windows ενημερωμένα. 2) Βεβαιώσου ότι το SMB 1.0/CIFS δεν είναι τσεκαρισμένο στο «Turn Windows "
               "features on or off». 3) Αν δεν μοιράζεσαι φακέλους, κλείσε το «File and printer sharing» (Settings → "
               "Network & internet → Advanced network settings → Advanced sharing settings). Για να τυπώνεις από αυτόν τον "
               "υπολογιστή δεν χρειάζεται."})

finding("redis", "medium",
        {"en": "Redis database reachable", "el": "Βάση Redis προσβάσιμη"},
        {"en": "A Redis server is reachable on the network. It asked for a password (good), but it is still exposed.",
         "el": "Ένας Redis server είναι προσβάσιμος από το δίκτυο. Ζήτησε κωδικό (καλό), αλλά παραμένει εκτεθειμένος."},
        {"en": "Bind it to 127.0.0.1 if only local apps use it.",
         "el": "Δέσ' τον στο 127.0.0.1 αν τον χρησιμοποιούν μόνο τοπικές εφαρμογές."})

finding("mqtt", "medium",
        {"en": "MQTT (IoT messaging) is open", "el": "Ανοιχτό MQTT (μηνύματα IoT)"},
        {"en": "MQTT is the 'post office' of smart devices. Without a password, anyone can read sensor data and send "
               "commands to your devices.",
         "el": "Το MQTT είναι το «ταχυδρομείο» των έξυπνων συσκευών. Χωρίς κωδικό, οποιοσδήποτε μπορεί να διαβάζει δεδομένα "
               "αισθητήρων και να στέλνει εντολές στις συσκευές σου."},
        {"en": "Enable authentication on the broker (e.g. Mosquitto password_file) and prefer TLS on port 8883.",
         "el": "Ενεργοποίησε κωδικό στον broker (π.χ. password_file στο Mosquitto) και προτίμησε TLS στην πόρτα 8883."})

finding("rtsp", "medium",
        {"en": "Camera video stream (RTSP) is open", "el": "Ανοιχτή ροή βίντεο κάμερας (RTSP)"},
        {"en": "RTSP serves live video. Many cameras allow watching the stream with a default password, or none.",
         "el": "Το RTSP στέλνει ζωντανό βίντεο. Πολλές κάμερες επιτρέπουν να δει κανείς τη ροή με εργοστασιακό κωδικό ή "
               "και χωρίς."},
        {"en": "Set a strong camera password, update its firmware and disable RTSP in the app if you don't use it.",
         "el": "Βάλε δυνατό κωδικό στην κάμερα, κάνε ενημέρωση firmware και κλείσε το RTSP από την εφαρμογή αν δεν το "
               "χρησιμοποιείς."})

finding("tr069", "medium",
        {"en": "TR-069 remote management port is open", "el": "Ανοιχτή πόρτα απομακρυσμένης διαχείρισης TR-069"},
        {"en": "TR-069 lets your internet provider manage the router remotely. Flaws in it have been used to hijack "
               "large numbers of home routers.",
         "el": "Το TR-069 επιτρέπει στον πάροχο internet να διαχειρίζεται το router από μακριά. Κενά σε αυτό έχουν "
               "χρησιμοποιηθεί για να «πέσουν» πολλά οικιακά router μαζί."},
        {"en": "Usually controlled by your provider. Keep the router firmware updated and ask your ISP if unsure.",
         "el": "Συνήθως το ελέγχει ο πάροχος. Κράτα το firmware του router ενημερωμένο και ρώτα τον πάροχο αν έχεις απορία."})

finding("router_upnp", "medium",
        {"en": "UPnP appears to be enabled on the router", "el": "Φαίνεται ενεργό το UPnP στο router"},
        {"en": "UPnP lets any device inside your network open ports on your router to the internet, without asking. "
               "Malware on one infected device can use it to expose your network.",
         "el": "Το UPnP επιτρέπει σε οποιαδήποτε συσκευή μέσα στο δίκτυο να ανοίγει πόρτες του router προς το internet, "
               "χωρίς να ρωτήσει. Ένα κακόβουλο πρόγραμμα σε μία μολυσμένη συσκευή μπορεί να το χρησιμοποιήσει για να "
               "εκθέσει το δίκτυό σου."},
        {"en": "Turn off UPnP in the router settings, unless a game console or app truly needs it.",
         "el": "Κλείσε το UPnP από τις ρυθμίσεις του router, εκτός αν κάποια κονσόλα ή εφαρμογή το χρειάζεται πραγματικά."})

finding("ssh", "low",
        {"en": "SSH is open", "el": "Ανοιχτό SSH"},
        {"en": "SSH is encrypted and safe by design, but it is a login door: weak passwords get guessed.",
         "el": "Το SSH είναι κρυπτογραφημένο και ασφαλές, αλλά είναι πόρτα εισόδου: οι αδύναμοι κωδικοί μαντεύονται."},
        {"en": "Use keys instead of passwords (or a long password) and disable root login.",
         "el": "Χρησιμοποίησε κλειδιά αντί για κωδικούς (ή πολύ μεγάλο κωδικό) και απενεργοποίησε τη σύνδεση ως root."})

finding("http_admin", "low",
        {"en": "Web interface without encryption (HTTP)", "el": "Σελίδα διαχείρισης χωρίς κρυπτογράφηση (HTTP)"},
        {"en": "This device has a web page over plain HTTP and no HTTPS. If you log in there, the password travels "
               "unencrypted inside your network.",
         "el": "Αυτή η συσκευή έχει σελίδα web μέσω απλού HTTP, χωρίς HTTPS. Αν κάνεις σύνδεση εκεί, ο κωδικός ταξιδεύει "
               "χωρίς κρυπτογράφηση μέσα στο δίκτυο."},
        {"en": "Change the default password, enable HTTPS if available, and log in only from a trusted network.",
         "el": "Άλλαξε τον εργοστασιακό κωδικό, ενεργοποίησε HTTPS αν υπάρχει και συνδέσου μόνο από έμπιστο δίκτυο."})

finding("airplay", "low",
        {"en": "AirPlay receiver on a non-Apple device", "el": "AirPlay σε συσκευή που δεν είναι της Apple"},
        {"en": "In 2025 researchers disclosed 'AirBorne', a set of flaws in Apple's AirPlay SDK that let attackers on the "
               "same Wi-Fi take over third-party AirPlay devices such as TVs and speakers. Apple fixed its own devices, "
               "but other brands must ship their own updates.",
         "el": "Το 2025 ερευνητές αποκάλυψαν το «AirBorne», μια σειρά κενών στο AirPlay SDK της Apple που επέτρεπαν σε "
               "κάποιον στο ίδιο Wi-Fi να πάρει τον έλεγχο συσκευών άλλων εταιρειών, όπως τηλεοράσεις και ηχεία. Η Apple "
               "διόρθωσε τις δικές της συσκευές, αλλά οι άλλες μάρκες πρέπει να βγάλουν δικές τους ενημερώσεις."},
        {"en": "Install the latest firmware on the device. If nobody uses AirPlay at home, turn it off.",
         "el": "Βάλε την τελευταία ενημέρωση λογισμικού στη συσκευή. Αν κανείς στο σπίτι δεν χρησιμοποιεί AirPlay, κλείσ' το."},
        "https://oligo.security/blog/airborne")

finding("netbios", "low",
        {"en": "NetBIOS is open", "el": "Ανοιχτό NetBIOS"},
        {"en": "An old Windows protocol that reveals information such as the computer's name.",
         "el": "Παλιό πρωτόκολλο Windows που αποκαλύπτει πληροφορίες, όπως το όνομα του υπολογιστή."},
        {"en": "Usually not needed. It can be disabled in the network adapter's IPv4 → Advanced → WINS settings.",
         "el": "Συνήθως δεν χρειάζεται. Κλείνει από τις ρυθμίσεις IPv4 της κάρτας δικτύου → Advanced → WINS."})

finding("version_leak", "info",
        {"en": "Software version visible", "el": "Φαίνεται η έκδοση λογισμικού"},
        {"en": "The service tells everyone exactly which software and version it runs. Attackers use this to look up "
               "known vulnerabilities (CVEs) for that exact version.",
         "el": "Η υπηρεσία λέει σε όλους ακριβώς ποιο λογισμικό και ποια έκδοση τρέχει. Οι επιτιθέμενοι το χρησιμοποιούν για "
               "να ψάξουν γνωστά κενά ασφαλείας (CVE) για τη συγκεκριμένη έκδοση."},
        {"en": "Keep the device updated. You can search the version in the NVD vulnerability database (link below).",
         "el": "Κράτα τη συσκευή ενημερωμένη. Μπορείς να ψάξεις την έκδοση στη βάση ευπαθειών NVD (link παρακάτω)."})

finding("unknown_device", "info",
        {"en": "Unidentified device", "el": "Συσκευή που δεν αναγνωρίστηκε"},
        {"en": "HomeGuard could not tell what this device is. It is probably yours, but every device on your network "
               "should be one you recognise.",
         "el": "Το HomeGuard δεν μπόρεσε να καταλάβει τι συσκευή είναι. Μάλλον είναι δική σου, αλλά κάθε συσκευή στο δίκτυο "
               "πρέπει να την αναγνωρίζεις."},
        {"en": "Check your router's list of connected devices, or turn devices off one by one to see which disappears. "
               "If you can't identify it, change your Wi-Fi password.",
         "el": "Δες τη λίστα συνδεδεμένων συσκευών στο router ή κλείνε συσκευές μία-μία για να δεις ποια εξαφανίζεται. Αν δεν "
               "τη βρεις, άλλαξε τον κωδικό του Wi-Fi."})

finding("new_device", "medium",
        {"en": "New device - first time seen on your network", "el": "Νέα συσκευή - πρώτη φορά στο δίκτυο"},
        {"en": "This device has never appeared in any previous scan. It may be a new gadget or a guest, or someone who "
               "knows your Wi-Fi password.",
         "el": "Αυτή η συσκευή δεν έχει εμφανιστεί σε κανένα προηγούμενο σκανάρισμα. Μπορεί να είναι νέα συσκευή ή "
               "επισκέπτης, ή κάποιος που ξέρει τον κωδικό του Wi-Fi σου."},
        {"en": "If you don't recognise it, change your Wi-Fi password and use WPA2/WPA3. Note: some phones change their "
               "private MAC address from time to time, which can make a known phone look new.",
         "el": "Αν δεν την αναγνωρίζεις, άλλαξε τον κωδικό του Wi-Fi και χρησιμοποίησε WPA2/WPA3. Σημείωση: κάποια κινητά "
               "αλλάζουν κατά διαστήματα την ιδιωτική τους MAC, οπότε ένα γνωστό κινητό μπορεί να φανεί νέο."})

PORT_FINDINGS = {
    23: "telnet", 2323: "telnet", 5555: "adb", 2375: "docker", 21: "ftp",
    5900: "vnc", 5901: "vnc", 3306: "database", 5432: "database", 1433: "database",
    27017: "database", 9200: "database", 11211: "database", 3389: "rdp", 445: "smb",
    1883: "mqtt", 554: "rtsp", 7547: "tr069", 22: "ssh", 139: "netbios",
}

HTTP_PORTS = {80, 81, 8000, 8080, 8081, 8088, 8888}
HTTPS_PORTS = {443, 8443}
UPNP_PORTS = {5000, 49152, 1900}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHT = {"critical": 35, "high": 20, "medium": 8, "low": 2, "info": 0}

# General advice that no network scan can check from the inside.
CHECKLIST = [
    {"en": "Change the router's admin password from the factory default (the one on the sticker).",
     "el": "Άλλαξε τον κωδικό διαχείρισης του router από τον εργοστασιακό (αυτόν στο αυτοκόλλητο)."},
    {"en": "Use WPA2 or WPA3 for Wi-Fi with a long password (12+ characters). Never WEP or 'open'.",
     "el": "Χρησιμοποίησε WPA2 ή WPA3 στο Wi-Fi με μεγάλο κωδικό (12+ χαρακτήρες). Ποτέ WEP ή «ανοιχτό» δίκτυο."},
    {"en": "Turn off WPS on the router - its PIN can be brute-forced.",
     "el": "Κλείσε το WPS στο router, γιατί το PIN του σπάει με brute-force."},
    {"en": "Turn off 'Remote management' so the router's admin page is not reachable from the internet.",
     "el": "Κλείσε το «Remote management», ώστε η σελίδα διαχείρισης του router να μη φαίνεται από το internet."},
    {"en": "Update the firmware of your router, TV, cameras and smart devices regularly.",
     "el": "Κάνε τακτικά ενημερώσεις firmware σε router, τηλεόραση, κάμερες και έξυπνες συσκευές."},
    {"en": "Put smart devices (cameras, TV boxes, air conditioners) on a guest Wi-Fi, separate from your computers.",
     "el": "Βάλε τις έξυπνες συσκευές (κάμερες, TV box, κλιματιστικά) σε Wi-Fi επισκεπτών, χωριστά από τους υπολογιστές."},
    {"en": "Check what is visible from the internet with an external port test (e.g. GRC ShieldsUP!).",
     "el": "Έλεγξε τι φαίνεται από το internet με ένα εξωτερικό τεστ πορτών (π.χ. GRC ShieldsUP!)."},
]
