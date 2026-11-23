// HomeGuard dashboard behaviour (kept in a separate file so the page can use a strict
// Content-Security-Policy that forbids inline scripts - a defence against XSS).

(function () {
  "use strict";

  // ---- Remember the consent checkbox (per browser) ----
  const consent = document.getElementById("consent");
  const scanBtn = document.getElementById("scanbtn");
  const running = document.body.dataset.running === "1";

  // localStorage can be blocked (private mode etc.), so always wrap it in try/catch
  function store(key, value) {
    try { localStorage.setItem(key, value); } catch (e) { /* ignore */ }
  }
  function read(key) {
    try { return localStorage.getItem(key); } catch (e) { return null; }
  }

  if (consent && scanBtn) {
    consent.checked = read("hg-consent") === "1";
    const sync = () => { if (!running) scanBtn.disabled = !consent.checked; };
    consent.addEventListener("change", () => { store("hg-consent", consent.checked ? "1" : "0"); sync(); });
    sync();
  }

  // ---- Print / PDF: open every finding first so the printout is complete ----
  const printBtn = document.getElementById("printbtn");
  if (printBtn) {
    printBtn.addEventListener("click", () => {
      document.querySelectorAll("details.finding").forEach(d => { d.open = true; });
      window.print();
    });
  }

  // ---- Live progress while a scan is running ----
  if (!running) return;
  const box = document.getElementById("progress");
  const phase = document.getElementById("phase");
  const count = document.getElementById("count");
  const fill = document.getElementById("bar-fill");
  const order = ["start", "discover", "identify", "ports", "banners"];

  async function poll() {
    try {
      const s = await (await fetch("/api/status", { cache: "no-store" })).json();
      if (!s.running) { location.href = "/"; return; }
      const i = Math.max(0, order.indexOf(s.phase));
      const part = s.total ? s.done / s.total : 0;
      // each phase is a quarter of the bar
      const pct = Math.min(99, ((Math.max(i, 1) - 1) + part) / 4 * 100);
      fill.style.width = Math.max(3, pct) + "%";
      phase.textContent = box.dataset[s.phase] || box.dataset.start;
      count.textContent = s.total ? `${s.done} / ${s.total}` : "";
    } catch (e) { /* server busy - try again */ }
    setTimeout(poll, 1200);
  }
  poll();
})();
