(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const SAMPLE = `Received: by mail.example.com with ESMTPS id zzz; Tue, 03 Nov 2026 06:00:00 +0000
Received: from outbound.badhost.example ([198.51.100.7]) by mail.example.com; Tue, 03 Nov 2026 06:05:00 +0000
Authentication-Results: mail.example.com; spf=pass smtp.mailfrom=bank-example.com; dkim=pass header.d=bank-example.com; dmarc=pass header.from=bank-example.com
Return-Path: <bounce@badhost.example>
From: "Your Bank" <alerts@bank-example.com>
Reply-To: <collect@badhost.example>
To: alice@example.com
Subject: Urgent: verify your account now
Message-ID: <x1@badhost.example>
Date: Tue, 03 Nov 2026 06:04:00 +0000`;

  function esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }
  function row(dl, k, v) {
    if (v == null) return;
    const dt = document.createElement("dt"); dt.textContent = k;
    const dd = document.createElement("dd"); dd.textContent = v;
    dl.appendChild(dt); dl.appendChild(dd);
  }

  function render(r) {
    const dl = $("claims"); dl.innerHTML = "";
    row(dl, "From", r.from); row(dl, "To", r.to); row(dl, "Subject", r.subject);
    row(dl, "Date", r.date); row(dl, "Return-Path", r.returnPath);
    row(dl, "Reply-To", r.replyTo); row(dl, "Message-ID", r.messageId);

    const hops = $("hops"); hops.innerHTML = "";
    $("nohops").hidden = r.hops.length > 0;
    r.hops.forEach((h, i) => {
      const li = document.createElement("li");
      li.innerHTML = "<span class='hopline'>" +
        (h.from ? "from " + esc(h.from) : "from (not recorded)") +
        (h.by ? " &rarr; by " + esc(h.by) : "") + "</span>" +
        (h.date ? "<br><span class='muted'>" + esc(h.date) + "</span>" : "");
      hops.appendChild(li);
    });

    const auth = $("auth"); auth.innerHTML = "";
    if (r.authPresent) {
      r.auth.forEach((a) => {
        const div = document.createElement("div");
        let html = "<p class='muted'>Asserted by <strong>" + esc(a.server || "unknown server") + "</strong> (unverified):</p>";
        for (const m of a.results) html += '<span class="badge">' + esc(m.method) + ": " + esc(m.result) + " (claimed)</span>";
        div.innerHTML = html; auth.appendChild(div);
      });
    } else {
      auth.innerHTML = "<p class='muted'>No Authentication-Results header in this paste.</p>";
    }
    const dk = $("dkim"); dk.innerHTML = "";
    if (r.dkimPresent) {
      let html = "<p class='muted'>DKIM signature header present - cannot be checked from pasted text:</p>";
      for (const d of r.dkim) html += '<span class="badge">d=' + esc(d.domain || "?") + "</span><span class='badge'>s=" + esc(d.selector || "?") + "</span>";
      dk.innerHTML = html;
    } else {
      dk.innerHTML = "<p class='muted'>No DKIM-Signature header in this paste.</p>";
    }

    const sig = $("signals"); sig.innerHTML = "";
    $("nosignals").hidden = r.signals.length > 0;
    for (const s of r.signals) {
      const div = document.createElement("div");
      div.className = "sig";
      let html = '<span class="chip ' + s.severity + '">' + s.severity + "</span><h3>" + esc(s.title) + "</h3>";
      html += "<p>" + esc(s.detail) + "</p>";
      for (const c of s.cites.slice(0, 4)) html += '<div class="cite">' + esc(c.slice(0, 220)) + "</div>";
      div.innerHTML = html;
      sig.appendChild(div);
    }
    $("results").hidden = false;
  }

  $("go").addEventListener("click", () => {
    const t = $("src").value;
    if (!t.trim()) { $("results").hidden = true; return; }
    render(window.HeaderTrace.analyze(t));
  });
  $("sample").addEventListener("click", () => { $("src").value = SAMPLE; $("go").click(); });
  $("clear").addEventListener("click", () => { $("src").value = ""; $("results").hidden = true; });
})();
