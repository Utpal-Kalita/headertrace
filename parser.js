// HeaderTrace deterministic email-header parser and signal checker.
//
// HARD BOUNDARY (design rule, do not weaken): pasted headers are UNTRUSTED input.
// Every line is an assertion by an unknown party. This tool never verifies, never
// scores, and never says "safe". It structures what the headers claim, checks
// internal consistency, and cites the exact lines behind every signal. An
// Authentication-Results header is the receiving server's claim about itself -
// a forged paste can contain a fake one - so it is always shown as "asserted,
// not verified". DKIM cannot be recomputed from pasted text (needs the exact
// original bytes and a DNS lookup), so DKIM headers are shown as "present,
// cannot be checked here".
(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.HeaderTrace = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Unfold continuation lines and split into ordered header entries, top first.
  function parseHeaders(text) {
    const lines = String(text).replace(/\r\n?/g, "\n").split("\n");
    const headers = [];
    for (const line of lines) {
      if (/^\s/.test(line) && headers.length > 0) {
        headers[headers.length - 1].value += " " + line.trim();
        headers[headers.length - 1].raw.push(line);
      } else {
        const idx = line.indexOf(":");
        if (idx <= 0) continue; // not a header line; skip silently
        headers.push({
          name: line.slice(0, idx).trim(),
          nameLower: line.slice(0, idx).trim().toLowerCase(),
          value: line.slice(idx + 1).trim(),
          raw: [line]
        });
      }
    }
    return headers;
  }

  function first(headers, name) {
    const h = headers.find((x) => x.nameLower === name.toLowerCase());
    return h ? h.value : null;
  }
  function all(headers, name) {
    return headers.filter((x) => x.nameLower === name.toLowerCase());
  }
  function addrDomain(v) {
    if (!v) return null;
    const m = v.match(/@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/);
    return m ? m[1].toLowerCase() : null;
  }
  function addrLocal(v) {
    if (!v) return null;
    const m = v.match(/([A-Za-z0-9._%+-]+)@/);
    return m ? m[1].toLowerCase() : null;
  }

  // Parse one Authentication-Results header into method=result pairs.
  function parseAuthResults(value) {
    const out = [];
    if (!value) return out;
    const server = value.split(";")[0].trim();
    const parts = value.split(";").slice(1).join(";").split(/\s+(?=[a-z-]+\s*=)/i);
    for (const p of parts) {
      const m = p.trim().match(/^([a-z-]+)\s*=\s*([a-z]+)/i);
      if (m) out.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase() });
    }
    return { server, results: out };
  }

  // Received chain: topmost header is the LAST hop (nearest the recipient).
  function parseReceived(value) {
    const fromM = value.match(/from\s+([^\s(]+)/i);
    const byM = value.match(/by\s+([^\s(]+)/i);
    const dateM = value.match(/;\s*(.+)$/);
    return {
      from: fromM ? fromM[1] : null,
      by: byM ? byM[1] : null,
      date: dateM ? dateM[1].trim() : null,
      timestamp: dateM ? Date.parse(dateM[1]) : NaN
    };
  }

  // Signal checks. Each returns null or a signal citing exact header lines.
  // Signals are consistency observations with honest uncertainty - never verdicts.
  function checkSignals(headers) {
    const signals = [];
    const fromV = first(headers, "From");
    const fromHs = all(headers, "From");
    const returnPath = first(headers, "Return-Path");
    const replyTo = first(headers, "Reply-To");
    const messageId = first(headers, "Message-ID");
    const authHs = all(headers, "Authentication-Results");
    const dkimHs = all(headers, "DKIM-Signature");
    const receivedHs = all(headers, "Received");

    if (fromHs.length > 1) {
      signals.push({
        id: "multiple-from",
        severity: "strong",
        title: "More than one From header",
        detail: "The paste contains " + fromHs.length + " From headers. Standards allow exactly one; multiple From lines are a known spoofing artifact.",
        cites: fromHs.map((h) => h.raw.join("\n"))
      });
    }

    const fromDom = addrDomain(fromV);
    const rpDom = addrDomain(returnPath);
    if (fromDom && rpDom && fromDom !== rpDom) {
      signals.push({
        id: "from-returnpath-mismatch",
        severity: "moderate",
        title: "From and Return-Path domains differ",
        detail: "The visible sender is " + fromDom + " but the envelope return address (where bounces and delivery errors go) is " + rpDom + ". This is normal for mailing lists and some providers, and it is also how simple spoofs look. The headers alone cannot say which. (Where replies go depends on any Reply-To header - checked separately.)",
        cites: ["From: " + fromV, "Return-Path: " + returnPath]
      });
    }

    const rtDom = addrDomain(replyTo);
    if (fromDom && rtDom && fromDom !== rtDom) {
      signals.push({
        id: "replyto-mismatch",
        severity: "moderate",
        title: "Reply-To points to a different domain",
        detail: "Replies would go to " + rtDom + ", not the visible sender " + fromDom + ". Sometimes legitimate (support desks), sometimes used to redirect replies away from a forged sender.",
        cites: ["From: " + fromV, "Reply-To: " + replyTo]
      });
    }

    if (messageId) {
      const midDom = addrDomain(messageId);
      if (fromDom && midDom && midDom !== fromDom) {
        signals.push({
          id: "messageid-domain-mismatch",
          severity: "weak",
          title: "Message-ID domain differs from the From domain",
          detail: "The Message-ID was minted at " + midDom + " while the sender shows " + fromDom + ". Common when a provider relays mail; also consistent with a message that did not originate where it claims.",
          cites: ["From: " + fromV, "Message-ID: " + messageId]
        });
      }
    }

    if (receivedHs.length >= 2) {
      const hops = receivedHs.map((h) => parseReceived(h.value));
      // Topmost Received = newest. Timestamps should not run backwards top-to-bottom.
      let inversions = 0;
      for (let i = 0; i + 1 < hops.length; i++) {
        const newer = hops[i].timestamp, older = hops[i + 1].timestamp;
        if (!isNaN(newer) && !isNaN(older) && newer < older - 60000) inversions++;
      }
      if (inversions > 0) {
        signals.push({
          id: "received-time-inversion",
          severity: inversions >= 2 ? "strong" : "moderate",
          title: "Received hops run backwards in time",
          detail: inversions + " hop(s) carry timestamps earlier than the hop below them. That can come from pasted or injected hop lines - and also from ordinary clock skew between servers, which is common. Worth a look, not proof of tampering.",
          cites: receivedHs.map((h) => h.raw.join("\n").slice(0, 200))
        });
      }
    } else if (receivedHs.length === 0) {
      signals.push({
        id: "no-received",
        severity: "weak",
        title: "No Received headers at all",
        detail: "A delivered message normally carries at least one Received hop from the receiving server. A paste without any may be incomplete, hand-written, or exported from the sender's side.",
        cites: []
      });
    }

    return signals;
  }

  function analyze(text) {
    const headers = parseHeaders(text);
    const authHs = all(headers, "Authentication-Results");
    const authParsed = authHs.map((h) => parseAuthResults(h.value));
    const dkimHs = all(headers, "DKIM-Signature");
    const receivedHs = all(headers, "Received");
    const hops = receivedHs.map((h) => parseReceived(h.value));
    const signals = checkSignals(headers);
    return {
      headerCount: headers.length,
      from: first(headers, "From"),
      to: first(headers, "To"),
      subject: first(headers, "Subject"),
      date: first(headers, "Date"),
      returnPath: first(headers, "Return-Path"),
      replyTo: first(headers, "Reply-To"),
      messageId: first(headers, "Message-ID"),
      hops,
      auth: authParsed,
      dkim: dkimHs.map((h) => {
        const d = h.value.match(/(?:^|\s)d=([^;\s]+)/i);
        const s = h.value.match(/(?:^|\s)s=([^;\s]+)/i);
        return { domain: d ? d[1] : null, selector: s ? s[1] : null, raw: h.raw.join("\n") };
      }),
      signals,
      authPresent: authHs.length > 0,
      dkimPresent: dkimHs.length > 0,
      spfHeader: first(headers, "Received-SPF")
    };
  }

  return { parseHeaders, parseAuthResults, parseReceived, checkSignals, analyze, addrDomain };
});
