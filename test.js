const P = require("./parser.js");
let pass = 0, fail = 0;
function ok(cond, name) { if (cond) { pass++; } else { fail++; console.log("FAIL: " + name); } }

const LEGIT = `Delivered-To: alice@example.com
Received: by mail.example.com with ESMTPS id abc123; Tue, 03 Nov 2026 06:10:00 +0000
Received: from smtp.bank-example.com (smtp.bank-example.com [203.0.113.10]) by mail.example.com; Tue, 03 Nov 2026 06:09:30 +0000
Authentication-Results: mail.example.com; spf=pass smtp.mailfrom=bank-example.com; dkim=pass header.d=bank-example.com; dmarc=pass header.from=bank-example.com
Return-Path: <alerts@bank-example.com>
From: "Bank Alerts" <alerts@bank-example.com>
To: alice@example.com
Subject: Your statement is ready
Message-ID: <stmt-991@bank-example.com>
Date: Tue, 03 Nov 2026 06:09:00 +0000`;

const r1 = P.analyze(LEGIT);
ok(r1.headerCount === 10, "parses all headers (got " + r1.headerCount + ")");
ok(r1.from === '"Bank Alerts" <alerts@bank-example.com>', "from parsed");
ok(r1.hops.length === 2, "two received hops");
ok(r1.hops[0].by === "mail.example.com", "top hop is newest (by)");
ok(r1.auth.length === 1 && r1.auth[0].results.length === 3, "auth results parsed into 3 methods");
ok(r1.auth[0].results.map((x) => x.method).join(",") === "spf,dkim,dmarc", "methods spf/dkim/dmarc");
ok(r1.signals.length === 0, "consistent legit headers raise no signals (got " + r1.signals.map((s) => s.id).join(",") + ")");

const SPOOF = `Received: by mail.example.com with ESMTPS id zzz; Tue, 03 Nov 2026 06:00:00 +0000
Received: from evil-relay.badhost.example ([198.51.100.7]) by mail.example.com; Tue, 03 Nov 2026 06:05:00 +0000
Return-Path: <bounce@badhost.example>
From: "Your Bank" <alerts@bank-example.com>
From: "Backup" <alerts@bank-example.com>
Reply-To: <collect@badhost.example>
To: alice@example.com
Subject: Urgent verify your account
Message-ID: <x1@badhost.example>
Date: Tue, 03 Nov 2026 06:04:00 +0000`;

const r2 = P.analyze(SPOOF);
const ids2 = r2.signals.map((s) => s.id);
ok(ids2.includes("multiple-from"), "multiple From flagged");
ok(ids2.includes("from-returnpath-mismatch"), "return-path mismatch flagged");
ok(ids2.includes("replyto-mismatch"), "reply-to mismatch flagged");
ok(ids2.includes("messageid-domain-mismatch"), "message-id mismatch flagged");
ok(ids2.includes("received-time-inversion"), "time inversion flagged (newest hop 06:00 above older 06:05)");
ok(r2.authPresent === false, "no auth assertions detected as absent");
ok(r2.signals.every((s) => s.cites.length > 0), "every spoof signal cites lines");

// HARD BOUNDARY: a forged Authentication-Results claiming pass must NOT verify anything.
const FORGED = `Authentication-Results: mail.example.com; spf=pass; dkim=pass; dmarc=pass
From: "Bank" <alerts@bank-example.com>
To: alice@example.com
Subject: hi
Date: Tue, 03 Nov 2026 06:00:00 +0000`;
const r3 = P.analyze(FORGED);
ok(r3.authPresent === true, "forged auth header parsed as present");
ok(r3.auth[0].results.every((x) => x.result === "pass"), "forged pass values parsed as claims");
// the model has no "verified" concept: analyze() output must never contain a verification verdict
ok(!("verified" in r3) && !("verdict" in r3) && !("safe" in r3), "no verdict/verified/safe fields exist");

// DKIM shown as present-but-uncheckable
const DK = `DKIM-Signature: v=1; a=rsa-sha256; d=bank-example.com; s=sel1; bh=abc; b=def
From: <alerts@bank-example.com>
Date: Tue, 03 Nov 2026 06:00:00 +0000`;
const r4 = P.analyze(DK);
ok(r4.dkimPresent && r4.dkim[0].domain === "bank-example.com" && r4.dkim[0].selector === "sel1", "dkim d=/s= extracted");

// malformed input degrades gracefully
const r5 = P.analyze("not a header at all\n\njust text");
ok(r5.headerCount === 0 && Array.isArray(r5.signals), "garbage input safe");

// determinism
ok(JSON.stringify(P.analyze(SPOOF)) === JSON.stringify(P.analyze(SPOOF)), "deterministic");

console.log(pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);
