# HeaderTrace

Paste the full headers of a suspicious email. HeaderTrace lays out what the headers
claim, in plain language, and checks whether the claims are consistent with each
other - citing the exact lines behind every observation. Everything runs in the
browser; nothing is uploaded.

## The boundary (the point of the tool)

Pasted headers are **untrusted input**. Any line can be forged before it is pasted.

- **Authentication-Results is a claim, not a finding.** It is written by a receiving
  server about its own checks; a forged paste can contain a fake one. HeaderTrace shows
  it as "asserted, unverified" - it cannot confirm or refute it from pasted text.
- **DKIM cannot be recomputed here.** Verifying a signature needs the message's exact
  original bytes and a live DNS lookup; a static page has neither. Signature headers
  are shown as "present, cannot be checked".
- **No verdicts, ever.** No score, no "safe", no risk percentage. Only internal-
  consistency signals (mismatched From/Return-Path, Reply-To redirection, multiple From
  lines, backwards-running Received hops, ...) with the cited lines, plus what each
  pattern can legitimately mean. When in doubt, verify with the organization through a
  channel you already trust.

Differentiation from analyst tools (e.g. MAILSCOPE, Microsoft Message Header Analyzer):
those score and triage for analysts; HeaderTrace explains a single pasted message to a
non-technical recipient and is explicit about what pasted text can never prove.

## Run

Static site - open `index.html` or serve the folder. Tests: `node test.js` (20 checks:
parsing, hop ordering, auth-claim extraction, all five signal families, the
forged-auth-results boundary, DKIM extraction, garbage input, determinism).
