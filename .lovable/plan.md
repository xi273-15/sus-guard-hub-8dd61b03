# Phishing Defense + Synthesis Architecture

Two coordinated changes in `src/lib/analysis.ts` (logic) and small touches in `src/routes/index.tsx` + `src/lib/categorize-findings.ts` (UI grouping). Scoring rules from previous turns are preserved.

---

## 1. New module: Link / CTA Integrity

Pure function `analyzeLinkIntegrity({ message, headers, companyDomain, trustedRoots })` that runs alongside the other modules (no network calls — heuristic only, fast and reliable).

### What it inspects
- All URLs extracted from the message body and from any HTML-style `<a href="...">` patterns, plus markdown `[text](url)` pairs.
- Visible CTA text paired with each href (button-like phrases: "Review", "View Job", "Apply", "Verify", "Confirm", "Sign in", "Download", "Open Portal", etc.).
- Static redirect/masking clues:
  - URL shorteners (`bit.ly`, `tinyurl`, `t.co`, `lnkd.in`, `is.gd`, `ow.ly`, `rb.gy`, `cutt.ly`, etc.)
  - Open-redirect patterns (`?url=`, `?redirect=`, `?next=`, `?to=`, Google/Facebook/LinkedIn redirect endpoints)
  - `@` in authority, hex/punycode hosts, `data:` / `javascript:` schemes
  - IP-literal hosts, deeply nested subdomains mimicking the brand
- Whether each destination root domain is in the **trusted set**: companyDomain root + its known affiliated roots (reuse `isLikelyAffiliated` from previous turn) + a small allowlist of obvious infrastructure (e.g. `linkedin.com`, `greenhouse.io`, `lever.co`, `workday.com`, `ashbyhq.com`, `notion.site`, `docs.google.com`, `calendly.com`).

### Output shape (added to `AnalysisResult`)
```ts
export type LinkIntegrityStatus = "clean" | "minor" | "suspicious" | "dangerous" | "unknown";

export type LinkFinding = {
  visible_text: string | null;
  url: string;
  host: string;
  status: "trusted" | "neutral" | "off_domain" | "shortener" | "redirect" | "masked" | "dangerous";
  note: string; // short human-readable reason
};

export type LinkIntegrityResult = {
  available: boolean;            // true when message contained at least one URL
  link_integrity_status: LinkIntegrityStatus;
  link_findings: LinkFinding[];
  link_summary: string;          // one-line plain English
  link_trusted_domains: string[];
  link_suspicious_destinations: string[];
  link_redirect_notes: string[];
};
```

Add `link_integrity: LinkIntegrityResult` to `AnalysisResult`.

### Scoring deltas (added to existing signal pipeline)
- Trusted CTA text + off-domain destination → `bad` signal, weight ~22, contributes to score floor 60.
- Off-domain destination (no trusted-action wording) → `caution`, weight ~12.
- Shortener / open-redirect / masked URL → `caution`, weight ~10 (stacks once, not per link).
- `data:` / `javascript:` / IP host / punycode / userinfo `@` → `bad`, weight ~25, floor 70.
- All links resolve to trusted set → small `positive`, weight ~4.

These are additive on top of the existing SPF/DKIM/DMARC/identity logic. The key invariant from the user's spec: **clean auth does NOT cancel a dangerous CTA destination** — link signals are evaluated independently and never suppressed by a positive sender-domain match.

---

## 2. Central AI Synthesis Layer

New helper `synthesizeNarrative(signals)` invoked once after all modules complete (only in the "have message / have headers" branch and in the no-message branch, both call sites). Replaces the current ad-hoc concatenation of `summaryParts`, `why_it_matters`, and `next_steps`.

### Inputs
A compact structured object built from already-collected results:
```
{
  level, score, domainCheck, headerAuth,
  signals: { scam[], caution[], positive[] },
  modules: { rdap, dns, safe_browsing, ct, wayback,
             recruiter_location, website_traffic,
             osint, recruiter_identity, link_integrity },
  context: { companyName, companyDomain, recruiterName, hasMessage, hasHeaders }
}
```

### Pipeline
1. **Deterministic classifier** (always runs): bins each finding into `email_findings` / `company_findings` / `recruiter_findings` per the user's grouping rules in §4 of the request. This is the source of truth for section grouping — the LLM only writes prose, never decides grouping.
2. **LLM call** via Lovable AI Gateway (`google/gemini-3-flash-preview`, low effort, JSON tool-call schema) producing:
   ```
   {
     summary: string,         // ≤ 4 sentences, leads with biggest danger or "low risk overall"
     why_it_matters: string,  // 2–4 sentences, no system dump
     next_steps: string[]     // 3–5 short imperative bullets
   }
   ```
   System prompt enforces: no jargon (SPF/DKIM only when essential), no contradiction with risk_level, must mention link/CTA red flag in plain language if `link_integrity_status` is `suspicious` or `dangerous`.
3. **Fallback**: if the LLM call fails / returns invalid JSON / no `LOVABLE_API_KEY`, fall back to the current deterministic builders (`buildAudioSummary`, `buildWhyItMatters`, existing `next_steps` set). Synthesis is an enhancement layer, not a hard dependency.
4. **Coherence guard**: post-processing trims summary > 6 sentences, drops bullets that duplicate findings already in `why_points`, and prepends a `⚠️` line for `High` / `Likely Scam` results.

### Where it runs
- `analyzeServer` in `src/lib/analysis.ts`, replacing both:
  - the no-message branch result construction (~line 4111)
  - the full-analysis result construction (~line 4548)

Existing `why_points` array stays as-is (it's the structured "Why it matters" detail list rendered in the UI). The synthesis layer overwrites `why_it_matters` (paragraph form), `audio_summary`, and `next_steps` only.

---

## 3. Section grouping (UI)

In `src/lib/categorize-findings.ts`:
- Extend `emailStats` to include link-integrity verdict.
- Add a `linkIntegrityVerdict()` helper.
- Update `emailVoiceText` to read from `link_integrity` when present.

In `src/routes/index.tsx`:
- Inside the existing **Email findings** modal, add a "Link / CTA Integrity" subsection rendering `link_integrity.link_summary`, the trusted vs. suspicious destinations, and per-link findings (visible text → host with status badge). No new top-level section.

Recruiter and Company sections are already correctly grouped from previous turns; only verify `recruiter_identity` and `recruiter_location` stay in Recruiter, and `website_traffic` / `safe_browsing` / `ct` / `wayback` / `rdap` / `dns` stay in Company.

---

## 4. Summary style enforcement

Hard rules baked into both the LLM system prompt and the post-processing guard:
- ≤ 6 short sentences, ≤ 300 words.
- Lead with biggest danger (or "low risk overall, here's why").
- Never enumerate subsystem names (DNS, RDAP, CT, Wayback, SPF/DKIM/DMARC) unless one of them is THE single decisive signal.
- Must explicitly call out CTA/link danger in plain language when `link_integrity_status ∈ {suspicious, dangerous}`.
- Must not contradict `risk_level`.

---

## Files touched
- `src/lib/analysis.ts` — add `LinkIntegrityResult` types, `analyzeLinkIntegrity()`, `synthesizeNarrative()`, wire into both result-construction paths, add link-integrity signals to scoring.
- `src/lib/categorize-findings.ts` — add `linkIntegrityVerdict`, fold into `emailStats` and `emailVoiceText`.
- `src/routes/index.tsx` — render Link / CTA Integrity inside the existing Email findings modal.

No new dependencies. No schema/db changes. Lovable AI Gateway is already wired (used by `runRecruiterIdentity` synthesis from the previous turn) so no new secret needed.
