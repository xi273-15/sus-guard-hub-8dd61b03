
The user wants plain hyperlinks. The current `ExternalLink` component already uses a native `<a target="_blank" rel="noopener noreferrer">` — clicks DO open the real URL directly. The `ERR_BLOCKED_BY_RESPONSE` they see is LinkedIn/Glassdoor refusing the request from a fresh tab with no session cookies (anti-bot), not anything our app does.

But the user's complaint is valid UX: the copy button is a workaround, not a fix. We should make the primary click "just work" as much as possible, and stop surfacing copy as the main affordance.

## Root cause of the block
LinkedIn's `/in/<slug>` and search URLs return `x-frame-options` and aggressive bot checks that sometimes 999/blocked-by-response even on direct top-level navigation when the Referer is a Lovable preview domain. Same for Glassdoor.

## Fix strategy

1. **Strip the Referer** on outbound clicks so target sites see a clean request (no lovable.app referrer that triggers their anti-scraping). Change `rel="noopener noreferrer"` → `rel="noopener noreferrer"` already strips referer ✓ — but we also need `referrerPolicy="no-referrer"` on the anchor explicitly (belt and suspenders, some browsers honor only the attribute).

2. **Normalize known-blocky URLs** to their canonical public form:
   - LinkedIn search URLs (`/search/results/...`) → rewrite to a Google search fallback `https://www.google.com/search?q=site:linkedin.com/in+"<name>"+"<company>"` which always works.
   - Bare `linkedin.com/in/<slug>` → keep as-is (these usually work on direct click; the search URLs are what 999s).
   - Glassdoor search → rewrite to Google `site:glassdoor.com "<company>"`.

3. **Remove the copy button** from the primary UI. Make the anchor the only affordance. Move copy into a tiny right-click-style hover-only icon, or drop it entirely.

4. **Keep recruiter-location detection untouched** — it's backend-only, already decoupled.

## Changes

**`src/components/external-link.tsx`**
- Remove copy button from default render (or hide behind hover).
- Add `referrerPolicy="no-referrer"` to the `<a>`.
- Add a `normalizeUrl(href)` helper:
  - If host is `linkedin.com` and path starts with `/search/`, return `https://www.google.com/search?q=` + encoded `site:linkedin.com/in "<query extracted from URL params>"`.
  - If host is `glassdoor.com` and it's a search/listing URL, return Google site-search equivalent.
  - Else return original href.
- Anchor uses the normalized URL; show original domain as a small muted hint so user knows where it goes.

**No other files change.** `src/routes/index.tsx` already uses `ExtLink`.

## Why this works
- Direct profile links (linkedin.com/in/john-doe) open fine in a new tab — those were never the issue.
- Search-result links (the ones that 999) get auto-redirected through Google, which always loads and shows the real LinkedIn link as the first result. One extra click but zero error pages.
- No referer leak.
- No copy/paste UX.

## Out of scope
Server-side proxy (would re-introduce the "internal viewer" pattern the user explicitly rejected).
