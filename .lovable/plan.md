
Great direction — splitting into a focused intro stage and a results stage will make Suscruit feel calmer and much more guided. Here's the plan.

## Two-stage flow

**Stage 1 — Intro + Input (default view)**
- Hide the results column entirely. The form gets the full width with a tighter, more focused layout.
- The floating ElevenLabs orb auto-introduces Suscruit on first load, explaining what it does and what each field is for. Subtitle strip behaves exactly like today.
- A short "Listen to intro" button is also visible for users who dismissed it.

**Stage 2 — Results**
- After the user clicks Analyze, we transition to a results view that hides the form and shows results full-width with a "Check another recruiter" button to return to Stage 1.
- The voice assistant switches to reading the analysis summary (current behavior).

Stage is tracked with a single `stage: "input" | "results"` state.

## Per-field "explain this" play buttons

Next to each field label, add a small ghost icon-button (`Volume2` icon, ~20px) that:
- Speaks a short scripted explanation of that field via the existing `/api/tts` endpoint.
- Reuses the FloatingAudioAssistant infrastructure by lifting playback into a small shared hook (`useTtsPlayer`) so the floating orb and inline buttons share one audio element — clicking a new one cancels the previous.
- Shows a mini loading spinner while fetching, and a pause icon while playing.

Scripts (kept short, ~1 sentence each):
- Recruiter name — "The full name the recruiter used to contact you. Helps us check if it matches their email."
- Recruiter email — "The email address that contacted you. We check the domain, infrastructure, and reputation."
- Company name — "The company they claim to represent. We compare it against their email domain and website."
- Company website — "The website of the company they mention. We check its history, reputation, and certificates."
- Message — "Paste their full message. We scan it for common scam wording, urgency, and red-flag patterns."
- Email headers — "The raw technical headers of the email. They prove who really sent it."

## Email headers help — guided slideshow

Next to the "Email headers" label, add a `HelpCircle` button that opens a Dialog containing a slideshow:

```text
[ Step 1/2 ]   ← →
+----------------------------+
|  Gmail screenshot (g2)     |
+----------------------------+
"In Gmail, open the email,
 click the three dots, then
 'Show original'."
```

- Two slides using the uploaded screenshots `g2.png` (open menu → Show original) and `g3.png` (copy contents inside the orange box).
- Built with shadcn `Dialog` + simple prev/next state (no carousel dep needed). Keyboard arrows + close on Esc.
- Images copied into `src/assets/headers-help/` and imported as ES modules.
- Caption per slide in plain language; final slide ends with "Paste everything you copied into the Email headers box."

## Refactor: shared TTS player

Create `src/hooks/use-tts-player.ts` exporting `useTtsPlayer()` that owns a singleton `<audio>` element + status, and exposes `play(text)`, `pause()`, `stop()`, `status`, `activeKey`. Both `FloatingAudioAssistant` and the new inline `SpeakButton` use it, so only one thing plays at a time and the floating orb visually reflects whatever is currently speaking (intro, field hint, or analysis summary).

A new `<SpeakButton text="..." trackKey="field:recruiterEmail" />` component renders the small play/pause icon next to labels.

## Auto-intro behavior

On first mount of Stage 1 in a session (tracked via `sessionStorage` flag `suscruit_intro_played`), automatically call `play(introScript)` after a 600ms delay so the page is settled. Users can pause anytime via the orb. The intro script is one short paragraph covering what Suscruit does and what to fill in.

## Files to change

- `src/routes/index.tsx` — add stage switcher, results "back" button, wire `SpeakButton` into each `Field`, add headers help dialog trigger.
- `src/components/floating-audio-assistant.tsx` — refactor to consume `useTtsPlayer`; keep the same visual behavior and subtitle strip; accept an optional `introScript` to auto-play on first load when no analysis exists.
- `src/hooks/use-tts-player.ts` — new shared player hook.
- `src/components/speak-button.tsx` — new small inline play/pause icon button.
- `src/components/headers-help-dialog.tsx` — new slideshow Dialog using the two uploaded screenshots.
- `src/assets/headers-help/gmail-menu.png` and `gmail-original.png` — copies of `g2.png` and `g3.png`.

## Visual style

- SpeakButton: `h-6 w-6 rounded-full` ghost button, primary-tinted on hover, sits inline with the field label.
- HelpCircle trigger: same size, muted-foreground default, primary on hover.
- Dialog: matches existing card styling (border-border/60, backdrop-blur), max-w-lg, image fills width with rounded-lg, prev/next arrow buttons + dot indicator.
- Stage transition: simple fade + slight translate-y (200ms) — no heavy animation.

## Out of scope (kept as-is)

- The analysis pipeline, all result cards, scoring, and existing ElevenLabs voice/style stay unchanged.
- No new API routes — everything reuses `/api/tts`.
