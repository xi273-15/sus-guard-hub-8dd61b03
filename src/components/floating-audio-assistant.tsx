import { useMemo } from "react";
import { Play, Pause, Loader2, MessageCircle, Accessibility, Square } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTtsPlayer } from "@/hooks/use-tts-player";

type Line = { text: string; words: string[] };

function splitIntoLines(text: string): Line[] {
  if (!text) return [];
  const sentences = text
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+(?=[A-Z0-9"“'])/g)
    .map((s) => s.trim())
    .filter(Boolean);

  const lines: Line[] = [];
  for (const s of sentences) {
    const words = s.split(/\s+/);
    const chunkSize = 8;
    if (words.length <= chunkSize + 2) {
      lines.push({ text: s, words });
    } else {
      for (let i = 0; i < words.length; i += chunkSize) {
        const slice = words.slice(i, i + chunkSize);
        lines.push({ text: slice.join(" "), words: slice });
      }
    }
  }
  return lines.length ? lines : [{ text: text.trim(), words: text.trim().split(/\s+/) }];
}

export function FloatingAudioAssistant({
  summary,
  introScript,
}: {
  summary?: string;
  introScript?: string;
  /** @deprecated autoplay is intentionally disabled — kept for backwards compatibility */
  autoPlayIntro?: boolean;
}) {
  const { play, stop, status, activeKey, activeText, currentTime, duration, level } = useTtsPlayer();

  // Decide what this orb should play when triggered: prefer summary, fallback to intro
  const primaryText = summary?.trim() || introScript?.trim() || "";
  const primaryKey = summary?.trim() ? "analysis:summary" : "intro:welcome";
  const hasContent = primaryText.length > 0;

  const lines = useMemo(() => splitIntoLines(activeText || ""), [activeText]);
  const totalWords = useMemo(
    () => lines.reduce((acc, l) => acc + l.words.length, 0),
    [lines],
  );

  // Compute active line/word from currentTime
  const { activeLine, activeWord } = useMemo(() => {
    if (!duration || !totalWords) return { activeLine: 0, activeWord: 0 };
    const ratio = Math.min(1, Math.max(0, currentTime / duration));
    const wordIdx = Math.min(totalWords - 1, Math.floor(ratio * totalWords));
    let cumulative = 0;
    for (let i = 0; i < lines.length; i++) {
      const len = lines[i].words.length;
      if (wordIdx < cumulative + len) {
        return { activeLine: i, activeWord: wordIdx - cumulative };
      }
      cumulative += len;
    }
    return { activeLine: 0, activeWord: 0 };
  }, [currentTime, duration, totalWords, lines]);

  const isActiveAnything = status === "playing" || status === "paused" || status === "loading";
  const hasStarted = isActiveAnything; // playback has begun (or is being prepared)
  const showSubtitle =
    isActiveAnything && lines.length > 0 && (status === "playing" || status === "paused");
  const currentLine = lines[activeLine];

  // Audio-reactive scale for the orb rings (smoothed)
  const reactive = status === "playing" ? level : 0;
  const ringScale = 1 + reactive * 0.18;
  const haloOpacity = 0.35 + reactive * 0.5;

  const orbLabel =
    status === "playing"
      ? "Stop spoken audio"
      : status === "paused"
        ? "Resume spoken audio"
        : status === "loading"
          ? "Generating spoken audio"
          : hasContent
            ? "Voice assistant ready — use the speech bubble to start"
            : "Voice assistant";

  const triggerLabel =
    status === "loading"
      ? "Generating audio"
      : hasStarted
        ? "Audio playing — use the orb to pause"
        : "Read aloud";

  function handleTriggerClick() {
    if (!hasContent || hasStarted) return;
    play(primaryText, primaryKey);
  }

  function handleOrbClick() {
    // Orb acts as global stop/resume for the active stream.
    if (!hasStarted) return;
    if (status === "paused") {
      // Resume the active section
      play(activeText, activeKey || primaryKey);
    } else {
      // Stop everything (single-stream guarantee)
      stop();
    }
  }

  return (
    <div
      className="fixed bottom-4 right-4 z-50 flex items-end justify-end gap-2 sm:bottom-6 sm:right-6"
      role="region"
      aria-label="Accessibility audio assistant"
    >
      {/* Subtitle strip — sits to the LEFT of the orb so motion never covers it */}
      <div
        aria-live="polite"
        aria-atomic="true"
        className={cn(
          "pointer-events-none relative z-30 max-w-[min(20rem,calc(100vw-7rem))] origin-bottom-right transition-all duration-300 ease-out",
          showSubtitle ? "opacity-100 scale-100 translate-x-0" : "opacity-0 scale-95 translate-x-1 pointer-events-none",
        )}
      >
        {showSubtitle && currentLine && (
          <div
            className="rounded-2xl border border-foreground/10 bg-foreground px-3.5 py-2 text-xs leading-snug text-background shadow-[0_10px_30px_-10px_rgba(0,0,0,0.45)] sm:text-sm"
            key={`${activeKey}-${activeLine}`}
          >
            <p className="m-0 whitespace-normal">
              {currentLine.words.map((w, i) => {
                const isActive = i === activeWord && status === "playing";
                const isPast = i < activeWord;
                return (
                  <span
                    key={i}
                    className={cn(
                      "transition-colors duration-150",
                      isActive
                        ? "font-semibold text-background"
                        : isPast
                          ? "text-background/60"
                          : "text-background/85",
                    )}
                  >
                    {i > 0 ? " " : ""}
                    {w}
                  </span>
                );
              })}
            </p>
          </div>
        )}
      </div>

      {/* Controls column — trigger + orb stacked on the right */}
      <div className="relative z-10 flex flex-col items-end gap-2">
        {/* Speech-bubble trigger — explicit "start reading" control */}
        {!hasStarted && (
          <button
            type="button"
            onClick={handleTriggerClick}
            disabled={!hasContent}
            aria-label={triggerLabel}
            title={!hasContent ? "Audio not available yet" : triggerLabel}
            className={cn(
              "pointer-events-auto inline-flex items-center gap-1.5 rounded-full border border-border/60 bg-card/90 px-3 py-2 text-xs font-medium text-foreground shadow-[var(--shadow-elegant)] backdrop-blur-xl transition-all hover:scale-[1.03] hover:border-primary/50 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-60 sm:text-sm",
            )}
          >
            <MessageCircle className="h-4 w-4" />
            <span>Read aloud</span>
          </button>
        )}

        {/* Floating orb — pause/resume control (only meaningful once started) */}
        <button
          type="button"
          onClick={handleOrbClick}
          disabled={!hasStarted || status === "loading"}
          aria-label={orbLabel}
          title={orbLabel}
          className={cn(
            "pointer-events-auto group relative inline-flex h-14 w-14 shrink-0 items-center justify-center rounded-full text-primary-foreground shadow-[var(--shadow-glow)] outline-none transition-transform focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background hover:scale-105 active:scale-95 disabled:cursor-default sm:h-16 sm:w-16",
            !hasStarted && "opacity-90",
          )}
          style={{ background: "var(--gradient-primary)" }}
        >
          {/* Audio-reactive halo (only while playing) */}
          {status === "playing" && (
            <>
              <span
                aria-hidden
                className="absolute inset-0 rounded-full transition-transform duration-100 ease-out"
                style={{
                  transform: `scale(${ringScale})`,
                  boxShadow: `0 0 ${18 + reactive * 26}px color-mix(in oklab, var(--primary) ${Math.round(35 + reactive * 40)}%, transparent)`,
                  opacity: haloOpacity,
                }}
              />
              <span
                aria-hidden
                className="absolute -inset-1 rounded-full transition-transform duration-150 ease-out"
                style={{
                  transform: `scale(${1 + reactive * 0.28})`,
                  background: `conic-gradient(from 0deg, color-mix(in oklab, var(--primary) ${Math.round(40 + reactive * 30)}%, transparent), transparent 55%, color-mix(in oklab, var(--cyber) ${Math.round(35 + reactive * 30)}%, transparent), transparent)`,
                  animation: "spin 4s linear infinite",
                  filter: `blur(${4 + reactive * 4}px)`,
                  opacity: 0.55 + reactive * 0.4,
                }}
              />
              {/* Waveform-like rim bars */}
              <span aria-hidden className="absolute inset-0 rounded-full overflow-hidden">
                {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => {
                  const h = 4 + reactive * 12 + Math.sin((Date.now() / 120) + i) * 2;
                  return (
                    <span
                      key={i}
                      className="absolute left-1/2 top-1/2 origin-bottom rounded-full bg-primary-foreground/40"
                      style={{
                        width: 2,
                        height: `${h}px`,
                        transform: `translate(-50%, -50%) rotate(${i * 45}deg) translateY(-${(typeof window !== "undefined" && window.innerWidth >= 640 ? 30 : 26)}px)`,
                      }}
                    />
                  );
                })}
              </span>
            </>
          )}

          {status === "paused" && (
            <span
              aria-hidden
              className="absolute inset-0 rounded-full"
              style={{
                boxShadow: "0 0 18px color-mix(in oklab, var(--primary) 30%, transparent)",
              }}
            />
          )}

          {status === "loading" && (
            <span
              aria-hidden
              className="absolute -inset-1 rounded-full"
              style={{
                background:
                  "conic-gradient(from 0deg, var(--primary), transparent 50%, var(--cyber), transparent)",
                animation: "spin 1.2s linear infinite",
                filter: "blur(2px)",
                opacity: 0.85,
              }}
            />
          )}

          <span className="relative flex items-center justify-center">
            {status === "loading" ? (
              <Loader2 className="h-6 w-6 animate-spin" />
            ) : status === "playing" ? (
              <Square className="h-5 w-5 fill-current" />
            ) : status === "paused" ? (
              <Play className="h-6 w-6 fill-current" />
            ) : (
              <Accessibility className="h-6 w-6" />
            )}
          </span>
        </button>
      </div>
    </div>
  );
}
