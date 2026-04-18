import { useEffect, useMemo, useRef } from "react";
import { Play, Pause, Loader2, Accessibility } from "lucide-react";
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
  autoPlayIntro,
}: {
  summary?: string;
  introScript?: string;
  autoPlayIntro?: boolean;
}) {
  const { play, status, activeKey, activeText, currentTime, duration } = useTtsPlayer();

  // Decide what this orb should play when clicked: prefer summary, fallback to intro
  const primaryText = summary?.trim() || introScript?.trim() || "";
  const primaryKey = summary?.trim() ? "analysis:summary" : "intro:welcome";

  // Auto-play intro once per session
  const introFiredRef = useRef(false);
  useEffect(() => {
    if (!autoPlayIntro || !introScript) return;
    if (introFiredRef.current) return;
    if (typeof window === "undefined") return;
    if (sessionStorage.getItem("suscruit_intro_played") === "1") return;
    introFiredRef.current = true;
    const t = setTimeout(() => {
      sessionStorage.setItem("suscruit_intro_played", "1");
      play(introScript, "intro:welcome");
    }, 600);
    return () => clearTimeout(t);
  }, [autoPlayIntro, introScript, play]);

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

  const hasContent = primaryText.length > 0;
  const isActiveAnything = status === "playing" || status === "paused" || status === "loading";
  const showSubtitle =
    isActiveAnything && lines.length > 0 && (status === "playing" || status === "paused");
  const currentLine = lines[activeLine];

  const buttonLabel =
    status === "playing"
      ? "Pause spoken summary"
      : status === "loading"
        ? "Generating spoken audio"
        : status === "paused"
          ? "Resume spoken audio"
          : "Play spoken summary";

  function handleClick() {
    if (!hasContent) return;
    play(primaryText, primaryKey);
  }

  return (
    <div
      className="fixed bottom-4 right-4 z-50 flex items-center gap-2 sm:bottom-6 sm:right-6"
      role="region"
      aria-label="Accessibility audio assistant"
    >
      {/* Subtitle strip */}
      <div
        aria-live="polite"
        aria-atomic="true"
        className={cn(
          "pointer-events-none max-w-[min(22rem,calc(100vw-6rem))] origin-right transition-all duration-300 ease-out",
          showSubtitle
            ? "translate-x-0 opacity-100 scale-100"
            : "translate-x-3 opacity-0 scale-95",
        )}
      >
        {showSubtitle && currentLine && (
          <div
            className="rounded-full border border-border/60 bg-card/90 px-3 py-1.5 text-xs leading-snug shadow-[var(--shadow-elegant)] backdrop-blur-xl sm:text-sm"
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
                        ? "font-semibold text-foreground"
                        : isPast
                          ? "text-muted-foreground/80"
                          : "text-muted-foreground",
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

      {/* Floating orb */}
      <button
        type="button"
        onClick={handleClick}
        disabled={status === "loading" || !hasContent}
        aria-label={buttonLabel}
        title={!hasContent ? "Audio not available yet" : buttonLabel}
        className={cn(
          "pointer-events-auto group relative inline-flex h-14 w-14 shrink-0 items-center justify-center rounded-full text-primary-foreground shadow-[var(--shadow-glow)] outline-none transition-transform focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background hover:scale-105 active:scale-95 disabled:cursor-not-allowed disabled:opacity-60 sm:h-16 sm:w-16",
        )}
        style={{ background: "var(--gradient-primary)" }}
      >
        {status === "idle" && hasContent && (
          <span
            aria-hidden
            className="absolute inset-0 rounded-full animate-pulse-glow"
            style={{
              boxShadow: "0 0 24px color-mix(in oklab, var(--primary) 45%, transparent)",
            }}
          />
        )}

        {status === "playing" && (
          <>
            <span
              aria-hidden
              className="absolute inset-0 rounded-full animate-ping"
              style={{
                background: "color-mix(in oklab, var(--primary) 30%, transparent)",
                animationDuration: "1.6s",
              }}
            />
            <span
              aria-hidden
              className="absolute -inset-1 rounded-full animate-ping"
              style={{
                background: "color-mix(in oklab, var(--cyber) 22%, transparent)",
                animationDuration: "2.2s",
                animationDelay: "0.3s",
              }}
            />
            <span
              aria-hidden
              className="absolute -inset-2 rounded-full opacity-70"
              style={{
                background:
                  "conic-gradient(from 0deg, color-mix(in oklab, var(--primary) 60%, transparent), transparent 60%, color-mix(in oklab, var(--cyber) 50%, transparent), transparent)",
                animation: "spin 3.5s linear infinite",
                filter: "blur(6px)",
              }}
            />
          </>
        )}

        {status === "paused" && (
          <span
            aria-hidden
            className="absolute inset-0 rounded-full"
            style={{
              boxShadow: "0 0 18px color-mix(in oklab, var(--primary) 35%, transparent)",
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
            <Pause className="h-6 w-6 fill-current" />
          ) : hasContent ? (
            <Play className="h-6 w-6 fill-current" />
          ) : (
            <Accessibility className="h-6 w-6" />
          )}
        </span>
      </button>
    </div>
  );
}
