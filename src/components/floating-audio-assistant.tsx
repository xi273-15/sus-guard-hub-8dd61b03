import { useEffect, useMemo, useRef, useState } from "react";
import { Play, Pause, Loader2, Accessibility } from "lucide-react";
import { cn } from "@/lib/utils";

type Status = "idle" | "loading" | "playing" | "paused";

type Line = { text: string; words: string[] };

function splitIntoLines(text: string): Line[] {
  if (!text) return [];
  const sentences = text
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+(?=[A-Z0-9"“'])/g)
    .map((s) => s.trim())
    .filter(Boolean);

  // Further break long sentences into ~8-word lines for subtitle feel
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

export function FloatingAudioAssistant({ summary }: { summary?: string }) {
  const [status, setStatus] = useState<Status>("idle");
  const [activeLine, setActiveLine] = useState(0);
  const [activeWord, setActiveWord] = useState(0);
  const [duration, setDuration] = useState(0);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const rafRef = useRef<number | null>(null);

  const lines = useMemo(() => splitIntoLines(summary || ""), [summary]);
  const totalWords = useMemo(() => lines.reduce((acc, l) => acc + l.words.length, 0), [lines]);
  const hasContent = lines.length > 0;

  // Reset when the analysis (summary) changes
  useEffect(() => {
    stopAudio();
    setActiveLine(0);
    setActiveWord(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary]);

  useEffect(() => {
    return () => {
      stopAudio();
    };
  }, []);

  function clearTracker() {
    if (rafRef.current !== null) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
  }

  function startTracker(audio: HTMLAudioElement, total: number) {
    clearTracker();
    if (!total || !isFinite(total) || totalWords === 0) return;

    const tick = () => {
      const ratio = Math.min(1, Math.max(0, audio.currentTime / total));
      const wordIdx = Math.min(totalWords - 1, Math.floor(ratio * totalWords));
      // Find which line this word lives in
      let cumulative = 0;
      for (let i = 0; i < lines.length; i++) {
        const len = lines[i].words.length;
        if (wordIdx < cumulative + len) {
          setActiveLine(i);
          setActiveWord(wordIdx - cumulative);
          break;
        }
        cumulative += len;
      }
      rafRef.current = requestAnimationFrame(tick);
    };
    rafRef.current = requestAnimationFrame(tick);
  }

  function stopAudio() {
    clearTracker();
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current.src = "";
      audioRef.current = null;
    }
    setStatus("idle");
  }

  async function handleClick() {
    if (status === "loading") return;
    if (status === "playing" && audioRef.current) {
      audioRef.current.pause();
      setStatus("paused");
      clearTracker();
      return;
    }
    if (status === "paused" && audioRef.current) {
      await audioRef.current.play();
      setStatus("playing");
      if (duration) startTracker(audioRef.current, duration);
      return;
    }

    if (!summary) return;
    try {
      setStatus("loading");
      const res = await fetch("/api/tts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: summary }),
      });
      if (!res.ok) throw new Error(await res.text());
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const audio = new Audio(url);
      audioRef.current = audio;
      audio.onloadedmetadata = () => {
        const d = audio.duration;
        setDuration(d);
        startTracker(audio, d);
      };
      audio.onended = () => {
        URL.revokeObjectURL(url);
        clearTracker();
        setStatus("idle");
        setActiveLine(0);
        setActiveWord(0);
      };
      audio.onerror = () => {
        URL.revokeObjectURL(url);
        clearTracker();
        setStatus("idle");
      };
      await audio.play();
      setStatus("playing");
    } catch (err) {
      console.error("TTS error:", err);
      setStatus("idle");
    }
  }

  const buttonLabel =
    status === "playing"
      ? "Pause spoken summary"
      : status === "loading"
        ? "Generating spoken summary"
        : status === "paused"
          ? "Resume spoken summary"
          : "Play spoken summary of analysis";

  const showSubtitle = hasContent && (status === "playing" || status === "paused");
  const currentLine = lines[activeLine];

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
            key={activeLine}
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
        {hasContent && status === "idle" && (
          <div className="sr-only">Spoken summary ready. Press play to listen.</div>
        )}
      </div>

      {/* Floating orb */}
      <button
        type="button"
        onClick={handleClick}
        disabled={status === "loading" || (!hasContent && status === "idle")}
        aria-label={buttonLabel}
        title={!hasContent ? "Run an analysis to enable audio" : buttonLabel}
        className={cn(
          "pointer-events-auto group relative inline-flex h-14 w-14 shrink-0 items-center justify-center rounded-full text-primary-foreground shadow-[var(--shadow-glow)] outline-none transition-transform focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background hover:scale-105 active:scale-95 disabled:cursor-not-allowed disabled:opacity-60 sm:h-16 sm:w-16",
        )}
        style={{ background: "var(--gradient-primary)" }}
      >
        {/* Idle soft glow */}
        {status === "idle" && hasContent && (
          <span
            aria-hidden
            className="absolute inset-0 rounded-full animate-pulse-glow"
            style={{
              boxShadow: "0 0 24px color-mix(in oklab, var(--primary) 45%, transparent)",
            }}
          />
        )}

        {/* Playing — multi-ring waveform-like ripple */}
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

        {/* Paused — gentle steady ring */}
        {status === "paused" && (
          <span
            aria-hidden
            className="absolute inset-0 rounded-full"
            style={{
              boxShadow: "0 0 18px color-mix(in oklab, var(--primary) 35%, transparent)",
            }}
          />
        )}

        {/* Loading — rotating gradient ring */}
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
