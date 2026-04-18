import { useEffect, useMemo, useRef, useState } from "react";
import {
  Play,
  Pause,
  Loader2,
  ChevronRight,
  ChevronLeft,
  Accessibility,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";

type Status = "idle" | "loading" | "playing" | "paused";

function splitIntoChunks(text: string): string[] {
  if (!text) return [];
  // Split on sentence boundaries while keeping things readable.
  const parts = text
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+(?=[A-Z0-9"“'])/g)
    .map((s) => s.trim())
    .filter(Boolean);
  return parts.length ? parts : [text.trim()];
}

export function FloatingAudioAssistant({ summary }: { summary?: string }) {
  const [status, setStatus] = useState<Status>("idle");
  const [open, setOpen] = useState(false);
  const [activeChunk, setActiveChunk] = useState(0);
  const [duration, setDuration] = useState(0);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const intervalRef = useRef<number | null>(null);
  const activeChunkRef = useRef<HTMLLIElement | null>(null);

  const chunks = useMemo(() => splitIntoChunks(summary || ""), [summary]);
  const hasContent = chunks.length > 0;

  // Reset when the analysis (summary) changes
  useEffect(() => {
    stopAudio();
    setActiveChunk(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary]);

  // Auto-scroll active chunk into view inside the panel
  useEffect(() => {
    if (open && activeChunkRef.current) {
      activeChunkRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [activeChunk, open]);

  useEffect(() => {
    return () => {
      stopAudio();
    };
  }, []);

  function clearTracker() {
    if (intervalRef.current !== null) {
      window.clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }

  function startTracker(audio: HTMLAudioElement, total: number) {
    clearTracker();
    if (chunks.length <= 1 || !total || !isFinite(total)) return;
    intervalRef.current = window.setInterval(() => {
      const ratio = audio.currentTime / total;
      const idx = Math.min(chunks.length - 1, Math.floor(ratio * chunks.length));
      setActiveChunk(idx);
    }, 200);
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

    // idle -> generate & play
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
        setActiveChunk(0);
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

  return (
    <div
      className="fixed bottom-4 right-4 z-50 flex items-end gap-2 sm:bottom-6 sm:right-6"
      role="region"
      aria-label="Accessibility audio assistant"
    >
      {/* Transcript panel */}
      <div
        id="audio-transcript-panel"
        className={cn(
          "pointer-events-auto origin-bottom-right overflow-hidden rounded-2xl border border-border/60 bg-card/95 shadow-[var(--shadow-elegant)] backdrop-blur-xl transition-all duration-300 ease-out",
          open
            ? "mb-0 w-[min(20rem,calc(100vw-7rem))] sm:w-80 opacity-100 translate-x-0"
            : "pointer-events-none w-0 opacity-0 translate-x-4",
        )}
        aria-hidden={!open}
      >
        <div className="flex items-center justify-between border-b border-border/60 px-3 py-2">
          <div className="flex items-center gap-2 min-w-0">
            <span
              className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-primary"
              style={{ backgroundColor: "color-mix(in oklab, var(--primary) 14%, transparent)" }}
            >
              <Accessibility className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0">
              <p className="truncate text-xs font-semibold leading-tight">Spoken summary</p>
              <p className="truncate text-[10px] text-muted-foreground">
                Accessibility · ElevenLabs
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="rounded-md p-1 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            aria-label="Close transcript panel"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
        <div className="max-h-[55vh] overflow-y-auto px-3 py-3 sm:max-h-80">
          {hasContent ? (
            <ol className="space-y-2">
              {chunks.map((c, i) => {
                const isActive = i === activeChunk && status === "playing";
                return (
                  <li
                    key={i}
                    ref={isActive ? activeChunkRef : null}
                    className={cn(
                      "rounded-md px-2 py-1.5 text-xs leading-relaxed transition-colors",
                      isActive
                        ? "bg-primary/15 text-foreground ring-1 ring-primary/40"
                        : i < activeChunk && status !== "idle"
                          ? "text-muted-foreground/70"
                          : "text-muted-foreground",
                    )}
                  >
                    {c}
                  </li>
                );
              })}
            </ol>
          ) : (
            <p className="text-xs leading-relaxed text-muted-foreground">
              Run an analysis to hear and read the spoken summary.
            </p>
          )}
        </div>
      </div>

      {/* Chevron toggle attached to the circle */}
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls="audio-transcript-panel"
        aria-label={open ? "Collapse transcript" : "Expand transcript"}
        className="pointer-events-auto inline-flex h-8 w-5 items-center justify-center rounded-l-md border border-r-0 border-border/60 bg-card/90 text-muted-foreground shadow-sm backdrop-blur transition-colors hover:bg-muted hover:text-foreground"
      >
        {open ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronLeft className="h-3.5 w-3.5" />}
      </button>

      {/* Main circular button */}
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
        {/* pulse ring while playing */}
        {status === "playing" && (
          <span
            aria-hidden
            className="absolute inset-0 animate-ping rounded-full"
            style={{ background: "color-mix(in oklab, var(--primary) 35%, transparent)" }}
          />
        )}
        <span className="relative flex items-center justify-center">
          {status === "loading" ? (
            <Loader2 className="h-6 w-6 animate-spin" />
          ) : status === "playing" ? (
            <Pause className="h-6 w-6 fill-current" />
          ) : (
            <Play className="h-6 w-6 fill-current" />
          )}
        </span>
      </button>
    </div>
  );
}
