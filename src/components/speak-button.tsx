import { Volume2, Pause, Loader2 } from "lucide-react";
import { useTtsPlayer } from "@/hooks/use-tts-player";
import { cn } from "@/lib/utils";

export function SpeakButton({
  text,
  trackKey,
  label,
  className,
}: {
  text: string;
  trackKey: string;
  label?: string;
  className?: string;
}) {
  const { play, status, activeKey } = useTtsPlayer();
  const isActive = activeKey === trackKey;
  const isLoading = isActive && status === "loading";
  const isPlaying = isActive && status === "playing";

  return (
    <button
      type="button"
      onClick={() => play(text, trackKey)}
      aria-label={label ?? (isPlaying ? "Pause explanation" : "Play explanation")}
      title={label ?? "Listen to a short explanation"}
      className={cn(
        "inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        isActive && "text-primary",
        className,
      )}
    >
      {isLoading ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      ) : isPlaying ? (
        <Pause className="h-3.5 w-3.5 fill-current" />
      ) : (
        <Volume2 className="h-3.5 w-3.5" />
      )}
    </button>
  );
}
