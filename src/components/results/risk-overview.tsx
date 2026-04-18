import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import type { AnalysisResult } from "@/lib/analysis";
import { SpeakButton } from "@/components/speak-button";

function levelTokens(level: AnalysisResult["risk_level"]) {
  switch (level) {
    case "Low":
      return {
        ring: "var(--success, #10b981)",
        chip: "text-emerald-400 border-emerald-400/30 bg-emerald-400/10",
        glow: "color-mix(in oklab, #10b981 40%, transparent)",
      };
    case "Caution":
      return {
        ring: "#f59e0b",
        chip: "text-amber-400 border-amber-400/30 bg-amber-400/10",
        glow: "color-mix(in oklab, #f59e0b 40%, transparent)",
      };
    case "High":
      return {
        ring: "#fb923c",
        chip: "text-orange-400 border-orange-400/30 bg-orange-400/10",
        glow: "color-mix(in oklab, #fb923c 40%, transparent)",
      };
    case "Likely Scam":
      return {
        ring: "#f43f5e",
        chip: "text-rose-400 border-rose-400/30 bg-rose-400/10",
        glow: "color-mix(in oklab, #f43f5e 50%, transparent)",
      };
  }
}

export function RiskOverview({
  result,
  tagline,
}: {
  result: AnalysisResult;
  tagline: string;
}) {
  const tokens = levelTokens(result.risk_level);
  const score = Math.max(0, Math.min(100, result.risk_score));

  // Animate the ring fill
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setAnimated(score));
    return () => cancelAnimationFrame(id);
  }, [score]);

  // Geometry
  const size = 200;
  const stroke = 14;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const dash = (animated / 100) * c;

  const voiceText = `Your risk score is ${result.risk_score} out of 100, which we classify as ${result.risk_level}. ${tagline}`;

  return (
    <div className="relative overflow-hidden rounded-2xl border border-border/60 bg-card/60 p-6 shadow-[var(--shadow-elegant)] backdrop-blur-xl sm:p-8">
      {/* Ambient tint */}
      <div
        aria-hidden
        className="pointer-events-none absolute -inset-px -z-10 opacity-60"
        style={{
          background: `radial-gradient(circle at 30% 20%, ${tokens.glow}, transparent 60%)`,
        }}
      />

      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-[0.2em] text-muted-foreground">
          Risk overview
        </p>
        <SpeakButton text={voiceText} trackKey="results:risk-overview" />
      </div>

      <div className="mt-6 flex flex-col items-center gap-6 sm:flex-row sm:items-center sm:gap-8">
        {/* Ring */}
        <div
          className="relative shrink-0"
          style={{ width: size, height: size }}
          role="img"
          aria-label={`Risk score ${result.risk_score} out of 100, ${result.risk_level}`}
        >
          <svg width={size} height={size} className="-rotate-90">
            <defs>
              <linearGradient id="risk-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="var(--primary)" />
                <stop offset="100%" stopColor={tokens.ring} />
              </linearGradient>
            </defs>
            <circle
              cx={size / 2}
              cy={size / 2}
              r={r}
              stroke="color-mix(in oklab, var(--foreground) 8%, transparent)"
              strokeWidth={stroke}
              fill="none"
            />
            <circle
              cx={size / 2}
              cy={size / 2}
              r={r}
              stroke="url(#risk-grad)"
              strokeWidth={stroke}
              strokeLinecap="round"
              fill="none"
              strokeDasharray={`${dash} ${c}`}
              style={{ transition: "stroke-dasharray 900ms cubic-bezier(0.2, 0.8, 0.2, 1)" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-5xl font-bold leading-none tracking-tight text-foreground sm:text-6xl">
              {result.risk_score}
            </span>
            <span className="mt-1 text-xs font-medium tracking-wider text-muted-foreground">
              / 100
            </span>
          </div>
        </div>

        {/* Level + tagline */}
        <div className="flex-1 text-center sm:text-left">
          <span
            className={cn(
              "inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm font-bold uppercase tracking-wider",
              tokens.chip,
            )}
          >
            {result.risk_level} risk
          </span>
          <p className="mt-3 text-base leading-relaxed text-foreground/90 sm:text-lg">
            {tagline}
          </p>
        </div>
      </div>
    </div>
  );
}
