import { useEffect, useState } from "react";
import { MapPin, Globe2, AlertTriangle } from "lucide-react";
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

function ConfidenceChip({ level }: { level: "low" | "medium" | "high" | "unknown" }) {
  const cls =
    level === "high"
      ? "text-emerald-500 border-emerald-500/30 bg-emerald-500/10"
      : level === "medium"
        ? "text-amber-500 border-amber-500/30 bg-amber-500/10"
        : "border-border/60 bg-background/60 text-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider leading-none",
        cls,
      )}
      title={`${level} confidence`}
    >
      {level}
    </span>
  );
}

function StatusChip({ status }: { status: "available" | "limited" | "unavailable" }) {
  const cls =
    status === "available"
      ? "text-emerald-500 border-emerald-500/30 bg-emerald-500/10"
      : status === "limited"
        ? "text-amber-500 border-amber-500/30 bg-amber-500/10"
        : "border-border/60 bg-background/60 text-muted-foreground";
  const label = status === "available" ? "Found" : status === "limited" ? "Limited" : "No data";
  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider leading-none",
        cls,
      )}
    >
      {label}
    </span>
  );
}

function RecruiterLocationBlock({ result }: { result: AnalysisResult }) {
  const loc = result.recruiter_location;
  return (
    <div className="rounded-xl border border-border/60 bg-background/40 p-3.5">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          <MapPin className="h-3.5 w-3.5 text-primary" />
          Recruiter location
        </div>
        {loc.available && <ConfidenceChip level={loc.location_confidence} />}
      </div>

      {loc.available && loc.recruiter_public_location ? (
        <>
          <p className="mt-2 text-sm font-medium text-foreground">
            {loc.recruiter_public_location}
          </p>
          {loc.location_source && (
            <p className="mt-0.5 text-xs text-muted-foreground">
              Source: <span className="text-foreground/80">{loc.location_source}</span>
            </p>
          )}
          {loc.hiring_context_label && (
            <p className="mt-0.5 text-xs text-muted-foreground">
              Compared to: <span className="text-foreground/80">{loc.hiring_context_label}</span>
            </p>
          )}
          {loc.mismatch && loc.caution_note && (
            <div className="mt-2.5 flex gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs leading-relaxed text-amber-700 dark:text-amber-300">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>{loc.caution_note}</span>
            </div>
          )}
        </>
      ) : (
        <p className="mt-2 text-xs leading-relaxed text-muted-foreground">{loc.summary}</p>
      )}
    </div>
  );
}

function TrafficContextBlock({ result }: { result: AnalysisResult }) {
  const t = result.website_traffic;
  return (
    <div className="rounded-xl border border-border/60 bg-background/40 p-3.5">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          <Globe2 className="h-3.5 w-3.5 text-primary" />
          Website traffic context
        </div>
        <StatusChip status={t.traffic_estimate_status} />
      </div>

      {t.checked_domain && (
        <p className="mt-2 text-xs text-muted-foreground">
          Checked domain:{" "}
          <span className="font-mono text-foreground/85">{t.checked_domain}</span>
        </p>
      )}

      {t.estimated_top_countries.length > 0 && (
        <div className="mt-2">
          <p className="text-xs text-muted-foreground">Estimated top audience regions:</p>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {t.estimated_top_countries.map((c) => (
              <span
                key={c}
                className="rounded-full border border-border/60 bg-card/60 px-2 py-0.5 text-[11px] font-medium text-foreground/85"
              >
                {c}
              </span>
            ))}
          </div>
        </div>
      )}

      <p className="mt-2 text-sm leading-relaxed text-foreground/90">
        {t.estimated_visibility_summary}
      </p>

      {t.geo_mismatch && t.hiring_context_label && (
        <div className="mt-2.5 flex gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs leading-relaxed text-amber-700 dark:text-amber-300">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{t.traffic_context_note}</span>
        </div>
      )}

      <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
        {t.sources.length > 0 ? `Sources consulted: ${t.sources.join(", ")}. ` : ""}
        Third-party estimate, not the company&apos;s real internal analytics.
      </p>
    </div>
  );
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

  const loc = result.recruiter_location;
  const traffic = result.website_traffic;
  const voiceText =
    `Your risk score is ${result.risk_score} out of 100, which we classify as ${result.risk_level}. ${tagline} ` +
    (loc.available && loc.recruiter_public_location
      ? `${loc.summary} ${loc.caution_note ?? ""} `
      : "") +
    (traffic.traffic_estimate_status !== "unavailable"
      ? `${traffic.estimated_visibility_summary} ${traffic.traffic_context_note}`
      : `${traffic.traffic_context_note}`);

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

      {/* Context signals — recruiter location + website traffic */}
      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        <RecruiterLocationBlock result={result} />
        <TrafficContextBlock result={result} />
      </div>
    </div>
  );
}
