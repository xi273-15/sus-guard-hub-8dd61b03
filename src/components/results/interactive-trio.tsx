import { useState } from "react";
import { ChevronDown, FileText, Lightbulb, ListChecks, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { SpeakButton } from "@/components/speak-button";
import type { AnalysisResult } from "@/lib/analysis";

type PanelId = "summary" | "why" | "next";

export function InteractiveTrio({ result }: { result: AnalysisResult }) {
  const [active, setActive] = useState<PanelId>("summary");

  const summaryText = result.audio_summary;
  const whyText =
    result.why_points.length > 0
      ? result.why_points.map((p) => `${p.finding}. ${p.why}`).join(" ")
      : result.why_it_matters;
  const nextText =
    result.next_steps.length > 0
      ? `Recommended next steps. ${result.next_steps.join(". ")}.`
      : "No specific next steps suggested.";

  return (
    <div className="space-y-3">
      <Panel
        id="summary"
        active={active}
        onActivate={setActive}
        title="Summary"
        icon={<FileText className="h-4 w-4" />}
        voice={{ text: summaryText, key: "results:summary" }}
      >
        <p className="text-sm leading-relaxed text-foreground/90 sm:text-base">
          {result.audio_summary}
        </p>
      </Panel>

      <Panel
        id="why"
        active={active}
        onActivate={setActive}
        title="Why it matters"
        icon={<Lightbulb className="h-4 w-4" />}
        voice={{ text: whyText, key: "results:why" }}
      >
        {result.why_points.length > 0 ? (
          <ul className="space-y-2.5">
            {result.why_points.map((p, i) => {
              const dot =
                p.severity === "good"
                  ? "bg-emerald-400"
                  : p.severity === "bad"
                    ? "bg-rose-400"
                    : p.severity === "caution"
                      ? "bg-amber-400"
                      : "bg-muted-foreground";
              return (
                <li key={i} className="flex gap-2.5 text-sm leading-relaxed">
                  <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", dot)} />
                  <span>
                    <span className="font-medium text-foreground">{p.finding}</span>{" "}
                    <span className="text-muted-foreground">— {p.why}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="text-sm leading-relaxed text-foreground/90">{result.why_it_matters}</p>
        )}
      </Panel>

      <Panel
        id="next"
        active={active}
        onActivate={setActive}
        title="Recommended next steps"
        icon={<ListChecks className="h-4 w-4" />}
        voice={{ text: nextText, key: "results:next" }}
      >
        <ul className="space-y-2.5">
          {result.next_steps.map((s, i) => (
            <li key={i} className="flex gap-2.5 text-sm leading-relaxed">
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
              <span>{s}</span>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}

function Panel({
  id,
  active,
  onActivate,
  title,
  icon,
  voice,
  children,
}: {
  id: PanelId;
  active: PanelId;
  onActivate: (id: PanelId) => void;
  title: string;
  icon: React.ReactNode;
  voice: { text: string; key: string };
  children: React.ReactNode;
}) {
  const isOpen = active === id;
  return (
    <div
      className={cn(
        "overflow-hidden rounded-2xl border bg-card/60 backdrop-blur-xl transition-all duration-300",
        isOpen
          ? "border-primary/40 shadow-[var(--shadow-elegant)]"
          : "border-border/60 hover:border-border",
      )}
      style={
        isOpen
          ? {
              boxShadow:
                "0 0 0 1px color-mix(in oklab, var(--primary) 30%, transparent), var(--shadow-elegant)",
            }
          : undefined
      }
    >
      <button
        type="button"
        onClick={() => onActivate(id)}
        aria-expanded={isOpen}
        className="flex w-full items-center justify-between gap-3 px-5 py-4 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <span className="flex items-center gap-2.5">
          <span
            className={cn(
              "inline-flex h-7 w-7 items-center justify-center rounded-md transition-colors",
              isOpen ? "text-primary" : "text-muted-foreground",
            )}
            style={
              isOpen
                ? { backgroundColor: "color-mix(in oklab, var(--primary) 14%, transparent)" }
                : undefined
            }
          >
            {icon}
          </span>
          <span
            className={cn(
              "text-sm font-semibold sm:text-base",
              isOpen ? "text-foreground" : "text-foreground/80",
            )}
          >
            {title}
          </span>
        </span>
        <span className="flex items-center gap-1">
          <span onClick={(e) => e.stopPropagation()} role="presentation">
            <SpeakButton text={voice.text} trackKey={voice.key} />
          </span>
          <ChevronDown
            className={cn(
              "h-4 w-4 text-muted-foreground transition-transform duration-300",
              isOpen ? "rotate-180" : "rotate-0",
            )}
          />
        </span>
      </button>

      <div
        className={cn(
          "grid transition-all duration-300 ease-out",
          isOpen ? "grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0",
        )}
      >
        <div className="overflow-hidden">
          <div className="px-5 pb-5 pt-1">{children}</div>
        </div>
      </div>
    </div>
  );
}
