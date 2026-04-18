import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";
import type { CategoryStats } from "@/lib/categorize-findings";

const verdictStyles: Record<CategoryStats["verdict"], string> = {
  good: "text-emerald-400 border-emerald-400/30 bg-emerald-400/10",
  neutral: "text-muted-foreground border-border/60 bg-background/60",
  caution: "text-amber-400 border-amber-400/30 bg-amber-400/10",
  bad: "text-rose-400 border-rose-400/30 bg-rose-400/10",
  unknown: "text-muted-foreground border-border/60 bg-background/60",
};

export function CategoryTile({
  icon,
  title,
  subtitle,
  stats,
  onClick,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  stats: CategoryStats;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group flex h-full flex-col items-start gap-4 rounded-2xl border border-border/60 bg-card/60 p-5 text-left shadow-[var(--shadow-elegant)] backdrop-blur-xl outline-none transition-all duration-200 hover:-translate-y-0.5 hover:border-primary/40 focus-visible:ring-2 focus-visible:ring-ring sm:p-6"
    >
      <span
        className="inline-flex h-11 w-11 items-center justify-center rounded-xl text-primary"
        style={{ backgroundColor: "color-mix(in oklab, var(--primary) 14%, transparent)" }}
      >
        {icon}
      </span>

      <div className="flex-1 space-y-1">
        <h3 className="text-base font-semibold text-foreground sm:text-lg">{title}</h3>
        <p className="text-xs text-muted-foreground sm:text-sm">{subtitle}</p>
      </div>

      <div className="flex w-full items-center justify-between gap-2">
        <span
          className={cn(
            "rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider",
            verdictStyles[stats.verdict],
          )}
        >
          {stats.chip}
        </span>
        <ChevronRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
      </div>
    </button>
  );
}
