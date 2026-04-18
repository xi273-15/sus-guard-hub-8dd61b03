import { cn } from "@/lib/utils";

export function FindingSection({
  title,
  children,
  className,
}: {
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("space-y-3", className)}>
      <h4 className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">
        {title}
      </h4>
      <div className="rounded-xl border border-border/60 bg-background/40 p-4">{children}</div>
    </section>
  );
}
