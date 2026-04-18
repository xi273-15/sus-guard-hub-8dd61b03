import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, HelpCircle } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import gmailMenu from "@/assets/headers-help/gmail-menu.png";
import gmailOriginal from "@/assets/headers-help/gmail-original.png";

const slides = [
  {
    img: gmailMenu,
    alt: "Gmail message with the three-dot menu open showing the Show original option",
    caption:
      "In Gmail, open the email, click the three-dot menu in the top right, then choose 'Show original'.",
  },
  {
    img: gmailOriginal,
    alt: "Gmail Show original page with the raw headers highlighted",
    caption:
      "On the page that opens, copy everything inside the highlighted box, then paste it into the Email headers field.",
  },
];

export function HeadersHelpDialog() {
  const [open, setOpen] = useState(false);
  const [idx, setIdx] = useState(0);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "ArrowLeft") setIdx((i) => Math.max(0, i - 1));
      if (e.key === "ArrowRight") setIdx((i) => Math.min(slides.length - 1, i + 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  useEffect(() => {
    if (!open) setIdx(0);
  }, [open]);

  const slide = slides[idx];

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <button
          type="button"
          aria-label="How to find email headers"
          title="How to find email headers"
          className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <HelpCircle className="h-3.5 w-3.5" />
        </button>
      </DialogTrigger>
      <DialogContent className="max-w-lg border-border/60 bg-card/95 backdrop-blur-xl">
        <DialogHeader>
          <DialogTitle>How to get your email headers</DialogTitle>
          <DialogDescription>
            A quick two-step walkthrough for Gmail.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="overflow-hidden rounded-lg border border-border/60 bg-background/40">
            <img
              src={slide.img}
              alt={slide.alt}
              className="block w-full object-contain"
            />
          </div>
          <p className="text-sm leading-relaxed text-foreground/90">{slide.caption}</p>
        </div>

        <div className="flex items-center justify-between pt-2">
          <button
            type="button"
            onClick={() => setIdx((i) => Math.max(0, i - 1))}
            disabled={idx === 0}
            className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-border/60 text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary disabled:opacity-40"
            aria-label="Previous step"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>

          <div className="flex items-center gap-1.5">
            {slides.map((_, i) => (
              <span
                key={i}
                className={cn(
                  "h-1.5 rounded-full transition-all",
                  i === idx ? "w-6 bg-primary" : "w-1.5 bg-muted-foreground/40",
                )}
              />
            ))}
            <span className="ml-2 text-xs text-muted-foreground">
              {idx + 1} / {slides.length}
            </span>
          </div>

          <button
            type="button"
            onClick={() => setIdx((i) => Math.min(slides.length - 1, i + 1))}
            disabled={idx === slides.length - 1}
            className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-border/60 text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary disabled:opacity-40"
            aria-label="Next step"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
