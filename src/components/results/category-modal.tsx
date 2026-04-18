import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SpeakButton } from "@/components/speak-button";

export function CategoryModal({
  open,
  onOpenChange,
  icon,
  title,
  voiceText,
  voiceKey,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  icon: React.ReactNode;
  title: string;
  voiceText: string;
  voiceKey: string;
  children: React.ReactNode;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        className="max-h-[88vh] overflow-y-auto rounded-2xl border-border/60 bg-card/95 p-0 shadow-[var(--shadow-elegant)] backdrop-blur-xl sm:max-w-2xl !slide-in-from-left-0 !slide-in-from-top-0 !slide-out-to-left-0 !slide-out-to-top-0 data-[state=open]:zoom-in-[0.98] data-[state=closed]:zoom-out-[0.98] duration-300"
      >
        <div
          aria-hidden
          className="h-1 w-full"
          style={{ background: "var(--gradient-primary)" }}
        />
        <DialogHeader className="space-y-0 px-6 pt-5 sm:px-7">
          <div className="flex items-center justify-between gap-3 pr-6">
            <DialogTitle className="flex items-center gap-2.5 text-base sm:text-lg">
              <span
                className="inline-flex h-8 w-8 items-center justify-center rounded-md text-primary"
                style={{ backgroundColor: "color-mix(in oklab, var(--primary) 14%, transparent)" }}
              >
                {icon}
              </span>
              {title}
            </DialogTitle>
            <SpeakButton text={voiceText} trackKey={voiceKey} />
          </div>
        </DialogHeader>
        <div className="space-y-6 px-6 pb-6 pt-4 sm:px-7 sm:pb-7">{children}</div>
      </DialogContent>
    </Dialog>
  );
}
