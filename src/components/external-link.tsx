import { useState } from "react";
import { Check, Copy, ExternalLink as ExternalLinkIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Plain external link. Renders a native <a target="_blank" rel="noopener noreferrer">.
 * No iframe, no modal, no interception, no proxy — the browser opens the real URL
 * directly in a new tab. Includes a small "copy link" affordance for sites that
 * block direct hits (LinkedIn, Glassdoor anti-bot, region locks, login walls).
 */
export function ExternalLink({
  href,
  title,
  className,
}: {
  href: string;
  title: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(href);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // ignore
    }
  };

  return (
    <span className={cn("inline-flex flex-1 items-start gap-2", className)}>
      <ExternalLinkIcon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary/80" />
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="break-all text-primary underline-offset-4 hover:underline"
        title="Opens the real URL in a new browser tab"
      >
        {title}
        <span className="sr-only"> (opens in a new tab)</span>
      </a>
      <button
        type="button"
        onClick={onCopy}
        aria-label={copied ? "Link copied" : "Copy link"}
        title={copied ? "Copied!" : "Copy link"}
        className="ml-auto inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-primary/10 hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
    </span>
  );
}
