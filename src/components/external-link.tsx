import { ExternalLink as ExternalLinkIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Plain external link. Renders a native <a target="_blank" rel="noopener noreferrer">.
 * No iframe, modal, interception, proxy, or URL rewriting — the browser opens the
 * real destination URL directly in a new tab, exactly like a normal hyperlink.
 *
 * `referrerPolicy="no-referrer"` is set so target sites see a clean request and
 * don't bounce us purely because of the referring origin.
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
  return (
    <span className={cn("inline-flex flex-1 items-start gap-2", className)}>
      <ExternalLinkIcon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary/80" />
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        referrerPolicy="no-referrer"
        className="break-all text-primary underline-offset-4 hover:underline"
        title="Opens in a new tab"
      >
        {title}
        <span className="sr-only"> (opens in a new tab)</span>
      </a>
    </span>
  );
}
