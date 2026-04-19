import { ExternalLink as ExternalLinkIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Normalize known-blocky URLs to forms that reliably load in a new tab.
 *
 * - LinkedIn search URLs (`/search/...`) often return 999 / ERR_BLOCKED_BY_RESPONSE
 *   when hit fresh without session cookies. We rewrite them to a Google site:
 *   search that always loads and surfaces the real profile as the first result.
 * - Glassdoor search/listing URLs behave similarly — same Google fallback.
 * - Direct profile URLs (linkedin.com/in/<slug>, company pages, etc.) are left
 *   alone because top-level navigation to them works fine.
 */
function normalizeUrl(href: string): { url: string; viaGoogle: boolean } {
  try {
    const u = new URL(href);
    const host = u.hostname.replace(/^www\./, "").toLowerCase();

    // LinkedIn search → Google site search
    if (host.endsWith("linkedin.com") && u.pathname.startsWith("/search")) {
      const keywords =
        u.searchParams.get("keywords") ||
        u.searchParams.get("q") ||
        decodeURIComponent(u.pathname.replace(/^\/+|\/+$/g, "").replace(/\//g, " "));
      const q = `site:linkedin.com/in ${keywords}`.trim();
      return {
        url: `https://www.google.com/search?q=${encodeURIComponent(q)}`,
        viaGoogle: true,
      };
    }

    // Glassdoor search/listing → Google site search
    if (
      host.endsWith("glassdoor.com") &&
      (u.pathname.includes("/Search") ||
        u.pathname.includes("/Reviews") ||
        u.searchParams.has("sc.keyword"))
    ) {
      const keywords =
        u.searchParams.get("sc.keyword") ||
        u.searchParams.get("q") ||
        u.pathname.split("/").filter(Boolean).pop() ||
        "";
      const q = `site:glassdoor.com ${keywords.replace(/-/g, " ")}`.trim();
      return {
        url: `https://www.google.com/search?q=${encodeURIComponent(q)}`,
        viaGoogle: true,
      };
    }

    return { url: href, viaGoogle: false };
  } catch {
    return { url: href, viaGoogle: false };
  }
}

/**
 * Plain external link. Renders a native <a target="_blank" rel="noopener noreferrer">.
 * No iframe, modal, interception, or proxy — the browser opens the URL directly.
 *
 * For sites known to block fresh hits (LinkedIn /search, Glassdoor search), the
 * URL is auto-rewritten to a Google site: search so the click always lands
 * somewhere useful instead of an ERR_BLOCKED_BY_RESPONSE page.
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
  const { url, viaGoogle } = normalizeUrl(href);

  return (
    <span className={cn("inline-flex flex-1 items-start gap-2", className)}>
      <ExternalLinkIcon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary/80" />
      <a
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        referrerPolicy="no-referrer"
        className="break-all text-primary underline-offset-4 hover:underline"
        title={viaGoogle ? `Opens a Google search for: ${href}` : "Opens in a new tab"}
      >
        {title}
        {viaGoogle && (
          <span className="ml-1 text-xs text-muted-foreground">(via Google)</span>
        )}
        <span className="sr-only"> (opens in a new tab)</span>
      </a>
    </span>
  );
}
