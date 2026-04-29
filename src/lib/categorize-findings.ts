import type { AnalysisResult, OsintLink } from "@/lib/analysis";

export type CategoryVerdict = "good" | "neutral" | "caution" | "bad" | "unknown";

export type CategoryStats = {
  good: number;
  caution: number;
  bad: number;
  total: number;
  verdict: CategoryVerdict;
  chip: string; // e.g. "3 OK · 1 caution"
};

export type FindingItem = {
  title: string;
  detail: string;
  severity: "good" | "info" | "caution" | "bad";
};

export type SplitOsint = {
  recruiter: { findings: string[]; links: OsintLink[] };
  company: { findings: string[]; links: OsintLink[] };
};

const PERSON_PROFILE_HOSTS = [
  "linkedin.com/in",
  "twitter.com/",
  "x.com/",
  "github.com/",
  "instagram.com/",
  "facebook.com/",
  "medium.com/@",
  "threads.net/",
  "about.me/",
];

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase();
  } catch {
    return "";
  }
}

function looksLikePersonProfile(url: string): boolean {
  const full = `${hostOf(url)}${pathOf(url)}`;
  return PERSON_PROFILE_HOSTS.some((h) => full.includes(h));
}

function mentionsName(text: string, name: string): boolean {
  if (!name.trim()) return false;
  const parts = name
    .trim()
    .split(/\s+/)
    .filter((p) => p.length > 1);
  if (parts.length === 0) return false;
  const lower = text.toLowerCase();
  // Require at least one name part to appear
  return parts.some((p) => lower.includes(p.toLowerCase()));
}

function mentionsDomain(text: string, domain: string): boolean {
  if (!domain.trim()) return false;
  const root = domain.toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  const bare = root.replace(/^www\./, "").split(".")[0];
  if (!bare) return false;
  return text.toLowerCase().includes(bare);
}

/**
 * Split Tavily/OSINT output into recruiter-vs-company buckets based on
 * whether each finding/link references the person's name or the company.
 */
export function splitOsint(
  result: AnalysisResult,
  recruiterName: string,
  companyName: string,
  companyDomain: string,
): SplitOsint {
  const recruiterFindings: string[] = [];
  const companyFindings: string[] = [];

  for (const f of result.osint_findings) {
    const isPerson = mentionsName(f, recruiterName);
    const isCompany =
      mentionsName(f, companyName) || mentionsDomain(f, companyDomain);
    if (isPerson && !isCompany) {
      recruiterFindings.push(f);
    } else if (isCompany && !isPerson) {
      companyFindings.push(f);
    } else if (isPerson && isCompany) {
      // Connection evidence — useful for recruiter card
      recruiterFindings.push(f);
    } else {
      // Default: company bucket (broader context)
      companyFindings.push(f);
    }
  }

  const recruiterLinks: OsintLink[] = [];
  const companyLinks: OsintLink[] = [];

  for (const l of result.osint_links) {
    const text = `${l.title} ${l.url}`;
    const profile = looksLikePersonProfile(l.url);
    const personMention = mentionsName(text, recruiterName);
    const companyMention =
      mentionsName(text, companyName) || mentionsDomain(text, companyDomain);

    if (profile || (personMention && !companyMention)) {
      recruiterLinks.push(l);
    } else if (companyMention) {
      companyLinks.push(l);
    } else {
      companyLinks.push(l);
    }
  }

  return {
    recruiter: { findings: recruiterFindings, links: recruiterLinks },
    company: { findings: companyFindings, links: companyLinks },
  };
}

function chipText(stats: { good: number; caution: number; bad: number }) {
  const parts: string[] = [];
  if (stats.good) parts.push(`${stats.good} OK`);
  if (stats.caution) parts.push(`${stats.caution} caution`);
  if (stats.bad) parts.push(`${stats.bad} red flag${stats.bad > 1 ? "s" : ""}`);
  return parts.length ? parts.join(" · ") : "No signals";
}

function rollUp(scores: Array<"good" | "neutral" | "caution" | "bad" | "unknown">): CategoryStats {
  let good = 0,
    caution = 0,
    bad = 0;
  for (const s of scores) {
    if (s === "good") good++;
    else if (s === "caution") caution++;
    else if (s === "bad") bad++;
  }
  let verdict: CategoryVerdict = "neutral";
  if (bad > 0) verdict = "bad";
  else if (caution > 0) verdict = "caution";
  else if (good > 0) verdict = "good";
  else verdict = "unknown";
  return { good, caution, bad, total: scores.length, verdict, chip: chipText({ good, caution, bad }) };
}

// --- Per-section verdict helpers ---

export function rdapVerdict(b: AnalysisResult["rdap"]["ageBucket"]): CategoryVerdict {
  switch (b) {
    case "very_new":
      return "bad";
    case "new":
      return "caution";
    case "young":
      return "caution";
    case "established":
      return "good";
    default:
      return "unknown";
  }
}

export function dnsVerdict(h: AnalysisResult["dns"]["health"]): CategoryVerdict {
  switch (h) {
    case "healthy":
      return "good";
    case "thin":
      return "caution";
    case "minimal":
      return "caution";
    case "missing":
      return "bad";
    default:
      return "unknown";
  }
}

export function safeBrowsingVerdict(
  s: AnalysisResult["safe_browsing"]["safe_browsing_status"],
): CategoryVerdict {
  switch (s) {
    case "flagged":
      return "bad";
    case "not_flagged":
      return "good";
    default:
      return "unknown";
  }
}

export function ctVerdict(h: AnalysisResult["ct"]["history"]): CategoryVerdict {
  switch (h) {
    case "very_recent":
      return "bad";
    case "recent":
      return "caution";
    case "established":
      return "good";
    case "normal":
      return "neutral";
    case "none":
      return "caution";
    default:
      return "unknown";
  }
}

export function waybackVerdict(s: AnalysisResult["wayback"]["archive_history_status"]): CategoryVerdict {
  switch (s) {
    case "established":
      return "good";
    case "moderate":
      return "neutral";
    case "thin":
      return "caution";
    case "recent_only":
      return "bad";
    case "none":
      return "caution";
    default:
      return "unknown";
  }
}

export function linkIntegrityVerdict(
  s: AnalysisResult["link_integrity"]["link_integrity_status"],
): CategoryVerdict {
  switch (s) {
    case "clean":
      return "good";
    case "minor":
      return "caution";
    case "suspicious":
      return "caution";
    case "dangerous":
      return "bad";
    default:
      return "unknown";
  }
}

// --- Aggregate stats per category card ---

export function emailStats(result: AnalysisResult): CategoryStats {
  const verdicts = [dnsVerdict(result.dns.health), rdapVerdict(result.rdap.ageBucket)];
  if (result.link_integrity?.available) {
    verdicts.push(linkIntegrityVerdict(result.link_integrity.link_integrity_status));
  }
  return rollUp(verdicts);
}

export function companyStats(
  result: AnalysisResult,
  split: SplitOsint,
): CategoryStats {
  const scores: CategoryVerdict[] = [
    safeBrowsingVerdict(result.safe_browsing.safe_browsing_status),
    waybackVerdict(result.wayback.archive_history_status),
    ctVerdict(result.ct.history),
  ];
  if (split.company.findings.length > 0) scores.push("neutral");
  return rollUp(scores);
}

export function recruiterStats(
  recruiterName: string,
  split: SplitOsint,
): CategoryStats {
  const has = split.recruiter.findings.length + split.recruiter.links.length;
  if (!recruiterName.trim() && has === 0) {
    return { good: 0, caution: 0, bad: 0, total: 0, verdict: "unknown", chip: "Limited info" };
  }
  // Public profiles found = mild positive context; absence is just unknown
  return rollUp(has > 0 ? ["good"] : ["unknown"]);
}

// --- Voice-friendly text per category ---

export function emailVoiceText(result: AnalysisResult): string {
  const parts: string[] = [];
  parts.push(`Email findings for the recruiter's domain.`);
  parts.push(result.dns.summary);
  parts.push(result.dns.interpretation);
  parts.push(result.rdap.ageSummary);
  parts.push(result.rdap.interpretation);
  if (result.link_integrity?.available) {
    parts.push(`Link and CTA integrity: ${result.link_integrity.link_summary}`);
  }
  return parts.filter(Boolean).join(" ");
}

export function companyVoiceText(result: AnalysisResult, split: SplitOsint): string {
  const parts: string[] = [];
  parts.push(`Company and domain findings.`);
  if (split.company.findings.length) {
    parts.push(`Public web evidence: ${split.company.findings.slice(0, 3).join(". ")}.`);
  }
  parts.push(result.safe_browsing.safe_browsing_summary);
  parts.push(result.wayback.website_history_summary);
  parts.push(result.wayback.interpretation);
  parts.push(result.ct.summary);
  return parts.filter(Boolean).join(" ");
}

export function recruiterVoiceText(
  recruiterName: string,
  split: SplitOsint,
): string {
  const parts: string[] = [];
  parts.push(
    recruiterName
      ? `Recruiter findings for ${recruiterName}.`
      : `Recruiter findings.`,
  );
  if (split.recruiter.findings.length) {
    parts.push(split.recruiter.findings.slice(0, 3).join(". "));
  } else {
    parts.push(
      "We didn't find clear public information about this person tied to the role.",
    );
  }
  parts.push(
    "Please double-check any profile links — search results may include other people with similar names.",
  );
  return parts.join(" ");
}
