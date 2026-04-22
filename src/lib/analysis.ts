import { createServerFn } from "@tanstack/react-start";

export type AnalysisInput = {
  recruiterName?: string;
  recruiterEmail?: string;
  companyName?: string;
  companyDomain?: string;
  message?: string;
  headers?: string;
  /** Optional claimed job/role location, e.g. "Berlin", "Remote-EU", "San Francisco". */
  roleLocation?: string;
};

export type RiskLevel = "Low" | "Caution" | "High" | "Likely Scam";

export type WhyPoint = {
  finding: string;
  why: string;
  severity: "good" | "info" | "caution" | "bad";
};

export type OsintLink = {
  title: string;
  url: string;
};

export type OsintResult = {
  summary: string;
  findings: string[];
  links: OsintLink[];
};

export type RdapAgeBucket = "very_new" | "new" | "young" | "established" | "unknown";

export type RdapResult = {
  available: boolean;
  domain: string | null;
  registrar: string | null;
  registrationDate: string | null; // ISO
  lastUpdated: string | null; // ISO
  nameservers: string[];
  statuses: string[];
  ageDays: number | null;
  ageBucket: RdapAgeBucket;
  ageSummary: string;
  interpretation: string;
  /** ISO 3166-1 alpha-2 country code from registrant address, when present. */
  registrantCountry: string | null;
  error?: string;
};

export type DnsHealth = "healthy" | "thin" | "minimal" | "missing" | "skipped" | "unknown";

export type DnsResult = {
  available: boolean;
  domain: string | null;
  hasMx: boolean;
  hasSpf: boolean;
  hasDmarc: boolean;
  hasA: boolean;
  hasAaaa: boolean;
  mxRecords: string[];
  spfRecord: string | null;
  dmarcRecord: string | null;
  health: DnsHealth;
  summary: string;
  interpretation: string;
  error?: string;
};

export type SafeBrowsingStatus = "flagged" | "not_flagged" | "unknown";

export type SafeBrowsingResult = {
  checked_url: string | null;
  safe_browsing_status: SafeBrowsingStatus;
  safe_browsing_findings: string[]; // e.g. ["MALWARE", "SOCIAL_ENGINEERING"]
  safe_browsing_summary: string;
  error?: string;
};

export type CtHistoryBucket = "very_recent" | "recent" | "normal" | "established" | "none" | "unknown";

export type CtResult = {
  available: boolean;
  domain: string | null;
  certificatesFound: boolean;
  totalCertificates: number; // count returned (capped)
  mostRecentIssuance: string | null; // ISO
  oldestIssuance: string | null; // ISO
  uniqueSubdomains: string[]; // up to ~12 most relevant
  suspiciousSubdomains: string[]; // lookalike / phishing-style names
  history: CtHistoryBucket;
  summary: string;
  interpretation: string;
  error?: string;
};

export type WaybackStatus = "established" | "moderate" | "recent_only" | "thin" | "none" | "unknown";

export type WaybackResult = {
  available: boolean;
  checked_url: string | null;
  archive_history_status: WaybackStatus;
  first_seen_archive_date: string | null; // ISO
  most_recent_archive_date: string | null; // ISO
  snapshot_count: number | null;
  website_history_summary: string;
  interpretation: string;
  error?: string;
};

export type LocationConfidence = "low" | "medium" | "high" | "unknown";

export type RecruiterLocationResult = {
  available: boolean;
  /** Free-form location string, e.g. "Berlin, Germany" or "United Kingdom". */
  recruiter_public_location: string | null;
  /** ISO 3166-1 alpha-2 country code when known. */
  recruiter_country: string | null;
  location_confidence: LocationConfidence;
  /** Short human-readable description of where this came from. */
  location_source: string | null;
  /** Comparison context used (e.g. "Berlin (claimed role)" or "United States (company HQ)"). */
  hiring_context_label: string | null;
  hiring_context_country: string | null;
  /** True if recruiter country differs from hiring context country (only when both known). */
  mismatch: boolean;
  /** One-line user-facing summary. */
  summary: string;
  /** Optional caution note, only set when mismatch is true. */
  caution_note: string | null;
};

export type TrafficEstimateStatus = "available" | "limited" | "unavailable";

export type WebsiteTrafficResult = {
  /** The bare domain we checked (no scheme, no path). Null if no domain was provided. */
  checked_domain: string | null;
  /** Did we find any usable third-party traffic-estimate signals? */
  traffic_estimate_status: TrafficEstimateStatus;
  /** Up to ~5 estimated top countries / regions where audience appears concentrated. */
  estimated_top_countries: string[];
  /** Plain-English one-liner about visibility (always third-party estimates). */
  estimated_visibility_summary: string;
  /** Short interpretive note (mismatch warning OR neutral context). */
  traffic_context_note: string;
  /** Names of third-party sources consulted (e.g. ["Cloudflare Radar", "Similarweb"]). */
  sources: string[];
  /** True only when estimated geography appears to differ from the claimed hiring context AND we have at least medium confidence. */
  geo_mismatch: boolean;
  /** Comparison context label (e.g. "Berlin (claimed role location)"). */
  hiring_context_label: string | null;
  hiring_context_country: string | null;
};

// ---------- Recruiter identity / public-profile discovery ----------

export type RecruiterIdentityConfidence = "low" | "medium" | "high" | "unknown";

export type RecruiterIdentityMatchTier = "likely" | "possible" | "uncertain";

export type RecruiterPublicProfile = {
  title: string;
  url: string;
  /** linkedin | github | x | facebook | instagram | medium | company_site | recruiter_directory | other */
  platform: string;
  /** "high" / "medium" / "low" — how confident we are this profile actually
   *  belongs to the claimed recruiter, given the surrounding context. */
  confidence: RecruiterIdentityConfidence;
  /** Short reason explaining the confidence label (e.g. "Title mentions both
   *  the recruiter name and the company"). */
  reason: string;
  /** likely / possible / uncertain — used to group in the UI. */
  match_tier: RecruiterIdentityMatchTier;
};

export type RecruiterIdentityResult = {
  /** Was a search actually run (recruiter name + Tavily key + at least some context)? */
  available: boolean;
  /** Short plain-English summary of what the identity discovery found. */
  recruiter_identity_summary: string;
  /** Profiles ranked into likely / possible / uncertain. */
  recruiter_public_profiles: RecruiterPublicProfile[];
  /** Free-text public mentions that aren't profile pages (articles, news, posts). */
  recruiter_public_mentions: string[];
  /** Overall confidence we have correctly identified the person. */
  recruiter_identity_confidence: RecruiterIdentityConfidence;
  /** Caveats / disambiguation notes ("multiple people share this name", etc.). */
  recruiter_identity_notes: string[];
};

export type AnalysisResult = {
  risk_score: number;
  risk_level: RiskLevel;
  findings: string[];
  why_it_matters: string;
  why_points: WhyPoint[];
  next_steps: string[];
  audio_summary: string;
  osint_summary: string;
  osint_findings: string[];
  osint_links: OsintLink[];
  rdap: RdapResult;
  dns: DnsResult;
  safe_browsing: SafeBrowsingResult;
  ct: CtResult;
  wayback: WaybackResult;
  recruiter_location: RecruiterLocationResult;
  website_traffic: WebsiteTrafficResult;
  recruiter_identity: RecruiterIdentityResult;
};

type SignalKind = "scam" | "caution" | "positive";

type Signal = {
  id: string;
  kind: SignalKind;
  weight: number; // positive number; for "positive" it lowers score
  finding: string;
  reason: string;
  next_step: string;
  test: (lower: string, original: string) => boolean;
};

const hasAny = (text: string, terms: string[]) => terms.some((t) => text.includes(t));

const hasWord = (text: string, words: string[]) => words.some((w) => new RegExp(`\\b${w}\\b`, "i").test(text));

// ---------- Strong scam signals (raise score a lot) ----------
const SCAM_SIGNALS: Signal[] = [
  {
    id: "urgency",
    kind: "scam",
    weight: 14,
    finding: "Message uses urgency language (e.g. 'urgent', 'immediately', 'asap').",
    reason: "Scammers pressure targets to act fast so there is no time to verify the offer.",
    next_step: "Slow down. Legitimate recruiters are fine with you taking time to verify them.",
    test: (l) =>
      hasWord(l, ["urgent", "urgently", "immediately", "asap", "today"]) ||
      hasAny(l, ["as soon as possible", "right away", "act now", "act fast"]),
  },
  {
    id: "offplatform",
    kind: "scam",
    weight: 20,
    finding: "Message asks you to move the conversation to Telegram, WhatsApp, or Signal.",
    reason:
      "Real recruiters interview on company tools (Zoom, Teams, Google Meet). Off-platform chats hide the scammer's identity.",
    next_step: "Refuse to move to Telegram, WhatsApp, or Signal for interviews. Ask for a company email or video call.",
    test: (l) =>
      hasAny(l, ["telegram", "whatsapp", "signal app", "signal chat"]) ||
      (/\bsignal\b/.test(l) && hasAny(l, ["chat", "message", "interview", "contact"])),
  },
  {
    id: "payment",
    kind: "scam",
    weight: 35,
    finding: "Message requests a payment, fee, or deposit from you.",
    reason:
      "Real employers never ask candidates to pay for a job, training, or onboarding. This is one of the strongest scam patterns.",
    next_step: "Do not send money or pay any fee. Any request for payment from a recruiter is a scam.",
    test: (l) =>
      hasAny(l, [
        "send payment",
        "send money",
        "pay a fee",
        "pay the fee",
        "application fee",
        "processing fee",
        "registration fee",
        "training fee",
        "onboarding fee",
        "security deposit",
        "refundable deposit",
        "wire transfer",
        "western union",
        "moneygram",
        "zelle",
        "venmo",
        "cash app",
      ]),
  },
  {
    id: "check_equipment",
    kind: "scam",
    weight: 38,
    finding: "Message mentions cashing a check or buying equipment with funds you'll be sent.",
    reason: "This is the classic fake-check scam: the check bounces after you've already spent or forwarded the money.",
    next_step:
      "Do not cash checks or purchase equipment for a recruiter. The check will bounce after you've spent the money.",
    test: (l) =>
      hasAny(l, [
        "cash the check",
        "cash this check",
        "deposit the check",
        "deposit this check",
        "purchase equipment",
        "buy equipment",
        "buy a laptop",
        "buy laptop",
        "purchase a laptop",
        "home office equipment",
        "office setup",
        "approved vendor",
        "preferred vendor",
      ]),
  },
  {
    id: "gift_crypto",
    kind: "scam",
    weight: 40,
    finding: "Message mentions gift cards or cryptocurrency payments.",
    reason: "No legitimate employer pays salary or expenses in gift cards or crypto. This is a strong scam indicator.",
    next_step: "Do not buy gift cards or send crypto. Cut off contact if they insist.",
    test: (l) =>
      hasAny(l, [
        "gift card",
        "gift cards",
        "itunes card",
        "amazon card",
        "google play card",
        "bitcoin",
        "btc",
        "ethereum",
        "usdt",
        "crypto wallet",
        "cryptocurrency",
      ]),
  },
  {
    id: "sensitive_docs",
    kind: "scam",
    weight: 32,
    finding: "Message asks for sensitive personal info (SSN, ID, passport, or bank details) early in the process.",
    reason: "Real employers only collect this after a signed offer through an HR portal — not over chat or email.",
    next_step:
      "Do not share banking information, your SSN, ID, or passport until you have a verified offer through the official company portal.",
    test: (l) =>
      hasAny(l, [
        "social security",
        "ssn",
        "passport",
        "driver's license",
        "drivers license",
        "bank account",
        "routing number",
        "account number",
        "copy of your id",
        "photo of your id",
      ]),
  },
  {
    id: "high_pay",
    kind: "scam",
    weight: 10,
    finding: "Message advertises unusually high pay for limited work.",
    reason: "Suspiciously high compensation is a lure. Real salaries match the role and market.",
    next_step:
      "Compare the offered pay to the role on Glassdoor or LinkedIn. If it's far above market, treat it as a red flag.",
    test: (l) =>
      (/\$\s?\d{2,3}\s?\/?\s?(hr|hour|hourly)/.test(l) && /\$\s?([2-9]\d|\d{3})/.test(l)) ||
      hasAny(l, ["$5000 weekly", "$5,000 weekly", "earn up to", "weekly pay of $", "no experience required and earn"]),
  },
  {
    id: "no_interview",
    kind: "scam",
    weight: 12,
    finding: "Message offers a job or next step without any real interview process.",
    reason:
      "Real employers interview candidates. Skipping straight to 'you're hired' or 'send your details' is a scam pattern.",
    next_step: "Insist on a video interview with an identifiable employee before sharing anything.",
    test: (l) =>
      hasAny(l, [
        "you have been hired",
        "you are hired",
        "you're hired",
        "congratulations you have been selected",
        "no interview",
        "without interview",
        "hired immediately",
      ]),
  },
  {
    id: "kindly",
    kind: "scam",
    weight: 5,
    finding: "Message uses scam-pattern wording like 'kindly'.",
    reason: "On its own this is mild, but 'kindly' combined with other red flags is common in recruiter scams.",
    next_step: "Treat as a minor signal — weigh it together with the other findings.",
    test: (l) => /\bkindly\b/.test(l),
  },
];

// ---------- Mild caution signals ----------
const CAUTION_SIGNALS: Signal[] = [
  {
    id: "generic_greeting",
    kind: "caution",
    weight: 6,
    finding: "Message uses a generic greeting like 'Dear Candidate' instead of your name.",
    reason: "Mass-sent outreach avoids names so it can be reused on many targets.",
    next_step: "Ask the recruiter to confirm which role and which of your skills they're contacting you about.",
    test: (l) =>
      hasAny(l, ["dear candidate", "dear applicant", "dear sir/madam", "dear sir or madam", "hello candidate"]),
  },
  {
    id: "vague_role",
    kind: "caution",
    weight: 7,
    finding: "Message mentions a 'contract role' or 'opportunity' without specifying the actual job.",
    reason: "Real recruiters name the role, team, and seniority. Vague pitches are a mild red flag.",
    next_step: "Ask for the exact job title, team, hiring manager, and a link to the official job posting.",
    test: (l, original) => {
      const vague = hasAny(l, [
        "contract role",
        "remote opportunity",
        "great opportunity",
        "exciting opportunity",
        "job opportunity",
        "work from home opportunity",
      ]);
      if (!vague) return false;
      // Only flag if no concrete role keyword appears
      return !hasAny(l, ROLE_TERMS);
    },
  },
  {
    id: "fast_reply",
    kind: "caution",
    weight: 6,
    finding: "Message asks for a quick reply (e.g. 'respond soon', 'get back to me today').",
    reason: "Mild pressure to respond fast isn't always a scam, but real recruiters usually give you time.",
    next_step: "It's fine to take a day or two to verify the company and recruiter before replying.",
    test: (l) =>
      hasAny(l, [
        "respond soon",
        "reply soon",
        "get back to me today",
        "get back to me asap",
        "let me know today",
        "reply today",
        "respond today",
      ]),
  },
  {
    id: "too_short",
    kind: "caution",
    weight: 8,
    finding: "Message is very short and lacks context about you, the role, or the company.",
    reason:
      "Real outreach usually references your background or a specific opening. One-liners often signal mass outreach.",
    next_step: "Ask for specifics: role, team, why they reached out to you, and a link to the job posting.",
    test: (_l, original) => original.trim().length < 80,
  },
  {
    id: "no_context",
    kind: "caution",
    weight: 6,
    finding: "Message doesn't reference a role, team, company, or concrete recruiting context.",
    reason: "Lack of specifics is common in mass scam outreach, even when no single phrase is alarming.",
    next_step: "Ask the recruiter to share the company name, role title, and where they found your profile.",
    test: (l) => {
      const hasRole = hasAny(l, ROLE_TERMS);
      const hasCompany =
        /\b(at|with|for)\s+[A-Z][A-Za-z0-9&.\- ]{2,}/.test(l) || hasAny(l, ["our company", "our team", "our client"]);
      const hasContext = hasAny(l, RECRUITING_CONTEXT);
      return !hasRole && !hasCompany && !hasContext;
    },
  },
];

// ---------- Positive legitimacy signals (lower score) ----------
const ROLE_TERMS = [
  "engineer",
  "developer",
  "designer",
  "manager",
  "analyst",
  "scientist",
  "architect",
  "consultant",
  "specialist",
  "lead",
  "director",
  "intern",
  "marketing",
  "sales",
  "product manager",
  "data scientist",
  "software",
  "frontend",
  "backend",
  "full stack",
  "fullstack",
  "devops",
  "qa",
  "recruiter",
];

const RECRUITING_CONTEXT = [
  "your profile",
  "your background",
  "your experience",
  "your linkedin",
  "your github",
  "your resume",
  "your cv",
  "saw your",
  "came across your",
  "reached out",
  "open role",
  "open position",
  "hiring",
  "we're hiring",
  "job description",
  "job posting",
  "jd",
  "interview process",
  "hiring manager",
  "team is growing",
  "headcount",
];

const NEXT_STEP_TERMS = [
  "schedule a call",
  "schedule a chat",
  "book a call",
  "book some time",
  "calendly",
  "set up a call",
  "set up a chat",
  "30 minute call",
  "30-minute call",
  "introductory call",
  "intro call",
  "phone screen",
  "screening call",
  "video interview",
  "zoom",
  "google meet",
  "microsoft teams",
  "ms teams",
  "available next week",
  "available this week",
  "let me know your availability",
];

const PROFESSIONAL_SIGNOFFS = [
  "best regards",
  "kind regards",
  "regards,",
  "thanks,",
  "thank you,",
  "looking forward",
  "best,",
  "cheers,",
  "sincerely,",
];

const POSITIVE_SIGNALS: Signal[] = [
  {
    id: "specific_role",
    kind: "positive",
    weight: 8,
    finding: "Message references a specific job title or role.",
    reason: "Naming the role suggests the outreach is targeted, not mass-sent.",
    next_step: "Still confirm the role exists on the company's official careers page.",
    test: (l) => hasAny(l, ROLE_TERMS),
  },
  {
    id: "company_mention",
    kind: "positive",
    weight: 6,
    finding: "Message mentions a company name in a natural way.",
    reason: "Real recruiters introduce who they work for and why they're reaching out.",
    next_step: "Cross-check the company name against the recruiter's email domain.",
    test: (l, original) =>
      /\b(at|with|for|from)\s+[A-Z][A-Za-z0-9&.\-]{1,}/.test(original) ||
      hasAny(l, ["our team at", "i work at", "i'm with", "represent "]),
  },
  {
    id: "normal_next_step",
    kind: "positive",
    weight: 7,
    finding: "Message proposes a normal next step like a call, intro chat, or interview.",
    reason: "Standard recruiting flow includes scheduling a conversation — not requests for money or IDs.",
    next_step: "If you're interested, propose a time on a verified company calendar tool.",
    test: (l) => hasAny(l, NEXT_STEP_TERMS),
  },
  {
    id: "recruiting_context",
    kind: "positive",
    weight: 6,
    finding: "Message references your background or a specific opening.",
    reason: "Real recruiters explain why they reached out and tie the role to your experience.",
    next_step: "Ask for the job description link to confirm the role is publicly posted.",
    test: (l) => hasAny(l, RECRUITING_CONTEXT),
  },
  {
    id: "professional_tone",
    kind: "positive",
    weight: 4,
    finding: "Message is reasonably specific and uses a professional sign-off.",
    reason: "Professional structure (greeting, context, sign-off) is typical of real recruiter outreach.",
    next_step: "Tone alone isn't proof — still verify the recruiter through the company's official site.",
    test: (l, original) => original.trim().length >= 200 && hasAny(l, PROFESSIONAL_SIGNOFFS),
  },
];

function levelFor(score: number): RiskLevel {
  if (score >= 75) return "Likely Scam";
  if (score >= 50) return "High";
  if (score >= 25) return "Caution";
  return "Low";
}

function defaultNextSteps(level: RiskLevel): string[] {
  const base = [
    "Verify the recruiter through the official company careers page.",
    "Do not send personal documents or ID until you've verified the company.",
  ];
  if (level === "Low") {
    return [...base, "If anything feels off later, run another check before responding."];
  }
  return base;
}
//lines below were edited by ceen gabbai
function buildWhyItMatters(level: RiskLevel, scamCount: number, cautionCount: number, positiveCount: number): string {
  const negCount = scamCount + cautionCount;

  if (level === "Likely Scam") {
    return `We found ${scamCount} strong scam signal${scamCount === 1 ? "" : "s"} in this message. The pattern closely matches known recruiter scams — treat any further contact as fraudulent until proven otherwise.`;
  }

  if (level === "High") {
    const tail = positiveCount
      ? ` We also noticed ${positiveCount} legitimate-sounding element${positiveCount === 1 ? "" : "s"}, but the scam signals outweigh them.`
      : "";
    return `We found ${negCount} concerning signal${negCount === 1 ? "" : "s"}. This combination commonly appears in recruiter scams, especially when the sender pressures you or asks for sensitive info.${tail}`;
  }

  if (level === "Caution") {
    if (positiveCount && negCount) {
      return `This message has ${positiveCount} legitimate-looking element${positiveCount === 1 ? "" : "s"} (like a specific role or normal next step) but also ${negCount} thing${negCount === 1 ? "" : "s"} worth a second look. It isn't clearly a scam, but verify before sharing anything personal.`;
    }
    if (negCount) {
      return `We found ${negCount} signal${negCount === 1 ? "" : "s"} worth a second look. The message isn't clearly a scam, but it has wording or vagueness that real recruiters usually avoid.`;
    }
    return "This message is borderline — not clearly safe and not clearly malicious. Verify the recruiter before continuing.";
  }

  // Low
  if (positiveCount) {
    return `This message reads like normal recruiter outreach: we found ${positiveCount} legitimacy signal${positiveCount === 1 ? "" : "s"} (such as a specific role, company mention, or normal next step) and no strong scam wording. Still verify the recruiter through the official company website before sharing personal info.`;
  }
  return "We didn't find obvious scam signals in this message. That doesn't guarantee it's safe — always verify the recruiter through the official company website before sharing personal info.";
}

// ---------- Domain alignment helpers ----------
//lines below were edited by ceen gabbai
// Common public email providers — sender domain matching these is not a company domain
const PUBLIC_EMAIL_DOMAINS = new Set([
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "yahoo.co.uk",
  "ymail.com",
  "hotmail.com",
  "outlook.com",
  "live.com",
  "msn.com",
  "aol.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "proton.me",
  "protonmail.com",
  "gmx.com",
  "gmx.net",
  "mail.com",
  "zoho.com",
  "yandex.com",
  "yandex.ru",
  "qq.com",
  "163.com",
  "126.com",
  "fastmail.com",
  "tutanota.com",
]);

// Multi-part public suffixes we want to preserve when extracting a "root" domain.
// Not exhaustive, but covers the common cases we care about.
const MULTI_PART_TLDS = new Set([
  "co.uk",
  "ac.uk",
  "gov.uk",
  "org.uk",
  "me.uk",
  "co.jp",
  "ac.jp",
  "or.jp",
  "ne.jp",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "co.nz",
  "net.nz",
  "org.nz",
  "co.in",
  "net.in",
  "org.in",
  "com.br",
  "com.mx",
  "com.ar",
  "com.sg",
  "com.hk",
  "com.tr",
  "com.tw",
]);

function extractEmailDomain(email: string): string | null {
  const trimmed = email.trim().toLowerCase();
  const m = trimmed.match(/^[^\s@]+@([a-z0-9.\-]+\.[a-z]{2,})$/);
  if (!m) return null;
  return m[1];
}

function normalizeCompanyDomain(input: string): string | null {
  let s = input.trim().toLowerCase();
  if (!s) return null;
  // Strip protocol
  s = s.replace(/^[a-z]+:\/\//, "");
  // Strip path/query/hash
  s = s.split("/")[0].split("?")[0].split("#")[0];
  // Strip user@ if present
  s = s.split("@").pop() ?? s;
  // Strip leading www.
  s = s.replace(/^www\./, "");
  if (!/^[a-z0-9.\-]+\.[a-z]{2,}$/.test(s)) return null;
  return s;
}

// Reduce a hostname to its registrable root, respecting common multi-part TLDs.
function rootDomain(host: string): string {
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  const lastTwo = parts.slice(-2).join(".");
  const lastThree = parts.slice(-3).join(".");
  if (MULTI_PART_TLDS.has(lastTwo)) {
    return parts.slice(-3).join(".");
  }
  // If the last-three already looks like x.co.uk style (handled above), fall through
  void lastThree;
  return lastTwo;
}

type DomainStatus = "match" | "subdomain" | "affiliated" | "mismatch" | "lookalike" | "public_email" | "unverifiable";

// Trusted institutional/governmental TLDs where a shared single-label name
// (e.g. "brooklyn") between sender root and company root strongly suggests
// the same organization family rather than a coincidence.
const INSTITUTIONAL_TLDS = new Set([
  "edu",
  "gov",
  "mil",
  "ac.uk",
  "gov.uk",
  "edu.au",
  "gov.au",
  "ac.jp",
  "go.jp",
  "edu.sg",
  "gov.sg",
  "edu.in",
  "gov.in",
  "edu.cn",
  "gov.cn",
]);

function publicSuffix(host: string): string {
  const parts = host.split(".");
  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join(".");
    if (MULTI_PART_TLDS.has(lastTwo) || INSTITUTIONAL_TLDS.has(lastTwo)) {
      return lastTwo;
    }
  }
  return parts[parts.length - 1] ?? "";
}

function isInstitutionalTld(host: string): boolean {
  const suffix = publicSuffix(host);
  return INSTITUTIONAL_TLDS.has(suffix);
}

// Detect "same organization family" relationships, e.g. brooklyn.edu vs
// brooklyn.cuny.edu, where a shared distinctive single-label name appears
// in both hosts under trusted institutional TLDs.
function isLikelyAffiliated(senderHost: string, senderRoot: string, companyHost: string, companyRoot: string): boolean {
  if (!senderHost || !companyHost) return false;
  if (senderRoot === companyRoot) return false; // already a match/subdomain
  // Both must live under trusted institutional/governmental suffixes —
  // otherwise "shared word" is too easy to spoof commercially.
  if (!isInstitutionalTld(senderHost) || !isInstitutionalTld(companyHost)) {
    return false;
  }
  const senderLabels = senderHost.split(".");
  const companyLabels = companyHost.split(".");
  // Shared distinctive label (length >= 4, not a generic word) appearing in both.
  const generic = new Set([
    "mail",
    "email",
    "www",
    "web",
    "info",
    "news",
    "home",
    "main",
    "office",
    "admin",
    "user",
    "users",
    "dept",
    "department",
    "school",
    "college",
    "university",
    "edu",
    "gov",
    "org",
    "com",
    "net",
  ]);
  for (const label of senderLabels) {
    if (label.length < 4) continue;
    if (generic.has(label)) continue;
    if (companyLabels.includes(label)) return true;
  }
  return false;
}

type DomainCheck = {
  status: DomainStatus;
  senderDomain: string | null;
  companyDomain: string | null;
  finding?: string;
  reason?: string;
  next_step?: string;
  scoreDelta: number; // negative = lowers risk
  /** Minimum risk floor enforced by this domain finding. */
  floor: number;
};

// Levenshtein distance for short strings (cheap, only used for root domains).
//lines below were edited by ceen gabbai
function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (!m) return n;
  if (!n) return m;
  const dp = new Array(n + 1);
  for (let j = 0; j <= n; j++) dp[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = dp[0];
    dp[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = dp[j];
      dp[j] = a[i - 1] === b[j - 1] ? prev : 1 + Math.min(prev, dp[j], dp[j - 1]);
      prev = tmp;
    }
  }
  return dp[n];
}

function isLookalike(senderRoot: string, companyRoot: string): boolean {
  if (!senderRoot || !companyRoot || senderRoot === companyRoot) return false;
  const sName = senderRoot.split(".")[0];
  const cName = companyRoot.split(".")[0];
  if (!sName || !cName || cName.length < 4) return false;
  // Substring tricks like "acme-inc", "acme-careers", "acmehr"
  if (sName.includes(cName) || cName.includes(sName)) return true;
  // Close typo (1-2 char edits) on a reasonably long name
  const dist = editDistance(sName, cName);
  if (cName.length >= 5 && dist > 0 && dist <= 2) return true;
  return false;
}

function analyzeDomainAlignment(
  recruiterEmail: string | undefined,
  companyDomainInput: string | undefined,
): DomainCheck {
  const senderDomain = recruiterEmail ? extractEmailDomain(recruiterEmail) : null;
  const companyDomain = companyDomainInput ? normalizeCompanyDomain(companyDomainInput) : null;

  if (!senderDomain || !companyDomain) {
    return {
      status: "unverifiable",
      senderDomain,
      companyDomain,
      finding: "Domain alignment could not be verified — recruiter email or company website is missing or invalid.",
      reason:
        "Without both a valid recruiter email and a company website, we can't check whether the sender's domain matches the company they claim to represent.",
      next_step:
        "Ask the recruiter for an email on their company domain and confirm the company website on their official careers page.",
      scoreDelta: 0,
      floor: 0,
    };
  }

  const senderRoot = rootDomain(senderDomain);
  const companyRoot = rootDomain(companyDomain);

  if (PUBLIC_EMAIL_DOMAINS.has(senderDomain)) {
    return {
      status: "public_email",
      senderDomain,
      companyDomain,
      finding: `Recruiter is writing from a personal email provider (${senderDomain}) instead of a ${companyRoot} address.`,
      reason:
        "Real recruiters almost always email from their company domain. A Gmail/Outlook/Yahoo address for a corporate role is a meaningful red flag.",
      next_step: `Ask for an email on @${companyRoot} before sharing anything personal. If they refuse, treat the contact as suspicious.`,
      scoreDelta: 28,
      floor: 35,
    };
  }

  if (senderRoot === companyRoot) {
    const exact = senderDomain === companyDomain;
    return {
      status: exact ? "match" : "subdomain",
      senderDomain,
      companyDomain,
      finding: exact
        ? `Recruiter email domain (${senderDomain}) matches the claimed company domain.`
        : `Recruiter email domain (${senderDomain}) is a subdomain of the claimed company domain (${companyRoot}).`,
      reason:
        "When the sender's domain aligns with the company they claim to represent, it's consistent with legitimate recruiter outreach.",
      next_step:
        "Domain alignment is a good sign, but still verify the recruiter on the company's official careers or LinkedIn page.",
      scoreDelta: -10,
      floor: 0,
    };
  }

  if (isLookalike(senderRoot, companyRoot)) {
    // Stronger framing when an institutional/governmental root (.edu/.gov/etc.)
    // is being mimicked by a commercial-looking variant (.com/.net/.co/.info)
    // that shares the brand name. This is a classic impersonation pattern.
    const senderSuffix = publicSuffix(senderDomain);
    const companySuffix = publicSuffix(companyDomain);
    const commercialSubstitution = INSTITUTIONAL_TLDS.has(companySuffix) && !INSTITUTIONAL_TLDS.has(senderSuffix);
    return {
      status: "lookalike",
      senderDomain,
      companyDomain,
      finding: commercialSubstitution
        ? `Recruiter email domain (${senderDomain}) resembles ${companyRoot} but uses a different root (.${senderSuffix}) instead of the legitimate .${companySuffix}.`
        : `Recruiter email domain (${senderDomain}) looks like a lookalike of the claimed company domain (${companyRoot}).`,
      reason: commercialSubstitution
        ? "Swapping a trusted institutional root (.edu/.gov/.ac.uk/etc.) for a commercial one (.com/.net/.info) while keeping the brand name is a classic impersonation pattern. The visual similarity is intentional."
        : "Lookalike domains (extra words, hyphens, or 1–2 character typos of the real company domain) are a classic impersonation tactic. A polished message does not change this.",
      next_step: `Do not reply on this address. Verify the recruiter through the official ${companyRoot} careers page or LinkedIn, and only respond to a genuine @${companyRoot} address.`,
      scoreDelta: commercialSubstitution ? 50 : 45,
      floor: commercialSubstitution ? 65 : 55,
    };
  }

  // Affiliated / same-organization-family check (e.g. brooklyn.cuny.edu vs
  // brooklyn.edu). Only kicks in for trusted institutional/governmental TLDs.
  if (isLikelyAffiliated(senderDomain, senderRoot, companyDomain, companyRoot)) {
    return {
      status: "affiliated",
      senderDomain,
      companyDomain,
      finding: `Recruiter email domain (${senderDomain}) appears affiliated with the claimed organization (${companyDomain}) — different domain, but likely part of the same institutional family.`,
      reason:
        "The sender's domain and the claimed organization's domain share a distinctive name under trusted institutional/governmental suffixes (.edu, .gov, .ac.uk, etc.). This is consistent with a real campus/department/member-institution relationship rather than impersonation.",
      next_step:
        "Affiliated institutional domains are common and usually legitimate. Still confirm the recruiter on the organization's official directory or careers page.",
      scoreDelta: -6,
      floor: 0,
    };
  }

  return {
    status: "mismatch",
    senderDomain,
    companyDomain,
    finding: `Recruiter email domain (${senderDomain}) does not match the claimed company domain (${companyRoot}).`,
    reason:
      "When the sender's domain is unrelated to the company they claim to represent, it often indicates impersonation or a scam recruiter using an unrelated address. A professional-sounding message does not cancel this out.",
    next_step: `Don't share personal info. Verify the recruiter through the official ${companyRoot} careers page or LinkedIn before replying.`,
    scoreDelta: 35,
    floor: 35,
  };
}

// ---------- Tavily OSINT enrichment ----------
type TavilySearchResult = {
  title?: string;
  url?: string;
  content?: string;
  score?: number;
};

type TavilyResponse = {
  answer?: string;
  results?: TavilySearchResult[];
};

type OsintInternal = {
  result: OsintResult;
  scoreDelta: number;
  whyPoints: WhyPoint[];
  nextSteps: string[];
};

const SCAM_KEYWORDS = [
  "scam",
  "scammer",
  "fraud",
  "fraudulent",
  "fake recruiter",
  "fake job",
  "phishing",
  "ripoff",
  "rip-off",
  "stolen",
  "complaint",
];

const LEGIT_KEYWORDS = [
  "linkedin.com/in/",
  "linkedin.com/company/",
  "crunchbase.com",
  "bloomberg.com",
  "glassdoor.com",
  "wikipedia.org",
  "github.com",
  "techcrunch.com",
];

async function tavilySearch(query: string, apiKey: string): Promise<TavilyResponse | null> {
  try {
    const res = await fetch("https://api.tavily.com/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        api_key: apiKey,
        query,
        search_depth: "basic",
        max_results: 5,
        include_answer: false,
      }),
    });
    if (!res.ok) {
      console.error(`Tavily query failed [${res.status}] for "${query}"`);
      return null;
    }
    return (await res.json()) as TavilyResponse;
  } catch (err) {
    console.error("Tavily request error:", err);
    return null;
  }
}

function dedupeLinks(links: OsintLink[]): OsintLink[] {
  const seen = new Set<string>();
  const out: OsintLink[] = [];
  for (const l of links) {
    if (!l.url || !l.title) continue;
    if (seen.has(l.url)) continue;
    seen.add(l.url);
    out.push(l);
    if (out.length >= 6) break;
  }
  return out;
}

async function runTavilyOsint(input: {
  recruiterName?: string;
  companyName?: string;
  companyDomain?: string;
}): Promise<OsintInternal> {
  const recruiter = (input.recruiterName ?? "").trim();
  const company = (input.companyName ?? "").trim();
  const domain = (input.companyDomain ?? "")
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");

  if (!recruiter && !company && !domain) {
    return {
      result: {
        summary:
          "We didn't run a public-web check because no recruiter name, company name, or company domain was provided.",
        findings: [],
        links: [],
      },
      scoreDelta: 0,
      whyPoints: [],
      nextSteps: [],
    };
  }

  const apiKey = process.env.TAVILY_API_KEY;
  if (!apiKey) {
    console.warn("TAVILY_API_KEY is not configured — skipping OSINT enrichment.");
    return {
      result: {
        summary: "Public-web check is currently unavailable.",
        findings: [],
        links: [],
      },
      scoreDelta: 0,
      whyPoints: [],
      nextSteps: [],
    };
  }

  const queries: { kind: "consistency" | "recruiter" | "company_scam" | "domain_scam"; q: string }[] = [];
  if (recruiter && company) queries.push({ kind: "consistency", q: `${recruiter} ${company}` });
  if (recruiter) queries.push({ kind: "recruiter", q: `${recruiter} recruiter` });
  if (company) queries.push({ kind: "company_scam", q: `${company} scam` });
  if (domain) queries.push({ kind: "domain_scam", q: `${domain} scam` });

  const responses = await Promise.all(queries.map((q) => tavilySearch(q.q, apiKey)));

  const findings: string[] = [];
  const allLinks: OsintLink[] = [];
  const whyPoints: WhyPoint[] = [];
  const nextSteps: string[] = [];
  let scoreDelta = 0;
  let consistencyHits = 0;
  let companyScamHits = 0;
  let domainScamHits = 0;
  let recruiterLegitHits = 0;
  let totalResults = 0;

  // Pending scam findings — we decide their severity AFTER we know whether the
  // company has strong legitimacy signals (so we can phrase real-org mentions
  // as "possible impersonation target" instead of "this company is suspicious").
  type PendingScam = {
    kind: "company_scam" | "domain_scam";
    subject: string;
    count: number;
    matches: TavilySearchResult[];
  };
  const pendingScams: PendingScam[] = [];

  for (let i = 0; i < queries.length; i++) {
    const { kind } = queries[i];
    const resp = responses[i];
    if (!resp || !resp.results) continue;
    const results = resp.results.slice(0, 5);
    totalResults += results.length;

    if (kind === "consistency") {
      const matches = results.filter((r) => {
        const text = `${r.title ?? ""} ${r.url ?? ""} ${r.content ?? ""}`.toLowerCase();
        return LEGIT_KEYWORDS.some((k) => text.includes(k));
      });
      if (matches.length > 0) {
        consistencyHits += matches.length;
        findings.push(
          `Public results connect ${recruiter} to ${company} (e.g. LinkedIn, Crunchbase, or company pages).`,
        );
        whyPoints.push({
          finding: `Public web results link ${recruiter} to ${company}.`,
          why: "Finding the recruiter on LinkedIn, Crunchbase, or the company's own pages is a small positive signal that the person and company they claim to represent are real and connected.",
          severity: "good",
        });
      }
      matches.slice(0, 2).forEach((r) => allLinks.push({ title: r.title ?? r.url ?? "Result", url: r.url ?? "" }));
    } else if (kind === "recruiter") {
      const legitMatches = results.filter((r) => {
        const text = `${r.title ?? ""} ${r.url ?? ""} ${r.content ?? ""}`.toLowerCase();
        return LEGIT_KEYWORDS.some((k) => text.includes(k));
      });
      recruiterLegitHits += legitMatches.length;
      results.slice(0, 2).forEach((r) => allLinks.push({ title: r.title ?? r.url ?? "Result", url: r.url ?? "" }));
    } else {
      const matches = results.filter((r) => {
        const text = `${r.title ?? ""} ${r.content ?? ""}`.toLowerCase();
        return SCAM_KEYWORDS.some((k) => text.includes(k));
      });
      if (matches.length > 0) {
        const subject = kind === "company_scam" ? company : domain;
        if (kind === "company_scam") companyScamHits += matches.length;
        else domainScamHits += matches.length;
        pendingScams.push({ kind, subject, count: matches.length, matches });
      }
    }
  }

  // Decide impersonation framing: if the company has strong legitimacy signals
  // (LinkedIn / Crunchbase / Wikipedia / company pages connecting the recruiter
  // or company), then scam mentions of the COMPANY name most likely describe
  // scammers impersonating that real organization — not the org itself.
  const looksLikeRealOrg = consistencyHits > 0 || recruiterLegitHits > 0;

  // Direct accusation patterns — a public article title or snippet directly
  // calling the subject (company, recruiter, or domain) a scam/fraud.
  // These are stronger than generic "may be impersonated" warnings.
  const DIRECT_ACCUSATION =
    /\b(scam company|fraud company|scam job|fake recruiter|fake job|is a scam|is a fraud|avoid this company|scam alert|scam warning|reported as scam|fraudulent company|known scam|confirmed scam)\b/i;

  for (const ps of pendingScams) {
    const isDomainScam = ps.kind === "domain_scam";

    // Detect DIRECT scam accusations in titles/snippets that name the subject
    // (e.g. "Acme Corp is a scam company"). This is a much stronger signal
    // than generic impersonation warnings.
    const subjectLc = ps.subject.toLowerCase();
    const directAccusations = ps.matches.filter((r) => {
      const title = (r.title ?? "").toLowerCase();
      const snippet = (r.content ?? "").toLowerCase();
      const titleMentionsSubject =
        title.includes(subjectLc) || (isDomainScam && title.includes(subjectLc.split(".")[0]));
      const snippetMentionsSubject = snippet.includes(subjectLc);
      const titleAccusation = DIRECT_ACCUSATION.test(title);
      const snippetAccusation = DIRECT_ACCUSATION.test(snippet);
      // Strong: title directly accuses + names the subject, OR snippet has both
      return (titleMentionsSubject && titleAccusation) || (snippetMentionsSubject && snippetAccusation);
    });

    if (directAccusations.length > 0) {
      // Direct accusation against the exact company / domain / recruiter.
      // This overrides the impersonation framing entirely.
      const subjectKind = isDomainScam ? "domain" : "company";
      findings.push(
        `Public articles directly describe ${ps.subject} as a scam (${directAccusations.length} report${directAccusations.length === 1 ? "" : "s"}). Open the linked sources before responding.`,
      );
      whyPoints.push({
        finding: `Public reports directly accuse ${ps.subject} of being a scam.`,
        why: `These are not generic impersonation warnings — the linked articles or reviews directly describe the exact ${subjectKind} as fraudulent. This is one of the strongest external risk signals available.`,
        severity: "bad",
      });
      nextSteps.push(
        `Open and read the linked scam reports about ${ps.subject} before replying or sharing any information.`,
      );
      // Strong score bump — domain-level direct accusations are the heaviest.
      scoreDelta += isDomainScam
        ? Math.min(45, 25 + directAccusations.length * 5)
        : Math.min(35, 18 + directAccusations.length * 4);
      directAccusations
        .slice(0, 3)
        .forEach((r) => allLinks.push({ title: r.title ?? r.url ?? "Result", url: r.url ?? "" }));
      // Skip the impersonation/soft-framing branches below for this subject.
      continue;
    }

    // Domain-level scam mentions tied to the exact analyzed domain stay a
    // strong red flag. Company-name scam mentions on a real org are reframed
    // as a cautionary impersonation warning.
    const treatAsImpersonation = !isDomainScam && looksLikeRealOrg;

    if (treatAsImpersonation) {
      findings.push(
        `Public scam warnings mention ${ps.subject} as a possible impersonation target (${ps.count} result${ps.count === 1 ? "" : "s"}).`,
      );
      whyPoints.push({
        finding: `Public scam warnings mention ${ps.subject} as a possible impersonation target.`,
        why: "These results don't mean the organization itself is fraudulent. They suggest scammers may be pretending to represent it. Be extra careful that the recruiter contacting you is genuinely from this organization — verify through its official careers page or a known employee.",
        severity: "caution",
      });
      nextSteps.push(
        `Confirm through ${ps.subject}'s official website or a known contact that this recruiter actually works there.`,
      );
      // Small risk bump only — this is cautionary, not direct fraud evidence.
      scoreDelta += Math.min(6, 2 + ps.count);
    } else if (isDomainScam) {
      // Decide whether the evidence is "strong and direct" vs. weak/indirect.
      const domainLc = ps.subject.toLowerCase();
      const directMatches = ps.matches.filter((r) => {
        const text = `${r.url ?? ""} ${r.content ?? ""}`.toLowerCase();
        const mentionsDomain = text.includes(domainLc);
        const directFraud = /\b(fraud|fraudulent|scam (site|website|domain)|phishing|ripoff|rip-off)\b/.test(text);
        const impersonationContext = /\b(impersonat|warning|beware|advisory|alert|spoof)/.test(text);
        return mentionsDomain && directFraud && !impersonationContext;
      });
      const strongDirect = directMatches.length > 0 && !looksLikeRealOrg;

      if (strongDirect) {
        findings.push(
          `Public web mentions scam complaints tied to the domain ${ps.subject} (${ps.count} result${ps.count === 1 ? "" : "s"}).`,
        );
        whyPoints.push({
          finding: `Scam complaints publicly tied to the domain ${ps.subject}.`,
          why: "When scam reports name the exact domain you're being contacted from, that's a much stronger red flag than mentions of a brand name. It suggests the address itself has a history tied to fraud complaints.",
          severity: "bad",
        });
        nextSteps.push(
          `Do not reply to ${ps.subject}. Read the public scam reports tied to that domain before taking any action.`,
        );
        scoreDelta += Math.min(25, 12 + ps.count * 3);
      } else {
        findings.push(`Scam-related public mentions were found near the domain ${ps.subject}, but context is limited.`);
        whyPoints.push({
          finding: `Public results mention ${ps.subject} in scam-related discussions, though context is limited.`,
          why: "These results are cautionary, not proof that the domain itself is fraudulent. The mentions may reflect impersonation warnings, general advisories, or unrelated references rather than direct evidence that this address is malicious. Verify the recruiter through an official channel before sharing anything.",
          severity: "caution",
        });
        nextSteps.push(
          `Skim the linked sources to see whether they actually describe ${ps.subject} as malicious, or just mention it in passing.`,
        );
        scoreDelta += looksLikeRealOrg ? Math.min(3, 1 + Math.floor(ps.count / 2)) : Math.min(6, 2 + ps.count);
      }
    } else {
      findings.push(
        `Public web includes scam-related mentions involving ${ps.subject} (${ps.count} result${ps.count === 1 ? "" : "s"}).`,
      );
      whyPoints.push({
        finding: `Scam-related public mentions involving ${ps.subject}.`,
        why: "These results may describe scams that target this name or that impersonate this organization. They aren't proof the organization itself is fraudulent — but they're a reason to verify the recruiter through an independent, official channel before sharing anything.",
        severity: "caution",
      });
      nextSteps.push(
        `Verify the recruiter through ${ps.subject}'s official website before sharing any personal info or replying.`,
      );
      scoreDelta += Math.min(8, 3 + ps.count);
    }

    ps.matches.slice(0, 2).forEach((r) => allLinks.push({ title: r.title ?? r.url ?? "Result", url: r.url ?? "" }));
  }

  if (consistencyHits >= 1 && domainScamHits === 0) {
    scoreDelta -= Math.min(8, 3 + consistencyHits);
  }

  const totalScamHits = companyScamHits + domainScamHits;

  let summary: string;
  if (totalResults === 0) {
    summary =
      "We found limited public evidence about this recruiter or company. That alone does not mean it's a scam — it just means we can't confirm much from public search results.";
    whyPoints.push({
      finding: "Limited public web evidence.",
      why: "Some real recruiters and small companies have a thin web footprint. Treat this as 'unknown' rather than proof of a scam — verify through the company's official careers page.",
      severity: "info",
    });
  } else if (domainScamHits > 0) {
    summary = looksLikeRealOrg
      ? "The organization looks legitimate. We found some scam-related public mentions near this domain, but the context is limited and may reflect impersonation warnings rather than direct evidence the domain itself is malicious."
      : "Public results mention this domain in scam-related discussions. The context isn't always clear, so review the linked sources before deciding — these are cautionary signals, not always proof the domain itself is fraudulent.";
  } else if (companyScamHits > 0 && looksLikeRealOrg) {
    summary =
      "The organization itself looks legitimate, but public scam warnings mention it as a possible impersonation target. Be extra careful to confirm this recruiter genuinely works there.";
  } else if (totalScamHits > 0) {
    summary =
      "Public results include scam-related mentions involving this name. They don't prove the organization is fraudulent, but it's worth verifying the recruiter through an official channel.";
  } else if (consistencyHits > 0) {
    summary =
      "Public web results are consistent with a real recruiter at this company (e.g. LinkedIn or company pages). This is a small positive signal, not a guarantee.";
  } else {
    summary =
      "We found limited public evidence connecting this recruiter to the claimed company. That alone does not mean it's a scam — verify through the company's official careers page.";
    whyPoints.push({
      finding: "Limited public evidence connecting recruiter and company.",
      why: "We couldn't find clear public sources tying this person to this company. This is not proof of a scam, but it's worth confirming through the company's official careers page or LinkedIn.",
      severity: "info",
    });
  }

  return {
    result: { summary, findings, links: dedupeLinks(allLinks) },
    scoreDelta,
    whyPoints,
    nextSteps,
  };
}

// ---------- RDAP domain registration lookup ----------

type RdapEvent = { eventAction?: string; eventDate?: string };
type RdapEntity = {
  roles?: string[];
  vcardArray?: unknown;
  publicIds?: { type?: string; identifier?: string }[];
};
type RdapNameserver = { ldhName?: string; unicodeName?: string };
type RdapDomainResponse = {
  ldhName?: string;
  unicodeName?: string;
  events?: RdapEvent[];
  entities?: RdapEntity[];
  nameservers?: RdapNameserver[];
  status?: string[];
};
//lines below were edited by ceen gabbai
function emptyRdap(domain: string | null, error?: string): RdapResult {
  return {
    available: false,
    domain,
    registrar: null,
    registrationDate: null,
    lastUpdated: null,
    nameservers: [],
    statuses: [],
    ageDays: null,
    ageBucket: "unknown",
    ageSummary: "Domain registration data could not be reliably retrieved.",
    interpretation:
      "We couldn't pull RDAP registration data for this domain, so domain age can't factor into the risk score. Treat this as 'unknown' rather than safe or unsafe.",
    registrantCountry: null,
    error,
  };
}

/**
 * Extract a registrant country (ISO 3166-1 alpha-2 if available, otherwise free text)
 * from RDAP entities. Looks across registrant/admin/tech roles.
 */
function extractRegistrantCountry(entities: RdapEntity[] | undefined): string | null {
  if (!entities) return null;
  const ROLES = ["registrant", "administrative", "technical"];
  for (const e of entities) {
    if (!e.roles?.some((r) => ROLES.includes(r))) continue;
    const vcard = e.vcardArray as unknown[] | undefined;
    if (!Array.isArray(vcard) || vcard.length < 2 || !Array.isArray(vcard[1])) continue;
    for (const entry of vcard[1] as unknown[]) {
      if (!Array.isArray(entry) || entry[0] !== "adr") continue;
      const params = entry[1] as Record<string, unknown> | undefined;
      const cc = params && typeof params.cc === "string" ? (params.cc as string) : null;
      if (cc && /^[A-Za-z]{2}$/.test(cc)) return cc.toUpperCase();
      const adrValue = entry[3];
      if (Array.isArray(adrValue)) {
        const country = adrValue[adrValue.length - 1];
        if (typeof country === "string" && country.trim().length > 0) return country.trim();
      }
    }
  }
  return null;
}

function extractRegistrarName(entities: RdapEntity[] | undefined): string | null {
  if (!entities) return null;
  for (const e of entities) {
    if (!e.roles?.includes("registrar")) continue;
    // vcardArray: ["vcard", [["version",{},"text","4.0"], ["fn",{},"text","NameCheap, Inc."], ...]]
    const vcard = e.vcardArray as unknown[] | undefined;
    if (Array.isArray(vcard) && vcard.length >= 2 && Array.isArray(vcard[1])) {
      for (const entry of vcard[1] as unknown[]) {
        if (Array.isArray(entry) && entry[0] === "fn" && typeof entry[3] === "string") {
          return entry[3] as string;
        }
      }
    }
    const pid = e.publicIds?.find((p) => typeof p.identifier === "string");
    if (pid?.identifier) return pid.identifier;
  }
  return null;
}

function bucketAge(days: number | null): { bucket: RdapAgeBucket; summary: string } {
  if (days === null) return { bucket: "unknown", summary: "Domain age unknown." };
  if (days < 30)
    return {
      bucket: "very_new",
      summary: `Registered ${days} day${days === 1 ? "" : "s"} ago — very recently created.`,
    };
  if (days < 90) return { bucket: "new", summary: `Registered ${days} days ago — under 90 days old.` };
  if (days < 365) {
    const months = Math.max(1, Math.round(days / 30));
    return {
      bucket: "young",
      summary: `Registered about ${months} month${months === 1 ? "" : "s"} ago — under a year old.`,
    };
  }
  const years = Math.floor(days / 365);
  return {
    bucket: "established",
    summary: `Registered about ${years} year${years === 1 ? "" : "s"} ago — an established domain.`,
  };
}

function buildRdapInterpretation(bucket: RdapAgeBucket, domain: string, companyName?: string): string {
  const orgClaim =
    companyName && companyName.trim().length > 0
      ? ` The recruiter claims to represent ${companyName.trim()}, which is worth weighing against this.`
      : "";
  switch (bucket) {
    case "very_new":
      return `The domain ${domain} was registered very recently. Brand-new domains are commonly used in recruiter scams, since attackers spin them up just before a campaign.${orgClaim} This alone is not proof of fraud, but it is a strong red flag.`;
    case "new":
      return `The domain ${domain} is under 90 days old. Recently created domains are not necessarily scams, but they're disproportionately used in fraudulent campaigns.${orgClaim} Treat this as a meaningful caution signal.`;
    case "young":
      return `The domain ${domain} is under a year old. Many real businesses use young domains, but combined with other red flags this can matter.${orgClaim}`;
    case "established":
      return `The domain ${domain} has existed for years, which is consistent with an established organization rather than a throwaway scam domain. This is mildly reassuring on its own, but still verify the recruiter through official channels.`;
    default:
      return `Registration data was not available for ${domain}, so domain age can't factor into the risk score.`;
  }
}

async function fetchRdap(domain: string): Promise<RdapDomainResponse | null> {
  try {
    // rdap.org is a thin redirector that knows the right RDAP server per TLD.
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: "application/rdap+json" },
      redirect: "follow",
    });
    if (!res.ok) {
      return null;
    }
    const data = (await res.json()) as RdapDomainResponse;
    return data;
  } catch (err) {
    console.error("RDAP fetch error:", err);
    return null;
  }
}

async function runRdapLookup(input: { recruiterEmail?: string; companyName?: string }): Promise<{
  result: RdapResult;
  scoreDelta: number;
  floor: number;
  whyPoint: WhyPoint | null;
  nextStep: string | null;
}> {
  const senderDomain = input.recruiterEmail ? extractEmailDomain(input.recruiterEmail) : null;
  if (!senderDomain) {
    return {
      result: emptyRdap(null, "no_sender_domain"),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }
  // Skip RDAP for public mailbox providers — RDAP would just return the
  // gmail.com/outlook.com registration which tells us nothing useful.
  if (PUBLIC_EMAIL_DOMAINS.has(senderDomain)) {
    return {
      result: {
        ...emptyRdap(senderDomain, "public_mailbox"),
        ageSummary: "Skipped — recruiter is writing from a public mailbox provider, so domain age doesn't apply here.",
        interpretation:
          "Domain registration data isn't meaningful when the recruiter is using a public email provider like Gmail or Outlook. The domain alignment check above is the relevant signal.",
      },
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }
  //lines below were edited by ceen gabbai
  const lookupDomain = rootDomain(senderDomain);
  const rdap = await fetchRdap(lookupDomain);
  if (!rdap) {
    return {
      result: emptyRdap(lookupDomain, "rdap_unavailable"),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }

  const events = rdap.events ?? [];
  const regEvent = events.find((e) => e.eventAction === "registration");
  const updEvent = events.find(
    (e) => e.eventAction === "last changed" || e.eventAction === "last update of RDAP database",
  );
  const registrationDate = regEvent?.eventDate ?? null;
  const lastUpdated = updEvent?.eventDate ?? null;
  const registrar = extractRegistrarName(rdap.entities);
  const registrantCountry = extractRegistrantCountry(rdap.entities);

  let ageDays: number | null = null;
  if (registrationDate) {
    const t = Date.parse(registrationDate);
    if (!isNaN(t)) {
      ageDays = Math.max(0, Math.floor((Date.now() - t) / (1000 * 60 * 60 * 24)));
    }
  }

  const { bucket, summary } = bucketAge(ageDays);
  const interpretation = buildRdapInterpretation(bucket, lookupDomain, input.companyName);

  const nameservers = (rdap.nameservers ?? [])
    .map((n) => (n.ldhName || n.unicodeName || "").toLowerCase())
    .filter(Boolean)
    .slice(0, 6);
  const statuses = (rdap.status ?? []).slice(0, 6);

  const result: RdapResult = {
    available: true,
    domain: lookupDomain,
    registrar,
    registrationDate,
    lastUpdated,
    nameservers,
    statuses,
    ageDays,
    ageBucket: bucket,
    ageSummary: summary,
    interpretation,
    registrantCountry,
  };

  let scoreDelta = 0;
  let floor = 0;
  let whyPoint: WhyPoint | null = null;
  let nextStep: string | null = null;

  if (bucket === "very_new") {
    scoreDelta = 25;
    floor = 40;
    whyPoint = {
      finding: `Sender domain ${lookupDomain} was registered ${ageDays} day${ageDays === 1 ? "" : "s"} ago.`,
      why: interpretation,
      severity: "bad",
    };
    nextStep = `Be very cautious — ${lookupDomain} is brand new. Verify the recruiter through the official company website before sharing anything.`;
  } else if (bucket === "new") {
    scoreDelta = 12;
    floor = 20;
    whyPoint = {
      finding: `Sender domain ${lookupDomain} is under 90 days old.`,
      why: interpretation,
      severity: "caution",
    };
    nextStep = `Treat ${lookupDomain} with caution — it's a recently created domain. Confirm the recruiter through an official, separate channel.`;
  } else if (bucket === "young") {
    scoreDelta = 4;
    whyPoint = {
      finding: `Sender domain ${lookupDomain} is under a year old.`,
      why: interpretation,
      severity: "caution",
    };
  } else if (bucket === "established") {
    scoreDelta = -3;
    whyPoint = {
      finding: `Sender domain ${lookupDomain} has been registered for years.`,
      why: interpretation,
      severity: "good",
    };
  }

  return { result, scoreDelta, floor, whyPoint, nextStep };
}

// ---------- DNS / email infrastructure lookup (DoH) ----------

type DohAnswer = { name?: string; type?: number; TTL?: number; data?: string };
type DohResponse = { Status?: number; Answer?: DohAnswer[] };

function emptyDns(domain: string | null, error?: string, summary?: string, interpretation?: string): DnsResult {
  return {
    available: false,
    domain,
    hasMx: false,
    hasSpf: false,
    hasDmarc: false,
    hasA: false,
    hasAaaa: false,
    mxRecords: [],
    spfRecord: null,
    dmarcRecord: null,
    health: error === "public_mailbox" ? "skipped" : "unknown",
    summary:
      summary ??
      (error === "public_mailbox"
        ? "DNS check skipped — recruiter is using a public mailbox provider, where these records belong to the provider, not the sender."
        : "We couldn't perform a DNS check for this domain."),
    interpretation:
      interpretation ??
      (error === "public_mailbox"
        ? "DNS / email infrastructure checks only make sense for company-owned domains."
        : "Treat this as 'unknown' rather than safe or unsafe."),
    error,
  };
}

async function dohQuery(name: string, type: string): Promise<DohAnswer[]> {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetch(url, { headers: { Accept: "application/dns-json" } });
    if (!res.ok) return [];
    const data = (await res.json()) as DohResponse;
    return data.Answer ?? [];
  } catch (err) {
    console.error(`DoH ${type} error for ${name}:`, err);
    return [];
  }
}

function stripQuotes(s: string): string {
  // DoH TXT data is often wrapped in quotes, possibly multi-string concatenated.
  return s.replace(/"\s*"/g, "").replace(/^"|"$/g, "");
}

async function runDnsLookup(input: { recruiterEmail?: string; companyName?: string }): Promise<{
  result: DnsResult;
  scoreDelta: number;
  floor: number;
  whyPoint: WhyPoint | null;
  nextStep: string | null;
}> {
  const senderDomain = input.recruiterEmail ? extractEmailDomain(input.recruiterEmail) : null;
  if (!senderDomain) {
    return { result: emptyDns(null, "no_sender_domain"), scoreDelta: 0, floor: 0, whyPoint: null, nextStep: null };
  }
  if (PUBLIC_EMAIL_DOMAINS.has(senderDomain)) {
    return {
      result: emptyDns(senderDomain, "public_mailbox"),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }
  //lines below were edited by ceen gabbai
  const lookupDomain = rootDomain(senderDomain);

  const [mxAns, txtAns, aAns, aaaaAns, dmarcAns] = await Promise.all([
    dohQuery(lookupDomain, "MX"),
    dohQuery(lookupDomain, "TXT"),
    dohQuery(lookupDomain, "A"),
    dohQuery(lookupDomain, "AAAA"),
    dohQuery(`_dmarc.${lookupDomain}`, "TXT"),
  ]);

  const mxRecords = mxAns
    .map((a) => (a.data ?? "").trim())
    .filter(Boolean)
    .slice(0, 6);
  const hasMx = mxRecords.length > 0;
  const hasA = aAns.some((a) => !!a.data);
  const hasAaaa = aaaaAns.some((a) => !!a.data);

  const txtStrings = txtAns.map((a) => stripQuotes((a.data ?? "").trim())).filter(Boolean);
  const spfRecord = txtStrings.find((s) => /^v=spf1\b/i.test(s)) ?? null;
  const hasSpf = !!spfRecord;

  const dmarcStrings = dmarcAns.map((a) => stripQuotes((a.data ?? "").trim())).filter(Boolean);
  const dmarcRecord = dmarcStrings.find((s) => /^v=DMARC1\b/i.test(s)) ?? null;
  const hasDmarc = !!dmarcRecord;

  // Health buckets
  let health: DnsHealth;
  if (!hasMx && !hasA && !hasAaaa) health = "missing";
  else if (!hasMx) health = "minimal";
  else if (hasMx && hasSpf && hasDmarc) health = "healthy";
  else health = "thin";

  const parts: string[] = [];
  parts.push(hasMx ? `MX present (${mxRecords.length} record${mxRecords.length === 1 ? "" : "s"})` : "MX missing");
  parts.push(hasSpf ? "SPF present" : "SPF missing");
  parts.push(hasDmarc ? "DMARC present" : "DMARC missing");
  parts.push(hasA || hasAaaa ? "A/AAAA present" : "A/AAAA missing");
  const summary = parts.join(" · ");

  let interpretation: string;
  let scoreDelta = 0;
  let floor = 0;
  let whyPoint: WhyPoint | null = null;
  let nextStep: string | null = null;

  if (health === "missing") {
    interpretation = `${lookupDomain} has no mail (MX) and no web (A/AAAA) records. A real recruiting domain almost always has both. This is a strong concern, though not proof of malicious intent on its own.`;
    scoreDelta = 18;
    floor = 30;
    whyPoint = {
      finding: `${lookupDomain} has no MX, A, or AAAA records.`,
      why: interpretation,
      severity: "bad",
    };
    nextStep = `Be very cautious — ${lookupDomain} doesn't appear to host normal email or web infrastructure. Verify the recruiter through the official company website.`;
  } else if (health === "minimal") {
    interpretation = `${lookupDomain} has web records but no MX records, meaning it isn't set up to receive email normally. A domain actively sending recruiter mail without MX is a meaningful caution.`;
    scoreDelta = 12;
    floor = 20;
    whyPoint = {
      finding: `${lookupDomain} has no MX records.`,
      why: interpretation,
      severity: "bad",
    };
    nextStep = `Treat ${lookupDomain} with caution — it isn't configured to receive email. Confirm the recruiter through an official, separate channel.`;
  } else if (health === "thin") {
    const missing: string[] = [];
    if (!hasSpf) missing.push("SPF");
    if (!hasDmarc) missing.push("DMARC");
    interpretation = `${lookupDomain} has working email infrastructure (MX${hasA || hasAaaa ? " and web records" : ""}) but is missing ${missing.join(" and ")}. Many small or older domains skip these — it's a mild caution, not proof of fraud.`;
    scoreDelta = missing.length === 2 ? 5 : 3;
    whyPoint = {
      finding: `${lookupDomain} is missing ${missing.join(" and ")} record${missing.length === 1 ? "" : "s"}.`,
      why: interpretation,
      severity: "caution",
    };
  } else {
    // healthy
    interpretation = `${lookupDomain} has normal email infrastructure: MX records for receiving mail, plus SPF and DMARC for sender authentication. This is consistent with a legitimately operated domain.`;
    scoreDelta = -3;
    whyPoint = {
      finding: `${lookupDomain} has normal email infrastructure (MX + SPF + DMARC).`,
      why: interpretation,
      severity: "good",
    };
  }

  const result: DnsResult = {
    available: true,
    domain: lookupDomain,
    hasMx,
    hasSpf,
    hasDmarc,
    hasA,
    hasAaaa,
    mxRecords,
    spfRecord,
    dmarcRecord,
    health,
    summary,
    interpretation,
  };

  return { result, scoreDelta, floor, whyPoint, nextStep };
}

// ---------- Google Safe Browsing ----------
function emptySafeBrowsing(
  checkedUrl: string | null,
  status: SafeBrowsingStatus,
  summary: string,
  error?: string,
): SafeBrowsingResult {
  return {
    checked_url: checkedUrl,
    safe_browsing_status: status,
    safe_browsing_findings: [],
    safe_browsing_summary: summary,
    error,
  };
}

async function runSafeBrowsing(input: { companyDomain?: string }): Promise<{
  result: SafeBrowsingResult;
  scoreDelta: number;
  floor: number;
  whyPoint: WhyPoint | null;
  nextStep: string | null;
}> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  const rawDomain = input.companyDomain ? normalizeCompanyDomain(input.companyDomain) : null;
  const checkedUrl = rawDomain ? `https://${rawDomain}` : null;

  if (!checkedUrl) {
    return {
      result: emptySafeBrowsing(null, "unknown", "No company website provided to check."),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }

  if (!apiKey) {
    return {
      result: emptySafeBrowsing(
        checkedUrl,
        "unknown",
        "Google Safe Browsing check is not configured, so site reputation could not be verified.",
        "missing_api_key",
      ),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }

  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "suscruit", clientVersion: "1.0.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: checkedUrl }],
          },
        }),
      },
    );

    if (!res.ok) {
      return {
        result: emptySafeBrowsing(
          checkedUrl,
          "unknown",
          "Google Safe Browsing did not return a result for this site, so its reputation could not be verified.",
          `http_${res.status}`,
        ),
        scoreDelta: 0,
        floor: 0,
        whyPoint: null,
        nextStep: null,
      };
    }

    const json = (await res.json()) as { matches?: Array<{ threatType?: string }> };
    const matches = Array.isArray(json.matches) ? json.matches : [];

    if (matches.length > 0) {
      const types = Array.from(new Set(matches.map((m) => (m.threatType ?? "UNKNOWN").toString())));
      const human = types
        .map((t) =>
          t === "MALWARE"
            ? "malware"
            : t === "SOCIAL_ENGINEERING"
              ? "phishing / social engineering"
              : t === "UNWANTED_SOFTWARE"
                ? "unwanted software"
                : t === "POTENTIALLY_HARMFUL_APPLICATION"
                  ? "potentially harmful application"
                  : t.toLowerCase(),
        )
        .join(", ");
      const summary = `Google Safe Browsing currently flags ${rawDomain} for: ${human}. Google considers this site unsafe or harmful.`;
      return {
        result: {
          checked_url: checkedUrl,
          safe_browsing_status: "flagged",
          safe_browsing_findings: types,
          safe_browsing_summary: summary,
        },
        scoreDelta: 25,
        floor: 60,
        whyPoint: {
          finding: `${rawDomain} is currently flagged by Google Safe Browsing (${human}).`,
          why: "Google's Safe Browsing service maintains a list of sites known to host malware, phishing, or other harmful content. A current flag is a strong signal that this site is unsafe.",
          severity: "bad",
        },
        nextStep: `Do not visit or submit any information to ${rawDomain}. Google Safe Browsing currently flags it as unsafe.`,
      };
    }

    const summary = `Google Safe Browsing does not currently flag ${rawDomain}, but that is not proof the site is safe.`;
    return {
      result: {
        checked_url: checkedUrl,
        safe_browsing_status: "not_flagged",
        safe_browsing_findings: [],
        safe_browsing_summary: summary,
      },
      scoreDelta: -1,
      floor: 0,
      whyPoint: {
        finding: `${rawDomain} is not currently on Google Safe Browsing's list of unsafe sites.`,
        why: "Google's Safe Browsing service didn't return a hit for this site. That is mildly reassuring but not proof of safety — many scam sites are too new or too small to be listed.",
        severity: "info",
      },
      nextStep: null,
    };
  } catch (err) {
    return {
      result: emptySafeBrowsing(
        checkedUrl,
        "unknown",
        "Google Safe Browsing check failed, so site reputation could not be verified.",
        err instanceof Error ? err.message : "unknown_error",
      ),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }
}

// ---------- Certificate Transparency (crt.sh) ----------
function emptyCt(domain: string | null, summary: string, error?: string): CtResult {
  return {
    available: false,
    domain,
    certificatesFound: false,
    totalCertificates: 0,
    mostRecentIssuance: null,
    oldestIssuance: null,
    uniqueSubdomains: [],
    suspiciousSubdomains: [],
    history: "unknown",
    summary,
    interpretation: summary,
    error,
  };
}

const SUSPICIOUS_SUBDOMAIN_TERMS = [
  "login",
  "secure",
  "verify",
  "verification",
  "account",
  "signin",
  "auth",
  "wallet",
  "recover",
  "reset",
  "support",
  "billing",
  "invoice",
  "payment",
  "pay",
  "update",
  "confirm",
  "mail",
  "webmail",
  "drive",
  "docs",
  "sharepoint",
  "office365",
  "okta",
  "sso",
];

type CrtShEntry = {
  name_value?: string;
  common_name?: string;
  not_before?: string;
  entry_timestamp?: string;
};

async function runCtLookup(input: { recruiterEmail?: string }): Promise<{
  result: CtResult;
  scoreDelta: number;
  floor: number;
  whyPoint: WhyPoint | null;
  nextStep: string | null;
}> {
  const senderDomain = input.recruiterEmail ? extractEmailDomain(input.recruiterEmail) : null;
  if (!senderDomain) {
    return {
      result: emptyCt(null, "No recruiter email provided, so certificate history could not be checked."),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }
  if (PUBLIC_EMAIL_DOMAINS.has(senderDomain)) {
    return {
      result: emptyCt(
        senderDomain,
        "Sender uses a public mailbox provider (Gmail, Outlook, etc.), so certificate history doesn't apply to the sender's own domain.",
      ),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }
  //lines below were edited by ceen gabbai
  const lookupDomain = rootDomain(senderDomain);

  let entries: CrtShEntry[] = [];
  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 8000);
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent("%." + lookupDomain)}&output=json`, {
      headers: { Accept: "application/json", "User-Agent": "suscruit-ct-check/1.0" },
      signal: ac.signal,
    });
    clearTimeout(timer);
    if (!res.ok) {
      return {
        result: emptyCt(
          lookupDomain,
          `Certificate Transparency lookup did not return data for ${lookupDomain}, so its certificate history could not be established.`,
          `http_${res.status}`,
        ),
        scoreDelta: 0,
        floor: 0,
        whyPoint: null,
        nextStep: null,
      };
    }
    const json = (await res.json()) as CrtShEntry[];
    if (Array.isArray(json)) entries = json;
  } catch (err) {
    return {
      result: emptyCt(
        lookupDomain,
        `Certificate Transparency lookup failed for ${lookupDomain}, so its certificate history could not be established.`,
        err instanceof Error ? err.message : "unknown_error",
      ),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }

  if (entries.length === 0) {
    const summary = `No public certificates were found for ${lookupDomain} in Certificate Transparency logs.`;
    return {
      result: {
        available: true,
        domain: lookupDomain,
        certificatesFound: false,
        totalCertificates: 0,
        mostRecentIssuance: null,
        oldestIssuance: null,
        uniqueSubdomains: [],
        suspiciousSubdomains: [],
        history: "none",
        summary,
        interpretation: `${summary} Most legitimately operated domains have a visible certificate history. This is a mild caution, not proof of fraud.`,
      },
      scoreDelta: 5,
      floor: 0,
      whyPoint: {
        finding: `No certificate history found for ${lookupDomain} in public CT logs.`,
        why: "Most actively used domains have at least one TLS certificate logged in Certificate Transparency. The absence of any history is unusual for a working recruiting domain.",
        severity: "caution",
      },
      nextStep: null,
    };
  }

  // Aggregate
  const subdomainSet = new Set<string>();
  let oldest = Number.POSITIVE_INFINITY;
  let newest = Number.NEGATIVE_INFINITY;

  for (const e of entries) {
    const names = (e.name_value ?? e.common_name ?? "")
      .split(/\n|,/)
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s && !s.startsWith("*."));
    for (const n of names) {
      if (n === lookupDomain || n.endsWith("." + lookupDomain)) {
        subdomainSet.add(n);
      }
    }
    const dateStr = e.not_before ?? e.entry_timestamp;
    if (dateStr) {
      const t = Date.parse(dateStr);
      if (!Number.isNaN(t)) {
        if (t < oldest) oldest = t;
        if (t > newest) newest = t;
      }
    }
  }

  const allSubs = Array.from(subdomainSet);
  const mostRecentIssuance = newest > 0 ? new Date(newest).toISOString() : null;
  const oldestIssuance = oldest < Number.POSITIVE_INFINITY ? new Date(oldest).toISOString() : null;

  const now = Date.now();
  const ageDaysOldest = oldest < Number.POSITIVE_INFINITY ? Math.floor((now - oldest) / 86_400_000) : null;
  const daysSinceNewest = newest > 0 ? Math.floor((now - newest) / 86_400_000) : null;

  // Suspicious subdomain detection
  const suspicious = allSubs.filter((s) => {
    const label = s.replace("." + lookupDomain, "").replace(lookupDomain, "");
    return SUSPICIOUS_SUBDOMAIN_TERMS.some((t) => label.includes(t));
  });

  // History bucket
  let history: CtHistoryBucket;
  if (ageDaysOldest === null) history = "unknown";
  else if (ageDaysOldest < 30) history = "very_recent";
  else if (ageDaysOldest < 180) history = "recent";
  else if (ageDaysOldest < 730) history = "normal";
  else history = "established";

  const total = entries.length;
  const subsForUi = allSubs.slice(0, 12);

  let scoreDelta = 0;
  let floor = 0;
  let whyPoint: WhyPoint | null = null;
  let nextStep: string | null = null;
  let interpretation: string;

  const recencyText =
    daysSinceNewest !== null
      ? daysSinceNewest === 0
        ? "today"
        : `${daysSinceNewest} day${daysSinceNewest === 1 ? "" : "s"} ago`
      : "unknown date";

  const summary = `${total} certificate${total === 1 ? "" : "s"} found · ${allSubs.length} subdomain${allSubs.length === 1 ? "" : "s"} · most recent issuance ${recencyText}${suspicious.length > 0 ? ` · ${suspicious.length} suspicious-looking subdomain${suspicious.length === 1 ? "" : "s"}` : ""}`;

  if (history === "very_recent") {
    interpretation = `${lookupDomain}'s earliest visible certificate is only ${ageDaysOldest} day${ageDaysOldest === 1 ? "" : "s"} old. Very fresh certificate history can be normal for a brand-new domain, but it's a mild-to-moderate caution for a recruiter contact — especially if the domain also has thin DNS or recent registration.`;
    scoreDelta = 8;
    whyPoint = {
      finding: `${lookupDomain} has a very recent certificate history (first seen ${ageDaysOldest} day${ageDaysOldest === 1 ? "" : "s"} ago).`,
      why: interpretation,
      severity: "caution",
    };
    nextStep = `Treat ${lookupDomain} with extra caution — its TLS certificates are very fresh, which is unusual for an established employer.`;
  } else if (history === "recent") {
    interpretation = `${lookupDomain}'s certificate history goes back about ${ageDaysOldest} day${ageDaysOldest === 1 ? "" : "s"}. Not very long, but not unusual on its own. Combine with other signals before drawing conclusions.`;
    scoreDelta = 3;
    whyPoint = {
      finding: `${lookupDomain} has a fairly recent certificate history (about ${ageDaysOldest} days).`,
      why: interpretation,
      severity: "info",
    };
  } else if (history === "normal") {
    interpretation = `${lookupDomain} has a normal certificate history (~${Math.round((ageDaysOldest ?? 0) / 30)} months of issuance). Consistent with a regularly operated domain.`;
    scoreDelta = -1;
    whyPoint = {
      finding: `${lookupDomain} has a normal certificate history.`,
      why: interpretation,
      severity: "info",
    };
  } else {
    // established
    interpretation = `${lookupDomain} has an established certificate history (over 2 years of TLS issuance). Consistent with a long-running, legitimately operated domain — though not proof on its own.`;
    scoreDelta = -2;
    whyPoint = {
      finding: `${lookupDomain} has an established certificate history.`,
      why: interpretation,
      severity: "good",
    };
  }

  if (suspicious.length > 0) {
    const examples = suspicious.slice(0, 3).join(", ");
    interpretation = `${interpretation} Notable subdomains in CT logs look phishing-style (${examples}${suspicious.length > 3 ? ", …" : ""}). That can indicate the domain has been used to host login or verification pages.`;
    scoreDelta += 8;
    whyPoint = {
      finding: `${lookupDomain} has phishing-style subdomains in CT logs (${examples}${suspicious.length > 3 ? ", …" : ""}).`,
      why: "Subdomains containing words like 'login', 'verify', 'secure', or 'wallet' are commonly used to host credential-harvesting pages. Their presence in CT logs is a meaningful caution signal.",
      severity: "bad",
    };
    nextStep =
      nextStep ??
      `Be cautious — ${lookupDomain} has subdomains in public CT logs that look like login or verification pages.`;
  }

  return {
    result: {
      available: true,
      domain: lookupDomain,
      certificatesFound: true,
      totalCertificates: total,
      mostRecentIssuance,
      oldestIssuance,
      uniqueSubdomains: subsForUi,
      suspiciousSubdomains: suspicious.slice(0, 6),
      history,
      summary,
      interpretation,
    },
    scoreDelta,
    floor,
    whyPoint,
    nextStep,
  };
}
//lines below were edited by ceen gabbai
// ---------- Wayback Machine (Internet Archive) ----------
function emptyWayback(checkedUrl: string | null, summary: string, error?: string): WaybackResult {
  return {
    available: false,
    checked_url: checkedUrl,
    archive_history_status: "unknown",
    first_seen_archive_date: null,
    most_recent_archive_date: null,
    snapshot_count: null,
    website_history_summary: summary,
    interpretation: summary,
    error,
  };
}

function parseWaybackTimestamp(ts: string): string | null {
  // Wayback timestamps look like 19980101000000
  const m = ts.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m;
  const iso = `${y}-${mo}-${d}T${h}:${mi}:${s}Z`;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return new Date(t).toISOString();
}

async function runWayback(input: { companyDomain?: string }): Promise<{
  result: WaybackResult;
  scoreDelta: number;
  floor: number;
  whyPoint: WhyPoint | null;
  nextStep: string | null;
}> {
  const rawDomain = input.companyDomain ? normalizeCompanyDomain(input.companyDomain) : null;
  const checkedUrl = rawDomain ? `https://${rawDomain}` : null;

  if (!rawDomain || !checkedUrl) {
    return {
      result: emptyWayback(null, "No company website was provided to check archive history."),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }

  let firstIso: string | null = null;
  let latestIso: string | null = null;
  let snapshotCount: number | null = null;

  try {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 10_000);

    // CDX gives us the first and latest snapshots and a total count via collapse=urlkey
    const cdxUrl =
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(rawDomain)}` +
      `&output=json&fl=timestamp&limit=100000&collapse=timestamp:8`;

    const res = await fetch(cdxUrl, {
      headers: { Accept: "application/json", "User-Agent": "suscruit-wayback-check/1.0" },
      signal: ac.signal,
    });
    clearTimeout(timer);

    if (!res.ok) {
      return {
        result: emptyWayback(
          checkedUrl,
          `Wayback Machine did not return data for ${rawDomain}, so its archive history could not be established.`,
          `http_${res.status}`,
        ),
        scoreDelta: 0,
        floor: 0,
        whyPoint: null,
        nextStep: null,
      };
    }

    const json = (await res.json()) as string[][];
    // First row is the header (["timestamp"]), rest are values.
    const rows = Array.isArray(json) && json.length > 0 ? json.slice(1) : [];
    if (rows.length > 0) {
      snapshotCount = rows.length;
      const first = rows[0]?.[0];
      const last = rows[rows.length - 1]?.[0];
      if (first) firstIso = parseWaybackTimestamp(first);
      if (last) latestIso = parseWaybackTimestamp(last);
    }
  } catch (err) {
    return {
      result: emptyWayback(
        checkedUrl,
        `Wayback Machine lookup failed for ${rawDomain}, so its archive history could not be established.`,
        err instanceof Error ? err.message : "unknown_error",
      ),
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }

  const now = Date.now();
  const firstTs = firstIso ? Date.parse(firstIso) : null;
  const latestTs = latestIso ? Date.parse(latestIso) : null;
  const ageDays = firstTs ? Math.floor((now - firstTs) / 86_400_000) : null;
  const daysSinceLatest = latestTs ? Math.floor((now - latestTs) / 86_400_000) : null;

  let status: WaybackStatus;
  if (snapshotCount === null || snapshotCount === 0) {
    status = "none";
  } else if (ageDays === null) {
    status = "unknown";
  } else if (ageDays >= 365 * 5 && snapshotCount >= 20) {
    status = "established";
  } else if (ageDays >= 365 * 2) {
    status = "moderate";
  } else if (ageDays < 180) {
    status = "recent_only";
  } else {
    status = "thin";
  }

  const niceFirst = firstIso ? firstIso.slice(0, 10) : null;
  const niceLatest = latestIso ? latestIso.slice(0, 10) : null;

  const summaryParts: string[] = [];
  if (snapshotCount !== null) {
    summaryParts.push(`${snapshotCount} snapshot${snapshotCount === 1 ? "" : "s"}`);
  }
  if (niceFirst) summaryParts.push(`first seen ${niceFirst}`);
  if (niceLatest) summaryParts.push(`latest ${niceLatest}`);
  if (daysSinceLatest !== null && daysSinceLatest > 365) {
    summaryParts.push(`(no fresh snapshot in ${Math.floor(daysSinceLatest / 30)} months)`);
  }
  const website_history_summary = summaryParts.length ? summaryParts.join(" · ") : "No archive history found.";

  let interpretation: string;
  let scoreDelta = 0;
  let whyPoint: WhyPoint | null = null;
  let nextStep: string | null = null;

  if (status === "established") {
    const years = Math.floor((ageDays ?? 0) / 365);
    interpretation = `${rawDomain} has long-standing archive history (~${years} years, ${snapshotCount} snapshots). Consistent with an established, regularly operated website — though not proof on its own.`;
    scoreDelta = -3;
    whyPoint = {
      finding: `${rawDomain} has long-standing visible web history (first archived around ${niceFirst}).`,
      why: interpretation,
      severity: "good",
    };
  } else if (status === "moderate") {
    const years = Math.floor((ageDays ?? 0) / 365);
    interpretation = `${rawDomain} has moderate archive history (~${years} year${years === 1 ? "" : "s"}, ${snapshotCount} snapshots). Reasonable but not as established as a long-running site.`;
    scoreDelta = -1;
    whyPoint = {
      finding: `${rawDomain} has moderate web history (~${years} year${years === 1 ? "" : "s"}).`,
      why: interpretation,
      severity: "info",
    };
  } else if (status === "thin") {
    interpretation = `${rawDomain} has only thin archive history (about ${ageDays} days, ${snapshotCount} snapshots). Possible for a small or recent site, but worth noting if the company is supposed to be well-established.`;
    scoreDelta = 4;
    whyPoint = {
      finding: `${rawDomain} has thin web history (about ${ageDays} days, ${snapshotCount} snapshots).`,
      why: interpretation,
      severity: "caution",
    };
  } else if (status === "recent_only") {
    interpretation = `${rawDomain} only appears in archive history very recently (about ${ageDays} day${ageDays === 1 ? "" : "s"} ago). Brand-new sites are normal for new companies, but a recruiter from a supposedly established employer using a brand-new site is a meaningful caution.`;
    scoreDelta = 8;
    whyPoint = {
      finding: `${rawDomain} only appears in web archive history very recently (~${ageDays} day${ageDays === 1 ? "" : "s"} ago).`,
      why: interpretation,
      severity: "caution",
    };
    nextStep = `Treat ${rawDomain} with extra caution — it has very little visible web history. Verify the company through an independent source.`;
  } else if (status === "none") {
    interpretation = `${rawDomain} has no visible Wayback Machine history. Most working business sites have at least a few snapshots. This is a mild caution, not proof of fraud.`;
    scoreDelta = 3;
    whyPoint = {
      finding: `${rawDomain} has no visible Wayback Machine history.`,
      why: interpretation,
      severity: "caution",
    };
  } else {
    interpretation = `Wayback Machine returned data for ${rawDomain} but its history could not be clearly classified.`;
    scoreDelta = 0;
    whyPoint = null;
  }

  return {
    result: {
      available: true,
      checked_url: checkedUrl,
      archive_history_status: status,
      first_seen_archive_date: firstIso,
      most_recent_archive_date: latestIso,
      snapshot_count: snapshotCount,
      website_history_summary,
      interpretation,
    },
    scoreDelta,
    floor: 0,
    whyPoint,
    nextStep,
  };
}

// ---------- Recruiter public-location discovery ----------
// Cautionary, contextual signal only. Country alone never proves fraud — it
// only matters when combined with other weak trust signals.
//lines below were edited by ceen gabbai
const COUNTRY_NAME_TO_CODE: Record<string, string> = {
  "united states": "US",
  usa: "US",
  "u.s.": "US",
  "u.s.a.": "US",
  america: "US",
  "united kingdom": "GB",
  uk: "GB",
  britain: "GB",
  england: "GB",
  scotland: "GB",
  wales: "GB",
  germany: "DE",
  deutschland: "DE",
  france: "FR",
  spain: "ES",
  españa: "ES",
  italy: "IT",
  netherlands: "NL",
  holland: "NL",
  belgium: "BE",
  ireland: "IE",
  portugal: "PT",
  switzerland: "CH",
  austria: "AT",
  sweden: "SE",
  norway: "NO",
  denmark: "DK",
  finland: "FI",
  poland: "PL",
  "czech republic": "CZ",
  czechia: "CZ",
  romania: "RO",
  greece: "GR",
  turkey: "TR",
  russia: "RU",
  ukraine: "UA",
  canada: "CA",
  mexico: "MX",
  brazil: "BR",
  argentina: "AR",
  chile: "CL",
  colombia: "CO",
  australia: "AU",
  "new zealand": "NZ",
  india: "IN",
  pakistan: "PK",
  bangladesh: "BD",
  china: "CN",
  "hong kong": "HK",
  taiwan: "TW",
  japan: "JP",
  "south korea": "KR",
  korea: "KR",
  singapore: "SG",
  malaysia: "MY",
  indonesia: "ID",
  philippines: "PH",
  thailand: "TH",
  vietnam: "VN",
  uae: "AE",
  "united arab emirates": "AE",
  "saudi arabia": "SA",
  israel: "IL",
  egypt: "EG",
  "south africa": "ZA",
  nigeria: "NG",
  kenya: "KE",
  morocco: "MA",
};

function normalizeCountryToCode(input: string | null | undefined): string | null {
  if (!input) return null;
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (/^[A-Z]{2}$/.test(trimmed)) return trimmed.toUpperCase();
  const lower = trimmed.toLowerCase();
  if (COUNTRY_NAME_TO_CODE[lower]) return COUNTRY_NAME_TO_CODE[lower];
  // Try last token (handles "Berlin, Germany")
  const lastPart = lower.split(",").pop()?.trim() ?? "";
  if (lastPart && COUNTRY_NAME_TO_CODE[lastPart]) return COUNTRY_NAME_TO_CODE[lastPart];
  return null;
}

function emptyRecruiterLocation(reason: string): RecruiterLocationResult {
  return {
    available: false,
    recruiter_public_location: null,
    recruiter_country: null,
    location_confidence: "unknown",
    location_source: null,
    hiring_context_label: null,
    hiring_context_country: null,
    mismatch: false,
    summary: reason,
    caution_note: null,
  };
}

// Deterministic fallback: scan OSINT text for a "City, Country" pattern.
// Used when the AI returns null so the same recruiter consistently surfaces a location.
function heuristicLocationFromText(text: string): { location: string; country: string | null; source: string } | null {
  if (!text) return null;
  // Match "Word(, Word)?, <Country>" — e.g. "Hyderabad, Telangana, India" or "Berlin, Germany"
  const countryAlternation = Object.keys(COUNTRY_NAME_TO_CODE)
    .filter((n) => n.length >= 4)
    .map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|");
  const re = new RegExp(
    `\\b([A-Z][A-Za-z.\\-]+(?:\\s+[A-Z][A-Za-z.\\-]+){0,2}(?:,\\s*[A-Z][A-Za-z.\\-]+(?:\\s+[A-Z][A-Za-z.\\-]+){0,2})?),\\s*(${countryAlternation})\\b`,
    "i",
  );
  const m = text.match(re);
  if (!m) return null;
  const city = m[1].trim();
  const countryName = m[2].trim();
  const code = COUNTRY_NAME_TO_CODE[countryName.toLowerCase()] ?? null;
  return {
    location: `${city}, ${countryName}`,
    country: code,
    source: "public web mentions",
  };
}

type LocationAiResult = {
  location: string | null;
  country: string | null;
  confidence: "low" | "medium" | "high";
  source: string | null;
};

async function extractRecruiterLocationViaAi(args: {
  recruiterName: string;
  companyName: string;
  message: string;
  headers: string;
  osintFindings: string[];
  osintLinks: OsintLink[];
}): Promise<LocationAiResult | null> {
  const apiKey = process.env.LOVABLE_API_KEY;
  if (!apiKey) {
    console.warn("LOVABLE_API_KEY not configured — skipping recruiter location extraction.");
    return null;
  }

  // Compact context. Keep it small to keep latency/cost down.
  const links = args.osintLinks
    .slice(0, 6)
    .map((l) => `- ${l.title} — ${l.url}`)
    .join("\n");
  const findings = args.osintFindings
    .slice(0, 6)
    .map((f) => `- ${f}`)
    .join("\n");
  const trimmedMsg = args.message.length > 1500 ? args.message.slice(0, 1500) + "…" : args.message;
  const trimmedHeaders = args.headers.length > 1500 ? args.headers.slice(0, 1500) + "…" : args.headers;

  const userContent = [
    `Recruiter name: ${args.recruiterName || "(unknown)"}`,
    `Claimed company: ${args.companyName || "(unknown)"}`,
    "",
    "Public web findings about them:",
    findings || "(none)",
    "",
    "Public links:",
    links || "(none)",
    "",
    "Recruiter message (look for signature, phone country code, address):",
    trimmedMsg || "(none)",
    "",
    "Email headers (look for X-Originating-IP region hints, server hostnames):",
    trimmedHeaders || "(none)",
  ].join("\n");

  try {
    const res = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          {
            role: "system",
            content:
              "You identify the most likely PUBLIC, professional location of a recruiter from public-web evidence. " +
              "Use only what's in the provided text — do NOT invent facts. " +
              "Prefer LinkedIn/team-page locations and email-signature addresses (high confidence). " +
              "Treat strong contextual evidence (company HQ clearly tied to the recruiter, regional employer) as medium confidence. " +
              "Treat weaker hints (phone country code, OSINT snippet mentioning a city/country near the recruiter's name, language/timezone clues) as low confidence — and STILL return them as a best-guess location with confidence='low' and a clear source, rather than returning null. " +
              "Only return location=null when there is genuinely zero locational signal anywhere in the provided text. " +
              "Return ISO 3166-1 alpha-2 country codes when possible.",
          },
          { role: "user", content: userContent },
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "report_recruiter_location",
              description: "Report the most likely public location for the recruiter.",
              parameters: {
                type: "object",
                properties: {
                  location: {
                    type: ["string", "null"],
                    description: "Best free-form location (e.g. 'Berlin, Germany', 'London, UK'). Null if unknown.",
                  },
                  country: {
                    type: ["string", "null"],
                    description: "ISO 3166-1 alpha-2 country code (e.g. 'DE', 'US'). Null if unknown.",
                  },
                  confidence: {
                    type: "string",
                    enum: ["low", "medium", "high"],
                    description:
                      "high = explicit profile/signature location; medium = strong contextual evidence; low = weak hints only.",
                  },
                  source: {
                    type: ["string", "null"],
                    description:
                      "Short human-readable source, e.g. 'LinkedIn profile', 'email signature', 'company team page', 'phone country code'.",
                  },
                },
                required: ["location", "country", "confidence", "source"],
                additionalProperties: false,
              },
            },
          },
        ],
        tool_choice: { type: "function", function: { name: "report_recruiter_location" } },
      }),
    });

    if (!res.ok) {
      console.error(`Recruiter-location AI failed [${res.status}]`);
      return null;
    }
    const json = (await res.json()) as {
      choices?: { message?: { tool_calls?: { function?: { arguments?: string } }[] } }[];
    };
    const argsStr = json.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments;
    if (!argsStr) return null;
    const parsed = JSON.parse(argsStr) as Partial<LocationAiResult>;
    return {
      location: typeof parsed.location === "string" && parsed.location.trim() ? parsed.location.trim() : null,
      country: typeof parsed.country === "string" && parsed.country.trim() ? parsed.country.trim().toUpperCase() : null,
      confidence: parsed.confidence === "high" || parsed.confidence === "medium" ? parsed.confidence : "low",
      source: typeof parsed.source === "string" && parsed.source.trim() ? parsed.source.trim() : null,
    };
  } catch (err) {
    console.error("Recruiter-location AI error:", err);
    return null;
  }
}

async function runRecruiterLocation(args: {
  recruiterName?: string;
  companyName?: string;
  roleLocation?: string;
  message?: string;
  headers?: string;
  osintFindings: string[];
  osintLinks: OsintLink[];
  rdapCountry: string | null;
}): Promise<{ result: RecruiterLocationResult; scoreDelta: number; whyPoint: WhyPoint | null }> {
  const recruiterName = (args.recruiterName ?? "").trim();
  const companyName = (args.companyName ?? "").trim();
  const message = args.message ?? "";
  const headers = args.headers ?? "";

  // Determine hiring context (preferred: explicit role location; fallback: company HQ from RDAP)
  const role = (args.roleLocation ?? "").trim();
  let hiringLabel: string | null = null;
  let hiringCountry: string | null = null;
  if (role) {
    hiringLabel = `${role} (claimed role location)`;
    hiringCountry = normalizeCountryToCode(role);
  } else if (args.rdapCountry) {
    const code = normalizeCountryToCode(args.rdapCountry);
    hiringLabel = `${args.rdapCountry} (company HQ via domain registration)`;
    hiringCountry = code;
  }

  // Need at least some signal to even attempt extraction.
  const hasContext =
    recruiterName.length > 0 ||
    args.osintFindings.length > 0 ||
    args.osintLinks.length > 0 ||
    message.length > 0 ||
    headers.length > 0;

  if (!hasContext) {
    return {
      result: emptyRecruiterLocation("Not enough public information to estimate the recruiter's location."),
      scoreDelta: 0,
      whyPoint: null,
    };
  }

  const ai = await extractRecruiterLocationViaAi({
    recruiterName,
    companyName,
    message,
    headers,
    osintFindings: args.osintFindings,
    osintLinks: args.osintLinks,
  });

  let aiResult = ai;

  // Deterministic fallback if the AI bailed: scan OSINT findings + links for "City, Country".
  if (!aiResult || !aiResult.location) {
    const haystack = [...args.osintFindings, ...args.osintLinks.map((l) => `${l.title} ${l.url}`), message].join("\n");
    const heuristic = heuristicLocationFromText(haystack);
    if (heuristic) {
      aiResult = {
        location: heuristic.location,
        country: heuristic.country,
        confidence: "low",
        source: heuristic.source,
      };
    }
  }

  if (!aiResult || !aiResult.location) {
    return {
      result: {
        ...emptyRecruiterLocation(
          "We couldn't pin down a clear public location for this recruiter. Absence of a public location is not a red flag on its own.",
        ),
        hiring_context_label: hiringLabel,
        hiring_context_country: hiringCountry,
      },
      scoreDelta: 0,
      whyPoint: null,
    };
  }

  const recruiterCountry = aiResult.country || normalizeCountryToCode(aiResult.location);
  const mismatch =
    !!recruiterCountry && !!hiringCountry && recruiterCountry.toUpperCase() !== hiringCountry.toUpperCase();

  const sourceText = aiResult.source ? ` based on ${aiResult.source}` : "";
  const summary = `Recruiter public location appears to be ${aiResult.location}${sourceText}. (${aiResult.confidence} confidence)`;

  let cautionNote: string | null = null;
  let whyPoint: WhyPoint | null = null;
  let scoreDelta = 0;

  if (mismatch) {
    cautionNote =
      "This differs from the claimed hiring/company context and may warrant extra verification. " +
      "Cross-border recruiter outreach is not inherently fraudulent, but it should be verified carefully, especially when combined with other weak trust signals.";
    whyPoint = {
      finding: `Recruiter's public location (${aiResult.location}) appears to differ from the claimed hiring context (${hiringLabel}).`,
      why: cautionNote,
      severity: "caution",
    };
    // Very small bump only — handler will optionally amplify when other weak
    // signals are present. Country alone is never proof.
    scoreDelta = aiResult.confidence === "high" ? 3 : aiResult.confidence === "medium" ? 2 : 1;
  }

  return {
    result: {
      available: true,
      recruiter_public_location: aiResult.location,
      recruiter_country: recruiterCountry,
      location_confidence: aiResult.confidence,
      location_source: aiResult.source,
      hiring_context_label: hiringLabel,
      hiring_context_country: hiringCountry,
      mismatch,
      summary,
      caution_note: cautionNote,
    },
    scoreDelta,
    whyPoint,
  };
}

// ============================================================================
// Website traffic context (third-party estimates only — Cloudflare Radar +
// Tavily snippets from Similarweb/Semrush/Ahrefs + AI extraction).
// This is intentionally framed as third-party intelligence, never as the
// company's real internal analytics. Country alone is never proof of fraud.
// ============================================================================

function emptyTrafficResult(
  domain: string | null,
  status: TrafficEstimateStatus,
  summary: string,
  note: string,
): WebsiteTrafficResult {
  return {
    checked_domain: domain,
    traffic_estimate_status: status,
    estimated_top_countries: [],
    estimated_visibility_summary: summary,
    traffic_context_note: note,
    sources: [],
    geo_mismatch: false,
    hiring_context_label: null,
    hiring_context_country: null,
  };
}

/**
 * Cloudflare Radar exposes a free public API for some domain rankings + audience
 * country distribution. We only enable it when CLOUDFLARE_RADAR_TOKEN is set —
 * otherwise we skip silently. Returns top country codes with traffic share.
 */
async function fetchCloudflareRadarCountries(domain: string): Promise<{ country: string; share: number }[] | null> {
  const token = process.env.CLOUDFLARE_RADAR_TOKEN;
  if (!token) return null;
  try {
    const url = `https://api.cloudflare.com/client/v4/radar/ranking/domains/${encodeURIComponent(domain)}/locations?limit=5`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) {
      console.warn(`Cloudflare Radar failed [${res.status}] for ${domain}`);
      return null;
    }
    const json = (await res.json()) as {
      result?: {
        top_locations?: { clientCountryAlpha2?: string; rank?: number; value?: string }[];
      };
    };
    const top = json.result?.top_locations ?? [];
    return top
      .map((t) => ({
        country: (t.clientCountryAlpha2 ?? "").toUpperCase(),
        share: Number(t.value ?? 0),
      }))
      .filter((t) => t.country);
  } catch (err) {
    console.warn("Cloudflare Radar error:", err);
    return null;
  }
}

type TrafficAiResult = {
  top_countries: string[];
  visibility_summary: string | null;
  status: "available" | "limited" | "unavailable";
};

async function extractTrafficViaAi(args: {
  domain: string;
  snippets: { source: string; title: string; content: string; url: string }[];
}): Promise<TrafficAiResult | null> {
  const apiKey = process.env.LOVABLE_API_KEY;
  if (!apiKey) return null;
  if (args.snippets.length === 0) return null;

  const ctx = args.snippets
    .slice(0, 8)
    .map((s, i) => `[${i + 1}] ${s.source} — ${s.title}\n${s.content}\nURL: ${s.url}`)
    .join("\n\n");

  try {
    const res = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          {
            role: "system",
            content:
              "You extract third-party website traffic ESTIMATES from snippets of pages like Similarweb, Semrush, Ahrefs, and Cloudflare Radar. " +
              "These are estimates by third-party intelligence tools, not the site's real internal analytics. " +
              "Only use what's literally in the snippets. Never guess. " +
              "Return up to 5 estimated top audience countries (use full country names like 'United States', 'Germany'). " +
              "Write a short visibility_summary in plain English (e.g. 'Modest estimated traffic with audience concentrated in the US and UK.'). " +
              "If the snippets don't say anything useful, set status='limited' or 'unavailable' and return an empty top_countries list.",
          },
          { role: "user", content: `Domain: ${args.domain}\n\nSnippets:\n${ctx}` },
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "report_traffic_estimate",
              description: "Report estimated top audience countries and visibility for the domain.",
              parameters: {
                type: "object",
                properties: {
                  status: {
                    type: "string",
                    enum: ["available", "limited", "unavailable"],
                    description:
                      "available = clear estimate found; limited = weak hints only; unavailable = nothing usable.",
                  },
                  top_countries: {
                    type: "array",
                    items: { type: "string" },
                    description: "Up to 5 estimated top audience countries (full names).",
                  },
                  visibility_summary: {
                    type: ["string", "null"],
                    description: "One-sentence plain-English summary of estimated visibility/audience.",
                  },
                },
                required: ["status", "top_countries", "visibility_summary"],
                additionalProperties: false,
              },
            },
          },
        ],
        tool_choice: { type: "function", function: { name: "report_traffic_estimate" } },
      }),
    });
    if (!res.ok) {
      console.warn(`Traffic AI extraction failed [${res.status}]`);
      return null;
    }
    const json = (await res.json()) as {
      choices?: { message?: { tool_calls?: { function?: { arguments?: string } }[] } }[];
    };
    const argsStr = json.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments;
    if (!argsStr) return null;
    const parsed = JSON.parse(argsStr) as Partial<TrafficAiResult>;
    return {
      status: parsed.status === "available" || parsed.status === "limited" ? parsed.status : "unavailable",
      top_countries: Array.isArray(parsed.top_countries)
        ? parsed.top_countries.filter((c): c is string => typeof c === "string" && c.trim().length > 0).slice(0, 5)
        : [],
      visibility_summary:
        typeof parsed.visibility_summary === "string" && parsed.visibility_summary.trim()
          ? parsed.visibility_summary.trim()
          : null,
    };
  } catch (err) {
    console.warn("Traffic AI error:", err);
    return null;
  }
}
//lines below were edited by ceen gabbai
const ISO_TO_COUNTRY_NAME: Record<string, string> = {
  US: "United States",
  GB: "United Kingdom",
  UK: "United Kingdom",
  DE: "Germany",
  FR: "France",
  NL: "Netherlands",
  IE: "Ireland",
  ES: "Spain",
  IT: "Italy",
  PT: "Portugal",
  BE: "Belgium",
  CH: "Switzerland",
  AT: "Austria",
  SE: "Sweden",
  NO: "Norway",
  DK: "Denmark",
  FI: "Finland",
  PL: "Poland",
  CZ: "Czech Republic",
  RO: "Romania",
  UA: "Ukraine",
  RU: "Russia",
  TR: "Turkey",
  CA: "Canada",
  MX: "Mexico",
  BR: "Brazil",
  AR: "Argentina",
  CL: "Chile",
  CO: "Colombia",
  AU: "Australia",
  NZ: "New Zealand",
  IN: "India",
  PK: "Pakistan",
  BD: "Bangladesh",
  CN: "China",
  HK: "Hong Kong",
  TW: "Taiwan",
  JP: "Japan",
  KR: "South Korea",
  SG: "Singapore",
  MY: "Malaysia",
  ID: "Indonesia",
  PH: "Philippines",
  TH: "Thailand",
  VN: "Vietnam",
  AE: "United Arab Emirates",
  SA: "Saudi Arabia",
  IL: "Israel",
  EG: "Egypt",
  ZA: "South Africa",
  NG: "Nigeria",
  KE: "Kenya",
  MA: "Morocco",
};

async function runWebsiteTraffic(args: {
  companyDomain?: string;
  roleLocation?: string;
  rdapCountry: string | null;
}): Promise<{ result: WebsiteTrafficResult; scoreDelta: number; whyPoint: WhyPoint | null }> {
  const rawDomain = (args.companyDomain ?? "")
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .toLowerCase();
  const domain = rawDomain || null;

  // Hiring context (same precedence as recruiter location).
  const role = (args.roleLocation ?? "").trim();
  let hiringLabel: string | null = null;
  let hiringCountry: string | null = null;
  if (role) {
    hiringLabel = `${role} (claimed role location)`;
    hiringCountry = normalizeCountryToCode(role);
  } else if (args.rdapCountry) {
    hiringLabel = `${args.rdapCountry} (company HQ via domain registration)`;
    hiringCountry = normalizeCountryToCode(args.rdapCountry);
  }

  if (!domain) {
    const r = emptyTrafficResult(
      null,
      "unavailable",
      "No company domain was provided, so we couldn't run a traffic-context check.",
      "Traffic-estimate data is unavailable without a domain. This is not a fraud signal on its own.",
    );
    r.hiring_context_label = hiringLabel;
    r.hiring_context_country = hiringCountry;
    return { result: r, scoreDelta: 0, whyPoint: null };
  }

  const sourcesUsed: string[] = [];
  const snippets: { source: string; title: string; content: string; url: string }[] = [];

  // 1) Cloudflare Radar (free, structured).
  const radar = await fetchCloudflareRadarCountries(domain);
  let radarCountries: string[] = [];
  if (radar && radar.length > 0) {
    sourcesUsed.push("Cloudflare Radar");
    radarCountries = radar.slice(0, 5).map((r) => ISO_TO_COUNTRY_NAME[r.country] ?? r.country);
    snippets.push({
      source: "Cloudflare Radar",
      title: `Top audience locations for ${domain}`,
      content: radar
        .map((r) => `${ISO_TO_COUNTRY_NAME[r.country] ?? r.country}${r.share ? ` (~${r.share}%)` : ""}`)
        .join(", "),
      url: `https://radar.cloudflare.com/domains/domain/${domain}`,
    });
  }

  // 2) Tavily snippets from Similarweb / Semrush / Ahrefs.
  const tavilyKey = process.env.TAVILY_API_KEY;
  if (tavilyKey) {
    const queries = [
      { source: "Similarweb", q: `site:similarweb.com ${domain} top countries` },
      { source: "Semrush", q: `site:semrush.com ${domain} traffic analytics countries` },
      { source: "Ahrefs", q: `site:ahrefs.com ${domain} traffic countries` },
    ];
    const results = await Promise.all(queries.map((qq) => tavilySearch(qq.q, tavilyKey)));
    for (let i = 0; i < queries.length; i++) {
      const r = results[i];
      if (!r || !r.results || r.results.length === 0) continue;
      sourcesUsed.push(queries[i].source);
      for (const hit of r.results.slice(0, 2)) {
        snippets.push({
          source: queries[i].source,
          title: hit.title ?? "",
          content: (hit.content ?? "").slice(0, 600),
          url: hit.url ?? "",
        });
      }
    }
  }

  // 3) AI-extract structured top countries + visibility summary.
  const ai = await extractTrafficViaAi({ domain, snippets });

  // Merge: prefer Radar + AI together; AI may add what's not in Radar.
  let topCountries: string[] = [];
  if (radarCountries.length > 0) topCountries = [...radarCountries];
  if (ai && ai.top_countries.length > 0) {
    for (const c of ai.top_countries) {
      if (!topCountries.some((existing) => existing.toLowerCase() === c.toLowerCase())) {
        topCountries.push(c);
      }
    }
  }
  topCountries = topCountries.slice(0, 5);

  let status: TrafficEstimateStatus = "unavailable";
  if (topCountries.length > 0) status = "available";
  else if (snippets.length > 0 || (ai && ai.status !== "unavailable")) status = "limited";

  let visibilitySummary: string;
  if (ai?.visibility_summary) {
    visibilitySummary = ai.visibility_summary;
  } else if (status === "available") {
    visibilitySummary = `Third-party traffic estimates suggest visible audience activity in ${topCountries.slice(0, 3).join(", ")}.`;
  } else if (status === "limited") {
    visibilitySummary = `Third-party traffic-estimate signals for ${domain} are limited.`;
  } else {
    visibilitySummary = `Traffic-estimate data is unavailable or limited for ${domain}.`;
  }

  // Geo-mismatch check: only when we have a hiring country AND at least one country code we can map back.
  let geoMismatch = false;
  if (hiringCountry && topCountries.length > 0) {
    const topCodes = topCountries.map((n) => normalizeCountryToCode(n)).filter((c): c is string => !!c);
    if (topCodes.length > 0 && !topCodes.includes(hiringCountry.toUpperCase())) {
      geoMismatch = true;
    }
  }

  let contextNote: string;
  if (status === "unavailable") {
    contextNote =
      "Traffic-estimate data is unavailable or limited for this domain. This is third-party intelligence — absence is not a fraud signal on its own.";
  } else if (geoMismatch && hiringLabel) {
    contextNote =
      `Estimated traffic geography may not fully align with the claimed business context (${hiringLabel}). ` +
      `This is a supporting context signal from third-party estimates, not proof of fraud.`;
  } else {
    contextNote =
      "Estimated audience geography is broadly consistent with the claimed context, or the comparison is inconclusive. " +
      "These figures come from third-party web-intelligence tools, not the company's real internal analytics.";
  }

  let whyPoint: WhyPoint | null = null;
  let scoreDelta = 0;
  if (geoMismatch && status === "available") {
    whyPoint = {
      finding: `Third-party traffic estimates suggest most visible audience activity for ${domain} comes from ${topCountries.slice(0, 2).join(" and ")}, which may not align with ${hiringLabel ?? "the claimed hiring context"}.`,
      why: "Estimated traffic geography is a weak supporting signal — not proof of fraud. It matters more when combined with other weak trust signals like an unverifiable address, suspicious domain history, or generic recruiter outreach.",
      severity: "caution",
    };
    // Tiny nudge — handler decides whether to apply based on other weak signals.
    scoreDelta = 2;
  }

  return {
    result: {
      checked_domain: domain,
      traffic_estimate_status: status,
      estimated_top_countries: topCountries,
      estimated_visibility_summary: visibilitySummary,
      traffic_context_note: contextNote,
      sources: Array.from(new Set(sourcesUsed)),
      geo_mismatch: geoMismatch,
      hiring_context_label: hiringLabel,
      hiring_context_country: hiringCountry,
    },
    scoreDelta,
    whyPoint,
  };
}

// ---------- Deep recruiter identity discovery ----------

function emptyRecruiterIdentity(summary: string): RecruiterIdentityResult {
  return {
    available: false,
    recruiter_identity_summary: summary,
    recruiter_public_profiles: [],
    recruiter_public_mentions: [],
    recruiter_identity_confidence: "unknown",
    recruiter_identity_notes: [],
  };
}

function detectPlatformFromUrl(url: string): string {
  const u = url.toLowerCase();
  if (u.includes("linkedin.com")) return "linkedin";
  if (u.includes("github.com")) return "github";
  if (u.includes("twitter.com") || u.includes("x.com/")) return "x";
  if (u.includes("facebook.com")) return "facebook";
  if (u.includes("instagram.com")) return "instagram";
  if (u.includes("medium.com")) return "medium";
  if (u.includes("threads.net")) return "threads";
  if (u.includes("about.me")) return "about_me";
  if (u.includes("crunchbase.com")) return "crunchbase";
  if (u.includes("/team") || u.includes("/staff") || u.includes("/people") || u.includes("/about"))
    return "company_site";
  return "other";
}

function looksLikeProfileUrl(url: string): boolean {
  const u = url.toLowerCase();
  return (
    u.includes("linkedin.com/in/") ||
    u.includes("github.com/") ||
    u.includes("twitter.com/") ||
    u.includes("x.com/") ||
    u.includes("facebook.com/") ||
    u.includes("instagram.com/") ||
    u.includes("medium.com/@") ||
    u.includes("threads.net/") ||
    u.includes("about.me/")
  );
}

function nameTokens(name: string): string[] {
  return name
    .toLowerCase()
    .split(/\s+/)
    .map((t) => t.replace(/[^a-z0-9-]/gi, ""))
    .filter((t) => t.length > 1);
}

/**
 * Deep recruiter identity discovery.
 *
 * Strategy:
 *  - Run multiple context-rich Tavily queries combining recruiter name with
 *    company / domain / LinkedIn / GitHub / staff-page / hiring keywords.
 *  - Score each result based on how many context tokens it matches in title +
 *    URL + snippet (recruiter tokens, company tokens, domain tokens, role tokens).
 *  - Bucket profile-shaped URLs into likely / possible / uncertain.
 *  - Use the LLM (LOVABLE_API_KEY, gemini-flash) to synthesize a short
 *    identity summary, an overall confidence label, and disambiguation notes.
 *  - Fall back to a deterministic summary if the LLM is unavailable.
 */
async function runRecruiterIdentity(input: {
  recruiterName?: string;
  recruiterEmail?: string;
  companyName?: string;
  companyDomain?: string;
  message?: string;
  roleLocation?: string;
}): Promise<RecruiterIdentityResult> {
  const recruiter = (input.recruiterName ?? "").trim();
  if (!recruiter) {
    return emptyRecruiterIdentity(
      "We didn't run a deep recruiter identity check because no recruiter name was provided.",
    );
  }

  const company = (input.companyName ?? "").trim();
  const domain = (input.companyDomain ?? "")
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
  const senderDomain = (() => {
    const e = (input.recruiterEmail ?? "").trim();
    const at = e.indexOf("@");
    return at >= 0 ? e.slice(at + 1).toLowerCase() : "";
  })();
  const role = (() => {
    // Heuristic: pull a short job-title phrase from the message if present.
    const m = (input.message ?? "").match(
      /\b(software|frontend|front-end|backend|back-end|full[- ]stack|data|product|design|marketing|sales|devops|security|engineer|developer|manager|recruiter|analyst|scientist|director|lead)\s+\w{0,12}/i,
    );
    return m ? m[0].trim() : "";
  })();

  const apiKey = process.env.TAVILY_API_KEY;
  if (!apiKey) {
    return emptyRecruiterIdentity(
      "Public-web recruiter identity check is currently unavailable.",
    );
  }

  // ---- Build a deep query set (context-rich) ----
  const q = (s: string) => s.replace(/\s+/g, " ").trim();
  const queries: string[] = [];
  const push = (s: string) => {
    const v = q(s);
    if (v && !queries.includes(v)) queries.push(v);
  };

  // Always: profile-shaped searches (use site: for precision).
  push(`"${recruiter}" site:linkedin.com/in`);
  push(`"${recruiter}" site:linkedin.com`);
  if (company) push(`"${recruiter}" "${company}" site:linkedin.com`);
  push(`"${recruiter}" recruiter`);

  // Context-rich (preferred over name-alone).
  if (company) {
    push(`"${recruiter}" "${company}"`);
    push(`"${recruiter}" recruiter "${company}"`);
    push(`"${recruiter}" hiring "${company}"`);
    push(`"${recruiter}" "${company}" team`);
  }
  if (domain) push(`"${recruiter}" "${domain}"`);
  if (senderDomain && senderDomain !== domain) push(`"${recruiter}" "${senderDomain}"`);
  if (role && company) push(`"${recruiter}" "${company}" "${role}"`);

  // Account-discovery searches across other platforms.
  push(`"${recruiter}" site:github.com`);
  push(`"${recruiter}" site:twitter.com OR site:x.com`);
  push(`"${recruiter}" site:facebook.com`);
  push(`"${recruiter}" site:medium.com`);
  push(`"${recruiter}" recruiter staffing`);
  if (company) push(`"${recruiter}" "${company}" staff OR team OR people`);

  // Deduped, capped (Tavily call cost).
  const finalQueries = queries.slice(0, 14);

  const responses = await Promise.all(finalQueries.map((qq) => tavilySearch(qq, apiKey)));

  // ---- Score and bucket each result ----
  const recruiterToks = nameTokens(recruiter);
  const companyToks = company ? nameTokens(company) : [];
  const domainTok = domain ? domain.split(".")[0].toLowerCase() : "";
  const senderDomainTok = senderDomain && senderDomain !== domain ? senderDomain.split(".")[0].toLowerCase() : "";
  const roleToks = role ? nameTokens(role) : [];

  type Scored = {
    title: string;
    url: string;
    content: string;
    score: number;
    matchesRecruiter: boolean;
    matchesCompany: boolean;
    matchesDomain: boolean;
    matchesRole: boolean;
    isProfile: boolean;
    platform: string;
  };
  const scored: Scored[] = [];
  const seenUrls = new Set<string>();

  for (const resp of responses) {
    if (!resp || !resp.results) continue;
    for (const r of resp.results.slice(0, 5)) {
      const url = (r.url ?? "").trim();
      if (!url || seenUrls.has(url)) continue;
      seenUrls.add(url);
      const title = (r.title ?? "").trim();
      const content = (r.content ?? "").trim();
      const hay = `${title} ${url} ${content}`.toLowerCase();

      const recHits = recruiterToks.filter((t) => hay.includes(t)).length;
      const matchesRecruiter = recHits >= Math.max(1, Math.min(2, recruiterToks.length));
      const matchesCompany = companyToks.length > 0 && companyToks.some((t) => hay.includes(t));
      const matchesDomain =
        (!!domainTok && hay.includes(domainTok)) || (!!senderDomainTok && hay.includes(senderDomainTok));
      const matchesRole = roleToks.length > 0 && roleToks.some((t) => hay.includes(t));
      const isProfile = looksLikeProfileUrl(url);
      const platform = detectPlatformFromUrl(url);

      let score = 0;
      score += recHits * 2;
      if (matchesCompany) score += 4;
      if (matchesDomain) score += 3;
      if (matchesRole) score += 2;
      if (isProfile) score += 3;
      if (platform === "linkedin") score += 2;

      scored.push({
        title: title || url,
        url,
        content,
        score,
        matchesRecruiter,
        matchesCompany,
        matchesDomain,
        matchesRole,
        isProfile,
        platform,
      });
    }
  }

  // Filter: must at least mention the recruiter name.
  const candidates = scored.filter((s) => s.matchesRecruiter);

  // ---- Bucket profiles into likely / possible / uncertain ----
  const profiles: RecruiterPublicProfile[] = [];
  const profileCandidates = candidates.filter((s) => s.isProfile);
  // Sort highest score first.
  profileCandidates.sort((a, b) => b.score - a.score);

  for (const c of profileCandidates.slice(0, 12)) {
    let tier: RecruiterIdentityMatchTier;
    let confidence: RecruiterIdentityConfidence;
    let reason: string;

    const ctxHits = (c.matchesCompany ? 1 : 0) + (c.matchesDomain ? 1 : 0) + (c.matchesRole ? 1 : 0);
    if (ctxHits >= 2 || (ctxHits >= 1 && c.platform === "linkedin")) {
      tier = "likely";
      confidence = "high";
      reason =
        c.matchesCompany && c.matchesDomain
          ? "Profile context mentions both the recruiter and the claimed company/domain."
          : c.matchesCompany
            ? "Profile context mentions the recruiter and the claimed company."
            : "Profile context mentions the recruiter and the claimed domain or role.";
    } else if (ctxHits === 1) {
      tier = "possible";
      confidence = "medium";
      reason = "Profile mentions the recruiter and one piece of supporting context.";
    } else {
      tier = "uncertain";
      confidence = "low";
      reason =
        "Profile matches the recruiter name only — multiple people may share this name. Verify it is the right person.";
    }

    profiles.push({
      title: c.title,
      url: c.url,
      platform: c.platform,
      confidence,
      reason,
      match_tier: tier,
    });
  }

  // ---- Public mentions (non-profile pages) ----
  const mentionCandidates = candidates.filter((s) => !s.isProfile).sort((a, b) => b.score - a.score);
  const mentions: string[] = [];
  for (const m of mentionCandidates.slice(0, 6)) {
    const ctxHits = (m.matchesCompany ? 1 : 0) + (m.matchesDomain ? 1 : 0) + (m.matchesRole ? 1 : 0);
    if (ctxHits === 0) continue; // skip name-only article mentions
    const snippet = m.content.length > 220 ? `${m.content.slice(0, 220).trim()}…` : m.content;
    mentions.push(
      snippet ? `${m.title} — ${snippet} (${m.url})` : `${m.title} (${m.url})`,
    );
  }

  // ---- Disambiguation notes ----
  const notes: string[] = [];
  const likelyCount = profiles.filter((p) => p.match_tier === "likely").length;
  const uncertainCount = profiles.filter((p) => p.match_tier === "uncertain").length;
  const platformCount = new Set(profiles.map((p) => p.platform)).size;

  if (likelyCount === 0 && uncertainCount > 1) {
    notes.push(
      "Multiple people appear to share this name — profile matching is uncertain. Verify against the claimed company before trusting.",
    );
  }
  if (likelyCount === 0 && profiles.length === 0) {
    notes.push(
      "We didn't find a strong public recruiter profile tied to the claimed company.",
    );
  }
  if (likelyCount > 0 && platformCount === 1 && profiles[0].platform === "linkedin") {
    notes.push(
      "Identity evidence is mostly limited to LinkedIn — cross-check against the company's official team page if possible.",
    );
  }
  notes.push(
    "Always double-check public profile links — search engines can return other people with similar names.",
  );

  // ---- Overall confidence ----
  let overall: RecruiterIdentityConfidence;
  if (likelyCount >= 1) overall = likelyCount >= 2 ? "high" : "medium";
  else if (profiles.some((p) => p.match_tier === "possible")) overall = "low";
  else overall = "unknown";

  // ---- Try LLM synthesis (optional, gracefully falls back) ----
  const synth = await synthesizeRecruiterIdentity({
    recruiter,
    company,
    domain,
    senderDomain,
    role,
    profiles,
    mentions,
  });

  const summary =
    synth?.summary ??
    (likelyCount > 0
      ? `We found ${likelyCount} likely public profile${likelyCount === 1 ? "" : "s"} associated with this recruiter, plus ${profiles.length - likelyCount} possible match${profiles.length - likelyCount === 1 ? "" : "es"}.`
      : profiles.length > 0
        ? "We found possible public profiles, but identity confidence is limited because the supporting context is thin."
        : mentions.length > 0
          ? "We found public mentions of this name in context, but no clear matching profile was located."
          : "We didn't find a strong public recruiter profile tied to the claimed company.");

  if (synth?.notes) {
    for (const n of synth.notes) if (n && !notes.includes(n)) notes.push(n);
  }

  return {
    available: true,
    recruiter_identity_summary: summary,
    recruiter_public_profiles: profiles,
    recruiter_public_mentions: mentions,
    recruiter_identity_confidence: synth?.confidence ?? overall,
    recruiter_identity_notes: notes,
  };
}

/**
 * Optional LLM pass that synthesizes a tighter identity summary,
 * confidence label, and 1-2 disambiguation notes. Falls back gracefully.
 */
async function synthesizeRecruiterIdentity(args: {
  recruiter: string;
  company: string;
  domain: string;
  senderDomain: string;
  role: string;
  profiles: RecruiterPublicProfile[];
  mentions: string[];
}): Promise<{ summary: string; confidence: RecruiterIdentityConfidence; notes: string[] } | null> {
  const apiKey = process.env.LOVABLE_API_KEY;
  if (!apiKey) return null;
  if (args.profiles.length === 0 && args.mentions.length === 0) return null;

  const profilesBlock = args.profiles
    .slice(0, 8)
    .map(
      (p) =>
        `- [${p.platform}] (${p.match_tier}/${p.confidence}) ${p.title} — ${p.url} :: ${p.reason}`,
    )
    .join("\n");
  const mentionsBlock = args.mentions.slice(0, 4).map((m) => `- ${m}`).join("\n");

  try {
    const res = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash-lite",
        messages: [
          {
            role: "system",
            content:
              "You synthesize recruiter identity discovery results into a SHORT, calm, plain-English summary for a non-technical user. " +
              "Rules: max 2 sentences for summary. Never claim a profile belongs to the recruiter unless context strongly supports it. " +
              "If multiple people share the name, say so. Return ONLY JSON with shape " +
              '{"summary":string,"confidence":"low"|"medium"|"high"|"unknown","notes":string[]}.',
          },
          {
            role: "user",
            content:
              `Recruiter: ${args.recruiter}\n` +
              `Claimed company: ${args.company || "—"}\n` +
              `Company domain: ${args.domain || "—"}\n` +
              `Sender email domain: ${args.senderDomain || "—"}\n` +
              `Likely role: ${args.role || "—"}\n\n` +
              `Profiles found:\n${profilesBlock || "(none)"}\n\n` +
              `Other public mentions:\n${mentionsBlock || "(none)"}\n\n` +
              `Return JSON only.`,
          },
        ],
        response_format: { type: "json_object" },
        temperature: 0.2,
      }),
    });
    if (!res.ok) return null;
    const json = (await res.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    const raw = json.choices?.[0]?.message?.content;
    if (!raw) return null;
    const parsed = JSON.parse(raw) as {
      summary?: string;
      confidence?: string;
      notes?: unknown;
    };
    const conf: RecruiterIdentityConfidence =
      parsed.confidence === "low" ||
      parsed.confidence === "medium" ||
      parsed.confidence === "high"
        ? parsed.confidence
        : "unknown";
    const notes = Array.isArray(parsed.notes)
      ? parsed.notes.filter((n): n is string => typeof n === "string").slice(0, 3)
      : [];
    return {
      summary: typeof parsed.summary === "string" && parsed.summary.trim() ? parsed.summary.trim() : "",
      confidence: conf,
      notes,
    };
  } catch (err) {
    console.warn("synthesizeRecruiterIdentity failed:", err);
    return null;
  }
}

export const analyzeRecruiter = createServerFn({ method: "POST" })
  .inputValidator((input: AnalysisInput) => input)
  .handler(async ({ data }): Promise<AnalysisResult> => {
    const message = (data.message ?? "").trim();
    const lower = message.toLowerCase();
    const domainCheck = analyzeDomainAlignment(data.recruiterEmail, data.companyDomain);

    // ---------- Tavily OSINT + RDAP + DNS (server-side only, in parallel) ----------
    const [osint, rdapLookup, dnsLookup, safeBrowsingLookup, ctLookup, waybackLookup] = await Promise.all([
      runTavilyOsint({
        recruiterName: data.recruiterName,
        companyName: data.companyName,
        companyDomain: data.companyDomain,
      }),
      runRdapLookup({
        recruiterEmail: data.recruiterEmail,
        companyName: data.companyName,
      }),
      runDnsLookup({
        recruiterEmail: data.recruiterEmail,
        companyName: data.companyName,
      }),
      runSafeBrowsing({
        companyDomain: data.companyDomain,
      }),
      runCtLookup({
        recruiterEmail: data.recruiterEmail,
      }),
      runWayback({
        companyDomain: data.companyDomain,
      }),
    ]);
    const rdap = rdapLookup.result;
    const dns = dnsLookup.result;
    const safeBrowsing = safeBrowsingLookup.result;
    const ct = ctLookup.result;
    const wayback = waybackLookup.result;

    // Recruiter public-location + Website traffic context (run in parallel,
    // both depend on Tavily + RDAP being done).
    const [recruiterLocationLookup, websiteTrafficLookup, recruiterIdentity] = await Promise.all([
      runRecruiterLocation({
        recruiterName: data.recruiterName,
        companyName: data.companyName,
        roleLocation: data.roleLocation,
        message: data.message,
        headers: data.headers,
        osintFindings: osint.result.findings,
        osintLinks: osint.result.links,
        rdapCountry: rdap.registrantCountry,
      }),
      runWebsiteTraffic({
        companyDomain: data.companyDomain,
        roleLocation: data.roleLocation,
        rdapCountry: rdap.registrantCountry,
      }),
      runRecruiterIdentity({
        recruiterName: data.recruiterName,
        recruiterEmail: data.recruiterEmail,
        companyName: data.companyName,
        companyDomain: data.companyDomain,
        message: data.message,
        roleLocation: data.roleLocation,
      }),
    ]);
    const recruiterLocation = recruiterLocationLookup.result;
    const websiteTraffic = websiteTrafficLookup.result;
    type HeaderAuthCheck = {
      spf: "pass" | "fail" | "softfail" | "none" | "unknown";
      dkim: "pass" | "fail" | "none" | "unknown";
      dmarc: "pass" | "fail" | "none" | "unknown";
      findings: string[];
      reasons: string[];
      nextSteps: string[];
      explanations: WhyPoint[];
      scoreDelta: number;
      floor: number;
    };

    function parseHeaderAuth(headers?: string): HeaderAuthCheck {
      const raw = (headers ?? "").trim();
      if (!raw) {
        return {
          spf: "unknown",
          dkim: "unknown",
          dmarc: "unknown",
          findings: [],
          reasons: [],
          nextSteps: [],
          explanations: [],
          scoreDelta: 0,
          floor: 0,
        };
      }

      // Normalize: unfold continuation lines (RFC 5322 — lines starting with space/tab
      // belong to the previous header). This is critical for Outlook/Gmail/Yahoo/Apple
      // which wrap long Authentication-Results across many lines.
      const unfolded = raw.replace(/\r?\n[ \t]+/g, " ");
      const lower = unfolded.toLowerCase();

      const result: HeaderAuthCheck = {
        spf: "unknown",
        dkim: "unknown",
        dmarc: "unknown",
        findings: [],
        reasons: [],
        nextSteps: [],
        explanations: [],
        scoreDelta: 0,
        floor: 0,
      };

      // Helper: detect a status for a given mechanism across many provider formats.
      // Matches:
      //   Authentication-Results: ... spf=pass ...           (Gmail, Outlook, Yahoo, Apple)
      //   ARC-Authentication-Results: i=1; ... spf=pass ...  (Gmail forwarders)
      //   Received-SPF: Pass (...)                           (Outlook/Exchange, Yahoo)
      //   X-MS-Exchange-Organization-SCL / compauth=fail     (Outlook)
      //   DKIM-Signature: v=1; a=...                         (presence only — not a pass)
      const statusFor = (mech: "spf" | "dkim" | "dmarc"): string | null => {
        // key=value form, e.g. spf=pass, dkim=fail, dmarc=bestguesspass
        const kv = new RegExp(`\\b${mech}\\s*[=:]\\s*([a-z]+)`, "i");
        const m = lower.match(kv);
        if (m) return m[1];
        return null;
      };

      // SPF — also fall back to "Received-SPF: <status>"
      let spfStatus = statusFor("spf");
      if (!spfStatus) {
        const rspf = lower.match(/received-spf:\s*([a-z]+)/);
        if (rspf) spfStatus = rspf[1];
      }

      // DMARC — accept "bestguesspass" as pass-ish, "permerror"/"temperror" as unknown
      let dmarcStatus = statusFor("dmarc");
      // DKIM — also infer "none" if no DKIM-Signature header AND no dkim= result
      let dkimStatus = statusFor("dkim");
      if (!dkimStatus && !/\bdkim-signature\s*:/.test(lower)) {
        dkimStatus = "none";
      }

      // Helper to keep findings, reasons, explanations, and steps in sync.
      const note = (severity: WhyPoint["severity"], finding: string, why: string, nextStep?: string) => {
        result.findings.push(finding);
        result.reasons.push(why);
        result.explanations.push({ finding, why, severity });
        if (nextStep) result.nextSteps.push(nextStep);
      };

      // SPF
      if (spfStatus === "pass") {
        result.spf = "pass";
        note(
          "good",
          "Sender check (SPF) passed — the email really did come from a server the company allows.",
          "SPF is like a guest list at the door. A 'pass' means the company confirms this email was sent from one of their approved mail servers, which is what you'd expect from a real recruiter.",
        );
      } else if (spfStatus === "softfail" || spfStatus === "neutral") {
        result.spf = "softfail";
        note(
          "caution",
          "Sender check (SPF) only partially passed — the company didn't fully confirm this email came from them.",
          "Think of SPF like a guest list at the door. A 'softfail' means the sender's name isn't clearly on the company's approved list, so the email might not really be from who it says it is.",
          "Ask the recruiter to resend the message from their official company email address.",
        );
        result.scoreDelta += 10;
        result.floor = Math.max(result.floor, 15);
      } else if (spfStatus === "fail" || spfStatus === "hardfail") {
        result.spf = "fail";
        note(
          "bad",
          "Sender check (SPF) failed — the company says this email did NOT come from their servers.",
          "This is like someone showing up claiming to be from a company, but that company's official 'guest list' says they never sent them. It's a strong sign the sender is faking their identity.",
          "Don't trust this sender. Go to the company's real website and contact them directly to check.",
        );
        result.scoreDelta += 18;
        result.floor = Math.max(result.floor, 25);
      } else if (spfStatus === "none") {
        result.spf = "none";
        note(
          "caution",
          "No sender check (SPF) found — there's no proof of where this email really came from.",
          "Legitimate companies usually set up SPF so you can confirm their emails are real. Without it, it's much easier for a scammer to pretend to be them.",
          "Ask the recruiter to send the message from the official company email, or verify them another way.",
        );
        result.scoreDelta += 6;
      }

      // DKIM
      const dkimBodyHashFail = /dkim=fail[^;]*body hash/i.test(raw);
      const compauthPass = /compauth=pass/i.test(lower);
      const dmarcLooksOk = dmarcStatus === "pass" || dmarcStatus === "bestguesspass";
      const dkimLikelyForwarderBreak = dkimStatus === "fail" && dkimBodyHashFail && (dmarcLooksOk || compauthPass);

      if (dkimStatus === "pass") {
        result.dkim = "pass";
        note(
          "good",
          "Digital signature (DKIM) passed — the email's 'wax seal' matches and wasn't tampered with.",
          "DKIM is a digital wax seal the company stamps onto every email. A pass means the seal is intact, so the message wasn't changed in transit and really came from the company.",
        );
      } else if (dkimLikelyForwarderBreak) {
        result.dkim = "pass";
        note(
          "info",
          "Digital signature (DKIM) didn't match exactly, but the company's anti-impersonation check (DMARC) still passed — usually normal.",
          "Most of the time this happens for innocent reasons: a mailing list, an email forwarder, or a company security filter slightly changed the message on its way to you, which breaks the original seal even though the sender is real. Because DMARC still passed here, it leans toward legitimate — but you should still sanity-check if anything else feels off (urgent tone, unexpected links, requests for money, or a reply-to address that doesn't match the sender).",
          "If the message itself looks normal, you can usually trust it. If anything feels off, confirm with the sender through a channel you already trust — don't just reply to this email.",
        );
        result.scoreDelta += 4;
        result.floor = Math.max(result.floor, 8);
      } else if (dkimStatus === "fail" || dkimStatus === "permerror") {
        result.dkim = "fail";
        note(
          "bad",
          "Digital signature (DKIM) failed — the message may have been faked or changed in transit.",
          "Real companies put a digital 'wax seal' on their emails. If the seal is broken or doesn't match, the email was either tampered with or wasn't really sent by that company.",
          "Treat this email as suspicious and contact the company through their official website to confirm.",
        );
        result.scoreDelta += 16;
        result.floor = Math.max(result.floor, 25);
      } else if (dkimStatus === "none") {
        result.dkim = "none";
        note(
          "caution",
          "No digital signature (DKIM) on this email — there's no way to confirm it wasn't tampered with.",
          "Without that 'wax seal,' you can't be sure the email is genuine or that no one changed it before it reached you.",
          "Confirm the recruiter is real by reaching out through the company's official website.",
        );
        result.scoreDelta += 6;
      }

      // DMARC
      if (dmarcStatus === "pass" || dmarcStatus === "bestguesspass") {
        result.dmarc = "pass";
        note(
          "good",
          "Anti-impersonation check (DMARC) passed — the email matches the company's own rules for what their real email looks like.",
          "DMARC is the company's own policy that says 'only real emails from us should pass.' A pass here means this message lines up with the company's identity rules, which is what you'd expect from a real recruiter.",
        );
      } else if (dmarcStatus === "fail") {
        result.dmarc = "fail";
        note(
          "bad",
          "Anti-impersonation check (DMARC) failed — a strong warning sign of a fake or spoofed email.",
          "DMARC is the company's own rule that says 'only real emails from us should pass.' When it fails, it usually means someone is trying to impersonate the company to trick you.",
          "Do not trust this sender. Go to the company's official careers page and contact them directly instead.",
        );
        result.scoreDelta += 22;
        result.floor = Math.max(result.floor, 35);
      } else if (dmarcStatus === "none") {
        result.dmarc = "none";
        note(
          "caution",
          "Company has no anti-impersonation protection (DMARC) — making it easier for scammers to fake their emails.",
          "Without DMARC, scammers can more easily send emails that look like they're from this company. You can't rely on the sender's name alone.",
          "Be careful and double-check the recruiter through a separate, trusted channel — not by replying to this email.",
        );
        result.scoreDelta += 8;
      }

      // Outlook-specific: compauth (composite authentication)
      const compauth = lower.match(/compauth=([a-z]+)(?:\s+reason=(\d+))?/);
      if (compauth) {
        const verdict = compauth[1];
        if (verdict === "fail") {
          note(
            "bad",
            "Outlook's overall trust check (compauth) failed — Microsoft's own systems flagged this as likely impersonation.",
            "Outlook combines all the sender checks into one final verdict. A 'fail' here means Microsoft itself doesn't believe this email really came from who it claims.",
            "Do not reply or click any links. Verify the recruiter through the company's official website.",
          );
          result.scoreDelta += 15;
          result.floor = Math.max(result.floor, 30);
        } else if (verdict === "softpass" || verdict === "none") {
          note(
            "caution",
            "Outlook couldn't fully confirm the sender's identity (compauth was not a clear pass).",
            "Microsoft wasn't able to fully verify this email. It's not an automatic red flag, but you shouldn't trust it on looks alone.",
          );
          result.scoreDelta += 5;
        } else if (verdict === "pass") {
          note(
            "good",
            "Outlook's overall trust check (compauth) passed — Microsoft's own systems vouch for this sender.",
            "Outlook rolls SPF, DKIM, and DMARC into one final verdict. A pass here means Microsoft's filters concluded this email really came from who it claims.",
          );
        }
      }

      // No auth info at all
      if (result.spf === "unknown" && result.dkim === "unknown" && result.dmarc === "unknown") {
        note(
          "caution",
          "We couldn't find sender authentication info (SPF, DKIM, or DMARC) in the headers you pasted.",
          "Most real emails from Gmail, Outlook, Yahoo, or Apple Mail include an 'Authentication-Results' line that proves where the email came from. If it's missing, you may have pasted only part of the headers — or the email skipped these checks, which is unusual for legitimate companies.",
          "In your email app, open the message and choose 'Show original' (Gmail), 'View message source' (Outlook/Yahoo), or 'View → Message → All Headers' (Apple Mail), then paste the full headers.",
        );
        result.scoreDelta += 4;
      }

      // Compact friendly summary when no issues were found.
      // Avoids overwhelming non-technical users with three "everything is fine" bullets.
      const hasIssue = result.explanations.some((e) => e.severity === "bad" || e.severity === "caution");
      const hasGood = result.explanations.some((e) => e.severity === "good");
      if (!hasIssue && hasGood) {
        const passed: string[] = [];
        if (result.spf === "pass") passed.push("SPF");
        if (result.dkim === "pass") passed.push("DKIM");
        if (result.dmarc === "pass") passed.push("DMARC");
        const passedList = passed.length ? ` (${passed.join(", ")} passed)` : "";
        const compact: WhyPoint = {
          finding: "Email header looks clean — no impersonation red flags.",
          why: `The standard sender-identity checks${passedList} all came back fine, so this email really does appear to come from where it says it does. Nothing in the header itself looks suspicious.`,
          severity: "good",
        };
        result.findings = [compact.finding];
        result.reasons = [compact.why];
        result.explanations = [compact];
        result.nextSteps = [];
      } else if (hasIssue && hasGood) {
        // Drop the "good" pointers when there are also issues — surface only
        // what the user needs to act on, not a wall of mixed pass/fail bullets.
        const issuesOnly = result.explanations.filter((e) => e.severity !== "good");
        result.explanations = issuesOnly;
        result.findings = issuesOnly.map((e) => e.finding);
        result.reasons = issuesOnly.map((e) => e.why);
      }

      return result;
    }
    const headerAuth = parseHeaderAuth(data.headers);
    if (!message) {
      const baseFindings = ["No message text was provided to analyze."];
      const baseSteps = ["Paste the recruiter's full message into the message field and run the analysis again."];
      if (domainCheck.finding) baseFindings.push(domainCheck.finding);
      baseFindings.push(...headerAuth.findings);
      if (domainCheck.next_step) baseSteps.push(domainCheck.next_step);
      headerAuth.nextSteps.forEach((s) => baseSteps.push(s));
      const noMsgNegative =
        domainCheck.status === "mismatch" ||
        domainCheck.status === "lookalike" ||
        domainCheck.status === "public_email";

      let noMsgScore = 0;
      const authDelta = headerAuth.scoreDelta;
      const authFloor = headerAuth.floor;
      if (
        domainCheck.scoreDelta > 0 ||
        authDelta > 0 ||
        osint.scoreDelta > 0 ||
        rdapLookup.scoreDelta > 0 ||
        dnsLookup.scoreDelta > 0
      ) {
        noMsgScore = Math.min(
          85,
          15 +
            domainCheck.scoreDelta +
            authDelta +
            Math.max(0, osint.scoreDelta) +
            Math.max(0, rdapLookup.scoreDelta) +
            Math.max(0, dnsLookup.scoreDelta),
        );
      }
      if (osint.scoreDelta < 0) noMsgScore = Math.max(0, noMsgScore + osint.scoreDelta);
      if (rdapLookup.scoreDelta < 0) noMsgScore = Math.max(0, noMsgScore + rdapLookup.scoreDelta);
      if (dnsLookup.scoreDelta < 0) noMsgScore = Math.max(0, noMsgScore + dnsLookup.scoreDelta);
      if (domainCheck.floor > 0) noMsgScore = Math.max(noMsgScore, domainCheck.floor);
      if (authFloor > 0) noMsgScore = Math.max(noMsgScore, authFloor);
      if (rdapLookup.floor > 0) noMsgScore = Math.max(noMsgScore, rdapLookup.floor);
      if (dnsLookup.floor > 0) noMsgScore = Math.max(noMsgScore, dnsLookup.floor);
      osint.result.findings.forEach((f) => baseFindings.push(f));
      osint.nextSteps.forEach((s) => baseSteps.push(s));
      if (rdap.available) {
        baseFindings.push(`Domain ${rdap.domain}: ${rdap.ageSummary}`);
      }
      if (rdapLookup.nextStep) baseSteps.push(rdapLookup.nextStep);
      if (dns.available) {
        baseFindings.push(`DNS for ${dns.domain}: ${dns.summary}`);
      }
      if (dnsLookup.nextStep) baseSteps.push(dnsLookup.nextStep);
      if (safeBrowsingLookup.scoreDelta > 0) {
        noMsgScore = Math.min(95, noMsgScore + safeBrowsingLookup.scoreDelta);
      } else if (safeBrowsingLookup.scoreDelta < 0) {
        noMsgScore = Math.max(0, noMsgScore + safeBrowsingLookup.scoreDelta);
      }
      if (safeBrowsingLookup.floor > 0) noMsgScore = Math.max(noMsgScore, safeBrowsingLookup.floor);
      if (safeBrowsing.safe_browsing_status === "flagged") {
        baseFindings.push(safeBrowsing.safe_browsing_summary);
      }
      if (safeBrowsingLookup.nextStep) baseSteps.push(safeBrowsingLookup.nextStep);
      if (ctLookup.scoreDelta > 0) {
        noMsgScore = Math.min(95, noMsgScore + ctLookup.scoreDelta);
      } else if (ctLookup.scoreDelta < 0) {
        noMsgScore = Math.max(0, noMsgScore + ctLookup.scoreDelta);
      }
      if (ctLookup.floor > 0) noMsgScore = Math.max(noMsgScore, ctLookup.floor);
      if (ct.available && ct.certificatesFound) {
        baseFindings.push(`CT for ${ct.domain}: ${ct.summary}`);
      } else if (ct.available && !ct.certificatesFound) {
        baseFindings.push(`No CT certificates found for ${ct.domain}`);
      }
      if (ctLookup.nextStep) baseSteps.push(ctLookup.nextStep);
      if (waybackLookup.scoreDelta > 0) {
        noMsgScore = Math.min(95, noMsgScore + waybackLookup.scoreDelta);
      } else if (waybackLookup.scoreDelta < 0) {
        noMsgScore = Math.max(0, noMsgScore + waybackLookup.scoreDelta);
      }
      if (waybackLookup.floor > 0) noMsgScore = Math.max(noMsgScore, waybackLookup.floor);
      if (wayback.available) {
        baseFindings.push(`Web history for ${wayback.checked_url}: ${wayback.website_history_summary}`);
      }
      if (waybackLookup.nextStep) baseSteps.push(waybackLookup.nextStep);

      const noMsgLevel = levelFor(noMsgScore);

      const noMsgWhyPoints: WhyPoint[] = [];
      if (
        domainCheck.finding &&
        domainCheck.reason &&
        domainCheck.status !== "match" &&
        domainCheck.status !== "subdomain" &&
        domainCheck.status !== "affiliated"
      ) {
        const sev: WhyPoint["severity"] = noMsgNegative
          ? "bad"
          : domainCheck.status === "unverifiable"
            ? "info"
            : "caution";
        noMsgWhyPoints.push({ finding: domainCheck.finding, why: domainCheck.reason, severity: sev });
      } else if (domainCheck.status === "affiliated" && domainCheck.finding && domainCheck.reason) {
        noMsgWhyPoints.push({ finding: domainCheck.finding, why: domainCheck.reason, severity: "good" });
      }
      headerAuth.explanations.forEach((e) => noMsgWhyPoints.push(e));
      osint.whyPoints.forEach((p) => noMsgWhyPoints.push(p));
      if (rdapLookup.whyPoint) noMsgWhyPoints.push(rdapLookup.whyPoint);
      if (dnsLookup.whyPoint) noMsgWhyPoints.push(dnsLookup.whyPoint);
      if (safeBrowsingLookup.whyPoint) noMsgWhyPoints.push(safeBrowsingLookup.whyPoint);
      if (ctLookup.whyPoint) noMsgWhyPoints.push(ctLookup.whyPoint);
      if (waybackLookup.whyPoint) noMsgWhyPoints.push(waybackLookup.whyPoint);
      if (recruiterLocationLookup.whyPoint) noMsgWhyPoints.push(recruiterLocationLookup.whyPoint);
      if (websiteTrafficLookup.whyPoint) noMsgWhyPoints.push(websiteTrafficLookup.whyPoint);

      return {
        risk_score: noMsgScore,
        risk_level: noMsgLevel,
        findings: baseFindings,
        why_it_matters: noMsgNegative
          ? `${domainCheck.reason} Paste the recruiter's full message to get a complete risk assessment — but note that a polished message would not cancel a sender/company domain mismatch.`
          : "Without the recruiter's message we can't check for scam wording. Paste their full message to get a real risk assessment.",
        why_points: noMsgWhyPoints,
        next_steps: baseSteps,
        audio_summary: noMsgNegative
          ? `${domainCheck.finding} Paste the recruiter's full message to get a complete risk assessment.`
          : "No message was provided. Paste the recruiter's full message to get a real risk assessment.",
        osint_summary: osint.result.summary,
        osint_findings: osint.result.findings,
        osint_links: osint.result.links,
        rdap,
        dns,
        safe_browsing: safeBrowsing,
        ct,
        wayback,
        recruiter_location: recruiterLocation,
        website_traffic: websiteTraffic,
      };
    }

    const matchedScam: Signal[] = [];
    const matchedCaution: Signal[] = [];
    const matchedPositive: Signal[] = [];

    let score = 10;
    let scamScore = 0;
    let cautionScore = 0;
    let positiveScore = 0;

    for (const s of SCAM_SIGNALS) {
      if (s.test(lower, message)) {
        matchedScam.push(s);
        scamScore += s.weight;
      }
    }
    for (const s of CAUTION_SIGNALS) {
      if (s.test(lower, message)) {
        matchedCaution.push(s);
        cautionScore += s.weight;
      }
    }
    for (const s of POSITIVE_SIGNALS) {
      if (s.test(lower, message)) {
        matchedPositive.push(s);
        positiveScore += s.weight;
      }
    }

    score += scamScore + cautionScore;
    score += headerAuth.scoreDelta;

    if (matchedScam.length >= 3) score += 6;
    if (matchedScam.length >= 5) score += 6;

    score += domainCheck.scoreDelta;
    score += osint.scoreDelta;
    score += rdapLookup.scoreDelta;
    score += dnsLookup.scoreDelta;
    score += safeBrowsingLookup.scoreDelta;
    score += ctLookup.scoreDelta;
    score += waybackLookup.scoreDelta;

    // ---- Combo bonuses for payment-related scam patterns ----
    // Payment/fee/check/crypto language combined with other scam patterns is
    // among the strongest signals in the system. Boost meaningfully.
    const hasPaymentSignal = matchedScam.some(
      (s) => s.id === "payment" || s.id === "check_equipment" || s.id === "gift_crypto",
    );
    const hasUrgency = matchedScam.some((s) => s.id === "urgency");
    const hasOffPlatform = matchedScam.some((s) => s.id === "offplatform");
    const hasOsintScam = osint.scoreDelta >= 12;

    if (hasPaymentSignal && hasUrgency) score += 12;
    if (hasPaymentSignal && hasOffPlatform) score += 18;
    if (hasPaymentSignal && hasOsintScam) score += 15;

    // Hard floor: any direct payment/fee/check/crypto request is at minimum
    // High Risk territory regardless of other "polished" signals.
    let paymentFloor = 0;
    if (matchedScam.some((s) => s.id === "payment")) paymentFloor = Math.max(paymentFloor, 65);
    if (matchedScam.some((s) => s.id === "check_equipment")) paymentFloor = Math.max(paymentFloor, 75);
    if (matchedScam.some((s) => s.id === "gift_crypto")) paymentFloor = Math.max(paymentFloor, 80);

    // Cap how much positive wording can lower the score. Strong red flags
    // (high-weight scam signals or domain mismatch/lookalike/public_email)
    // must not be neutralized by a polished message.
    const hasStrongRedFlag =
      matchedScam.some((s) => s.weight >= 15) ||
      domainCheck.status === "mismatch" ||
      domainCheck.status === "lookalike" ||
      domainCheck.status === "public_email" ||
      headerAuth.dmarc === "fail" ||
      headerAuth.spf === "fail" ||
      headerAuth.dkim === "fail";
    const positiveCap = hasStrongRedFlag ? 5 : 18;
    const positiveDeduction = Math.min(positiveScore, positiveCap);
    score -= positiveDeduction;

    if (matchedScam.length === 0 && !hasStrongRedFlag && matchedPositive.length >= 3) {
      score -= 6;
    }
    //lines below were edited by ceen gabbai
    // Enforce domain-driven minimum risk floor.
    if (domainCheck.floor > 0) {
      score = Math.max(score, domainCheck.floor);
    }
    if (headerAuth.floor > 0) {
      score = Math.max(score, headerAuth.floor);
    }
    if (rdapLookup.floor > 0) {
      score = Math.max(score, rdapLookup.floor);
    }
    if (dnsLookup.floor > 0) {
      score = Math.max(score, dnsLookup.floor);
    }
    if (safeBrowsingLookup.floor > 0) {
      score = Math.max(score, safeBrowsingLookup.floor);
    }
    if (ctLookup.floor > 0) {
      score = Math.max(score, ctLookup.floor);
    }
    if (waybackLookup.floor > 0) {
      score = Math.max(score, waybackLookup.floor);
    }
    if (paymentFloor > 0) {
      score = Math.max(score, paymentFloor);
    }
    // Direct public scam accusations (very strong osint signal) get their own floor.
    if (osint.scoreDelta >= 25) {
      score = Math.max(score, 70);
    } else if (osint.scoreDelta >= 18) {
      score = Math.max(score, 55);
    }
    score = Math.max(0, Math.min(100, Math.round(score)));
    const level = levelFor(score);

    const domainIsNegative =
      domainCheck.status === "mismatch" || domainCheck.status === "lookalike" || domainCheck.status === "public_email";
    const domainIsPositive =
      domainCheck.status === "match" || domainCheck.status === "subdomain" || domainCheck.status === "affiliated";
    const domainIsAffiliated = domainCheck.status === "affiliated";

    const findings: string[] = [];
    if (domainIsNegative && domainCheck.finding) findings.push(domainCheck.finding);
    for (const m of matchedScam) findings.push(m.finding);
    for (const m of matchedCaution) findings.push(m.finding);
    // Surface email-header findings into the main findings list (per-pointer
    // explanations live in `header_explanations` for a dedicated section).
    for (const h of headerAuth.findings) findings.push(h);
    if (matchedPositive.length) {
      const positiveSummary = `Legitimacy signals detected: ${matchedPositive
        .map((p) => p.finding.replace(/\.$/, "").replace(/^Message /, ""))
        .join("; ")}.`;
      findings.push(positiveSummary);
    }
    if (domainIsPositive && domainCheck.finding) findings.push(domainCheck.finding);
    if (domainCheck.status === "unverifiable" && domainCheck.finding && (data.recruiterEmail || data.companyDomain)) {
      findings.push(domainCheck.finding);
    }
    if (!findings.length) {
      findings.push("No common scam wording was detected in the message text.");
    }

    const stepSet = new Set<string>();
    if (domainIsNegative && domainCheck.next_step) stepSet.add(domainCheck.next_step);
    headerAuth.nextSteps.forEach((s) => stepSet.add(s));
    for (const m of matchedScam) stepSet.add(m.next_step);
    for (const m of matchedCaution) stepSet.add(m.next_step);
    if (!matchedScam.length && !matchedCaution.length && !domainIsNegative) {
      defaultNextSteps(level).forEach((s) => stepSet.add(s));
    }
    if (matchedPositive.length && stepSet.size < 5) {
      stepSet.add("Even with positive signals, confirm the role exists on the company's official careers page.");
    }
    if (
      domainCheck.status === "unverifiable" &&
      domainCheck.next_step &&
      stepSet.size < 5 &&
      (data.recruiterEmail || data.companyDomain)
    ) {
      stepSet.add(domainCheck.next_step);
    }
    const next_steps = Array.from(stepSet).slice(0, 5);

    let why_it_matters = buildWhyItMatters(level, matchedScam.length, matchedCaution.length, matchedPositive.length);
    if (domainIsNegative) {
      why_it_matters = `${domainCheck.reason} A polished, professional-sounding message does not cancel a sender/company domain mismatch — scammers can and do write normal-sounding outreach. ${why_it_matters}`;
    } else if (domainIsPositive) {
      why_it_matters = `${why_it_matters} On the identity side, the sender's email domain aligns with the claimed company, which is consistent with legitimate outreach.`;
    } else if (domainCheck.status === "unverifiable" && (data.recruiterEmail || data.companyDomain)) {
      why_it_matters = `${why_it_matters} Note: we couldn't verify whether the sender's domain aligns with the claimed company.`;
    }
    // Note: header-auth reasons are NOT appended here — they're surfaced as
    // paired finding/explanation entries in `header_explanations` so the user
    // gets a clean per-pointer breakdown instead of a wall of text.

    // Build a STRICT short executive-style summary.
    // Hard rules: max ~6 sentences, lead with biggest danger, no subsystem
    // dump, no counts, no "why it matters", no next steps. The detailed
    // panels (Why it matters, Recommended next steps, Detailed signals)
    // already cover everything else.
    const summaryParts: string[] = [];

    // Sentence 1: score + level (one short line, no extras).
    summaryParts.push(`This recruiter check scored ${score} out of 100, which is ${level}.`);

    // Priority 1: direct payment / check / equipment / sensitive-info scam language.
    const paymentMatches = matchedScam.filter(
      (s) => s.id === "payment" || s.id === "check_equipment" || s.id === "gift_crypto" || s.id === "sensitive_docs",
    );
    const directScamFinding = osint.result.findings.find((f) => /directly describe/i.test(f));

    if (paymentMatches.length) {
      const kinds: string[] = [];
      if (paymentMatches.some((m) => m.id === "payment")) kinds.push("payment or fees");
      if (paymentMatches.some((m) => m.id === "check_equipment")) kinds.push("cashing checks or buying equipment");
      if (paymentMatches.some((m) => m.id === "gift_crypto")) kinds.push("gift cards or crypto");
      if (paymentMatches.some((m) => m.id === "sensitive_docs")) kinds.push("sensitive personal or financial details");
      summaryParts.push(`⚠️ This message asks for ${kinds.join(" / ")}, which legitimate recruiters do not do.`);
    }

    // Priority 2: direct public scam evidence about this exact subject.
    if (directScamFinding) {
      summaryParts.push(
        `⚠️ Public reports directly describe this company or recruiter as a scam — open the linked sources before responding.`,
      );
    }

    // Priority 3: identity / domain deception (only the strongest cases).
    // Affiliated institutional domains are NOT a deception signal — they're
    // legitimate same-organization-family relationships.
    if (domainCheck.status === "lookalike") {
      summaryParts.push("The sender's email domain looks like a deceptive lookalike of the claimed organization.");
    } else if (domainCheck.status === "mismatch") {
      summaryParts.push("The sender's email domain does not match the claimed company.");
    }

    // Priority 4: brief reassurance — only if no payment/direct-scam danger
    // was already surfaced. Keep to one compressed sentence.
    if (!paymentMatches.length && !directScamFinding) {
      const reassurances: string[] = [];
      if (matchedPositive.some((m) => m.id === "specific_role" || m.id === "natural_company_mention")) {
        reassurances.push("the message itself sounds professional");
      }
      if (domainIsAffiliated) {
        reassurances.push("the sender domain appears affiliated with the organization");
      } else if (domainIsPositive) {
        reassurances.push("the sender domain appears tied to the organization");
      }
      if (wayback.archive_history_status === "established" || rdap.ageBucket === "established") {
        reassurances.push("the company website appears established");
      }
      if (reassurances.length) {
        summaryParts.push(`Some details look legitimate: ${reassurances.slice(0, 2).join(" and ")}.`);
      } else if (matchedCaution.length && !matchedScam.length) {
        summaryParts.push("A few smaller details are worth a second look, but nothing strongly suggests a scam.");
      }
    } else {
      // Even with danger present, briefly acknowledge legit-looking signals
      // so users don't dismiss the warning as obviously bogus.
      if (matchedPositive.length > 0 || domainIsPositive || wayback.archive_history_status === "established") {
        summaryParts.push(
          "Some details look legitimate, but legitimate-looking accounts can still be hacked or impersonated.",
        );
      }
    }

    // Bottom line: one short closing sentence.
    if (paymentMatches.length || matchedScam.length >= 2) {
      summaryParts.push(
        "Bottom line: do not send money or share sensitive details, and verify the recruiter independently before continuing.",
      );
    } else if (directScamFinding || level === "Likely Scam" || level === "High") {
      summaryParts.push(
        "Bottom line: read the linked sources and verify the recruiter through official channels before responding.",
      );
    } else if (level === "Caution") {
      summaryParts.push(
        "Bottom line: proceed carefully and verify the recruiter through the official company website before sharing anything.",
      );
    } else {
      summaryParts.push(
        "Bottom line: this looks mostly legitimate, but a quick verification through official channels is still wise.",
      );
    }

    // Build per-finding "why this matters" bullets so the user gets a clean,
    // point-by-point breakdown instead of one big paragraph.
    const why_points: WhyPoint[] = [];
    if (domainIsNegative && domainCheck.finding && domainCheck.reason) {
      why_points.push({ finding: domainCheck.finding, why: domainCheck.reason, severity: "bad" });
    }
    for (const m of matchedScam) {
      why_points.push({ finding: m.finding, why: m.reason, severity: "bad" });
    }
    for (const m of matchedCaution) {
      why_points.push({ finding: m.finding, why: m.reason, severity: "caution" });
    }
    // Email-header explanations slot in here so red flags from the headers
    // appear right alongside the message-based findings.
    headerAuth.explanations.forEach((e) => why_points.push(e));
    if (domainIsPositive && domainCheck.finding && domainCheck.reason) {
      why_points.push({ finding: domainCheck.finding, why: domainCheck.reason, severity: "good" });
    }
    if (
      domainCheck.status === "unverifiable" &&
      domainCheck.finding &&
      domainCheck.reason &&
      (data.recruiterEmail || data.companyDomain)
    ) {
      why_points.push({ finding: domainCheck.finding, why: domainCheck.reason, severity: "info" });
    }
    for (const m of matchedPositive) {
      why_points.push({ finding: m.finding, why: m.reason, severity: "good" });
    }
    // OSINT (Tavily) findings, why-points, and next steps
    osint.result.findings.forEach((f) => findings.push(f));
    osint.whyPoints.forEach((p) => why_points.push(p));
    osint.nextSteps.forEach((s) => {
      if (next_steps.length < 6 && !next_steps.includes(s)) next_steps.push(s);
    });

    // RDAP findings, why-point, next step, and audio summary
    if (rdap.available) {
      findings.push(`Domain ${rdap.domain}: ${rdap.ageSummary}`);
    }
    if (rdapLookup.whyPoint) why_points.push(rdapLookup.whyPoint);
    if (rdapLookup.nextStep && next_steps.length < 6 && !next_steps.includes(rdapLookup.nextStep)) {
      next_steps.push(rdapLookup.nextStep);
    }
    // NOTE: subsystem details (RDAP/DNS/SafeBrowsing/CT/Wayback/recruiter
    // location/website traffic) are intentionally NOT pushed into summaryParts.
    // The Summary must stay short — those details belong in Why it Matters,
    // Recommended Next Steps, and Detailed Findings panels.

    // DNS findings, why-point, next step, and audio summary
    if (dns.available) {
      findings.push(`DNS for ${dns.domain}: ${dns.summary}`);
    }
    if (dnsLookup.whyPoint) why_points.push(dnsLookup.whyPoint);
    if (dnsLookup.nextStep && next_steps.length < 6 && !next_steps.includes(dnsLookup.nextStep)) {
      next_steps.push(dnsLookup.nextStep);
    }
    // (DNS subsystem details intentionally not pushed into summaryParts.)

    // Safe Browsing findings, why-point, next step, and audio summary
    if (safeBrowsing.safe_browsing_status === "flagged") {
      findings.push(safeBrowsing.safe_browsing_summary);
    }
    if (safeBrowsingLookup.whyPoint) why_points.push(safeBrowsingLookup.whyPoint);
    if (safeBrowsingLookup.nextStep && next_steps.length < 6 && !next_steps.includes(safeBrowsingLookup.nextStep)) {
      next_steps.push(safeBrowsingLookup.nextStep);
    }
    // (Safe Browsing subsystem details intentionally not pushed into summaryParts.)

    // CT findings, why-point, next step, and audio summary
    if (ct.available && ct.certificatesFound) {
      findings.push(`CT for ${ct.domain}: ${ct.summary}`);
    }
    if (ctLookup.whyPoint) why_points.push(ctLookup.whyPoint);
    if (ctLookup.nextStep && next_steps.length < 6 && !next_steps.includes(ctLookup.nextStep)) {
      next_steps.push(ctLookup.nextStep);
    }
    // (Certificate Transparency subsystem details intentionally not pushed into summaryParts.)

    // Wayback findings, why-point, next step, and audio summary
    if (wayback.available) {
      findings.push(`Web history for ${wayback.checked_url}: ${wayback.website_history_summary}`);
    }
    if (waybackLookup.whyPoint) why_points.push(waybackLookup.whyPoint);
    if (waybackLookup.nextStep && next_steps.length < 6 && !next_steps.includes(waybackLookup.nextStep)) {
      next_steps.push(waybackLookup.nextStep);
    }
    // (Wayback subsystem details intentionally not pushed into summaryParts.)

    // Recruiter public-location: contextual caution only. Country alone is
    // never proof of fraud, so we only nudge the score when other weak trust
    // signals are also present (caution-weight signals, header/domain issues,
    // OSINT scam mentions, etc.). Otherwise we surface it informationally.
    if (recruiterLocationLookup.whyPoint) why_points.push(recruiterLocationLookup.whyPoint);
    if (recruiterLocation.available && recruiterLocation.mismatch) {
      const otherWeakSignals =
        matchedCaution.length > 0 ||
        domainCheck.status === "unverifiable" ||
        domainCheck.status === "lookalike" ||
        domainCheck.status === "mismatch" ||
        domainCheck.status === "public_email" ||
        headerAuth.spf === "none" ||
        headerAuth.dkim === "none" ||
        headerAuth.dmarc === "none" ||
        osint.scoreDelta > 0 ||
        rdap.ageBucket === "very_new" ||
        rdap.ageBucket === "new" ||
        rdap.ageBucket === "young" ||
        dns.health === "thin" ||
        dns.health === "minimal" ||
        dns.health === "missing";
      if (otherWeakSignals) {
        score = Math.min(100, score + recruiterLocationLookup.scoreDelta);
      }
      // (Recruiter location detail intentionally not pushed into summaryParts.)
      findings.push(
        `Recruiter public location appears to be ${recruiterLocation.recruiter_public_location} — differs from ${recruiterLocation.hiring_context_label}.`,
      );
    }

    // Website traffic context: third-party estimates only. Same gating logic
    // as recruiter location — geo mismatch alone is never proof of fraud.
    if (websiteTrafficLookup.whyPoint) why_points.push(websiteTrafficLookup.whyPoint);
    // (Website traffic context intentionally not pushed into summaryParts.)
    if (websiteTraffic.geo_mismatch && websiteTrafficLookup.scoreDelta > 0) {
      const otherWeakSignals =
        matchedCaution.length > 0 ||
        domainCheck.status === "unverifiable" ||
        domainCheck.status === "lookalike" ||
        domainCheck.status === "mismatch" ||
        domainCheck.status === "public_email" ||
        osint.scoreDelta > 0 ||
        rdap.ageBucket === "very_new" ||
        rdap.ageBucket === "new" ||
        rdap.ageBucket === "young" ||
        dns.health === "thin" ||
        dns.health === "minimal" ||
        dns.health === "missing" ||
        wayback.archive_history_status === "thin" ||
        wayback.archive_history_status === "recent_only";
      if (otherWeakSignals) {
        score = Math.min(100, score + websiteTrafficLookup.scoreDelta);
      }
    }

    return {
      risk_score: score,
      risk_level: level,
      findings,
      why_it_matters,
      why_points,
      next_steps,
      audio_summary: summaryParts.join(" "),
      osint_summary: osint.result.summary,
      osint_findings: osint.result.findings,
      osint_links: osint.result.links,
      rdap,
      dns,
      safe_browsing: safeBrowsing,
      ct,
      wayback,
      recruiter_location: recruiterLocation,
      website_traffic: websiteTraffic,
    };
  });
