import { createServerFn } from "@tanstack/react-start";

export type AnalysisInput = {
  recruiterName?: string;
  recruiterEmail?: string;
  companyName?: string;
  companyDomain?: string;
  message?: string;
  headers?: string;
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
  error?: string;
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
    weight: 12,
    finding: "Message uses urgency language (e.g. 'urgent', 'immediately', 'asap').",
    reason: "Scammers pressure targets to act fast so there is no time to verify the offer.",
    next_step: "Slow down. Legitimate recruiters are fine with you taking time to verify them.",
    test: (l) =>
      hasWord(l, ["urgent", "urgently", "immediately", "asap"]) ||
      hasAny(l, ["as soon as possible", "right away", "act now", "act fast"]),
  },
  {
    id: "offplatform",
    kind: "scam",
    weight: 18,
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
    weight: 20,
    finding: "Message requests a payment, fee, or deposit from you.",
    reason: "Real employers never ask candidates to pay for a job, training, or onboarding.",
    next_step: "Do not send any money. Any request for payment from a recruiter is a scam.",
    test: (l) =>
      hasAny(l, [
        "send payment",
        "pay a fee",
        "processing fee",
        "registration fee",
        "training fee",
        "onboarding fee",
        "wire transfer",
        "western union",
        "moneygram",
      ]),
  },
  {
    id: "check_equipment",
    kind: "scam",
    weight: 22,
    finding: "Message mentions cashing a check or buying equipment with funds you'll be sent.",
    reason: "This is the classic fake-check scam: the check bounces after you've already spent or forwarded the money.",
    next_step: "Do not deposit any check from this recruiter or buy equipment with funds they send you.",
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
      ]),
  },
  {
    id: "gift_crypto",
    kind: "scam",
    weight: 22,
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
    weight: 18,
    finding: "Message asks for sensitive personal info (SSN, ID, passport, or bank details) early in the process.",
    reason: "Real employers only collect this after a signed offer through an HR portal — not over chat or email.",
    next_step:
      "Do not share your SSN, ID, passport, or bank info until you have a verified offer through the official company portal.",
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

type DomainStatus = "match" | "subdomain" | "mismatch" | "lookalike" | "public_email" | "unverifiable";

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
    return {
      status: "lookalike",
      senderDomain,
      companyDomain,
      finding: `Recruiter email domain (${senderDomain}) looks like a lookalike of the claimed company domain (${companyRoot}).`,
      reason:
        "Lookalike domains (extra words, hyphens, or 1–2 character typos of the real company domain) are a classic impersonation tactic. A polished message does not change this.",
      next_step: `Do not reply on this address. Verify the recruiter through the official ${companyRoot} careers page or LinkedIn, and only respond to a genuine @${companyRoot} address.`,
      scoreDelta: 45,
      floor: 55,
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
      matches.slice(0, 2).forEach((r) =>
        allLinks.push({ title: r.title ?? r.url ?? "Result", url: r.url ?? "" }),
      );
    } else if (kind === "recruiter") {
      const legitMatches = results.filter((r) => {
        const text = `${r.title ?? ""} ${r.url ?? ""} ${r.content ?? ""}`.toLowerCase();
        return LEGIT_KEYWORDS.some((k) => text.includes(k));
      });
      recruiterLegitHits += legitMatches.length;
      results.slice(0, 2).forEach((r) =>
        allLinks.push({ title: r.title ?? r.url ?? "Result", url: r.url ?? "" }),
      );
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

  for (const ps of pendingScams) {
    const isDomainScam = ps.kind === "domain_scam";
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
      // Strong = the exact domain appears inside the result content/url AND the
      // result is clearly about fraud (not just a warning/impersonation advisory).
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
        scoreDelta += Math.min(15, 6 + ps.count * 3);
      } else {
        // Indirect / weak / possibly-impersonation evidence — soften the wording
        // and treat as minor caution rather than a major red flag.
        findings.push(
          `Scam-related public mentions were found near the domain ${ps.subject}, but context is limited.`,
        );
        whyPoints.push({
          finding: `Public results mention ${ps.subject} in scam-related discussions, though context is limited.`,
          why: "These results are cautionary, not proof that the domain itself is fraudulent. The mentions may reflect impersonation warnings, general advisories, or unrelated references rather than direct evidence that this address is malicious. Verify the recruiter through an official channel before sharing anything.",
          severity: "caution",
        });
        nextSteps.push(
          `Skim the linked sources to see whether they actually describe ${ps.subject} as malicious, or just mention it in passing.`,
        );
        // Small bump only when there are no strong legitimacy signals; if the
        // org looks legit, keep the overall risk essentially unchanged.
        scoreDelta += looksLikeRealOrg ? Math.min(3, 1 + Math.floor(ps.count / 2)) : Math.min(6, 2 + ps.count);
      }
    } else {
      // No legitimacy signals AND a company-name scam hit — keep cautionary
      // wording (we still don't want to call the org itself fraudulent).
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

    ps.matches.slice(0, 2).forEach((r) =>
      allLinks.push({ title: r.title ?? r.url ?? "Result", url: r.url ?? "" }),
    );
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
    error,
  };
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
  if (days < 30) return { bucket: "very_new", summary: `Registered ${days} day${days === 1 ? "" : "s"} ago — very recently created.` };
  if (days < 90) return { bucket: "new", summary: `Registered ${days} days ago — under 90 days old.` };
  if (days < 365) {
    const months = Math.max(1, Math.round(days / 30));
    return { bucket: "young", summary: `Registered about ${months} month${months === 1 ? "" : "s"} ago — under a year old.` };
  }
  const years = Math.floor(days / 365);
  return {
    bucket: "established",
    summary: `Registered about ${years} year${years === 1 ? "" : "s"} ago — an established domain.`,
  };
}

function buildRdapInterpretation(
  bucket: RdapAgeBucket,
  domain: string,
  companyName?: string,
): string {
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

async function runRdapLookup(input: {
  recruiterEmail?: string;
  companyName?: string;
}): Promise<{ result: RdapResult; scoreDelta: number; floor: number; whyPoint: WhyPoint | null; nextStep: string | null }> {
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
        ageSummary:
          "Skipped — recruiter is writing from a public mailbox provider, so domain age doesn't apply here.",
        interpretation:
          "Domain registration data isn't meaningful when the recruiter is using a public email provider like Gmail or Outlook. The domain alignment check above is the relevant signal.",
      },
      scoreDelta: 0,
      floor: 0,
      whyPoint: null,
      nextStep: null,
    };
  }

  const lookupDomain = rootDomain(senderDomain);
  const rdap = await fetchRdap(lookupDomain);
  if (!rdap) {
    return { result: emptyRdap(lookupDomain, "rdap_unavailable"), scoreDelta: 0, floor: 0, whyPoint: null, nextStep: null };
  }

  const events = rdap.events ?? [];
  const regEvent = events.find((e) => e.eventAction === "registration");
  const updEvent = events.find((e) => e.eventAction === "last changed" || e.eventAction === "last update of RDAP database");
  const registrationDate = regEvent?.eventDate ?? null;
  const lastUpdated = updEvent?.eventDate ?? null;
  const registrar = extractRegistrarName(rdap.entities);

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


export const analyzeRecruiter = createServerFn({ method: "POST" })
  .inputValidator((input: AnalysisInput) => input)
  .handler(async ({ data }): Promise<AnalysisResult> => {
    const message = (data.message ?? "").trim();
    const lower = message.toLowerCase();
    const domainCheck = analyzeDomainAlignment(data.recruiterEmail, data.companyDomain);

    // ---------- Tavily OSINT + RDAP (server-side only, in parallel) ----------
    const [osint, rdapLookup] = await Promise.all([
      runTavilyOsint({
        recruiterName: data.recruiterName,
        companyName: data.companyName,
        companyDomain: data.companyDomain,
      }),
      runRdapLookup({
        recruiterEmail: data.recruiterEmail,
        companyName: data.companyName,
      }),
    ]);
    const rdap = rdapLookup.result;
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
      const note = (
        severity: WhyPoint["severity"],
        finding: string,
        why: string,
        nextStep?: string,
      ) => {
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
      const dkimLikelyForwarderBreak = (dkimStatus === "fail") && dkimBodyHashFail && (dmarcLooksOk || compauthPass);

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
      if (
        result.spf === "unknown" &&
        result.dkim === "unknown" &&
        result.dmarc === "unknown"
      ) {
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
      const hasIssue = result.explanations.some(
        (e) => e.severity === "bad" || e.severity === "caution",
      );
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
        rdapLookup.scoreDelta > 0
      ) {
        noMsgScore = Math.min(
          85,
          15 +
            domainCheck.scoreDelta +
            authDelta +
            Math.max(0, osint.scoreDelta) +
            Math.max(0, rdapLookup.scoreDelta),
        );
      }
      if (osint.scoreDelta < 0) noMsgScore = Math.max(0, noMsgScore + osint.scoreDelta);
      if (rdapLookup.scoreDelta < 0) noMsgScore = Math.max(0, noMsgScore + rdapLookup.scoreDelta);
      if (domainCheck.floor > 0) noMsgScore = Math.max(noMsgScore, domainCheck.floor);
      if (authFloor > 0) noMsgScore = Math.max(noMsgScore, authFloor);
      if (rdapLookup.floor > 0) noMsgScore = Math.max(noMsgScore, rdapLookup.floor);
      osint.result.findings.forEach((f) => baseFindings.push(f));
      osint.nextSteps.forEach((s) => baseSteps.push(s));
      if (rdap.available) {
        baseFindings.push(`Domain ${rdap.domain}: ${rdap.ageSummary}`);
      }
      if (rdapLookup.nextStep) baseSteps.push(rdapLookup.nextStep);

      const noMsgLevel = levelFor(noMsgScore);

      const noMsgWhyPoints: WhyPoint[] = [];
      if (
        domainCheck.finding &&
        domainCheck.reason &&
        domainCheck.status !== "match" &&
        domainCheck.status !== "subdomain"
      ) {
        const sev: WhyPoint["severity"] =
          noMsgNegative ? "bad" : domainCheck.status === "unverifiable" ? "info" : "caution";
        noMsgWhyPoints.push({ finding: domainCheck.finding, why: domainCheck.reason, severity: sev });
      }
      headerAuth.explanations.forEach((e) => noMsgWhyPoints.push(e));
      osint.whyPoints.forEach((p) => noMsgWhyPoints.push(p));
      if (rdapLookup.whyPoint) noMsgWhyPoints.push(rdapLookup.whyPoint);

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
    score = Math.max(0, Math.min(100, Math.round(score)));
    const level = levelFor(score);

    const domainIsNegative =
      domainCheck.status === "mismatch" || domainCheck.status === "lookalike" || domainCheck.status === "public_email";
    const domainIsPositive = domainCheck.status === "match" || domainCheck.status === "subdomain";

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

    const summaryParts: string[] = [`This recruiter check scored ${score} out of 100, which is ${level}.`];
    if (matchedScam.length) {
      summaryParts.push(
        `We detected ${matchedScam.length} scam signal${matchedScam.length === 1 ? "" : "s"}: ${matchedScam
          .map((m) => m.finding.replace(/\.$/, ""))
          .join("; ")}.`,
      );
    } else if (matchedCaution.length) {
      summaryParts.push(
        `We didn't find strong scam wording, but ${matchedCaution.length} thing${matchedCaution.length === 1 ? "" : "s"} ${matchedCaution.length === 1 ? "is" : "are"} worth a second look: ${matchedCaution
          .map((m) => m.finding.replace(/\.$/, ""))
          .join("; ")}.`,
      );
    } else {
      summaryParts.push("We didn't find obvious scam wording.");
    }
    if (matchedPositive.length) {
      summaryParts.push(
        `On the positive side, we found ${matchedPositive.length} legitimacy signal${matchedPositive.length === 1 ? "" : "s"}: ${matchedPositive
          .map((m) => m.finding.replace(/\.$/, ""))
          .join("; ")}.`,
      );
    }
    if (domainIsNegative) {
      summaryParts.push(domainCheck.finding!);
    } else if (domainIsPositive) {
      summaryParts.push("The sender's email domain aligns with the claimed company.");
    } else if (domainCheck.status === "unverifiable" && domainCheck.finding && (data.recruiterEmail || data.companyDomain)) {
      summaryParts.push(domainCheck.finding);
    }
    // Email header summary
    if (headerAuth.explanations.length) {
      summaryParts.push(
        `Email header check: ${headerAuth.explanations
          .map((e) => e.finding.replace(/\.$/, ""))
          .join("; ")}.`,
      );
    }
    // OSINT / public web evidence
    if (osint.result.findings.length) {
      summaryParts.push(
        `Public web evidence: ${osint.result.summary} ${osint.result.findings
          .map((f) => f.replace(/\.$/, ""))
          .join("; ")}.`,
      );
    }
    // Why it matters context
    summaryParts.push(`Why this matters: ${why_it_matters}`);
    // Next steps — read all, not just the first
    const stepsForAudio = Array.from(stepSet).slice(0, 5);
    if (stepsForAudio.length) {
      summaryParts.push(
        `Recommended next steps: ${stepsForAudio
          .map((s, i) => `${i + 1}. ${s.replace(/\.$/, "")}`)
          .join(". ")}.`,
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
    if (rdap.available) {
      summaryParts.push(`Domain registration: ${rdap.ageSummary} ${rdap.interpretation}`);
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
    };
  });
