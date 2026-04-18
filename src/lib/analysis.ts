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

export type AnalysisResult = {
  risk_score: number;
  risk_level: RiskLevel;
  findings: string[];
  why_it_matters: string;
  next_steps: string[];
  audio_summary: string;
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

export const analyzeRecruiter = createServerFn({ method: "POST" })
  .inputValidator((input: AnalysisInput) => input)
  .handler(async ({ data }): Promise<AnalysisResult> => {
    const message = (data.message ?? "").trim();
    const lower = message.toLowerCase();
    const domainCheck = analyzeDomainAlignment(data.recruiterEmail, data.companyDomain);
    console.log("INPUT DATA:", data);
    console.log("DOMAIN CHECK:", domainCheck);
    console.log("HEADERS:", data.headers);
    type HeaderAuthCheck = {
      spf: "pass" | "fail" | "softfail" | "none" | "unknown";
      dkim: "pass" | "fail" | "none" | "unknown";
      dmarc: "pass" | "fail" | "none" | "unknown";
      findings: string[];
      reasons: string[];
      nextSteps: string[];
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

      // SPF
      if (spfStatus === "pass") {
        result.spf = "pass";
      } else if (spfStatus === "softfail" || spfStatus === "neutral") {
        result.spf = "softfail";
        result.findings.push("The email's sender check (SPF) only partially passed — the company didn't fully confirm this email came from them.");
        result.reasons.push("Think of SPF like a guest list at the door. A 'softfail' means the sender's name isn't clearly on the company's approved list, so the email might not really be from who it says it is.");
        result.nextSteps.push("Ask the recruiter to resend the message from their official company email address.");
        result.scoreDelta += 10;
        result.floor = Math.max(result.floor, 15);
      } else if (spfStatus === "fail" || spfStatus === "hardfail") {
        result.spf = "fail";
        result.findings.push("The email failed the sender check (SPF) — the company says this email did NOT come from their servers.");
        result.reasons.push("This is like someone showing up claiming to be from a company, but that company's official 'guest list' says they never sent them. It's a strong sign the sender is faking their identity.");
        result.nextSteps.push("Don't trust this sender. Go to the company's real website and contact them directly to check.");
        result.scoreDelta += 18;
        result.floor = Math.max(result.floor, 25);
      } else if (spfStatus === "none") {
        result.spf = "none";
        result.findings.push("No sender check (SPF) was found in the email — there's no proof of where it really came from.");
        result.reasons.push("Legitimate companies usually set up SPF so you can confirm their emails are real. Without it, it's much easier for a scammer to pretend to be them.");
        result.nextSteps.push("Ask the recruiter to send the message from the official company email, or verify them another way.");
        result.scoreDelta += 6;
      }

      // DKIM
      // Common false-positive: a forwarder, mailing list, or security gateway
      // (Proofpoint, Mimecast, university filters, etc.) rewrote the body, which
      // breaks the original DKIM body hash even though the email is legitimate.
      // Telltale signs: "body hash did not verify" AND DMARC still passes
      // and/or Outlook's compauth says pass.
      const dkimBodyHashFail = /dkim=fail[^;]*body hash/i.test(raw);
      const compauthPass = /compauth=pass/i.test(lower);
      const dmarcLooksOk = dmarcStatus === "pass" || dmarcStatus === "bestguesspass";
      const dkimLikelyForwarderBreak = (dkimStatus === "fail") && dkimBodyHashFail && (dmarcLooksOk || compauthPass);

      if (dkimStatus === "pass") {
        result.dkim = "pass";
      } else if (dkimLikelyForwarderBreak) {
        // Not a clean pass, but not a red flag either — give the user context
        // so they can decide for themselves.
        result.dkim = "pass";
        result.findings.push("The email's digital 'wax seal' (DKIM) didn't match exactly, but the company's anti-impersonation check (DMARC) still passed. This is usually normal — but not always.");
        result.reasons.push("Most of the time this happens for innocent reasons: a mailing list, an email forwarder, or a company security filter slightly changed the message on its way to you, which breaks the original seal even though the sender is real. In rare cases a scammer can also cause this by replaying or tweaking a real email. Because DMARC still passed here, it leans toward legitimate — but you should still sanity-check the sender if anything else feels off (urgent tone, unexpected links, requests for money or personal info, or a reply-to address that doesn't match the sender).");
        result.nextSteps.push("If the message itself looks normal, you can usually trust it. If anything feels off, confirm with the sender through a channel you already trust (their official website, a known phone number, or an existing email thread) — don't just reply to this email.");
        result.scoreDelta += 4;
        result.floor = Math.max(result.floor, 8);
      } else if (dkimStatus === "fail" || dkimStatus === "permerror") {
        result.dkim = "fail";
        result.findings.push("The email's digital signature (DKIM) failed — the message may have been faked or changed.");
        result.reasons.push("Real companies put a digital 'wax seal' on their emails. If the seal is broken or doesn't match, the email was either tampered with or wasn't really sent by that company.");
        result.nextSteps.push("Treat this email as suspicious and contact the company through their official website to confirm.");
        result.scoreDelta += 16;
        result.floor = Math.max(result.floor, 25);
      } else if (dkimStatus === "none") {
        result.dkim = "none";
        result.findings.push("The email has no digital signature (DKIM) — there's no way to confirm it wasn't tampered with.");
        result.reasons.push("Without that 'wax seal,' you can't be sure the email is genuine or that no one changed it before it reached you.");
        result.nextSteps.push("Confirm the recruiter is real by reaching out through the company's official website.");
        result.scoreDelta += 6;
      }

      // DMARC
      if (dmarcStatus === "pass" || dmarcStatus === "bestguesspass") {
        result.dmarc = "pass";
      } else if (dmarcStatus === "fail") {
        result.dmarc = "fail";
        result.findings.push("The email failed the company's anti-impersonation check (DMARC) — a strong warning sign of a fake or spoofed email.");
        result.reasons.push("DMARC is the company's own rule that says 'only real emails from us should pass.' When it fails, it usually means someone is trying to impersonate the company to trick you.");
        result.nextSteps.push("Do not trust this sender. Go to the company's official careers page and contact them directly instead.");
        result.scoreDelta += 22;
        result.floor = Math.max(result.floor, 35);
      } else if (dmarcStatus === "none") {
        result.dmarc = "none";
        result.findings.push("The company doesn't have anti-impersonation protection (DMARC) set up for this email — making it easier for scammers to fake.");
        result.reasons.push("Without DMARC, scammers can more easily send emails that look like they're from this company. You can't rely on the sender's name alone.");
        result.nextSteps.push("Be careful and double-check the recruiter through a separate, trusted channel — not by replying to this email.");
        result.scoreDelta += 8;
      }

      // Outlook-specific: compauth (composite authentication). reason codes 000/001 = fail.
      const compauth = lower.match(/compauth=([a-z]+)(?:\s+reason=(\d+))?/);
      if (compauth) {
        const verdict = compauth[1];
        if (verdict === "fail") {
          result.findings.push("Outlook's overall trust check (compauth) failed — Microsoft's own systems flagged this email as likely impersonation.");
          result.reasons.push("Outlook combines all the sender checks into one final verdict. A 'fail' here means Microsoft itself doesn't believe this email really came from who it claims.");
          result.nextSteps.push("Do not reply or click any links. Verify the recruiter through the company's official website.");
          result.scoreDelta += 15;
          result.floor = Math.max(result.floor, 30);
        } else if (verdict === "softpass" || verdict === "none") {
          result.findings.push("Outlook couldn't fully confirm the sender's identity (compauth was not a clear pass).");
          result.reasons.push("Microsoft wasn't able to fully verify this email. It's not an automatic red flag, but you shouldn't trust it on looks alone.");
          result.scoreDelta += 5;
        }
      }

      // If we still know absolutely nothing, surface that so the user knows the
      // headers were received but unreadable (e.g. they pasted only the body).
      if (
        result.spf === "unknown" &&
        result.dkim === "unknown" &&
        result.dmarc === "unknown"
      ) {
        result.findings.push("We couldn't find sender authentication info (SPF, DKIM, or DMARC) in the headers you pasted.");
        result.reasons.push("Most real emails from Gmail, Outlook, Yahoo, or Apple Mail include an 'Authentication-Results' line that proves where the email came from. If it's missing, you may have pasted only part of the headers — or the email skipped these checks, which is unusual for legitimate companies.");
        result.nextSteps.push("In your email app, open the message and choose 'Show original' (Gmail), 'View message source' (Outlook/Yahoo), or 'View → Message → All Headers' (Apple Mail), then paste the full headers.");
        result.scoreDelta += 4;
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
      if (domainCheck.scoreDelta > 0 || authDelta > 0) {
        noMsgScore = Math.min(85, 15 + domainCheck.scoreDelta + authDelta);
      }
      if (domainCheck.floor > 0) noMsgScore = Math.max(noMsgScore, domainCheck.floor);
      if (authFloor > 0) noMsgScore = Math.max(noMsgScore, authFloor);

      const noMsgLevel = levelFor(noMsgScore);

      return {
        risk_score: noMsgScore,
        risk_level: noMsgLevel,
        findings: baseFindings,
        why_it_matters: noMsgNegative
          ? `${domainCheck.reason} Paste the recruiter's full message to get a complete risk assessment — but note that a polished message would not cancel a sender/company domain mismatch.`
          : "Without the recruiter's message we can't check for scam wording. Paste their full message to get a real risk assessment.",
        next_steps: baseSteps,
        audio_summary: noMsgNegative
          ? `${domainCheck.finding} Paste the recruiter's full message to get a complete risk assessment.`
          : "No message was provided. Paste the recruiter's full message to get a real risk assessment.",
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
    score = Math.max(0, Math.min(100, Math.round(score)));
    const level = levelFor(score);
    console.log("FINAL SCORE:", {
      score,
      level,
      domainStatus: domainCheck.status,
      domainDelta: domainCheck.scoreDelta,
      domainFloor: domainCheck.floor,
      headerAuthDelta: headerAuth.scoreDelta,
      headerAuthFloor: headerAuth.floor,
    });

    const domainIsNegative =
      domainCheck.status === "mismatch" || domainCheck.status === "lookalike" || domainCheck.status === "public_email";
    const domainIsPositive = domainCheck.status === "match" || domainCheck.status === "subdomain";

    const findings: string[] = [];
    if (domainIsNegative && domainCheck.finding) findings.push(domainCheck.finding);
    for (const m of matchedScam) findings.push(m.finding);
    for (const m of matchedCaution) findings.push(m.finding);
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
    if (headerAuth.reasons.length) {
      why_it_matters = `${why_it_matters} ${headerAuth.reasons.join(" ")}`;
    }

    const summaryParts: string[] = [`This recruiter check scored ${score} out of 100, which is ${level}.`];
    if (matchedScam.length) {
      summaryParts.push(
        `We detected ${matchedScam.length} scam signal${matchedScam.length === 1 ? "" : "s"}, including: ${matchedScam
          .slice(0, 3)
          .map((m) => m.finding.replace(/\.$/, ""))
          .join("; ")}.`,
      );
    } else if (matchedCaution.length) {
      summaryParts.push(
        `We didn't find strong scam wording, but ${matchedCaution.length} thing${matchedCaution.length === 1 ? "" : "s"} ${matchedCaution.length === 1 ? "is" : "are"} worth a second look.`,
      );
    } else {
      summaryParts.push("We didn't find obvious scam wording.");
    }
    if (matchedPositive.length) {
      summaryParts.push(
        `On the positive side, we found ${matchedPositive.length} legitimacy signal${matchedPositive.length === 1 ? "" : "s"}.`,
      );
    }
    if (domainIsNegative) {
      summaryParts.push(domainCheck.finding!);
    } else if (domainIsPositive) {
      summaryParts.push("The sender's email domain aligns with the claimed company.");
    }
    if (next_steps[0]) summaryParts.push(`Recommended next step: ${next_steps[0]}`);

    return {
      risk_score: score,
      risk_level: level,
      findings,
      why_it_matters,
      next_steps,
      audio_summary: summaryParts.join(" "),
    };
  });
