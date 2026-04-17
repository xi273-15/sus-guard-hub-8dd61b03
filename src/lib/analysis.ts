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

const hasAny = (text: string, terms: string[]) =>
  terms.some((t) => text.includes(t));

const hasWord = (text: string, words: string[]) =>
  words.some((w) => new RegExp(`\\b${w}\\b`, "i").test(text));

// ---------- Strong scam signals (raise score a lot) ----------
const SCAM_SIGNALS: Signal[] = [
  {
    id: "urgency",
    kind: "scam",
    weight: 12,
    finding: "Message uses urgency language (e.g. 'urgent', 'immediately', 'asap').",
    reason:
      "Scammers pressure targets to act fast so there is no time to verify the offer.",
    next_step:
      "Slow down. Legitimate recruiters are fine with you taking time to verify them.",
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
    next_step:
      "Refuse to move to Telegram, WhatsApp, or Signal for interviews. Ask for a company email or video call.",
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
        "send payment", "pay a fee", "processing fee", "registration fee",
        "training fee", "onboarding fee", "wire transfer", "western union", "moneygram",
      ]),
  },
  {
    id: "check_equipment",
    kind: "scam",
    weight: 22,
    finding: "Message mentions cashing a check or buying equipment with funds you'll be sent.",
    reason:
      "This is the classic fake-check scam: the check bounces after you've already spent or forwarded the money.",
    next_step:
      "Do not deposit any check from this recruiter or buy equipment with funds they send you.",
    test: (l) =>
      hasAny(l, [
        "cash the check", "cash this check", "deposit the check", "deposit this check",
        "purchase equipment", "buy equipment", "buy a laptop", "buy laptop",
        "purchase a laptop", "home office equipment", "office setup",
      ]),
  },
  {
    id: "gift_crypto",
    kind: "scam",
    weight: 22,
    finding: "Message mentions gift cards or cryptocurrency payments.",
    reason:
      "No legitimate employer pays salary or expenses in gift cards or crypto. This is a strong scam indicator.",
    next_step: "Do not buy gift cards or send crypto. Cut off contact if they insist.",
    test: (l) =>
      hasAny(l, [
        "gift card", "gift cards", "itunes card", "amazon card", "google play card",
        "bitcoin", "btc", "ethereum", "usdt", "crypto wallet", "cryptocurrency",
      ]),
  },
  {
    id: "sensitive_docs",
    kind: "scam",
    weight: 18,
    finding:
      "Message asks for sensitive personal info (SSN, ID, passport, or bank details) early in the process.",
    reason:
      "Real employers only collect this after a signed offer through an HR portal — not over chat or email.",
    next_step:
      "Do not share your SSN, ID, passport, or bank info until you have a verified offer through the official company portal.",
    test: (l) =>
      hasAny(l, [
        "social security", "ssn", "passport", "driver's license", "drivers license",
        "bank account", "routing number", "account number", "copy of your id", "photo of your id",
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
      hasAny(l, [
        "$5000 weekly", "$5,000 weekly", "earn up to",
        "weekly pay of $", "no experience required and earn",
      ]),
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
        "you have been hired", "you are hired", "you're hired",
        "congratulations you have been selected", "no interview",
        "without interview", "hired immediately",
      ]),
  },
  {
    id: "kindly",
    kind: "scam",
    weight: 5,
    finding: "Message uses scam-pattern wording like 'kindly'.",
    reason:
      "On its own this is mild, but 'kindly' combined with other red flags is common in recruiter scams.",
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
        "contract role", "remote opportunity", "great opportunity",
        "exciting opportunity", "job opportunity", "work from home opportunity",
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
    reason:
      "Mild pressure to respond fast isn't always a scam, but real recruiters usually give you time.",
    next_step: "It's fine to take a day or two to verify the company and recruiter before replying.",
    test: (l) =>
      hasAny(l, [
        "respond soon", "reply soon", "get back to me today", "get back to me asap",
        "let me know today", "reply today", "respond today",
      ]),
  },
  {
    id: "too_short",
    kind: "caution",
    weight: 8,
    finding: "Message is very short and lacks context about you, the role, or the company.",
    reason: "Real outreach usually references your background or a specific opening. One-liners often signal mass outreach.",
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
      const hasCompany = /\b(at|with|for)\s+[A-Z][A-Za-z0-9&.\- ]{2,}/.test(l) ||
        hasAny(l, ["our company", "our team", "our client"]);
      const hasContext = hasAny(l, RECRUITING_CONTEXT);
      return !hasRole && !hasCompany && !hasContext;
    },
  },
];

// ---------- Positive legitimacy signals (lower score) ----------
const ROLE_TERMS = [
  "engineer", "developer", "designer", "manager", "analyst", "scientist",
  "architect", "consultant", "specialist", "lead", "director", "intern",
  "marketing", "sales", "product manager", "data scientist", "software",
  "frontend", "backend", "full stack", "fullstack", "devops", "qa", "recruiter",
];

const RECRUITING_CONTEXT = [
  "your profile", "your background", "your experience", "your linkedin",
  "your github", "your resume", "your cv", "saw your", "came across your",
  "reached out", "open role", "open position", "hiring", "we're hiring",
  "job description", "job posting", "jd", "interview process", "hiring manager",
  "team is growing", "headcount",
];

const NEXT_STEP_TERMS = [
  "schedule a call", "schedule a chat", "book a call", "book some time",
  "calendly", "set up a call", "set up a chat", "30 minute call", "30-minute call",
  "introductory call", "intro call", "phone screen", "screening call",
  "video interview", "zoom", "google meet", "microsoft teams", "ms teams",
  "available next week", "available this week", "let me know your availability",
];

const PROFESSIONAL_SIGNOFFS = [
  "best regards", "kind regards", "regards,", "thanks,", "thank you,",
  "looking forward", "best,", "cheers,", "sincerely,",
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

function buildWhyItMatters(
  level: RiskLevel,
  scamCount: number,
  cautionCount: number,
  positiveCount: number,
): string {
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

export const analyzeRecruiter = createServerFn({ method: "POST" })
  .inputValidator((input: AnalysisInput) => input)
  .handler(async ({ data }): Promise<AnalysisResult> => {
    const message = (data.message ?? "").trim();
    const lower = message.toLowerCase();

    if (!message) {
      return {
        risk_score: 0,
        risk_level: "Low",
        findings: ["No message text was provided to analyze."],
        why_it_matters:
          "Without the recruiter's message we can't check for scam wording. Paste their full message to get a real risk assessment.",
        next_steps: [
          "Paste the recruiter's full message into the message field and run the analysis again.",
        ],
        audio_summary:
          "No message was provided. Paste the recruiter's full message to get a real risk assessment.",
      };
    }

    const matchedScam: Signal[] = [];
    const matchedCaution: Signal[] = [];
    const matchedPositive: Signal[] = [];

    let score = 10; // neutral base

    for (const s of SCAM_SIGNALS) {
      if (s.test(lower, message)) {
        matchedScam.push(s);
        score += s.weight;
      }
    }
    for (const s of CAUTION_SIGNALS) {
      if (s.test(lower, message)) {
        matchedCaution.push(s);
        score += s.weight;
      }
    }
    for (const s of POSITIVE_SIGNALS) {
      if (s.test(lower, message)) {
        matchedPositive.push(s);
        score -= s.weight;
      }
    }

    // Stacking penalty: many independent scam flags compound
    if (matchedScam.length >= 3) score += 6;
    if (matchedScam.length >= 5) score += 6;

    // Stacking bonus: multiple positives without scam signals reads very legitimate
    if (matchedScam.length === 0 && matchedPositive.length >= 3) score -= 6;

    score = Math.max(0, Math.min(100, Math.round(score)));
    const level = levelFor(score);

    // Build findings: scam first, then caution, then a single combined positive line if any
    const findings: string[] = [];
    for (const m of matchedScam) findings.push(m.finding);
    for (const m of matchedCaution) findings.push(m.finding);
    if (matchedPositive.length) {
      const positiveSummary = `Legitimacy signals detected: ${matchedPositive
        .map((p) => p.finding.replace(/\.$/, "").replace(/^Message /, ""))
        .join("; ")}.`;
      findings.push(positiveSummary);
    }
    if (!findings.length) {
      findings.push("No common scam wording was detected in the message text.");
    }

    // Next steps: prioritize scam steps, then caution, then a positive verification step
    const stepSet = new Set<string>();
    for (const m of matchedScam) stepSet.add(m.next_step);
    for (const m of matchedCaution) stepSet.add(m.next_step);
    if (!matchedScam.length && !matchedCaution.length) {
      defaultNextSteps(level).forEach((s) => stepSet.add(s));
    }
    if (matchedPositive.length && stepSet.size < 5) {
      stepSet.add("Even with positive signals, confirm the role exists on the company's official careers page.");
    }
    const next_steps = Array.from(stepSet).slice(0, 5);

    const why_it_matters = buildWhyItMatters(
      level,
      matchedScam.length,
      matchedCaution.length,
      matchedPositive.length,
    );

    const summaryParts: string[] = [
      `This recruiter message scored ${score} out of 100, which is ${level}.`,
    ];
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
    summaryParts.push(`Recommended next step: ${next_steps[0]}`);

    return {
      risk_score: score,
      risk_level: level,
      findings,
      why_it_matters,
      next_steps,
      audio_summary: summaryParts.join(" "),
    };
  });
