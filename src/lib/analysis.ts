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

type Signal = {
  id: string;
  weight: number;
  finding: string;
  reason: string;
  next_step: string;
  test: (lower: string, original: string) => boolean;
};

const hasAny = (text: string, terms: string[]) =>
  terms.some((t) => text.includes(t));

const hasWord = (text: string, words: string[]) =>
  words.some((w) => new RegExp(`\\b${w}\\b`, "i").test(text));

const SIGNALS: Signal[] = [
  {
    id: "urgency",
    weight: 12,
    finding:
      "Message uses urgency language (e.g. 'urgent', 'immediately', 'asap').",
    reason:
      "Scammers pressure targets to act fast so there is no time to verify the offer.",
    next_step:
      "Slow down. Legitimate recruiters are fine with you taking time to verify them.",
    test: (l) =>
      hasWord(l, ["urgent", "urgently", "immediately", "asap", "right away"]) ||
      hasAny(l, ["as soon as possible", "right away", "act now", "act fast"]),
  },
  {
    id: "offplatform",
    weight: 18,
    finding:
      "Message asks you to move the conversation to Telegram, WhatsApp, or Signal.",
    reason:
      "Real recruiters interview on company tools (Zoom, Teams, Google Meet). Off-platform chats hide the scammer's identity.",
    next_step:
      "Refuse to move to Telegram, WhatsApp, or Signal for interviews. Ask for a company email or video call.",
    test: (l) => hasAny(l, ["telegram", "whatsapp", "signal app", "signal chat"]) ||
      /\bsignal\b/.test(l) && hasAny(l, ["chat", "message", "interview", "contact"]),
  },
  {
    id: "payment",
    weight: 20,
    finding: "Message requests a payment, fee, or deposit from you.",
    reason:
      "Real employers never ask candidates to pay for a job, training, or onboarding.",
    next_step:
      "Do not send any money. Any request for payment from a recruiter is a scam.",
    test: (l) =>
      hasAny(l, [
        "send payment",
        "pay a fee",
        "processing fee",
        "registration fee",
        "training fee",
        "onboarding fee",
        "deposit",
        "wire transfer",
        "western union",
        "moneygram",
      ]),
  },
  {
    id: "check_equipment",
    weight: 22,
    finding:
      "Message mentions cashing a check or buying equipment with funds you'll be sent.",
    reason:
      "This is the classic fake-check scam: the check bounces after you've already spent or forwarded the money.",
    next_step:
      "Do not deposit any check from this recruiter or buy equipment with funds they send you.",
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
    weight: 22,
    finding: "Message mentions gift cards or cryptocurrency payments.",
    reason:
      "No legitimate employer pays salary or expenses in gift cards or crypto. This is a strong scam indicator.",
    next_step:
      "Do not buy gift cards or send crypto. Cut off contact if they insist.",
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
    weight: 18,
    finding:
      "Message asks for sensitive personal info (SSN, ID, passport, or bank details) early in the process.",
    reason:
      "Real employers only collect this after a signed offer through an HR portal — not over chat or email.",
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
    weight: 10,
    finding: "Message advertises unusually high pay for limited work.",
    reason:
      "Suspiciously high compensation is a lure. Real salaries match the role and market.",
    next_step:
      "Compare the offered pay to the role on Glassdoor or LinkedIn. If it's far above market, treat it as a red flag.",
    test: (l) =>
      /\$\s?\d{2,3}\s?\/?\s?(hr|hour|hourly)/.test(l) &&
      /\$\s?([2-9]\d|\d{3})/.test(l) ||
      hasAny(l, [
        "$5000 weekly",
        "$5,000 weekly",
        "earn up to",
        "weekly pay of $",
        "no experience required and earn",
      ]),
  },
  {
    id: "generic",
    weight: 8,
    finding:
      "Message is generic — no specific role, team, or details about you.",
    reason:
      "Mass-sent scam messages avoid specifics so they can be reused on many targets.",
    next_step:
      "Ask for the exact job title, team, hiring manager, and a link to the official job posting.",
    test: (l, original) => {
      if (original.length < 40) return true;
      const generic = ["dear candidate", "dear applicant", "dear sir/madam", "dear sir or madam"];
      return hasAny(l, generic);
    },
  },
  {
    id: "kindly",
    weight: 6,
    finding: "Message uses scam-pattern wording like 'kindly'.",
    reason:
      "On its own this is mild, but 'kindly' combined with other red flags is common in recruiter scams.",
    next_step:
      "Treat as a minor signal — weigh it together with the other findings.",
    test: (l) => /\bkindly\b/.test(l),
  },
  {
    id: "no_interview",
    weight: 10,
    finding:
      "Message offers a job or next step without any real interview process.",
    reason:
      "Real employers interview candidates. Skipping straight to 'you're hired' or 'send your details' is a scam pattern.",
    next_step:
      "Insist on a video interview with an identifiable employee before sharing anything.",
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
];

function levelFor(score: number): RiskLevel {
  if (score >= 75) return "Likely Scam";
  if (score >= 50) return "High";
  if (score >= 25) return "Caution";
  return "Low";
}

function buildWhyItMatters(level: RiskLevel, hits: number): string {
  switch (level) {
    case "Likely Scam":
      return `We found ${hits} strong scam signal${hits === 1 ? "" : "s"} in this message. The pattern closely matches known recruiter scams — treat any further contact as fraudulent until proven otherwise.`;
    case "High":
      return `We found ${hits} concerning signal${hits === 1 ? "" : "s"}. This combination commonly appears in recruiter scams, especially when the sender pressures you or asks for sensitive info.`;
    case "Caution":
      return `We found ${hits} signal${hits === 1 ? "" : "s"} worth a second look. The message isn't clearly a scam, but it has wording or requests that real recruiters usually avoid.`;
    case "Low":
      return "We didn't find obvious scam signals in this message. That doesn't guarantee it's safe — always verify the recruiter through the official company website before sharing personal info.";
  }
}

function defaultNextSteps(level: RiskLevel): string[] {
  const base = [
    "Verify the recruiter through the official company careers page.",
    "Do not send personal documents or ID until you've verified the company.",
  ];
  if (level === "Low") {
    return [
      ...base,
      "If anything feels off later, run another check before responding.",
    ];
  }
  return base;
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

    const matched: Signal[] = [];
    let score = 5; // low base score
    for (const s of SIGNALS) {
      if (s.test(lower, message)) {
        matched.push(s);
        score += s.weight;
      }
    }

    // Stacking penalty: many independent red flags compound
    if (matched.length >= 3) score += 5;
    if (matched.length >= 5) score += 5;

    score = Math.max(0, Math.min(100, Math.round(score)));
    const level = levelFor(score);

    const findings = matched.length
      ? matched.map((m) => m.finding)
      : ["No common scam wording was detected in the message text."];

    const next_steps = matched.length
      ? Array.from(new Set(matched.map((m) => m.next_step))).slice(0, 5)
      : defaultNextSteps(level);

    const why_it_matters = matched.length
      ? matched.map((m) => m.reason)[0] +
        (matched.length > 1
          ? ` Combined with ${matched.length - 1} other signal${matched.length - 1 === 1 ? "" : "s"}, this raises the overall risk.`
          : "")
      : buildWhyItMatters(level, 0);

    const audio_summary =
      `This recruiter message scored ${score} out of 100, which is ${level}. ` +
      (matched.length
        ? `We detected ${matched.length} scam signal${matched.length === 1 ? "" : "s"}, including: ${matched
            .slice(0, 3)
            .map((m) => m.finding.replace(/\.$/, ""))
            .join("; ")}. ` + `Recommended next step: ${next_steps[0]}`
        : "We didn't find obvious scam wording, but always verify the recruiter through the official company website before sharing personal information.");

    return {
      risk_score: score,
      risk_level: level,
      findings,
      why_it_matters: matched.length ? why_it_matters : buildWhyItMatters(level, 0),
      next_steps,
      audio_summary,
    };
  });
