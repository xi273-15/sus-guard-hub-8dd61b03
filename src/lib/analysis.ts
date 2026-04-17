import { createServerFn } from "@tanstack/react-start";

export type AnalysisInput = {
  recruiterName?: string;
  recruiterEmail?: string;
  companyName?: string;
  companyDomain?: string;
  message?: string;
  headers?: string;
};

export type AnalysisResult = {
  risk_score: number;
  risk_level: "Low" | "Medium" | "High" | "Critical";
  findings: string[];
  why_it_matters: string;
  next_steps: string[];
  audio_summary: string;
};

export const analyzeRecruiter = createServerFn({ method: "POST" })
  .inputValidator((input: AnalysisInput) => input)
  .handler(async (): Promise<AnalysisResult> => {
    // Simulate processing latency
    await new Promise((r) => setTimeout(r, 900));

    return {
      risk_score: 72,
      risk_level: "High",
      findings: [
        "Recruiter email domain does not clearly match the claimed company.",
        "Message contains urgency language.",
        "No verification has been performed yet on domain age or email authentication.",
      ],
      why_it_matters:
        "This combination of signals can appear in recruiter scams, especially when the sender pressures the target to respond quickly.",
      next_steps: [
        "Verify the recruiter through the official company careers page.",
        "Do not send personal documents yet.",
        "Do not move the conversation to Telegram or WhatsApp.",
      ],
      audio_summary:
        "This recruiter appears high risk. We found urgency language and a possible mismatch between the sender and company identity. Verify through the official company website before sharing personal information.",
    };
  });
