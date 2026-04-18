import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { SpeakButton } from "@/components/speak-button";
import { HeadersHelpDialog } from "@/components/headers-help-dialog";
import { ArrowLeft } from "lucide-react";
import {
  Shield,
  ShieldAlert,
  Search,
  FileText,
  Mail,
  Building2,
  Globe,
  User,
  AlertTriangle,
  ListChecks,
  Info,
  Sparkles,
  Loader2,
  CheckCircle2,
  Mailbox,
  Globe2,
  ExternalLink,
  CalendarClock,
  Network,
  ShieldCheck,
  ScrollText,
  History,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { ThemeToggle } from "@/components/theme-toggle";
import type {
  RdapResult,
  DnsResult,
  SafeBrowsingResult,
  CtResult,
  WaybackResult,
} from "@/lib/analysis";
import { analyzeRecruiter, type AnalysisResult } from "@/lib/analysis";
import { FloatingAudioAssistant } from "@/components/floating-audio-assistant";

export const Route = createFileRoute("/")({
  component: Index,
  head: () => ({
    meta: [
      { title: "Suscruit — Recruiter scam detection for job seekers" },
      {
        name: "description",
        content:
          "Suscruit checks recruiter emails, domains, and messages for scam signals — and explains the results in plain language.",
      },
      { property: "og:title", content: "Suscruit — Recruiter scam detection" },
      {
        property: "og:description",
        content:
          "Check a recruiter in seconds. Suscruit flags suspicious emails, domains, and messages so you can apply with confidence.",
      },
    ],
  }),
});

type FormState = {
  recruiterName: string;
  recruiterEmail: string;
  companyName: string;
  companyDomain: string;
  message: string;
  headers: string;
};

const initialForm: FormState = {
  recruiterName: "",
  recruiterEmail: "",
  companyName: "",
  companyDomain: "",
  message: "",
  headers: "",
};

function riskLevelClasses(level: AnalysisResult["risk_level"]) {
  switch (level) {
    case "Low":
      return "text-emerald-500 border-emerald-500/30 bg-emerald-500/10";
    case "Caution":
      return "text-amber-500 border-amber-500/30 bg-amber-500/10";
    case "High":
      return "text-orange-500 border-orange-500/30 bg-orange-500/10";
    case "Likely Scam":
      return "text-red-500 border-red-500/30 bg-red-500/10";
  }
}

function Index() {
  const [form, setForm] = useState<FormState>(initialForm);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stage, setStage] = useState<"input" | "results">("input");

  const update = (k: keyof FormState) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await analyzeRecruiter({ data: form });
      setResult(res);
      setStage("results");
      requestAnimationFrame(() => {
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    } catch (err) {
      console.error(err);
      setError("Something went wrong while analyzing. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const resetToInput = () => {
    setStage("input");
    setResult(null);
    setError(null);
    requestAnimationFrame(() => window.scrollTo({ top: 0, behavior: "smooth" }));
  };

  const introScript =
    "Welcome to Suscruit. I help you check if a recruiter who contacted you might be a scam. Just fill in what you know — the recruiter's name and email, the company they claim to represent, their message, and if you have it, the raw email headers. Tap the small speaker icon next to any field to hear what it's for. When you're ready, hit Analyze and I'll walk you through what we found.";


  return (
    <div className="relative min-h-screen bg-background text-foreground">
      {/* Ambient background */}
      <div
        className="pointer-events-none fixed inset-x-0 top-0 -z-10 h-[520px]"
        style={{ background: "var(--gradient-hero)", opacity: 0.55 }}
        aria-hidden
      />
      <div
        className="pointer-events-none fixed -top-40 left-1/2 -z-10 h-[460px] w-[760px] -translate-x-1/2 rounded-full blur-3xl"
        style={{ background: "var(--gradient-primary)", opacity: 0.1 }}
        aria-hidden
      />

      {/* Top nav */}
      <nav className="sticky top-0 z-30 border-b border-border/60 bg-background/70 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <span
              className="inline-flex h-10 w-10 items-center justify-center rounded-xl shadow-[var(--shadow-glow)]"
              style={{ background: "var(--gradient-primary)" }}
            >
              <Shield className="h-5 w-5 text-primary-foreground" />
            </span>
            <div className="flex flex-col">
              <span className="text-xl font-bold tracking-tight">Suscruit</span>
              <span className="text-[11px] font-medium text-muted-foreground">Protecting job seekers</span>
            </div>
            <span className="ml-2 hidden rounded-md border border-border/60 bg-muted/40 px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground sm:inline">
              Beta
            </span>
          </div>
          <ThemeToggle />
        </div>
      </nav>

      {/* Hero */}
      <header className="mx-auto max-w-6xl px-6 pt-12 pb-10 sm:pt-16 sm:pb-14">
        <div className="inline-flex items-center gap-2 rounded-full border border-border/60 bg-background/60 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
          </span>
          Recruiter scam check
        </div>
        <h1 className="mt-5 max-w-3xl text-4xl font-bold tracking-tight sm:text-5xl lg:text-6xl leading-[1.15]">
          Spot suspicious recruiters{" "}
          <span className="text-gradient-cyber">before they scam you.</span>
        </h1>
        <p className="mt-5 max-w-2xl text-lg leading-relaxed text-muted-foreground sm:text-xl">
          Paste a recruiter's email or message and Suscruit checks it for the most common
          hiring scam signals — then explains what we found in plain language.
        </p>
      </header>

      <main className="mx-auto max-w-3xl px-6 pb-20">
        {stage === "input" && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">

            <Card className="border-border/60 bg-card/85 shadow-[var(--shadow-elegant)] backdrop-blur">
              <CardHeader className="border-b border-border/60">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <CardTitle className="flex items-center gap-2 text-lg sm:text-xl">
                      <Search className="h-5 w-5 text-primary" />
                      Check a recruiter
                    </CardTitle>
                    <CardDescription className="mt-1.5 text-sm sm:text-base">
                      Fill in what you have — even a single field helps.
                    </CardDescription>
                  </div>
                  <span className="hidden rounded-md border border-border/60 bg-background/60 px-2 py-1 text-[11px] font-medium text-muted-foreground sm:inline">
                    Step 1 of 1
                  </span>
                </div>
              </CardHeader>

              <form onSubmit={onSubmit}>
                <CardContent className="space-y-8 pt-6">
                  {/* Section: Recruiter */}
                  <FormSection
                    eyebrow="01"
                    title="Recruiter"
                    description="Who reached out to you?"
                  >
                    <div className="grid gap-5 sm:grid-cols-2">
                      <Field
                        id="recruiterName"
                        label="Recruiter name"
                        icon={<User className="h-3.5 w-3.5" />}
                        speakText="The full name the recruiter used to contact you. We use it to check if it matches their email and the company they claim to represent."
                        speakKey="field:recruiterName"
                      >
                        <Input
                          id="recruiterName"
                          placeholder="e.g. Jane Doe"
                          value={form.recruiterName}
                          onChange={update("recruiterName")}
                        />
                      </Field>
                      <Field
                        id="recruiterEmail"
                        label="Recruiter email"
                        icon={<Mail className="h-3.5 w-3.5" />}
                        required
                        speakText="The email address the recruiter contacted you from. We check the domain, its registration history, mail infrastructure, and reputation."
                        speakKey="field:recruiterEmail"
                      >
                        <Input
                          id="recruiterEmail"
                          type="email"
                          placeholder="jane@company.com"
                          value={form.recruiterEmail}
                          onChange={update("recruiterEmail")}
                        />
                      </Field>
                    </div>

                  </FormSection>

                  <Separator className="bg-border/60" />

                  {/* Section: Company */}
                  <FormSection
                    eyebrow="02"
                    title="Company"
                    description="Who do they say they work for?"
                  >
                    <div className="grid gap-5 sm:grid-cols-2">
                      <Field
                        id="companyName"
                        label="Company name"
                        icon={<Building2 className="h-3.5 w-3.5" />}
                        speakText="The company the recruiter says they work for. We compare it against their email domain and website to spot mismatches."
                        speakKey="field:companyName"
                      >
                        <Input
                          id="companyName"
                          placeholder="Acme Inc."
                          value={form.companyName}
                          onChange={update("companyName")}
                        />
                      </Field>
                      <Field
                        id="companyDomain"
                        label="Company website"
                        icon={<Globe className="h-3.5 w-3.5" />}
                        speakText="The website of the company they mention. We check its history, certificate record, and whether Google Safe Browsing has flagged it."
                        speakKey="field:companyDomain"
                      >
                        <Input
                          id="companyDomain"
                          placeholder="acme.com"
                          value={form.companyDomain}
                          onChange={update("companyDomain")}
                        />
                      </Field>
                    </div>

                  </FormSection>

                  <Separator className="bg-border/60" />

                  {/* Section: Evidence */}
                  <FormSection
                    eyebrow="03"
                    title="Evidence"
                    description="The more context you share, the more accurate the result."
                  >
                    <Field
                      id="message"
                      label="The message they sent"
                      icon={<FileText className="h-3.5 w-3.5" />}
                      speakText="Paste the recruiter's full message, DM, or job offer here. We scan it for common scam wording, urgency, and red-flag patterns."
                      speakKey="field:message"
                    >
                      <Textarea
                        id="message"
                        placeholder="Paste the recruiter's message, DM, or job offer here..."
                        className="min-h-[140px] resize-y"
                        value={form.message}
                        onChange={update("message")}
                      />
                    </Field>

                    <Field
                      id="headers"
                      label="Email headers"
                      icon={<FileText className="h-3.5 w-3.5" />}
                      hint="Optional · Paste the raw email headers if you have them — improves accuracy."
                      speakText="The raw technical headers of the email. They reveal who actually sent it, regardless of what the From line says. Tap the question mark to learn how to find them in Gmail."
                      speakKey="field:headers"
                      trailingAction={<HeadersHelpDialog />}
                    >
                      <Textarea
                        id="headers"
                        placeholder="Received: from mail.example.com ..."
                        className="min-h-[140px] resize-y font-mono text-xs"
                        value={form.headers}
                        onChange={update("headers")}
                      />
                    </Field>

                  </FormSection>

                  {error && (
                    <div
                      role="alert"
                      className="rounded-md border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive"
                    >
                      {error}
                    </div>
                  )}
                </CardContent>

                <div className="flex flex-col-reverse items-stretch justify-between gap-3 border-t border-border/60 px-6 py-4 sm:flex-row sm:items-center">
                  <p className="text-xs text-muted-foreground">
                    We never store your data. Analysis runs on your request only.
                  </p>
                  <Button
                    type="submit"
                    size="lg"
                    disabled={loading}
                    className="text-primary-foreground shadow-[var(--shadow-glow)] hover:opacity-95 transition-opacity"
                    style={{ background: "var(--gradient-primary)" }}
                  >
                    {loading ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Analyzing…
                      </>
                    ) : (
                      <>
                        <Sparkles className="h-4 w-4" />
                        Analyze recruiter
                      </>
                    )}
                  </Button>
                </div>
              </form>
            </Card>
          </div>
        )}


        {stage === "results" && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
          <div className="flex items-center justify-between gap-3">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={resetToInput}
              className="gap-2"
            >
              <ArrowLeft className="h-4 w-4" />
              Check another recruiter
            </Button>
            <span className="text-xs text-muted-foreground">Analysis results</span>
          </div>

          {/* Risk summary */}
          <Card className="overflow-hidden border-border/60 bg-card/85 shadow-[var(--shadow-elegant)] backdrop-blur">
            <div
              className="h-1 w-full"
              style={{ background: "var(--gradient-primary)" }}
              aria-hidden
            />
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Risk score
                </CardTitle>
                <span
                  className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                    result
                      ? riskLevelClasses(result.risk_level)
                      : "border-border/60 bg-background/60 text-muted-foreground"
                  }`}
                >
                  {loading ? "Analyzing…" : result ? result.risk_level : "Pending"}
                </span>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-baseline gap-2">
                <span
                  className={`text-5xl font-bold tracking-tight ${
                    result ? "text-foreground" : "text-foreground/40"
                  }`}
                >
                  {loading ? "…" : result ? result.risk_score : "—"}
                </span>
                <span className="text-sm text-muted-foreground">/ 100</span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full bg-primary transition-all duration-500"
                  style={{ width: `${result ? result.risk_score : 0}%` }}
                />
              </div>
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>Low</span>
                <span>Medium</span>
                <span>High</span>
                <span>Critical</span>
              </div>
            </CardContent>
          </Card>

          {/* Detailed results */}
          <section aria-labelledby="results-heading" className="mt-4 space-y-5">
          <div className="flex items-end justify-between gap-4">
            <div>
              <h2
                id="results-heading"
                className="text-2xl font-semibold tracking-tight"
              >
                Detailed analysis
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {loading
                  ? "Analyzing the recruiter…"
                  : result
                    ? "Here's what we found."
                    : "Run a check above to populate this section."}
              </p>
            </div>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <ResultCard
              icon={<ShieldAlert className="h-4 w-4" />}
              title="Risk score"
              description="See exactly how concerning this recruiter looks."
              loading={loading}
              hasData={!!result}
            >
              {result && (
                <div className="flex items-baseline gap-3">
                  <span className="text-4xl font-bold tracking-tight">
                    {result.risk_score}
                  </span>
                  <span className="text-sm text-muted-foreground">/ 100</span>
                </div>
              )}
            </ResultCard>

            <ResultCard
              icon={<AlertTriangle className="h-4 w-4" />}
              title="Risk level"
              description="An at-a-glance label for how concerned you should be."
              loading={loading}
              hasData={!!result}
            >
              {result && (
                <span
                  className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-semibold ${riskLevelClasses(result.risk_level)}`}
                >
                  <AlertTriangle className="h-4 w-4" />
                  {result.risk_level}
                </span>
              )}
            </ResultCard>

            <ResultCard
              icon={<ListChecks className="h-4 w-4" />}
              title="Findings"
              description="Signals from the email, domain, and message."
              loading={loading}
              hasData={!!result}
            >
              {result && (
                <ul className="space-y-2">
                  {result.findings.map((f, i) => (
                    <li key={i} className="flex gap-2 text-sm leading-relaxed">
                      <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              )}
            </ResultCard>

            <ResultCard
              icon={<Info className="h-4 w-4" />}
              title="Why it matters"
              description="What each finding means for you, in plain English."
              loading={loading}
              hasData={!!result}
            >
              {result && (
                <div className="space-y-3">
                  {result.why_points.length > 0 ? (
                    <ul className="space-y-2.5">
                      {result.why_points.map((p, i) => {
                        const sev = p.severity;
                        const dot =
                          sev === "good"
                            ? "bg-emerald-500"
                            : sev === "bad"
                              ? "bg-red-500"
                              : sev === "caution"
                                ? "bg-amber-500"
                                : "bg-muted-foreground";
                        return (
                          <li key={i} className="flex gap-2.5 text-sm leading-relaxed">
                            <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${dot}`} />
                            <span>
                              <span className="font-medium text-foreground">{p.finding}</span>{" "}
                              <span className="text-muted-foreground">— {p.why}</span>
                            </span>
                          </li>
                        );
                      })}
                    </ul>
                  ) : (
                    <p className="text-sm leading-relaxed text-foreground/90">
                      {result.why_it_matters}
                    </p>
                  )}
                </div>
              )}
            </ResultCard>
          </div>

          <ResultCard
            icon={<Shield className="h-4 w-4" />}
            title="Recommended next steps"
            description="Clear, practical actions to verify the recruiter or protect yourself."
            full
            loading={loading}
            hasData={!!result}
          >
            {result && (
              <ul className="space-y-2.5">
                {result.next_steps.map((s, i) => (
                  <li key={i} className="flex gap-2.5 text-sm leading-relaxed">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-primary" />
                    <span>{s}</span>
                  </li>
                ))}
              </ul>
            )}
          </ResultCard>

          <ResultCard
            icon={<Globe2 className="h-4 w-4" />}
            title="Public web evidence"
            description="What public search results say about this recruiter, company, or domain. Powered by Tavily."
            full
            loading={loading}
            hasData={!!result}
          >
            {result && (
              <div className="space-y-4">
                <p className="text-sm leading-relaxed text-foreground/90">{result.osint_summary}</p>
                {result.osint_findings.length > 0 && (
                  <ul className="space-y-2">
                    {result.osint_findings.map((f, i) => (
                      <li key={i} className="flex gap-2 text-sm leading-relaxed">
                        <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                        <span>{f}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {result.osint_links.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                      Relevant public links
                    </p>
                    <ul className="space-y-1.5">
                      {result.osint_links.map((l, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm leading-relaxed">
                          <ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary/80" />
                          <a
                            href={l.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="break-all text-primary underline-offset-4 hover:underline"
                          >
                            {l.title}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </ResultCard>

          <ResultCard
            icon={<CalendarClock className="h-4 w-4" />}
            title="Domain registration"
            description="When the recruiter's email domain was registered, and what that means. Powered by RDAP."
            full
            loading={loading}
            hasData={!!result}
          >
            {result && <RdapCardBody rdap={result.rdap} />}
          </ResultCard>

          <ResultCard
            icon={<Network className="h-4 w-4" />}
            title="DNS and email infrastructure"
            description="Whether the recruiter's email domain has normal mail (MX), authentication (SPF/DMARC), and web (A/AAAA) records."
            full
            loading={loading}
            hasData={!!result}
          >
            {result && <DnsCardBody dns={result.dns} />}
          </ResultCard>

          <ResultCard
            icon={<ShieldCheck className="h-4 w-4" />}
            title="Site reputation"
            description="Whether the company website is currently flagged by Google Safe Browsing for malware, phishing, or other harmful content."
            full
            loading={loading}
            hasData={!!result}
          >
            {result && <SafeBrowsingCardBody safeBrowsing={result.safe_browsing} />}
          </ResultCard>

          <ResultCard
            icon={<ScrollText className="h-4 w-4" />}
            title="Certificate history"
            description="Public TLS certificate issuance history for the recruiter's email domain (Certificate Transparency logs)."
            full
            loading={loading}
            hasData={!!result}
          >
            {result && <CtCardBody ct={result.ct} />}
          </ResultCard>

          <ResultCard
            icon={<History className="h-4 w-4" />}
            title="Website history"
            description="How long the company website has been visible in the Internet Archive Wayback Machine."
            full
            loading={loading}
            hasData={!!result}
          >
            {result && <WaybackCardBody wayback={result.wayback} />}
          </ResultCard>
          </section>
        </div>
        )}

        <footer className="mt-16 border-t border-border/60 pt-8 pb-6 text-center text-sm text-muted-foreground">
          <p className="font-medium">Suscruit</p>
          <p className="mt-1">Built to protect job seekers</p>
        </footer>
      </main>

      {/* Floating accessibility audio assistant */}
      <FloatingAudioAssistant
        summary={result?.audio_summary}
        introScript={introScript}
        autoPlayIntro={stage === "input" && !result}
      />
    </div>
  );
}

function FormSection({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-5">
      <div className="flex items-baseline gap-3">
        <span className="text-sm font-bold tracking-widest text-primary/90">
          {eyebrow}
        </span>
        <div>
          <h3 className="text-base font-semibold text-foreground">{title}</h3>
          {description && (
            <p className="text-sm text-muted-foreground">{description}</p>
          )}
        </div>
      </div>
      {children}
    </section>
  );
}

function Field({
  id,
  label,
  icon,
  hint,
  required,
  speakText,
  speakKey,
  trailingAction,
  children,
}: {
  id: string;
  label: string;
  icon?: React.ReactNode;
  hint?: string;
  required?: boolean;
  speakText?: string;
  speakKey?: string;
  trailingAction?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <Label
          htmlFor={id}
          className="flex items-center gap-1.5 text-sm font-medium text-foreground"
        >
          {icon && <span className="text-primary/80">{icon}</span>}
          {label}
          {required && <span className="text-primary">*</span>}
        </Label>
        <div className="flex items-center gap-0.5">
          {speakText && speakKey && (
            <SpeakButton text={speakText} trackKey={speakKey} />
          )}
          {trailingAction}
        </div>
      </div>
      {children}
      {hint && <p className="text-xs leading-relaxed text-muted-foreground">{hint}</p>}
    </div>
  );
}



function ResultCard({
  icon,
  title,
  description,
  full,
  loading,
  hasData,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  full?: boolean;
  loading?: boolean;
  hasData?: boolean;
  children?: React.ReactNode;
}) {
  const status = loading ? "Analyzing" : hasData ? "Ready" : "Pending";
  return (
    <Card
      className={`group border-border/60 bg-card/60 backdrop-blur transition-colors hover:border-primary/40 ${
        full ? "md:col-span-2" : ""
      }`}
    >
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between gap-3">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold">
            <span
              className="inline-flex h-7 w-7 items-center justify-center rounded-md text-primary"
              style={{ backgroundColor: "color-mix(in oklab, var(--primary) 14%, transparent)" }}
            >
              {icon}
            </span>
            {title}
          </CardTitle>
          <span className="rounded-full border border-border/60 bg-background/60 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            {status}
          </span>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        {loading ? (
          <div className="space-y-2">
            <div className="h-3 w-3/4 animate-pulse rounded bg-muted" />
            <div className="h-3 w-1/2 animate-pulse rounded bg-muted" />
            <div className="h-3 w-2/3 animate-pulse rounded bg-muted" />
          </div>
        ) : hasData ? (
          <div>{children}</div>
        ) : (
          <div className="flex h-20 items-center justify-center rounded-md border border-dashed border-border/60 bg-background/40 text-xs text-muted-foreground">
            No data yet
          </div>
        )}
        <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

function RdapCardBody({ rdap }: { rdap: RdapResult }) {
  if (!rdap.available) {
    return (
      <div className="space-y-3">
        <p className="text-sm leading-relaxed text-foreground/90">{rdap.ageSummary}</p>
        <p className="text-sm leading-relaxed text-muted-foreground">{rdap.interpretation}</p>
      </div>
    );
  }

  const bucketStyles: Record<RdapResult["ageBucket"], string> = {
    very_new: "text-red-500 border-red-500/30 bg-red-500/10",
    new: "text-orange-500 border-orange-500/30 bg-orange-500/10",
    young: "text-amber-500 border-amber-500/30 bg-amber-500/10",
    established: "text-emerald-500 border-emerald-500/30 bg-emerald-500/10",
    unknown: "border-border/60 bg-background/60 text-muted-foreground",
  };
  const bucketLabel: Record<RdapResult["ageBucket"], string> = {
    very_new: "Very new",
    new: "Recently registered",
    young: "Under 1 year",
    established: "Established",
    unknown: "Unknown",
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <RdapField label="Checked domain" value={rdap.domain ?? "—"} mono />
        <RdapField label="Registrar" value={rdap.registrar ?? "Unknown"} />
        <RdapField label="Registered" value={formatDate(rdap.registrationDate)} />
        <RdapField label="Last updated" value={formatDate(rdap.lastUpdated)} />
      </div>

      <div className="flex items-center gap-2">
        <span
          className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${bucketStyles[rdap.ageBucket]}`}
        >
          {bucketLabel[rdap.ageBucket]}
        </span>
        <span className="text-sm text-foreground/90">{rdap.ageSummary}</span>
      </div>

      <p className="text-sm leading-relaxed text-muted-foreground">{rdap.interpretation}</p>

      {(rdap.nameservers.length > 0 || rdap.statuses.length > 0) && (
        <div className="grid gap-3 sm:grid-cols-2">
          {rdap.nameservers.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Nameservers
              </p>
              <ul className="mt-1 space-y-0.5 font-mono text-xs text-foreground/80">
                {rdap.nameservers.map((n, i) => (
                  <li key={i} className="break-all">{n}</li>
                ))}
              </ul>
            </div>
          )}
          {rdap.statuses.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Domain status
              </p>
              <ul className="mt-1 flex flex-wrap gap-1.5">
                {rdap.statuses.map((s, i) => (
                  <li
                    key={i}
                    className="rounded-md border border-border/60 bg-background/60 px-2 py-0.5 text-[11px] text-muted-foreground"
                  >
                    {s}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function RdapField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-md border border-border/60 bg-background/40 px-3 py-2">
      <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</p>
      <p className={`mt-0.5 text-sm text-foreground/90 ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}

function DnsCardBody({ dns }: { dns: DnsResult }) {
  if (!dns.available) {
    return (
      <div className="space-y-3">
        <p className="text-sm leading-relaxed text-foreground/90">{dns.summary}</p>
        <p className="text-sm leading-relaxed text-muted-foreground">{dns.interpretation}</p>
      </div>
    );
  }

  const healthStyles: Record<DnsResult["health"], string> = {
    healthy: "text-emerald-500 border-emerald-500/30 bg-emerald-500/10",
    thin: "text-amber-500 border-amber-500/30 bg-amber-500/10",
    minimal: "text-orange-500 border-orange-500/30 bg-orange-500/10",
    missing: "text-red-500 border-red-500/30 bg-red-500/10",
    skipped: "border-border/60 bg-background/60 text-muted-foreground",
    unknown: "border-border/60 bg-background/60 text-muted-foreground",
  };
  const healthLabel: Record<DnsResult["health"], string> = {
    healthy: "Normal infrastructure",
    thin: "Thin infrastructure",
    minimal: "Minimal — no MX",
    missing: "No mail or web records",
    skipped: "Skipped",
    unknown: "Unknown",
  };

  const records: { label: string; present: boolean }[] = [
    { label: "MX (mail)", present: dns.hasMx },
    { label: "SPF", present: dns.hasSpf },
    { label: "DMARC", present: dns.hasDmarc },
    { label: "A / AAAA (web)", present: dns.hasA || dns.hasAaaa },
  ];

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <RdapField label="Checked domain" value={dns.domain ?? "—"} mono />
        <div className="rounded-md border border-border/60 bg-background/40 px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Status</p>
          <span
            className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${healthStyles[dns.health]}`}
          >
            {healthLabel[dns.health]}
          </span>
        </div>
      </div>

      <ul className="grid gap-2 sm:grid-cols-2">
        {records.map((r) => (
          <li
            key={r.label}
            className="flex items-center justify-between rounded-md border border-border/60 bg-background/40 px-3 py-2 text-sm"
          >
            <span className="text-foreground/90">{r.label}</span>
            <span
              className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                r.present
                  ? "text-emerald-500 border-emerald-500/30 bg-emerald-500/10"
                  : "text-red-500 border-red-500/30 bg-red-500/10"
              }`}
            >
              {r.present ? "Present" : "Missing"}
            </span>
          </li>
        ))}
      </ul>

      <p className="text-sm leading-relaxed text-muted-foreground">{dns.interpretation}</p>

      {dns.mxRecords.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">MX records</p>
          <ul className="mt-1 space-y-0.5 font-mono text-xs text-foreground/80">
            {dns.mxRecords.map((m, i) => (
              <li key={i} className="break-all">{m}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function SafeBrowsingCardBody({ safeBrowsing }: { safeBrowsing: SafeBrowsingResult }) {
  const statusStyles: Record<SafeBrowsingResult["safe_browsing_status"], string> = {
    flagged: "text-rose-500 border-rose-500/30 bg-rose-500/10",
    not_flagged: "text-emerald-500 border-emerald-500/30 bg-emerald-500/10",
    unknown: "border-border/60 bg-background/60 text-muted-foreground",
  };
  const statusLabel: Record<SafeBrowsingResult["safe_browsing_status"], string> = {
    flagged: "Flagged as unsafe",
    not_flagged: "Not currently flagged",
    unknown: "Unknown",
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <RdapField label="Checked URL" value={safeBrowsing.checked_url ?? "—"} mono />
        <div className="rounded-md border border-border/60 bg-background/40 px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Safe Browsing status
          </p>
          <span
            className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${statusStyles[safeBrowsing.safe_browsing_status]}`}
          >
            {statusLabel[safeBrowsing.safe_browsing_status]}
          </span>
        </div>
      </div>

      {safeBrowsing.safe_browsing_findings.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Threat categories
          </p>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {safeBrowsing.safe_browsing_findings.map((f, i) => (
              <li
                key={i}
                className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 font-mono text-[10px] text-rose-500"
              >
                {f}
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="text-sm leading-relaxed text-muted-foreground">
        {safeBrowsing.safe_browsing_summary}
      </p>
    </div>
  );
}

function CtCardBody({ ct }: { ct: CtResult }) {
  if (!ct.available) {
    return (
      <div className="space-y-3">
        <p className="text-sm leading-relaxed text-foreground/90">{ct.summary}</p>
        <p className="text-sm leading-relaxed text-muted-foreground">{ct.interpretation}</p>
      </div>
    );
  }

  const historyStyles: Record<CtResult["history"], string> = {
    very_recent: "text-rose-500 border-rose-500/30 bg-rose-500/10",
    recent: "text-amber-500 border-amber-500/30 bg-amber-500/10",
    normal: "text-foreground/80 border-border/60 bg-background/60",
    established: "text-emerald-500 border-emerald-500/30 bg-emerald-500/10",
    none: "text-amber-500 border-amber-500/30 bg-amber-500/10",
    unknown: "border-border/60 bg-background/60 text-muted-foreground",
  };
  const historyLabel: Record<CtResult["history"], string> = {
    very_recent: "Very recent issuance",
    recent: "Recent issuance",
    normal: "Normal history",
    established: "Established history",
    none: "No certificates found",
    unknown: "Unknown",
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <RdapField label="Checked domain" value={ct.domain ?? "—"} mono />
        <div className="rounded-md border border-border/60 bg-background/40 px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            History
          </p>
          <span
            className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${historyStyles[ct.history]}`}
          >
            {historyLabel[ct.history]}
          </span>
        </div>
        <RdapField
          label="Certificates found"
          value={ct.certificatesFound ? String(ct.totalCertificates) : "0"}
        />
        <RdapField label="Most recent issuance" value={formatDate(ct.mostRecentIssuance)} />
      </div>

      {ct.suspiciousSubdomains.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Suspicious-looking subdomains
          </p>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {ct.suspiciousSubdomains.map((s, i) => (
              <li
                key={i}
                className="rounded-full border border-rose-500/30 bg-rose-500/10 px-2 py-0.5 font-mono text-[10px] text-rose-500 break-all"
              >
                {s}
              </li>
            ))}
          </ul>
        </div>
      )}

      {ct.uniqueSubdomains.length > 0 && (
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Subdomains in CT logs
          </p>
          <ul className="mt-1 flex flex-wrap gap-1.5 font-mono text-[11px] text-foreground/80">
            {ct.uniqueSubdomains.map((s, i) => (
              <li
                key={i}
                className="rounded-md border border-border/60 bg-background/40 px-2 py-0.5 break-all"
              >
                {s}
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="text-sm leading-relaxed text-muted-foreground">{ct.interpretation}</p>
    </div>
  );
}

function WaybackCardBody({ wayback }: { wayback: WaybackResult }) {
  if (!wayback.available) {
    return (
      <div className="space-y-3">
        <p className="text-sm leading-relaxed text-foreground/90">{wayback.website_history_summary}</p>
        <p className="text-sm leading-relaxed text-muted-foreground">{wayback.interpretation}</p>
      </div>
    );
  }

  const statusStyles: Record<WaybackResult["archive_history_status"], string> = {
    established: "text-emerald-500 border-emerald-500/30 bg-emerald-500/10",
    moderate: "text-foreground/80 border-border/60 bg-background/60",
    thin: "text-amber-500 border-amber-500/30 bg-amber-500/10",
    recent_only: "text-rose-500 border-rose-500/30 bg-rose-500/10",
    none: "text-amber-500 border-amber-500/30 bg-amber-500/10",
    unknown: "border-border/60 bg-background/60 text-muted-foreground",
  };
  const statusLabel: Record<WaybackResult["archive_history_status"], string> = {
    established: "Long-standing history",
    moderate: "Moderate history",
    thin: "Thin history",
    recent_only: "Very recent only",
    none: "No archive history",
    unknown: "Unknown",
  };

  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <RdapField label="Checked URL" value={wayback.checked_url ?? "—"} mono />
        <div className="rounded-md border border-border/60 bg-background/40 px-3 py-2">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Archive history
          </p>
          <span
            className={`mt-1 inline-block rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${statusStyles[wayback.archive_history_status]}`}
          >
            {statusLabel[wayback.archive_history_status]}
          </span>
        </div>
        <RdapField label="First seen" value={formatDate(wayback.first_seen_archive_date)} />
        <RdapField label="Latest snapshot" value={formatDate(wayback.most_recent_archive_date)} />
        {wayback.snapshot_count !== null && (
          <RdapField label="Snapshots" value={String(wayback.snapshot_count)} />
        )}
      </div>

      <p className="text-sm leading-relaxed text-muted-foreground">{wayback.interpretation}</p>
    </div>
  );
}
