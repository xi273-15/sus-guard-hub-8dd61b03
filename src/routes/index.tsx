import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { SpeakButton } from "@/components/speak-button";
import { HeadersHelpDialog } from "@/components/headers-help-dialog";
import { RiskOverview } from "@/components/results/risk-overview";
import { InteractiveTrio } from "@/components/results/interactive-trio";
import { CategoryTile } from "@/components/results/category-tile";
import { CategoryModal } from "@/components/results/category-modal";
import { FindingSection } from "@/components/results/finding-section";
import {
  splitOsint,
  emailStats,
  companyStats,
  recruiterStats,
  emailVoiceText,
  companyVoiceText,
  recruiterVoiceText,
} from "@/lib/categorize-findings";
import { ArrowLeft } from "lucide-react";
import {
  Shield,
  Search,
  FileText,
  Mail,
  Building2,
  Globe,
  User,
  Sparkles,
  Loader2,
  ExternalLink,
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
  roleLocation: string;
  message: string;
  headers: string;
};

const initialForm: FormState = {
  recruiterName: "",
  recruiterEmail: "",
  companyName: "",
  companyDomain: "",
  roleLocation: "",
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

      <main className={`mx-auto px-6 pb-20 ${stage === "results" ? "max-w-6xl" : "max-w-3xl"}`}>
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
                    <Field
                      id="roleLocation"
                      label="Job / role location"
                      icon={<Globe className="h-3.5 w-3.5" />}
                      hint="Optional · e.g. 'Berlin', 'Remote-EU', 'San Francisco'. We compare the recruiter's public location to this."
                      speakText="Where the role is supposed to be based. We use this to compare against the recruiter's likely public location."
                      speakKey="field:roleLocation"
                    >
                      <Input
                        id="roleLocation"
                        placeholder="e.g. Berlin or Remote-EU"
                        value={form.roleLocation}
                        onChange={update("roleLocation")}
                      />
                    </Field>

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


        {stage === "results" && result && (
          <ResultsView result={result} input={form} onReset={resetToInput} />
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

function ResultsView({
  result,
  input,
  onReset,
}: {
  result: AnalysisResult;
  input: FormState;
  onReset: () => void;
}) {
  const [openCategory, setOpenCategory] = useState<
    "email" | "company" | "recruiter" | null
  >(null);

  const split = useMemo(
    () => splitOsint(result, input.recruiterName, input.companyName, input.companyDomain),
    [result, input.recruiterName, input.companyName, input.companyDomain],
  );

  const eStats = useMemo(() => emailStats(result), [result]);
  const cStats = useMemo(() => companyStats(result, split), [result, split]);
  const rStats = useMemo(
    () => recruiterStats(input.recruiterName, split),
    [input.recruiterName, split],
  );

  const tagline = useMemo(() => {
    const all = [eStats, cStats, rStats];
    const good = all.reduce((s, x) => s + x.good, 0);
    const caution = all.reduce((s, x) => s + x.caution, 0);
    const bad = all.reduce((s, x) => s + x.bad, 0);
    const parts: string[] = [];
    if (good) parts.push(`${good} positive signal${good > 1 ? "s" : ""}`);
    if (caution) parts.push(`${caution} caution${caution > 1 ? "s" : ""}`);
    if (bad) parts.push(`${bad} red flag${bad > 1 ? "s" : ""}`);
    return parts.length
      ? `${parts.join(" · ")} across email, company, and recruiter checks.`
      : "Analysis complete — explore the categories below for details.";
  }, [eStats, cStats, rStats]);

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-300">
      {/* Header */}
      <div className="flex items-center justify-between gap-3">
        <Button type="button" variant="outline" size="sm" onClick={onReset} className="gap-2">
          <ArrowLeft className="h-4 w-4" />
          Check another recruiter
        </Button>
        <span className="text-xs uppercase tracking-[0.2em] text-muted-foreground">
          Analysis results
        </span>
      </div>

      {/* Tier 1 — Hero */}
      <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <RiskOverview result={result} tagline={tagline} />
        <InteractiveTrio result={result} />
      </div>

      {/* Tier 2 — Category tiles */}
      <section aria-labelledby="categories-heading" className="space-y-4">
        <div>
          <h2
            id="categories-heading"
            className="text-xl font-semibold tracking-tight sm:text-2xl"
          >
            Detailed signals
          </h2>
          <p className="mt-1 text-sm text-muted-foreground">
            Tap a card to dive into the findings behind the score.
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <CategoryTile
            icon={<Mail className="h-5 w-5" />}
            title="Email findings"
            subtitle="Sender identity, authentication & infrastructure"
            stats={eStats}
            onClick={() => setOpenCategory("email")}
          />
          <CategoryTile
            icon={<Building2 className="h-5 w-5" />}
            title="Company / domain"
            subtitle="Website history, reputation & registration"
            stats={cStats}
            onClick={() => setOpenCategory("company")}
          />
          <CategoryTile
            icon={<User className="h-5 w-5" />}
            title="Recruiter"
            subtitle="Public information about the person"
            stats={rStats}
            onClick={() => setOpenCategory("recruiter")}
          />
        </div>
      </section>

      {/* Modals */}
      <CategoryModal
        open={openCategory === "email"}
        onOpenChange={(o) => !o && setOpenCategory(null)}
        icon={<Mail className="h-4 w-4" />}
        title="Email findings"
        voiceText={emailVoiceText(result)}
        voiceKey="results:email-modal"
      >
        <FindingSection title="DNS & email infrastructure">
          <DnsCardBody dns={result.dns} />
        </FindingSection>
        <FindingSection title="Sender domain registration">
          <RdapCardBody rdap={result.rdap} />
        </FindingSection>
      </CategoryModal>

      <CategoryModal
        open={openCategory === "company"}
        onOpenChange={(o) => !o && setOpenCategory(null)}
        icon={<Building2 className="h-4 w-4" />}
        title="Company & domain findings"
        voiceText={companyVoiceText(result, split)}
        voiceKey="results:company-modal"
      >
        {(split.company.findings.length > 0 || split.company.links.length > 0) && (
          <FindingSection title="Public web evidence">
            {split.company.findings.length > 0 && (
              <ul className="space-y-2">
                {split.company.findings.map((f, i) => (
                  <li key={i} className="flex gap-2 text-sm leading-relaxed">
                    <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
            )}
            {split.company.links.length > 0 && (
              <ul className="mt-3 space-y-1.5">
                {split.company.links.map((l, i) => (
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
            )}
          </FindingSection>
        )}
        <FindingSection title="Website history (Wayback Machine)">
          <WaybackCardBody wayback={result.wayback} />
        </FindingSection>
        <FindingSection title="Site reputation (Safe Browsing)">
          <SafeBrowsingCardBody safeBrowsing={result.safe_browsing} />
        </FindingSection>
        <FindingSection title="Certificate history (CT logs)">
          <CtCardBody ct={result.ct} />
        </FindingSection>
      </CategoryModal>

      <CategoryModal
        open={openCategory === "recruiter"}
        onOpenChange={(o) => !o && setOpenCategory(null)}
        icon={<User className="h-4 w-4" />}
        title="Recruiter / individual findings"
        voiceText={recruiterVoiceText(input.recruiterName, split)}
        voiceKey="results:recruiter-modal"
      >
        <FindingSection title="Who reached out">
          <div className="space-y-1 text-sm">
            <p>
              <span className="text-muted-foreground">Name:</span>{" "}
              <span className="font-medium text-foreground">
                {input.recruiterName || "Not provided"}
              </span>
            </p>
            <p>
              <span className="text-muted-foreground">Email:</span>{" "}
              <span className="font-mono text-xs text-foreground/90">
                {input.recruiterEmail || "Not provided"}
              </span>
            </p>
            <p>
              <span className="text-muted-foreground">Claimed company:</span>{" "}
              <span className="font-medium text-foreground">
                {input.companyName || "Not provided"}
              </span>
            </p>
          </div>
        </FindingSection>

        <FindingSection title="Public information found">
          {split.recruiter.findings.length > 0 || split.recruiter.links.length > 0 ? (
            <>
              {split.recruiter.findings.length > 0 && (
                <ul className="space-y-2">
                  {split.recruiter.findings.map((f, i) => (
                    <li key={i} className="flex gap-2 text-sm leading-relaxed">
                      <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              )}
              {split.recruiter.links.length > 0 && (
                <>
                  <ul className="mt-3 space-y-1.5">
                    {split.recruiter.links.map((l, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm leading-relaxed">
                        <ExternalLink className="mt-0.5 h-3.5 w-3.5 shrink-0 text-primary/80" />
                        <a
                          href={l.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          onClick={(e) => {
                            // Force open in a real new tab — escapes embedded
                            // preview iframes that can otherwise block sites
                            // like LinkedIn with ERR_BLOCKED_BY_RESPONSE.
                            e.preventDefault();
                            try {
                              const w = window.open(l.url, "_blank", "noopener,noreferrer");
                              if (!w && typeof window !== "undefined") {
                                window.top?.location.assign(l.url);
                              }
                            } catch {
                              window.location.href = l.url;
                            }
                          }}
                          className="break-all text-primary underline-offset-4 hover:underline"
                          title="Opens in a new tab"
                        >
                          {l.title}
                          <span className="sr-only"> (opens in a new tab)</span>
                        </a>
                      </li>
                    ))}
                  </ul>
                  <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                    Links open in a new browser tab. Some sites like LinkedIn
                    may block embedded viewing — if a link looks broken, copy
                    it into a normal browser window.
                  </p>
                </>
              )}
            </>
          ) : (
            <p className="text-sm leading-relaxed text-muted-foreground">
              We didn't find clear public information about this person tied to the
              claimed role and company. That's not necessarily a red flag — many
              legitimate recruiters keep a low public profile.
            </p>
          )}
          <p className="mt-3 text-xs italic leading-relaxed text-muted-foreground">
            Double-check public profile links — search results may include other
            people with similar names. Look for a profile that explicitly mentions
            the claimed role and company.
          </p>
        </FindingSection>
      </CategoryModal>
    </div>
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
