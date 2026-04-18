import { createFileRoute } from "@tanstack/react-router";
import { useRef, useState } from "react";
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
  Volume2,
  Square,
  Loader2,
  Accessibility,
  CheckCircle2,
  Mailbox,
  Globe2,
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
import { analyzeRecruiter, type AnalysisResult } from "@/lib/analysis";

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

  const update = (k: keyof FormState) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await analyzeRecruiter({ data: form });
      setResult(res);
      // Smooth scroll to results on small screens
      requestAnimationFrame(() => {
        document.getElementById("results-heading")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch (err) {
      console.error(err);
      setError("Something went wrong while analyzing. Please try again.");
    } finally {
      setLoading(false);
    }
  };

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

      <main className="mx-auto max-w-6xl px-6 pb-20">
        <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_360px]">
          {/* Form column */}
          <div className="space-y-6">
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

          {/* Results column */}
          <aside className="space-y-6 lg:sticky lg:top-20 lg:self-start">
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

            {/* Listen to this analysis */}
            <ListenCard summary={result?.audio_summary} />
          </aside>
        </div>

        {/* Detailed results */}
        <section aria-labelledby="results-heading" className="mt-12 space-y-5">
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
        </section>

        <footer className="mt-16 border-t border-border/60 pt-8 pb-6 text-center text-sm text-muted-foreground">
          <p className="font-medium">Suscruit</p>
          <p className="mt-1">Built to protect job seekers</p>
        </footer>
      </main>
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
  children,
}: {
  id: string;
  label: string;
  icon?: React.ReactNode;
  hint?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label
        htmlFor={id}
        className="flex items-center gap-1.5 text-sm font-medium text-foreground"
      >
        {icon && <span className="text-primary/80">{icon}</span>}
        {label}
        {required && <span className="text-primary">*</span>}
      </Label>
      {children}
      {hint && <p className="text-xs leading-relaxed text-muted-foreground">{hint}</p>}
    </div>
  );
}

function ListenCard({ summary }: { summary?: string }) {
  const [status, setStatus] = useState<"idle" | "loading" | "playing">("idle");
  const audioRef = useRef<HTMLAudioElement | null>(null);

  const fallback =
    "Here is a spoken summary of your recruiter analysis. Once you run a check, this will read out the overall risk score, the risk category, the key signals we found in the email and message, why those signals matter for your safety, and the recommended next steps you can take to verify the recruiter or protect yourself.";

  const stop = () => {
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current.src = "";
      audioRef.current = null;
    }
    setStatus("idle");
  };

  const play = async () => {
    try {
      stop();
      setStatus("loading");
      const res = await fetch("/api/tts", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: summary || fallback }),
      });
      if (!res.ok) throw new Error(await res.text());
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const audio = new Audio(url);
      audioRef.current = audio;
      audio.onended = () => {
        URL.revokeObjectURL(url);
        setStatus("idle");
      };
      audio.onerror = () => {
        URL.revokeObjectURL(url);
        setStatus("idle");
      };
      await audio.play();
      setStatus("playing");
    } catch (err) {
      console.error("TTS error:", err);
      setStatus("idle");
    }
  };

  return (
    <Card className="border-border/60 bg-card/85 shadow-[var(--shadow-elegant)] backdrop-blur">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base font-semibold">
          <span
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-primary"
            style={{ backgroundColor: "color-mix(in oklab, var(--primary) 14%, transparent)" }}
          >
            <Accessibility className="h-4 w-4" />
          </span>
          Listen to this analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm leading-relaxed text-muted-foreground">
          Listen to a spoken summary of your analysis. This feature is designed for
          accessibility and powered by ElevenLabs.
        </p>
        <div className="flex items-center gap-2">
          <Button
            type="button"
            onClick={play}
            disabled={status === "loading"}
            className="flex-1 text-primary-foreground shadow-[var(--shadow-glow)] hover:opacity-95 transition-opacity"
            style={{ background: "var(--gradient-primary)" }}
            aria-label="Play audio summary of the analysis"
          >
            {status === "loading" ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Generating…
              </>
            ) : (
              <>
                <Volume2 className="h-4 w-4" />
                Read analysis aloud
              </>
            )}
          </Button>
          {status === "playing" && (
            <Button
              type="button"
              variant="outline"
              size="icon"
              onClick={stop}
              aria-label="Stop audio"
            >
              <Square className="h-4 w-4" />
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
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
