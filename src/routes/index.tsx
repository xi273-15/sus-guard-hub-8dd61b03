import { createFileRoute } from "@tanstack/react-router";
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
  ChevronRight,
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

function Index() {
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
          <div className="flex items-center gap-2.5">
            <span
              className="inline-flex h-8 w-8 items-center justify-center rounded-lg shadow-[var(--shadow-glow)]"
              style={{ background: "var(--gradient-primary)" }}
            >
              <Shield className="h-4 w-4 text-primary-foreground" />
            </span>
            <span className="text-base font-semibold tracking-tight">Suscruit</span>
            <span className="ml-2 hidden rounded-md border border-border/60 bg-muted/40 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground sm:inline">
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
        <h1 className="mt-5 max-w-3xl text-4xl font-bold tracking-tight sm:text-6xl">
          Spot suspicious recruiters{" "}
          <span className="text-gradient-cyber">before they scam you.</span>
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-relaxed text-muted-foreground sm:text-lg">
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
                    <CardTitle className="flex items-center gap-2 text-xl">
                      <Search className="h-5 w-5 text-primary" />
                      Check a recruiter
                    </CardTitle>
                    <CardDescription className="mt-1">
                      Fill in what you have — even a single field helps.
                    </CardDescription>
                  </div>
                  <span className="hidden rounded-md border border-border/60 bg-background/60 px-2 py-1 text-[11px] font-medium text-muted-foreground sm:inline">
                    Step 1 of 1
                  </span>
                </div>
              </CardHeader>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                }}
              >
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
                        <Input id="recruiterName" placeholder="e.g. Jane Doe" />
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
                        <Input id="companyName" placeholder="Acme Inc." />
                      </Field>
                      <Field
                        id="companyDomain"
                        label="Company website"
                        icon={<Globe className="h-3.5 w-3.5" />}
                      >
                        <Input id="companyDomain" placeholder="acme.com" />
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
                      />
                    </Field>
                  </FormSection>
                </CardContent>

                <div className="flex flex-col-reverse items-stretch justify-between gap-3 border-t border-border/60 px-6 py-4 sm:flex-row sm:items-center">
                  <p className="text-xs text-muted-foreground">
                    We never store your data. Analysis runs on your request only.
                  </p>
                  <Button
                    type="submit"
                    size="lg"
                    className="text-primary-foreground shadow-[var(--shadow-glow)] hover:opacity-95 transition-opacity"
                    style={{ background: "var(--gradient-primary)" }}
                  >
                    <Sparkles className="h-4 w-4" />
                    Analyze recruiter
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
                  <span className="rounded-full border border-border/60 bg-background/60 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
                    Pending
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-baseline gap-2">
                  <span className="text-5xl font-bold tracking-tight text-foreground/40">
                    —
                  </span>
                  <span className="text-sm text-muted-foreground">/ 100</span>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
                  <div className="h-full w-0 bg-primary" />
                </div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>Low</span>
                  <span>Medium</span>
                  <span>High</span>
                  <span>Critical</span>
                </div>
              </CardContent>
            </Card>

            {/* What you'll get */}
            <Card className="border-border/60 bg-card/60 backdrop-blur">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  What you'll get
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
              <SummaryRow
                icon={<AlertTriangle className="h-4 w-4" />}
                title="Risk assessment"
                description="See if this looks safe, suspicious, or clearly a scam."
              />
              <SummaryRow
                icon={<ListChecks className="h-4 w-4" />}
                title="What we checked"
                description="We analyze email headers, website details, and message patterns."
              />
              <SummaryRow
                icon={<Info className="h-4 w-4" />}
                title="Why we flagged it"
                description="Simple explanations so you understand the warning signs."
              />
              <SummaryRow
                icon={<Shield className="h-4 w-4" />}
                title="Next steps"
                description="Clear advice on what to do to stay safe."
              />
              </CardContent>
            </Card>
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
                Run a check above to populate this section.
              </p>
            </div>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <ResultCard
              icon={<ShieldAlert className="h-4 w-4" />}
              title="Risk score breakdown"
              description="See exactly what raised or lowered the score."
            />
            <ResultCard
              icon={<AlertTriangle className="h-4 w-4" />}
              title="Risk level"
              description="An at-a-glance label for how concerned you should be."
            />
            <ResultCard
              icon={<ListChecks className="h-4 w-4" />}
              title="Findings"
              description="Signals from the email, domain, and message."
            />
            <ResultCard
              icon={<Info className="h-4 w-4" />}
              title="Why it matters"
              description="What each finding means for you, in plain English."
            />
          </div>

          <ResultCard
            icon={<Shield className="h-4 w-4" />}
            title="Recommended next steps"
            description="Clear, practical actions to verify the recruiter or protect yourself."
            full
          />
        </section>

        <footer className="mt-16 border-t border-border/60 pt-6 pb-4 text-center text-xs text-muted-foreground">
          Suscruit · Built to protect job seekers
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
    <section className="space-y-4">
      <div className="flex items-baseline gap-3">
        <span className="text-xs font-semibold tracking-widest text-primary/80">
          {eyebrow}
        </span>
        <div>
          <h3 className="text-sm font-semibold text-foreground">{title}</h3>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
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
    <div className="space-y-1.5">
      <Label
        htmlFor={id}
        className="flex items-center gap-1.5 text-xs font-medium text-foreground/90"
      >
        {icon && <span className="text-primary/70">{icon}</span>}
        {label}
        {required && <span className="text-primary">*</span>}
      </Label>
      {children}
      {hint && <p className="text-[11px] leading-relaxed text-muted-foreground">{hint}</p>}
    </div>
  );
}

function SummaryRow({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="flex items-start gap-3 rounded-md border border-border/50 bg-background/40 p-2.5">
      <span
        className="mt-0.5 inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-primary"
        style={{ backgroundColor: "color-mix(in oklab, var(--primary) 14%, transparent)" }}
      >
        {icon}
      </span>
      <div className="min-w-0">
        <p className="text-sm font-medium text-foreground">{title}</p>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      <ChevronRight className="ml-auto h-4 w-4 shrink-0 text-muted-foreground/50" />
    </div>
  );
}

function ResultCard({
  icon,
  title,
  description,
  full,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  full?: boolean;
}) {
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
            Pending
          </span>
        </div>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="flex h-20 items-center justify-center rounded-md border border-dashed border-border/60 bg-background/40 text-xs text-muted-foreground">
          No data yet
        </div>
        <p className="mt-3 text-xs leading-relaxed text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}
