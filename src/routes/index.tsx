import { createFileRoute } from "@tanstack/react-router";
import { Shield, ShieldAlert, Search, FileText, Mail, Building2, Globe, User, AlertTriangle, ListChecks, Info, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ThemeToggle } from "@/components/theme-toggle";

export const Route = createFileRoute("/")({
  component: Index,
  head: () => ({
    meta: [
      { title: "Suscruit — Spot suspicious recruiters before they scam job seekers" },
      {
        name: "description",
        content:
          "Suscruit helps job seekers detect fake recruiters and hiring scams by analyzing email, domains, and messages — in plain language.",
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
      {/* Soft ambient background */}
      <div
        className="pointer-events-none fixed inset-x-0 top-0 -z-10 h-[600px]"
        style={{ background: "var(--gradient-hero)", opacity: 0.6 }}
        aria-hidden
      />
      <div
        className="pointer-events-none fixed -top-40 left-1/2 -z-10 h-[500px] w-[800px] -translate-x-1/2 rounded-full blur-3xl"
        style={{ background: "var(--gradient-primary)", opacity: 0.12 }}
        aria-hidden
      />

      {/* Top bar */}
      <div className="relative mx-auto flex max-w-5xl items-center justify-between px-6 pt-6">
        <div className="flex items-center gap-2">
          <span
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg shadow-[var(--shadow-glow)]"
            style={{ background: "var(--gradient-primary)" }}
          >
            <Shield className="h-5 w-5 text-primary-foreground" />
          </span>
          <span className="text-base font-semibold tracking-tight">Suscruit</span>
        </div>
        <ThemeToggle />
      </div>

      {/* Header */}
      <header className="relative">
        <div className="relative mx-auto max-w-5xl px-6 py-12 sm:py-16">
          <div className="inline-flex items-center gap-2 rounded-full border border-border/60 bg-background/60 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
            </span>
            Recruiter scam check
          </div>
          <h1 className="mt-6 text-5xl font-bold tracking-tight sm:text-7xl">
            <span className="text-gradient-cyber">Suscruit</span>
          </h1>
          <p className="mt-4 max-w-2xl text-xl font-medium text-foreground/85 sm:text-2xl">
            Spot suspicious recruiters before they scam job seekers.
          </p>
          <p className="mt-5 max-w-2xl text-base leading-relaxed text-muted-foreground">
            Paste a recruiter's email or message and we'll check it for the most common
            hiring scam signals — then explain what we found in plain language.
          </p>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-6 pb-16 space-y-10">
        {/* Input Form */}
        <Card className="relative overflow-hidden border-border/60 bg-card/80 shadow-[var(--shadow-elegant)] backdrop-blur">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-2xl">
              <Search className="h-5 w-5 text-primary" />
              Check a recruiter
            </CardTitle>
            <CardDescription>
              Fill in what you have — even a single field helps. The more you share, the
              more accurate the result.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form
              className="space-y-6"
              onSubmit={(e) => {
                e.preventDefault();
              }}
            >
              <div className="grid gap-5 sm:grid-cols-2">
                <Field id="recruiterName" label="Recruiter name" icon={<User className="h-4 w-4" />}>
                  <Input id="recruiterName" placeholder="e.g. Jane Doe" />
                </Field>
                <Field id="recruiterEmail" label="Recruiter email" icon={<Mail className="h-4 w-4" />}>
                  <Input id="recruiterEmail" type="email" placeholder="jane@company.com" />
                </Field>
                <Field id="companyName" label="Company name" icon={<Building2 className="h-4 w-4" />}>
                  <Input id="companyName" placeholder="Acme Inc." />
                </Field>
                <Field id="companyDomain" label="Company website" icon={<Globe className="h-4 w-4" />}>
                  <Input id="companyDomain" placeholder="acme.com" />
                </Field>
              </div>

              <Field
                id="message"
                label="The message they sent"
                icon={<FileText className="h-4 w-4" />}
              >
                <Textarea
                  id="message"
                  placeholder="Paste the recruiter's message, DM, or job offer here..."
                  className="min-h-[140px] resize-y"
                />
              </Field>

              <Field
                id="headers"
                label="Email details (optional)"
                icon={<FileText className="h-4 w-4" />}
                hint="Advanced — paste the raw email headers if you have them. Improves accuracy."
              >
                <Textarea
                  id="headers"
                  placeholder="Paste the full raw email headers here..."
                  className="min-h-[140px] resize-y font-mono text-xs"
                />
              </Field>

              <div className="flex justify-end pt-2">
                <Button
                  type="submit"
                  size="lg"
                  className="text-primary-foreground shadow-[var(--shadow-glow)] hover:opacity-95 transition-opacity"
                  style={{ background: "var(--gradient-primary)" }}
                >
                  <Sparkles className="h-4 w-4" />
                  Analyze
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        {/* Results */}
        <section aria-labelledby="results-heading" className="space-y-5">
          <div>
            <h2 id="results-heading" className="text-2xl font-semibold tracking-tight">
              Your results
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Submit the form above to see your analysis here.
            </p>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <ResultCard
              icon={<ShieldAlert className="h-5 w-5" />}
              title="Risk score"
              description="A simple 0–100 score showing how risky this recruiter looks."
            />
            <ResultCard
              icon={<AlertTriangle className="h-5 w-5" />}
              title="Risk level"
              description="An at-a-glance label: low, medium, high, or critical."
            />
          </div>

          <ResultCard
            icon={<ListChecks className="h-5 w-5" />}
            title="What we found"
            description="The specific signals we picked up from the email, domain, and message."
          />
          <ResultCard
            icon={<Info className="h-5 w-5" />}
            title="Why it matters"
            description="A plain-language explanation of what each finding means for you."
          />
          <ResultCard
            icon={<Shield className="h-5 w-5" />}
            title="What to do next"
            description="Clear, practical steps to verify the recruiter or protect yourself."
          />
        </section>

        <footer className="pt-6 pb-2 text-center text-xs text-muted-foreground">
          Suscruit · Built to protect job seekers
        </footer>
      </main>
    </div>
  );
}

function Field({
  id,
  label,
  icon,
  hint,
  children,
}: {
  id: string;
  label: string;
  icon?: React.ReactNode;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id} className="flex items-center gap-2 text-sm font-medium">
        <span className="text-primary/80">{icon}</span>
        {label}
      </Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function ResultCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
}) {
  return (
    <Card className="group relative overflow-hidden border-border/60 bg-card/60 backdrop-blur transition-colors hover:border-primary/40">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <span
            className="inline-flex h-8 w-8 items-center justify-center rounded-md text-primary"
            style={{ backgroundColor: "color-mix(in oklab, var(--primary) 14%, transparent)" }}
          >
            {icon}
          </span>
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex h-20 items-center justify-center rounded-md border border-dashed border-border/60 bg-background/50 text-sm text-muted-foreground">
          Waiting for your analysis
        </div>
        <p className="mt-3 text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}
