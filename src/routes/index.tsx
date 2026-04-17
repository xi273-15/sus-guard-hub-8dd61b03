import { createFileRoute } from "@tanstack/react-router";
import { Shield, ShieldAlert, Search, FileText, Mail, Building2, Globe, User, AlertTriangle, ListChecks, Info, Sparkles, Lock, Terminal } from "lucide-react";
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
          "Suscruit detects fake recruiters and hiring scams by analyzing email authentication, domain intelligence, public web evidence, and scam signals.",
      },
      { property: "og:title", content: "Suscruit — Recruiter scam detection" },
      {
        property: "og:description",
        content:
          "Analyze recruiter emails, domains, and messages to spot hiring scams before they cost you.",
      },
    ],
  }),
});

function Index() {
  return (
    <div className="relative min-h-screen bg-background text-foreground">
      {/* Ambient background */}
      <div className="pointer-events-none fixed inset-0 -z-10 bg-cyber-grid opacity-60" aria-hidden />
      <div
        className="pointer-events-none fixed inset-x-0 top-0 -z-10 h-[600px]"
        style={{ background: "var(--gradient-hero)", opacity: 0.7 }}
        aria-hidden
      />
      <div
        className="pointer-events-none fixed -top-40 left-1/2 -z-10 h-[500px] w-[800px] -translate-x-1/2 rounded-full blur-3xl"
        style={{ background: "var(--gradient-primary)", opacity: 0.18 }}
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
          <span className="font-mono text-sm tracking-widest text-muted-foreground">
            SUSCRUIT<span className="text-primary">_</span>
          </span>
        </div>
        <ThemeToggle />
      </div>

      {/* Header */}
      <header className="relative">
        <div className="relative mx-auto max-w-5xl px-6 py-12 sm:py-16">
          <div className="inline-flex items-center gap-2 rounded-full border border-border/60 bg-background/40 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-60" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
            </span>
            <span className="font-mono uppercase tracking-wider">Recruiter Threat Intel</span>
          </div>
          <h1 className="mt-6 text-5xl font-bold tracking-tight sm:text-7xl">
            <span className="text-gradient-cyber">Suscruit</span>
          </h1>
          <p className="mt-4 max-w-2xl text-xl font-medium text-foreground/85 sm:text-2xl">
            Spot suspicious recruiters before they scam job seekers.
          </p>
          <p className="mt-5 max-w-2xl text-base leading-relaxed text-muted-foreground">
            Suscruit detects fake recruiters and hiring scams by analyzing email authentication,
            domain intelligence, public web evidence, and scam signals — all in one place.
          </p>

          <div className="mt-8 flex flex-wrap gap-2 font-mono text-xs">
            <Chip icon={<Lock className="h-3 w-3" />}>SPF · DKIM · DMARC</Chip>
            <Chip icon={<Globe className="h-3 w-3" />}>WHOIS · DNS</Chip>
            <Chip icon={<Terminal className="h-3 w-3" />}>Header forensics</Chip>
            <Chip icon={<ShieldAlert className="h-3 w-3" />}>Scam patterns</Chip>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-6 pb-16 space-y-10">
        {/* Input Form */}
        <Card className="relative overflow-hidden border-border/60 bg-card/70 shadow-[var(--shadow-elegant)] backdrop-blur">
          <div
            className="pointer-events-none absolute inset-x-0 top-0 h-px"
            style={{ background: "var(--gradient-primary)" }}
            aria-hidden
          />
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-2xl">
              <Search className="h-5 w-5 text-primary" />
              Analyze a recruiter
            </CardTitle>
            <CardDescription>
              Provide as much detail as possible. The more signals you share, the more
              accurate the analysis.
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
                <Field id="recruiterName" label="Recruiter Name" icon={<User className="h-4 w-4" />}>
                  <Input id="recruiterName" placeholder="e.g. Jane Doe" />
                </Field>
                <Field id="recruiterEmail" label="Recruiter Email" icon={<Mail className="h-4 w-4" />}>
                  <Input id="recruiterEmail" type="email" placeholder="jane@company.com" />
                </Field>
                <Field id="companyName" label="Company Name" icon={<Building2 className="h-4 w-4" />}>
                  <Input id="companyName" placeholder="Acme Inc." />
                </Field>
                <Field id="companyDomain" label="Company Website or Domain" icon={<Globe className="h-4 w-4" />}>
                  <Input id="companyDomain" placeholder="acme.com" />
                </Field>
              </div>

              <Field
                id="message"
                label="Suspicious Message Text"
                icon={<FileText className="h-4 w-4" />}
              >
                <Textarea
                  id="message"
                  placeholder="Paste the recruiter's message, DM, or job offer..."
                  className="min-h-[140px] resize-y"
                />
              </Field>

              <Field
                id="headers"
                label="Raw Email Headers"
                icon={<Terminal className="h-4 w-4" />}
              >
                <Textarea
                  id="headers"
                  placeholder="Received: from mail.example.com ..."
                  className="min-h-[160px] resize-y font-mono text-xs"
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
                  Run analysis
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>

        {/* Results */}
        <section aria-labelledby="results-heading" className="space-y-5">
          <div className="flex items-end justify-between">
            <div>
              <h2 id="results-heading" className="text-2xl font-semibold tracking-tight">
                Analysis results
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Submit the form above to see findings here.
              </p>
            </div>
            <span className="hidden font-mono text-xs text-muted-foreground sm:inline">
              status: <span className="text-primary">idle</span>
            </span>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <ResultCard
              icon={<ShieldAlert className="h-5 w-5" />}
              title="Risk Score"
              description="A 0–100 score summarizing how risky this recruiter looks."
            />
            <ResultCard
              icon={<AlertTriangle className="h-5 w-5" />}
              title="Risk Category"
              description="Low, medium, high, or critical risk classification."
            />
          </div>

          <ResultCard
            icon={<ListChecks className="h-5 w-5" />}
            title="Findings"
            description="Detailed signals from email auth, domain checks, and message analysis."
          />
          <ResultCard
            icon={<Info className="h-5 w-5" />}
            title="Why This Matters"
            description="Plain-language explanation of what each finding means for you."
          />
          <ResultCard
            icon={<Shield className="h-5 w-5" />}
            title="Recommended Next Steps"
            description="Concrete actions to verify or protect yourself before responding."
          />
        </section>

        <footer className="pt-6 pb-2 text-center font-mono text-xs text-muted-foreground">
          // Suscruit · built to protect job seekers
        </footer>
      </main>
    </div>
  );
}

function Chip({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-border/60 bg-card/60 px-2.5 py-1 text-muted-foreground backdrop-blur">
      <span className="text-primary">{icon}</span>
      {children}
    </span>
  );
}

function Field({
  id,
  label,
  icon,
  children,
}: {
  id: string;
  label: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id} className="flex items-center gap-2 text-sm font-medium">
        <span className="text-primary/80">{icon}</span>
        {label}
      </Label>
      {children}
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
    <Card className="group relative overflow-hidden border-border/60 bg-card/50 backdrop-blur transition-colors hover:border-primary/50">
      <div
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity group-hover:opacity-100"
        style={{
          background:
            "radial-gradient(600px circle at 50% 0%, color-mix(in oklab, var(--primary) 10%, transparent), transparent 60%)",
        }}
        aria-hidden
      />
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
        <div className="relative flex h-20 items-center justify-center overflow-hidden rounded-md border border-dashed border-border/60 bg-background/40 font-mono text-xs text-muted-foreground animate-scan">
          <span className="animate-pulse-glow">awaiting_analysis...</span>
        </div>
        <p className="mt-3 text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}
