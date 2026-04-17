import { createFileRoute } from "@tanstack/react-router";
import { Shield, ShieldAlert, Search, FileText, Mail, Building2, Globe, User, AlertTriangle, ListChecks, Info, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

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
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="relative overflow-hidden border-b border-border">
        <div
          className="absolute inset-0 opacity-[0.07]"
          style={{
            backgroundImage:
              "radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)",
            backgroundSize: "24px 24px",
            color: "var(--brand)",
          }}
          aria-hidden
        />
        <div
          className="absolute inset-0"
          style={{ background: "var(--gradient-hero)", opacity: 0.04 }}
          aria-hidden
        />
        <div className="relative mx-auto max-w-5xl px-6 py-16 sm:py-20">
          <div className="flex items-center gap-2 text-sm font-medium text-primary">
            <span
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg shadow-[var(--shadow-glow)]"
              style={{ background: "var(--gradient-primary)" }}
            >
              <Shield className="h-5 w-5 text-primary-foreground" />
            </span>
            <span className="tracking-wide uppercase text-xs text-muted-foreground">
              Recruiter Scam Detection
            </span>
          </div>
          <h1 className="mt-6 text-4xl font-bold tracking-tight text-foreground sm:text-6xl">
            Suscruit
          </h1>
          <p className="mt-3 text-xl font-medium text-foreground/80 sm:text-2xl">
            Spot suspicious recruiters before they scam job seekers.
          </p>
          <p className="mt-5 max-w-2xl text-base leading-relaxed text-muted-foreground">
            Suscruit helps job seekers detect fake recruiters and hiring scams by analyzing
            email authentication, domain intelligence, public web evidence, and scam
            signals — all in one place.
          </p>
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-6 py-12 space-y-10">
        {/* Input Form */}
        <Card className="shadow-[var(--shadow-elegant)] border-border/60">
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
                icon={<FileText className="h-4 w-4" />}
              >
                <Textarea
                  id="headers"
                  placeholder="Paste the full raw email headers here..."
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
              Analysis results
            </h2>
            <p className="text-sm text-muted-foreground mt-1">
              Submit the form above to see findings here.
            </p>
          </div>

          <div className="grid gap-5 md:grid-cols-2">
            <ResultCard
              icon={<ShieldAlert className="h-5 w-5" />}
              title="Risk Score"
              description="A 0–100 score summarizing how risky this recruiter looks."
              accent
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
        <span className="text-muted-foreground">{icon}</span>
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
  accent = false,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  accent?: boolean;
}) {
  return (
    <Card
      className={`border-dashed border-border/70 bg-muted/30 transition-colors hover:border-primary/40 ${
        accent ? "md:row-span-1" : ""
      }`}
    >
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <span
            className="inline-flex h-8 w-8 items-center justify-center rounded-md text-primary"
            style={{ backgroundColor: "color-mix(in oklab, var(--primary) 12%, transparent)" }}
          >
            {icon}
          </span>
          {title}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex h-20 items-center justify-center rounded-md border border-dashed border-border/60 bg-background/60 text-sm text-muted-foreground">
          Awaiting analysis
        </div>
        <p className="mt-3 text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );
}
