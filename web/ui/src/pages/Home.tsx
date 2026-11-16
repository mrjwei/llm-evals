// Home (Plan P6 "Home"): the three entry cards, then the health tiles.
import { ArrowRight, ClipboardCheck, ListChecks, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router";
import { Badge } from "@/components/ui/badge";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { HealthPanel } from "@/components/HealthPanel";
import { cn } from "@/lib/utils";

interface Entry {
  to: string;
  title: string;
  icon: ReactNode;
  text: string;
  ready: boolean;
}

export const ENTRIES: Entry[] = [
  {
    to: "/triage",
    title: "Triage",
    icon: <ShieldAlert />,
    text: "Have Claude triage Wazuh alerts from a demo session, a file you upload or a live time window, then work through the queue and export the verdicts.",
    ready: true,
  },
  {
    to: "/rate",
    title: "Rate",
    icon: <ClipboardCheck />,
    text: "Rate triage answers blind against the rubric, one at a time (expert evaluation, WP5′).",
    ready: true,
  },
  {
    to: "/results",
    title: "Results",
    icon: <ListChecks />,
    text: "Browse the research runs by experiment and research question, and see which result is canonical.",
    ready: true,
  },
];

function EntryCard({ entry }: { entry: Entry }) {
  const card = (
    <Card className={cn("h-full transition-colors", entry.ready ? "hover:border-foreground/30" : "opacity-60")}>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base [&>svg]:size-5">
          {entry.icon}
          {entry.title}
          {entry.ready ? <ArrowRight className="ml-auto text-muted-foreground" /> : <Badge variant="secondary" className="ml-auto">Not available yet</Badge>}
        </CardTitle>
        <CardDescription>{entry.text}</CardDescription>
      </CardHeader>
    </Card>
  );
  return entry.ready ? (
    <Link to={entry.to} className="rounded-xl focus-visible:outline-2">
      {card}
    </Link>
  ) : (
    <div aria-disabled>{card}</div>
  );
}

export function Home() {
  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        {ENTRIES.map((entry) => (
          <EntryCard key={entry.to} entry={entry} />
        ))}
      </div>
      <HealthPanel />
    </div>
  );
}
