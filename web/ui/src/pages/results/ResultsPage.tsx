// Results (Plan P6 "Results"): every research run, as INDEX.md lists them,
// with experiment, RQ, status, headline and a canonical badge. Filters by
// experiment and RQ live in the URL. Read-only.
import { Link, useSearchParams } from "react-router";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { dateTime } from "@/lib/format";
import { figuresFor, useRuns } from "@/lib/results";
import type { RunSummary, RunsList } from "@/lib/types";
import { RunStatusBadge, CanonicalBadge } from "./badges";

const ALL = "all";

export function ResultsPage() {
  const runs = useRuns();
  const [params, setParams] = useSearchParams();
  const experiment = params.get("experiment");
  const rq = params.get("rq");
  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value === ALL) next.delete(key);
    else next.set(key, value);
    setParams(next, { replace: true });
  };

  const shown = (runs.data?.runs ?? []).filter(
    (r) => (!experiment || r.experiment === experiment) && (!rq || (r.rq ?? []).includes(rq)),
  );

  return (
    <div className="space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Results</h1>
        <p className="text-sm text-muted-foreground">
          Every research run in <span className="font-mono">data/runs/</span>, newest first. A canonical run is the one the report's figures and tables
          come from (<span className="font-mono">results/canonical.yaml</span>). This page only reads.
        </p>
      </div>
      {runs.isPending && <Skeleton className="h-64" />}
      {runs.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not load the runs</AlertTitle>
          <AlertDescription>{runs.error.message}</AlertDescription>
        </Alert>
      )}
      {runs.data && (
        <>
          <div className="flex flex-wrap items-end gap-4">
            <Filter label="Experiment" value={experiment} options={runs.data.experiments} onChange={(v) => setFilter("experiment", v)} />
            <Filter label="Research question" value={rq} options={runs.data.rqs} onChange={(v) => setFilter("rq", v)} />
            <p className="ml-auto text-sm text-muted-foreground">
              {shown.length} of {runs.data.runs.length} runs
            </p>
          </div>
          {runs.data.pin_problems.length > 0 && (
            <Alert variant="destructive">
              <AlertTitle>A canonical pin names a run that is missing</AlertTitle>
              <AlertDescription>Pins: {runs.data.pin_problems.join(", ")}. Re-pin with cjp runs mark-canonical.</AlertDescription>
            </Alert>
          )}
          {runs.data.runs.length === 0 && <p className="text-sm text-muted-foreground">No runs yet.</p>}
          <div className="space-y-3">
            {shown.map((r) => (
              <RunCard key={r.address} run={r} list={runs.data} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function Filter({ label, value, options, onChange }: { label: string; value: string | null; options: string[]; onChange: (v: string) => void }) {
  const id = `filter-${label.toLowerCase().replace(/\W+/g, "-")}`;
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      <Select value={value ?? ALL} onValueChange={onChange}>
        <SelectTrigger id={id} className="w-44">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={ALL}>All</SelectItem>
          {options.map((o) => (
            <SelectItem key={o} value={o}>
              {o}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function RunCard({ run, list }: { run: RunSummary; list: RunsList }) {
  const feeds = run.canonical.flatMap((key) => figuresFor(list, key));
  return (
    <Card className="gap-2 py-4">
      <CardHeader className="gap-1.5 px-4">
        <CardTitle className="flex flex-wrap items-center gap-2 text-base">
          <Link to={`/results/${run.address}`} className="font-mono underline-offset-4 hover:underline">
            {run.run_id}
          </Link>
          <span className="font-normal text-muted-foreground">
            {run.experiment} {run.experiment_slug}
          </span>
          {(run.rq ?? []).map((q) => (
            <Badge key={q} variant="secondary">
              {q}
            </Badge>
          ))}
          <RunStatusBadge run={run} />
          {run.canonical.length > 0 && <CanonicalBadge keys={run.canonical} />}
        </CardTitle>
        {run.question && <CardDescription>{run.question}</CardDescription>}
      </CardHeader>
      <CardContent className="space-y-1.5 px-4 text-sm">
        <p className="break-words">{run.status === "failed" ? run.error : run.headline}</p>
        <p className="flex flex-wrap gap-x-4 text-xs text-muted-foreground">
          {run.git_describe && <span className="font-mono">{run.git_describe}</span>}
          {run.finished_at && <span>finished {dateTime(run.finished_at)}</span>}
          {feeds.length > 0 && <span>feeds {feeds.join(", ")}</span>}
          {!run.has_report && <span>no report.md</span>}
        </p>
      </CardContent>
    </Card>
  );
}
