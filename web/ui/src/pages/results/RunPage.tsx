// One run (Plan P6 "Results"): its facts from run.json, a link per
// condition report, and the open report.md with its charts. The open
// report is `?doc=` in the URL, so a reload or Back keeps it.
import type { ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { query } from "@/lib/api";
import { count, dateTime } from "@/lib/format";
import { useReport, useRun } from "@/lib/results";
import type { RunDetail } from "@/lib/types";
import { cn } from "@/lib/utils";
import { CanonicalBadge, RunStatusBadge } from "./badges";
import { ReportMarkdown } from "./ReportMarkdown";

export function RunPage() {
  const { experiment = "", run = "" } = useParams();
  const address = `${experiment}/${run}`;
  const [params] = useSearchParams();
  const doc = params.get("doc") ?? "report.md";
  const detail = useRun(address);
  const report = useReport(address, doc);

  return (
    <div className="space-y-4">
      <nav className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground" aria-label="Breadcrumb">
        <Link to="/results" className="hover:underline">
          Results
        </Link>
        <span>/</span>
        <Link to={`/results?experiment=${experiment.split("-")[0]}`} className="hover:underline">
          {experiment}
        </Link>
        <span>/</span>
        <span className="font-mono text-foreground">{run}</span>
      </nav>
      {detail.isPending && <Skeleton className="h-40" />}
      {detail.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not open this run</AlertTitle>
          <AlertDescription>{detail.error.message}</AlertDescription>
        </Alert>
      )}
      {detail.data && <RunHeader run={detail.data} doc={doc} />}
      <Card>
        <CardContent className="px-4 sm:px-6">
          {report.isPending && <Skeleton className="h-96" />}
          {report.isError && (
            <Alert variant="destructive">
              <AlertTitle>Could not open {doc}</AlertTitle>
              <AlertDescription>{report.error.message}</AlertDescription>
            </Alert>
          )}
          {report.data && <ReportMarkdown address={address} doc={report.data.doc} markdown={report.data.markdown} />}
        </CardContent>
      </Card>
    </div>
  );
}

function RunHeader({ run, doc }: { run: RunDetail; doc: string }) {
  const model = typeof run.model === "string" ? run.model : run.model ? Object.values(run.model).filter((v, i, a) => a.indexOf(v) === i).join(", ") : null;
  return (
    <Card className="gap-3">
      <CardHeader className="gap-2">
        <CardTitle className="flex flex-wrap items-center gap-2">
          {run.experiment} {run.experiment_slug}
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
      <CardContent className="space-y-4">
        <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2 lg:grid-cols-3">
          <Fact label="Corpus">
            {run.corpus}
            {run.corpus_sha256 && <span className="ml-1 font-mono text-xs text-muted-foreground">sha256 {run.corpus_sha256.slice(0, 12)}</span>}
          </Fact>
          {model && <Fact label="Model"><span className="font-mono text-xs">{model}</span></Fact>}
          <Fact label="Code"><span className="font-mono text-xs">{run.git_describe ?? "?"}</span></Fact>
          <Fact label="Started">{dateTime(run.created_at)}</Fact>
          <Fact label="Finished">{run.finished_at ? dateTime(run.finished_at) : "not finished"}</Fact>
          {run.cache?.api_calls !== undefined && (
            <Fact label="Claude calls">
              {count(run.cache.api_calls)} paid, {count(run.cache.cache_hits)} from cache, {count(run.cache.tokens_billed)} tokens billed
            </Fact>
          )}
        </dl>
        {run.status === "failed" && run.error && <p className="text-sm text-destructive">{run.error}</p>}
        <div className="flex flex-wrap gap-1.5" aria-label="Reports">
          <DocLink doc={null} active={doc === "report.md"} disabled={!run.has_report}>
            Run report
          </DocLink>
          {run.conditions.map((c) => (
            <DocLink key={c.id} doc={`conditions/${c.id}/report.md`} active={doc === `conditions/${c.id}/report.md`} disabled={!c.has_report}>
              <span className="font-mono text-xs">{c.id}</span>
            </DocLink>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function DocLink({ doc, active, disabled, children }: { doc: string | null; active: boolean; disabled: boolean; children: ReactNode }) {
  const cls = cn("rounded-md border px-2.5 py-1 text-sm", active ? "border-primary bg-primary text-primary-foreground" : "hover:bg-accent");
  if (disabled) return <span className={cn(cls, "opacity-50")} title="No report.md">{children}</span>;
  return (
    <Link to={{ search: query({ doc }) }} className={cls} aria-current={active ? "page" : undefined}>
      {children}
    </Link>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 gap-2">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}
