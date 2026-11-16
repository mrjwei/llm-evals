// A job's run panel (Plan P6 "Run"): the estimate and the approval step
// before any paid call, progress while it runs, and the actual tokens and
// cost after. Approving sends exactly the paid calls the person saw; the
// server refuses a job that needs more (decision 014).
import { useState } from "react";
import { CircleStop, Loader2, Play, RotateCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { ApiError } from "@/lib/api";
import { count, dateTime, plural, usd } from "@/lib/format";
import { RESTARTABLE, estimateWords, sourceSummary, useReestimate, useStartJob, useStopJob } from "@/lib/triage";
import type { Job } from "@/lib/types";
import { JobBadge } from "./JobBadge";

export function JobRun({ job }: { job: Job }) {
  const start = useStartJob(job.id);
  const stop = useStopJob(job.id);
  const reestimate = useReestimate(job.id);
  const [toApprove, setToApprove] = useState<Job | null>(null); // the estimate the dialog shows

  const restartable = RESTARTABLE.includes(job.status);
  const fresh = job.status === "planned";
  const answered = job.progress.answered;
  const percent = job.progress.total ? Math.round((answered / job.progress.total) * 100) : 0;

  /** Run, or resume. A resume first estimates what is left, so the person
   * approves the calls still to make, not the whole job's. Free runs need
   * no approval step. */
  async function begin() {
    start.reset();
    const current = fresh ? job : await reestimate.mutateAsync().catch(() => null);
    if (!current) return;
    if (current.estimate.calls === 0) start.mutate(0);
    else setToApprove(current);
  }

  function approve() {
    if (!toApprove) return;
    setToApprove(null);
    start.mutate(toApprove.estimate.calls);
  }

  const overBudget = start.error instanceof ApiError && start.error.status === 409;
  const busy = start.isPending || reestimate.isPending;

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-4">
        <div className="min-w-0 space-y-1.5">
          <CardTitle className="flex flex-wrap items-center gap-2 text-lg">
            <JobBadge status={job.status} />
            <span className="min-w-0 break-words">{sourceSummary(job.source)}</span>
          </CardTitle>
          <CardDescription>
            {plural(job.alerts, "alert")}
            {job.options.bodies && `, ${count(job.bodies_matched)} with request bodies`} · {job.options.formats.map((f) => `Format ${f}`).join(" and ")} ·{" "}
            {job.model_id} · created {dateTime(job.created_at)} · job {job.id}
          </CardDescription>
        </div>
        <div className="flex gap-2">
          {job.status === "running" && (
            <Button variant="outline" onClick={() => stop.mutate()} disabled={stop.isPending}>
              <CircleStop /> Stop
            </Button>
          )}
          {restartable && (
            <Button onClick={begin} disabled={busy}>
              {busy ? <Loader2 className="animate-spin" /> : fresh ? <Play /> : <RotateCw />}
              {fresh ? "Run triage" : "Resume"}
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {job.warnings.length > 0 && (
          <Alert>
            <AlertTitle>When the alerts were read</AlertTitle>
            <AlertDescription>
              <ul className="list-disc pl-4">
                {job.warnings.map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        )}

        {fresh && <EstimateBox job={job} />}

        {!fresh && (
          <div className="space-y-1.5">
            <div className="flex justify-between text-sm">
              <span>
                {count(answered)} of {plural(job.progress.total, "answer")}
                {job.status === "running" && " so far"}
              </span>
              <span className="text-muted-foreground">{percent}%</span>
            </div>
            <Progress value={percent} aria-label="Triage progress" />
          </div>
        )}

        {job.error && job.status === "failed" && (
          <Alert variant="destructive">
            <AlertTitle>The run stopped</AlertTitle>
            <AlertDescription>{job.error}</AlertDescription>
          </Alert>
        )}
        {job.status === "interrupted" && (
          <Alert>
            <AlertTitle>The app was closed while this job ran</AlertTitle>
            <AlertDescription>Resume it: the answers it already has are kept.</AlertDescription>
          </Alert>
        )}

        {!fresh && <ActualCost job={job} />}

        {(start.error || reestimate.error || stop.error) && (
          <Alert variant="destructive">
            <AlertTitle>{overBudget ? "This needs more paid calls than you approved" : "That didn't work"}</AlertTitle>
            <AlertDescription>
              <p>{(start.error ?? reestimate.error ?? stop.error)?.message}</p>
              {overBudget && (
                <Button size="sm" variant="outline" className="mt-2" onClick={begin}>
                  Estimate again
                </Button>
              )}
            </AlertDescription>
          </Alert>
        )}
      </CardContent>

      <Dialog open={toApprove !== null} onOpenChange={(open) => !open && setToApprove(null)}>
        {toApprove && (
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Approve paid calls?</DialogTitle>
              <DialogDescription>{estimateWords(toApprove).headline}</DialogDescription>
            </DialogHeader>
            <ul className="list-disc space-y-1 pl-5 text-sm">
              {estimateWords(toApprove).details.map((d) => (
                <li key={d}>{d}</li>
              ))}
            </ul>
            <DialogFooter>
              <DialogClose asChild>
                <Button variant="outline">Cancel</Button>
              </DialogClose>
              <Button onClick={approve}>Approve {plural(toApprove.estimate.calls, "paid call")} and run</Button>
            </DialogFooter>
          </DialogContent>
        )}
      </Dialog>
    </Card>
  );
}

function EstimateBox({ job }: { job: Job }) {
  const words = estimateWords(job);
  return (
    <div className="rounded-lg border bg-muted/40 p-4">
      <p className="font-medium">Before running: {words.headline}</p>
      <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm text-muted-foreground">
        {words.details.map((d) => (
          <li key={d}>{d}</li>
        ))}
      </ul>
    </div>
  );
}

function ActualCost({ job }: { job: Job }) {
  const a = job.actual;
  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
      <Stat label="Billed for this job" value={usd(a.cost_usd)} hint={`${plural(a.calls, "paid call")}`} />
      <Stat label="Tokens sent / received" value={`${count(a.input_tokens)} / ${count(a.output_tokens)}`} />
      <Stat label="From the cache (free)" value={count(a.cache_hits)} hint={`first made for ${usd(a.answers_cost_usd)} at list price`} />
      <Stat label="Failed calls" value={count(a.failed_calls)} hint={a.failed_calls ? "Resume to retry them" : undefined} />
      {a.unpriced.length > 0 && (
        <p className="col-span-full text-xs text-warn">No list price for {a.unpriced.join(", ")}; its cost is not included.</p>
      )}
    </dl>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="text-base font-medium tabular-nums">{value}</dd>
      {hint && <dd className="text-xs text-muted-foreground">{hint}</dd>}
    </div>
  );
}
