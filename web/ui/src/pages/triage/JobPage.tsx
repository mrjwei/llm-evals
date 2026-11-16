// /triage/jobs/:jobId: the run panel, then the queue beside the verdict.
// The queue's state lives in the URL (?format=&lane=&label=&disposition=
// &source=&alert=), so a reload or a shared link opens the same view. The
// alert is a query parameter, not a path segment: Wazuh alert IDs contain a
// dot, and the server answers unknown paths with a dot as missing files.
import { useEffect, useRef } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Skeleton } from "@/components/ui/skeleton";
import { useJob, useQueue } from "@/lib/triage";
import type { Format, Job, Lane } from "@/lib/types";
import { cn } from "@/lib/utils";
import { JobRun } from "./JobRun";
import { QueueView, type QueueState } from "./QueueView";
import { VerdictPane } from "./VerdictView";

const LANES: Lane[] = ["queue", "human", "pending"];

export function JobPage() {
  const { jobId = "" } = useParams();
  const job = useJob(jobId);
  return (
    <div className="space-y-4">
      <Link to="/triage" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> All triage jobs
      </Link>
      {job.isPending && <Skeleton className="h-40" />}
      {job.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not open this job</AlertTitle>
          <AlertDescription>{job.error.message}</AlertDescription>
        </Alert>
      )}
      {job.data && <JobView job={job.data} />}
    </div>
  );
}

function useQueueState(formats: Format[]): [QueueState, (patch: Partial<QueueState>) => void] {
  const [params, setParams] = useSearchParams();
  const format = params.get("format") as Format | null;
  const lane = params.get("lane") as Lane | null;
  const state: QueueState = {
    format: format && formats.includes(format) ? format : formats[0],
    lane: lane && LANES.includes(lane) ? lane : "queue",
    label: params.get("label"),
    disposition: params.get("disposition"),
    source: params.get("source"),
    alert: params.get("alert"),
  };
  const update = (patch: Partial<QueueState>) => {
    const next = { ...state, ...patch };
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(next)) if (v) q.set(k, v);
    setParams(q, { replace: !("alert" in patch) }); // opening an alert is a history step; filters are not
  };
  return [state, update];
}

function JobView({ job }: { job: Job }) {
  const [state, update] = useQueueState(job.options.formats);
  const running = job.status === "running";
  const queue = useQueue(job.id, { format: state.format, label: state.label, disposition: state.disposition, source: state.source }, running);
  const client = useQueryClient();

  // When a run ends, read the queue and the open verdict once more.
  const wasRunning = useRef(running);
  useEffect(() => {
    if (wasRunning.current && !running) {
      client.invalidateQueries({ queryKey: ["triage", "queue", job.id] });
      client.invalidateQueries({ queryKey: ["triage", "verdict", job.id] });
    }
    wasRunning.current = running;
  }, [running, job.id, client]);

  // On a phone the verdict replaces the queue; show it from its top.
  const pane = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (state.alert && !globalThis.matchMedia?.("(min-width: 1024px)").matches) pane.current?.scrollIntoView?.({ block: "start" });
  }, [state.alert]);

  const started = job.status !== "planned" || job.progress.answered > 0;
  return (
    <>
      <JobRun job={job} />
      {queue.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not load the queue</AlertTitle>
          <AlertDescription>{queue.error.message}</AlertDescription>
        </Alert>
      )}
      {started && (
        <div className="grid items-start gap-4 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
          <div className={cn(state.alert && "hidden lg:block")}>
            <QueueView jobId={job.id} formats={job.options.formats} queue={queue.data} loading={queue.isPending} state={state} update={update} />
          </div>
          <div ref={pane} className={cn("lg:sticky lg:top-4 lg:max-h-[calc(100svh-2rem)] lg:overflow-y-auto", !state.alert && "hidden lg:block")}>
            {state.alert ? (
              <VerdictPane jobId={job.id} alertId={state.alert} formats={job.options.formats} format={state.format} running={running}
                onFormat={(format) => update({ format })} onClose={() => update({ alert: null })} />
            ) : (
              <p className="rounded-xl border border-dashed p-10 text-center text-sm text-muted-foreground">
                Pick an alert from the queue to see its verdict.
              </p>
            )}
          </div>
        </div>
      )}
    </>
  );
}
