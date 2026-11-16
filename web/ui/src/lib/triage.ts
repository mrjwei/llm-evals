// The Triage page's server state (/api/triage/*) and the words it uses.
// The wording rules come from decision 015: calibration is a track record
// "in evaluation", never a probability; the instruction flag is a warning
// that can be evaded, never a guarantee.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, query } from "./api";
import { count, plural, usd } from "./format";
import type {
  Arm,
  Calibration,
  CalibrationLevel,
  Feedback,
  Format,
  Job,
  JobSource,
  JobStatus,
  Lane,
  NewJob,
  Queue,
  Sources,
  VerdictDetail,
} from "./types";

const JOBS = "/api/triage/jobs";
const POLL_MS = 1000;

export const RESTARTABLE: JobStatus[] = ["planned", "stopped", "failed", "interrupted"];

// ── queries ──────────────────────────────────────────────────────────────────
export function useSources() {
  return useQuery({ queryKey: ["triage", "sources"], queryFn: () => api.get<Sources>("/api/triage/sources"), staleTime: 60_000 });
}

export function useJobs() {
  return useQuery({
    queryKey: ["triage", "jobs"],
    queryFn: () => api.get<Job[]>(JOBS),
    refetchInterval: (q) => (q.state.data?.some((j) => j.status === "running") ? POLL_MS * 2 : false),
  });
}

export function useJob(jobId: string) {
  return useQuery({
    queryKey: ["triage", "job", jobId],
    queryFn: () => api.get<Job>(`${JOBS}/${jobId}`),
    refetchInterval: (q) => (q.state.data?.status === "running" ? POLL_MS : false),
  });
}

export interface QueueFilters {
  format: Format | null;
  label: string | null;
  disposition: string | null;
  source: string | null;
}

/** The queue, refreshed while the job runs so answers appear as they arrive. */
export function useQueue(jobId: string, filters: QueueFilters, running: boolean) {
  return useQuery({
    queryKey: ["triage", "queue", jobId, filters],
    queryFn: () => api.get<Queue>(`${JOBS}/${jobId}/queue${query({ ...filters })}`),
    refetchInterval: running ? POLL_MS * 2 : false,
    placeholderData: (previous) => previous,
  });
}

export function useVerdict(jobId: string, alertId: string | null, running: boolean) {
  return useQuery({
    queryKey: ["triage", "verdict", jobId, alertId],
    queryFn: () => api.get<VerdictDetail>(`${JOBS}/${jobId}/alerts/${encodeURIComponent(alertId!)}`),
    enabled: alertId !== null,
    refetchInterval: running ? POLL_MS * 3 : false,
  });
}

// ── mutations ────────────────────────────────────────────────────────────────
function useJobMutation<T>(fn: (arg: T) => Promise<Job>) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: (job) => {
      client.setQueryData(["triage", "job", job.id], job);
      client.invalidateQueries({ queryKey: ["triage", "jobs"] });
    },
  });
}

/** Capture a source, plan and estimate. Spends nothing. */
export function useCreateJob() {
  return useJobMutation((job: NewJob) => api.post<Job>(JOBS, job));
}

/** Run or resume, approving at most `maxCalls` paid calls (decision 014). */
export function useStartJob(jobId: string) {
  return useJobMutation((maxCalls: number) => api.post<Job>(`${JOBS}/${jobId}/start`, { max_calls: maxCalls }));
}

export function useStopJob(jobId: string) {
  return useJobMutation(() => api.post<Job>(`${JOBS}/${jobId}/stop`));
}

export function useReestimate(jobId: string) {
  return useJobMutation(() => api.post<Job>(`${JOBS}/${jobId}/estimate`));
}

export function useFeedback(jobId: string, alertId: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (body: { format: Format; verdict: Feedback["verdict"]; note?: string | null }) =>
      api.post<Feedback>(`${JOBS}/${jobId}/alerts/${encodeURIComponent(alertId)}/feedback`, body),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["triage", "verdict", jobId, alertId] });
      client.invalidateQueries({ queryKey: ["triage", "queue", jobId] });
    },
  });
}

export const exportUrl = (jobId: string, ext: "csv" | "json") => `${JOBS}/${jobId}/export.${ext}`;

// ── words ────────────────────────────────────────────────────────────────────
export const ARM_WORDS: Record<Arm, string> = {
  "S1-plain": "S1 · plain access log",
  "S2-body-in-url": "S2 · body appended to the URL",
  "S3-body-field": "S3 · body in its own log field",
};

export const LANE_WORDS: Record<Lane, string> = {
  queue: "To act on",
  human: "Needs a human",
  pending: "Not triaged yet",
};

export const DISPOSITION_WORDS: Record<string, string> = {
  escalate: "Escalate",
  needs_more_info: "Needs more info",
  dismiss_false_positive: "Dismiss (false positive)",
};

export const STATUS_WORDS: Record<JobStatus, string> = {
  planned: "Ready to run",
  running: "Running",
  complete: "Complete",
  stopped: "Stopped",
  failed: "Failed",
  interrupted: "Interrupted",
};

export const FORMAT_WORDS: Record<Format, string> = {
  A: "Format A · full answer",
  B: "Format B · decision only",
};

export function disposition(value: string | undefined): string {
  return value ? (DISPOSITION_WORDS[value] ?? value) : "";
}

export function sourceSummary(source: JobSource): string {
  switch (source.kind) {
    case "demo":
      return `Demo · ${source.corpus} ${source.session} · ${ARM_WORDS[source.arm] ?? source.arm}`;
    case "upload":
      return `Upload · ${source.filename}${source.ingest_log ? " (with ingest log)" : ""}`;
    case "live": {
      const t = (iso: string) => new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
      return `Live Wazuh · ${t(source.start)} to ${t(source.end)} · ${ARM_WORDS[source.arm] ?? source.arm}${source.agent ? ` · agent ${source.agent}` : ""}`;
    }
  }
}

/** The estimate as the approval dialog states it. */
export function estimateWords(job: Job): { headline: string; details: string[] } {
  const e = job.estimate;
  const answers = job.progress.total - job.progress.answered;
  if (e.calls === 0) {
    return {
      headline: `Free: all ${plural(answers, "answer")} come from the cache.`,
      details: ["Nothing is sent to Claude, so nothing is billed."],
    };
  }
  const details = [
    `${count(e.input_tokens)} input tokens to ${job.model_id}.`,
    `The most it can cost assumes every answer uses its full ${count(e.max_tokens)}-token limit, so the real cost is lower (list prices of ${e.price_retrieved}).`,
  ];
  if (e.cached) details.unshift(`${plural(e.cached, "answer")} come from the cache for free.`);
  if (e.method) details.push(`Tokens counted by ${e.method}.`);
  return { headline: `${plural(e.calls, "paid call")} to Claude, at most ${usd(e.cost_max_usd)}.`, details };
}

const DIFFERS_WORDS: Record<Calibration["differs"][number], string> = {
  model: "model",
  format: "output format",
  arm: "SIEM log arm",
  bodies: "request-bodies setting",
};

function levelWords(what: string, level: CalibrationLevel | null): string {
  if (!level || level.committed === 0) return `no ${what} answers to compare`;
  const n = `the right ${what} ${count(level.correct)} of ${count(level.committed)} times`;
  return level.enough ? n : `${n} (too few to judge)`;
}

/** The calibration chip in words: a track record in evaluation, with n,
 * never a probability (decision 015). */
export function calibrationWords(c: Calibration): { headline: string; source: string; caveat: string | null } {
  const headline =
    `In evaluation on ${c.measured_on.corpus}, “${c.confidence}” answers had ` +
    `${levelWords("label", c.label)} and ${levelWords("disposition", c.disposition)}.`;
  const source = `Measured in ${c.measured_on.experiment}, condition ${c.measured_on.condition}.`;
  const caveat = c.differs.length
    ? `That condition used a different ${c.differs.map((d) => DIFFERS_WORDS[d]).join(", ")} from this job.`
    : null;
  return { headline, source, caveat };
}
