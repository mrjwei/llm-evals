// The API's response shapes (web/api/*.py). Kept by hand: the API is small,
// and a field renamed there shows up here as a type error in `npm run build`.

export type CheckStatus = "ok" | "warn" | "fail" | "skip";
export type Readiness = "ok" | "fail" | "unknown";
export type SourceKind = "demo" | "upload" | "live";

/** GET /api/health: doctor.run_checks() plus plain words (web/api/health.py). */
export interface Health {
  checked_at: string;
  offline: boolean;
  overall: "ok" | "warn" | "fail";
  counts: Record<CheckStatus, number>;
  ready: Record<SourceKind, { status: Readiness; blocking: string[] }>;
  groups: HealthGroup[];
}

export interface HealthGroup {
  id: string;
  title: string;
  checks: HealthCheck[];
}

export interface HealthCheck {
  group: string;
  name: string;
  status: CheckStatus;
  detail: string;
  fix: string | null;
  about: string;
}

/** GET /api/info */
export interface Info {
  app: "cjp";
  version: string;
  git_describe: string;
  data_dir: string;
  ui_built: boolean;
}

// ── Triage (cjp/triage_jobs.py, cjp/triage_queue.py) ──────────────────────────
export type Format = "A" | "B";
export type Arm = "S1-plain" | "S2-body-in-url" | "S3-body-field";
export type JobStatus = "planned" | "running" | "complete" | "stopped" | "failed" | "interrupted";
export type Lane = "queue" | "human" | "pending";

/** GET /api/triage/sources */
export interface Sources {
  demo: {
    corpora: { id: string; note: string | null; sessions: { name: string; alerts: Partial<Record<Arm, number>> | null }[] }[];
    default_corpus: string;
  };
  arms: Arm[];
  formats: Format[];
  models: Record<string, string>;
  default_model: string;
  live: { bodies_from_vm: boolean; default_limit: number; max_minutes: number };
  max_alerts: number;
  max_upload_bytes: number;
}

export type NewSource =
  | { kind: "demo"; corpus: string; session: string; arm: Arm }
  | { kind: "upload"; content: string; filename: string; ingest_log?: string | null }
  | { kind: "live"; minutes?: number; start?: string; end?: string; arm: Arm; agent?: string | null; limit: number };

export interface NewJob {
  source: NewSource;
  bodies: boolean;
  formats: Format[];
  model?: string | null;
}

export type JobSource =
  | { kind: "demo"; corpus: string; session: string; arm: Arm }
  | { kind: "upload"; filename: string; sha256: string; ingest_log: boolean }
  | { kind: "live"; start: string; end: string; arm: Arm; agent: string | null; limit: number };

export interface Estimate {
  calls: number;
  cached: number;
  input_tokens: number;
  output_tokens_max: number;
  cost_max_usd: number | null;
  method: string | null;
  max_tokens: number;
  price_retrieved: string;
  estimated_at: string;
}

export interface Actual {
  calls: number;
  cache_hits: number;
  failed_calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  answers_cost_usd: number;
  unpriced: string[];
}

/** One job's job.json, with its live status (GET /api/triage/jobs/{id}). */
export interface Job {
  id: string;
  created_at: string;
  status: JobStatus;
  source: JobSource;
  options: { bodies: boolean; formats: Format[]; model: string };
  model_id: string;
  alerts: number;
  bodies_matched: number;
  warnings: string[];
  estimate: Estimate;
  progress: { total: number; answered: number };
  actual: Actual;
  error: string | null;
  finished_at?: string | null;
}

export interface CalibrationLevel {
  committed: number;
  correct: number;
  right_rate: number | null;
  enough: boolean;
}

/** How often answers at this confidence level were right in evaluation. */
export interface Calibration {
  confidence: string;
  label: CalibrationLevel | null;
  disposition: CalibrationLevel | null;
  measured_on: { experiment: string; run: string; condition: string; corpus: string };
  differs: ("model" | "format" | "arm" | "bodies")[];
  min_n: number;
}

/** One format's answer for one alert. */
export interface Verdict {
  status: "ok" | "invalid" | "api_error" | "pending";
  technique_label?: string;
  candidate_labels?: string[];
  disposition?: string;
  confidence?: string;
  recommended_action?: string;
  event_type?: string;
  severity?: string;
  reasoning?: string;
  evidence?: string;
  cognitive_notes?: string;
  errors?: string[];
  error?: string | null;
  model?: string;
  cache_hit?: boolean;
  // verdict view only
  calibration?: Calibration | null;
  lane?: Lane;
  human_reasons?: string[];
}

export interface Feedback {
  verdict: "agree" | "disagree" | null;
  note?: string | null;
  at?: string;
}

export interface InstructionFlag {
  found: { where: string; phrase: string }[];
}

export interface QueueItem {
  alert_id: string;
  timestamp: string | null;
  rule: { id: string | null; level: number | null; description: string | null };
  source: string;
  has_body: boolean;
  instruction_like: InstructionFlag | null;
  verdicts: Partial<Record<Format, Verdict>>;
  formats_agree: boolean | null;
  feedback: Partial<Record<Format, Feedback | null>>;
  lane: Lane;
  human_reasons: string[];
}

/** GET /api/triage/jobs/{id}/queue */
export interface Queue {
  job: Pick<Job, "id" | "status" | "source" | "options" | "progress">;
  format: Format;
  filters: { lane: Lane | null; label: string | null; disposition: string | null; source: string | null };
  facets: { label: Record<string, number>; disposition: Record<string, number>; source: Record<string, number>; lane: Partial<Record<Lane, number>> };
  lanes: Record<Lane, QueueItem[]>;
}

/** GET /api/triage/jobs/{id}/alerts/{alert_id} */
export interface VerdictDetail extends Omit<QueueItem, "lane" | "human_reasons"> {
  alert: Record<string, unknown>;
  body: { alert_id: string; request_body: string; response_body: string } | null;
  arm: string | null;
  calibration_note: string | null;
}

// ── Rate (Plan P6.6, /api/rating/*) ──────────────────────────────────────────
export type Rater = "A" | "B";
export type RubricId = "R1" | "R2" | "R3" | "R4" | "R5";

export interface RubricItem {
  id: RubricId;
  name: string;
  question: string;
  scale?: [number, number];
  anchors?: Record<string, string>;
  options?: { value: string; label: string }[];
}

export interface Rubric {
  version: number;
  sha256: string;
  blind: boolean;
  items: RubricItem[];
}

export type ScoreRecord = Partial<Record<RubricId, number | string | null>> & { saved_at?: string };

export interface RaterProgress {
  complete: number;
  total: number;
  next: number | null;
  calibration_complete: number;
  started_at: string | null;
  updated_at: string | null;
  via: "app" | "pack" | null;
}

export interface RatingBatch {
  id: string;
  created_at: string | null;
  items: number;
  calibration: number;
  raters: Record<Rater, RaterProgress | null>;
}

export interface RatingSession {
  batch: string;
  rater: Rater;
  order: string[];
  calibration: string[];
  ratings: Record<string, ScoreRecord>;
  progress: RaterProgress;
  rubric: { version: number; sha256: string };
}

/** What a rater may see: the alert, its body, the answer. Nothing else. */
export interface RatingItem {
  item: string;
  calibration: boolean;
  alert: Record<string, unknown> & { rule?: { id?: string; level?: number; description?: string }; timestamp?: string; full_log?: string };
  body: { request_body?: string; response_body?: string } | null;
  answer: Record<string, unknown>;
}

export interface SaveResult {
  item: string;
  record: ScoreRecord;
  progress: RaterProgress;
}

// ── Results (Plan P6.7, /api/runs) ───────────────────────────────────────────
export type RunStatus = "running" | "complete" | "failed" | "superseded";

export interface RunSummary {
  address: string;
  run_id: string;
  experiment: string;
  experiment_slug: string | null;
  question: string | null;
  rq: string[] | null;
  status: RunStatus;
  headline: string | null;
  error: string | null;
  superseded_by: string | null;
  git_describe: string | null;
  created_at: string | null;
  finished_at: string | null;
  model: string | Record<string, string> | null;
  kind: string | null;
  reps: number | null;
  corpus: string | null;
  canonical: string[];
  has_report: boolean;
}

export interface RunsList {
  runs: RunSummary[];
  experiments: string[];
  rqs: string[];
  figures: { key: string; title: string | null; from: string[] }[];
  pin_problems: string[];
}

export interface RunDetail extends RunSummary {
  conditions: { id: string; has_report: boolean }[];
  corpus_sha256: string | null;
  git_sha: string | null;
  prompt_hash: string | null;
  cache: { processed?: number; cache_hits?: number; api_calls?: number; api_errors?: number; tokens_billed?: number } | null;
  resumes: unknown[];
}

export interface RunReport {
  address: string;
  doc: string;
  markdown: string;
}
