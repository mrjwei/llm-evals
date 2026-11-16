// Verdict detail (Plan P6 "Verdict detail"): one alert's answer in the
// chosen format, the calibration chip, the instruction-like-text warning,
// analyst feedback, and the raw alert and bodies, collapsed. Everything
// from the log or the model is rendered as text (decision 016).
import { useState, type ReactNode } from "react";
import { ArrowLeft, ThumbsDown, ThumbsUp, X } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { dateTime } from "@/lib/format";
import { LANE_WORDS, disposition, useFeedback, useVerdict } from "@/lib/triage";
import type { Format, Verdict, VerdictDetail } from "@/lib/types";
import { cn } from "@/lib/utils";
import { CalibrationChip } from "./CalibrationChip";
import { DispositionBadge, LabelText, SeverityBadge } from "./badges";
import { InstructionWarning } from "./InstructionWarning";
import { FormatToggle } from "./QueueView";

const NOTE_MAX = 500;

export function VerdictPane({ jobId, alertId, formats, format, running, onFormat, onClose }: {
  jobId: string;
  alertId: string;
  formats: Format[];
  format: Format;
  running: boolean;
  onFormat: (f: Format) => void;
  onClose: () => void;
}) {
  const verdict = useVerdict(jobId, alertId, running);
  return (
    <Card className="gap-4">
      <CardHeader className="gap-2">
        <div className="flex items-center justify-between gap-2">
          <Button variant="ghost" size="sm" className="-ml-2 lg:hidden" onClick={onClose}>
            <ArrowLeft /> Queue
          </Button>
          <FormatToggle formats={formats} value={format} onChange={onFormat} />
          <Button variant="ghost" size="icon" className="ml-auto hidden lg:inline-flex" onClick={onClose} aria-label="Close the verdict">
            <X />
          </Button>
        </div>
        {verdict.data && <VerdictHeader detail={verdict.data} />}
      </CardHeader>
      <CardContent className="space-y-5">
        {verdict.isPending && <Skeleton className="h-64" />}
        {verdict.isError && (
          <Alert variant="destructive">
            <AlertTitle>Could not open this alert</AlertTitle>
            <AlertDescription>{verdict.error.message}</AlertDescription>
          </Alert>
        )}
        {verdict.data && <VerdictBody jobId={jobId} detail={verdict.data} format={format} />}
      </CardContent>
    </Card>
  );
}

function VerdictHeader({ detail }: { detail: VerdictDetail }) {
  return (
    <>
      <CardTitle className="text-lg leading-snug break-words">{detail.rule.description ?? "(no rule description)"}</CardTitle>
      <CardDescription className="flex flex-wrap gap-x-3 gap-y-1">
        <span>Wazuh rule {detail.rule.id ?? "?"} · level {detail.rule.level ?? "?"}</span>
        <span>{dateTime(detail.timestamp)}</span>
        <span className="break-all">{detail.source}</span>
        <span className="font-mono text-xs break-all">alert {detail.alert_id}</span>
      </CardDescription>
    </>
  );
}

function VerdictBody({ jobId, detail, format }: { jobId: string; detail: VerdictDetail; format: Format }) {
  const v = detail.verdicts[format] ?? { status: "pending" as const };
  const other = (Object.keys(detail.verdicts) as Format[]).find((f) => f !== format);
  return (
    <>
      <InstructionWarning flag={detail.instruction_like} />
      {v.lane === "human" && (
        <p className="rounded-md bg-warn-soft/60 px-3 py-2 text-sm">
          <span className="font-medium">{LANE_WORDS.human}:</span> {v.human_reasons?.join(", ")}.
        </p>
      )}
      <Answer v={v} note={detail.calibration_note} />
      {detail.formats_agree === false && other && <Disagreement format={format} other={other} v={detail.verdicts[other]!} />}
      {v.status === "ok" && <FeedbackBox key={`${detail.alert_id}-${format}`} jobId={jobId} detail={detail} format={format} />}
      <Raw title="Raw alert" text={JSON.stringify(detail.alert, null, 2)} />
      {detail.body?.request_body && <Raw title="Request body" text={detail.body.request_body} />}
      {detail.body?.response_body && <Raw title="Response body" text={detail.body.response_body} />}
      {!detail.has_body && <p className="text-xs text-muted-foreground">No request or response body was attached to this alert.</p>}
    </>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid gap-1 sm:grid-cols-[10rem_1fr]">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-sm break-words">{children}</dd>
    </div>
  );
}

export function Answer({ v, note }: { v: Verdict; note?: string | null }) {
  if (v.status === "pending") return <p className="text-sm text-muted-foreground">Not triaged yet.</p>;
  if (v.status === "api_error") {
    return (
      <Alert variant="destructive">
        <AlertTitle>The call to Claude failed</AlertTitle>
        <AlertDescription>{v.error ?? "unknown error"}. Resume the job to retry it.</AlertDescription>
      </Alert>
    );
  }
  if (v.status === "invalid") {
    return (
      <Alert variant="destructive">
        <AlertTitle>No usable answer</AlertTitle>
        <AlertDescription>{v.errors?.join("; ")}</AlertDescription>
      </Alert>
    );
  }
  return (
    <dl className="space-y-3">
      <Row label="Disposition">
        <span className="flex flex-wrap items-center gap-2">
          <DispositionBadge value={v.disposition} />
          {v.severity && <SeverityBadge value={v.severity} />}
          {v.cache_hit && <Badge variant="secondary">from cache</Badge>}
        </span>
      </Row>
      <Row label="Technique">
        <LabelText value={v.technique_label} />
        {v.candidate_labels && v.candidate_labels.length > 0 && (
          <span className="block text-xs text-muted-foreground">
            Could be: <span className="font-mono">{v.candidate_labels.join(", ")}</span>
          </span>
        )}
      </Row>
      <Row label="Confidence">
        <span className="font-medium capitalize">{v.confidence}</span>
        <div className="mt-1.5">
          <CalibrationChip calibration={v.calibration} note={note} />
        </div>
      </Row>
      {v.recommended_action && (
        <Row label="Recommended action">
          <span className="font-medium">{v.recommended_action}</span>
        </Row>
      )}
      {v.event_type && <Row label="What happened">{v.event_type}</Row>}
      {v.reasoning && <Row label="Reasoning">{v.reasoning}</Row>}
      {v.evidence && <Row label="Evidence"><span className="font-mono text-xs">{v.evidence}</span></Row>}
      {v.cognitive_notes && <Row label="Context">{v.cognitive_notes}</Row>}
    </dl>
  );
}

function Disagreement({ format, other, v }: { format: Format; other: Format; v: Verdict }) {
  return (
    <p className="rounded-md border border-dashed px-3 py-2 text-sm">
      <span className="font-medium">Format {other} answered differently:</span> {disposition(v.disposition)},{" "}
      <span className="font-mono">{v.technique_label}</span>, {v.confidence} confidence. Switch to Format {other} above to see it in full
      (this is Format {format}).
    </p>
  );
}

function FeedbackBox({ jobId, detail, format }: { jobId: string; detail: VerdictDetail; format: Format }) {
  const saved = detail.feedback[format] ?? null;
  const send = useFeedback(jobId, detail.alert_id);
  const [note, setNote] = useState(saved?.note ?? "");

  const choose = (verdict: "agree" | "disagree" | null) =>
    send.mutate({ format, verdict, note: verdict ? note.trim() || null : null });

  return (
    <div className="space-y-2 rounded-lg border p-3">
      <p className="text-sm font-medium">Do you agree with this verdict?</p>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant={saved?.verdict === "agree" ? "default" : "outline"} onClick={() => choose("agree")} disabled={send.isPending}
          aria-pressed={saved?.verdict === "agree"}>
          <ThumbsUp /> Agree
        </Button>
        <Button size="sm" variant={saved?.verdict === "disagree" ? "default" : "outline"} onClick={() => choose("disagree")}
          disabled={send.isPending} aria-pressed={saved?.verdict === "disagree"}>
          <ThumbsDown /> Disagree
        </Button>
        {saved && (
          <Button size="sm" variant="ghost" onClick={() => { setNote(""); choose(null); }} disabled={send.isPending}>
            Clear
          </Button>
        )}
      </div>
      <Textarea value={note} maxLength={NOTE_MAX} onChange={(e) => setNote(e.target.value)} placeholder="Optional note, saved with your choice"
        aria-label="Feedback note" className="min-h-14 text-sm" />
      {send.error && <p className="text-sm text-destructive">{send.error.message}</p>}
      <p className="text-xs text-muted-foreground">
        {saved ? `Saved: you ${saved.verdict === "agree" ? "agreed" : "disagreed"}${saved.at ? ` (${dateTime(saved.at)})` : ""}. ` : ""}
        Kept with this job to improve the app. It is never used as research data.
      </p>
    </div>
  );
}

function Raw({ title, text }: { title: string; text: string }) {
  return (
    <details className="group rounded-lg border">
      <summary className="cursor-pointer px-3 py-2 text-sm font-medium select-none">{title}</summary>
      <pre className={cn("max-h-96 overflow-auto border-t bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere]")}>{text}</pre>
    </details>
  );
}
