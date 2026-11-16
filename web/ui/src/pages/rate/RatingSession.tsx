// One rater working through a batch (Plan P6 "Rate"): one item per screen,
// the calibration round first, then the rater's own shuffled order. The
// item's position is `?n=` in the URL, so a reload stays put. Every click on
// the rubric is saved at once. Log and model text is rendered as text
// (decision 016), and nothing on the screen names a condition, model,
// format or outcome.
import { useEffect, useState, type ReactNode } from "react";
import { ArrowLeft, ArrowRight, Check, CircleAlert } from "lucide-react";
import { Link, useParams, useSearchParams } from "react-router";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { ANSWER_FIELDS, firstOpen, isComplete, position, useItem, useRubric, useSave, useSession } from "@/lib/rating";
import type { RatingItem, RatingSession as Session, Rater, RubricItem, ScoreRecord } from "@/lib/types";
import { cn } from "@/lib/utils";
import { DispositionBadge, LabelText, SeverityBadge } from "../triage/badges";

export function RatingSession() {
  const { batch = "", rater: raterParam = "" } = useParams();
  if (raterParam !== "A" && raterParam !== "B") {
    return <Problem title="Unknown rater" text="The rater must be A or B." />;
  }
  return <SessionFor batch={batch} rater={raterParam} />;
}

function SessionFor({ batch, rater }: { batch: string; rater: Rater }) {
  const session = useSession(batch, rater);
  const rubric = useRubric();
  const [params, setParams] = useSearchParams();
  const n = params.get("n");

  // Arriving without ?n= opens the first unrated item and writes it into the
  // URL, so finishing an item never moves the screen on by itself.
  useEffect(() => {
    const open = session.data ? firstOpen(session.data) : null;
    if (n === null && open !== null) setParams({ n: String(open + 1) }, { replace: true });
  }, [session.data, n, setParams]);

  if (session.isPending || rubric.isPending) return <Skeleton className="mx-auto h-96 max-w-5xl" />;
  if (session.isError) return <Problem title="Could not open this batch" text={session.error.message} />;
  if (rubric.isError) return <Problem title="Could not load the rubric" text={rubric.error.message} />;

  const s = session.data;
  const open = firstOpen(s);
  const done = n === null && open === null;
  const pos = position(n, s.order.length, open ?? 0);
  const go = (n: number | null) => setParams(n === null ? {} : { n: String(n + 1) });

  return (
    <div className="mx-auto max-w-5xl space-y-4">
      <SessionHeader s={s} pos={done ? null : pos} />
      {done ? (
        <DoneCard total={s.order.length} onReview={() => go(0)} />
      ) : (
        <ItemScreen key={s.order[pos]} batch={batch} rater={rater} s={s} pos={pos} rubric={rubric.data.items} go={go} />
      )}
    </div>
  );
}

function SessionHeader({ s, pos }: { s: Session; pos: number | null }) {
  const calibration = pos !== null && s.calibration.includes(s.order[pos]);
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Link to="/rate" className="text-sm text-muted-foreground hover:underline">
          Rate
        </Link>
        <span className="text-muted-foreground">/</span>
        <span className="font-mono text-sm">{s.batch}</span>
        <Badge variant="secondary">Rater {s.rater}</Badge>
        {pos !== null && <span className="text-sm font-medium">Item {pos + 1} of {s.order.length}</span>}
        {calibration && (
          <Badge variant="outline" className="border-warn/50 bg-warn-soft text-warn">
            Calibration round
          </Badge>
        )}
        <span className="ml-auto text-sm text-muted-foreground">
          {s.progress.complete} of {s.progress.total} rated
        </span>
      </div>
      <Progress value={(100 * s.progress.complete) / Math.max(s.progress.total, 1)} aria-label="Items rated" />
    </div>
  );
}

function ItemScreen({ batch, rater, s, pos, rubric, go }: {
  batch: string;
  rater: Rater;
  s: Session;
  pos: number;
  rubric: RubricItem[];
  go: (n: number | null) => void;
}) {
  const itemId = s.order[pos];
  const item = useItem(batch, itemId);
  const last = pos + 1 === s.order.length;
  const next = () => {
    if (!last) return go(pos + 1);
    const open = firstOpen(s);
    go(open === null ? null : open);
  };
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_26rem]">
      <div className="min-w-0 space-y-4">
        {item.isPending && <Skeleton className="h-80" />}
        {item.isError && <Problem title="Could not load this item" text={item.error.message} />}
        {item.data && <AlertCard item={item.data} />}
        {item.data && <AnswerCard answer={item.data.answer} />}
        <p className="font-mono text-xs text-muted-foreground">Item {itemId}</p>
      </div>
      <div className="space-y-3 lg:sticky lg:top-4 lg:self-start">
        <RubricForm batch={batch} rater={rater} itemId={itemId} saved={s.ratings[itemId]} rubric={rubric} />
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" disabled={pos === 0} onClick={() => go(pos - 1)}>
            <ArrowLeft /> Previous
          </Button>
          <Button variant="ghost" onClick={() => go(firstOpen(s))}>
            First unrated
          </Button>
          <Button className="ml-auto" onClick={next}>
            {last ? "Finish" : "Next"} <ArrowRight />
          </Button>
        </div>
      </div>
    </div>
  );
}

// ── what the rater sees ──────────────────────────────────────────────────────
function AlertCard({ item }: { item: RatingItem }) {
  const a = item.alert;
  const body = item.body ?? {};
  return (
    <Card className="gap-3">
      <CardHeader>
        <CardTitle className="text-lg leading-snug break-words">{a.rule?.description ?? "(no rule description)"}</CardTitle>
        <CardDescription>
          Wazuh rule {a.rule?.id ?? "?"} · level {a.rule?.level ?? "?"}
          {a.timestamp && ` · ${a.timestamp}`}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {a.full_log && <Pre text={a.full_log} />}
        {body.request_body && <Raw title="Request body" text={body.request_body} />}
        {body.response_body && <Raw title="Response body" text={body.response_body} />}
        {!body.request_body && !body.response_body && (
          <p className="text-xs text-muted-foreground">No request or response body came with this alert.</p>
        )}
        <Raw title="Raw alert" text={JSON.stringify(a, null, 2)} />
      </CardContent>
    </Card>
  );
}

function AnswerCard({ answer }: { answer: Record<string, unknown> }) {
  return (
    <Card className="gap-3">
      <CardHeader>
        <CardTitle className="text-base">Triage answer</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="space-y-3">
          {ANSWER_FIELDS.map(([key, label]) => {
            const v = answer[key];
            if (v === undefined || v === null || v === "" || (Array.isArray(v) && v.length === 0)) return null;
            return (
              <Row key={key} label={label}>
                <AnswerValue field={key} value={v} />
              </Row>
            );
          })}
        </dl>
      </CardContent>
    </Card>
  );
}

function AnswerValue({ field, value }: { field: string; value: unknown }) {
  const text = Array.isArray(value) ? value.join(", ") : String(value);
  switch (field) {
    case "disposition":
      return <DispositionBadge value={text} />;
    case "severity":
      return <SeverityBadge value={text} />;
    case "technique_label":
      return <LabelText value={text} />;
    case "candidate_labels":
    case "evidence":
      return <span className="font-mono text-xs">{text}</span>;
    case "confidence":
      return <span className="font-medium capitalize">{text}</span>;
    case "recommended_action":
      return <span className="font-medium">{text}</span>;
    default:
      return <>{text}</>;
  }
}

// ── the rubric, autosaved ────────────────────────────────────────────────────
function RubricForm({ batch, rater, itemId, saved, rubric }: {
  batch: string;
  rater: Rater;
  itemId: string;
  saved: ScoreRecord | undefined;
  rubric: RubricItem[];
}) {
  const save = useSave(batch, rater);
  const [local, setLocal] = useState<ScoreRecord>(saved ?? {});
  const choose = (id: RubricItem["id"], value: number | string) => {
    setLocal((r) => ({ ...r, [id]: value }));
    save.mutate({ item: itemId, scores: { [id]: value } });
  };
  return (
    <Card className="gap-3 py-4">
      <CardContent className="space-y-4 px-4">
        {rubric.map((spec) => (
          <RubricField key={spec.id} spec={spec} value={local[spec.id]} onChoose={(v) => choose(spec.id, v)} />
        ))}
        <SaveState pending={save.isPending} error={save.error?.message} complete={isComplete(local)} saved={!!saved?.saved_at || save.isSuccess} />
      </CardContent>
    </Card>
  );
}

function RubricField({ spec, value, onChoose }: { spec: RubricItem; value: unknown; onChoose: (v: number | string) => void }) {
  const options: { value: number | string; label: string; anchor?: string }[] = spec.options
    ? spec.options
    : Array.from({ length: spec.scale![1] - spec.scale![0] + 1 }, (_, i) => {
        const v = spec.scale![0] + i;
        return { value: v, label: String(v), anchor: spec.anchors?.[String(v)] };
      });
  return (
    <fieldset className="space-y-1.5">
      <legend className="text-sm font-medium">
        {spec.id} · {spec.name}
      </legend>
      <p className="text-xs text-muted-foreground">{spec.question}</p>
      <div className={cn("grid gap-1.5", spec.options ? "grid-cols-1" : "grid-cols-5")}>
        {options.map((o) => {
          const checked = value === o.value;
          return (
            <label key={o.value} className="relative cursor-pointer">
              <input type="radio" name={spec.id} value={String(o.value)} checked={checked} onChange={() => onChoose(o.value)} className="peer sr-only" />
              <span
                className={cn(
                  "flex h-full flex-col items-center justify-start rounded-md border px-1.5 py-1.5 text-center text-sm peer-focus-visible:ring-2 peer-focus-visible:ring-ring",
                  checked ? "border-primary bg-primary text-primary-foreground" : "hover:bg-accent",
                  spec.options && "items-start px-3 text-left",
                )}
              >
                <span className="font-medium">{o.label}</span>
                {o.anchor && <span className={cn("text-[0.7rem] leading-tight", checked ? "text-primary-foreground/80" : "text-muted-foreground")}>{o.anchor}</span>}
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}

function SaveState({ pending, error, complete, saved }: { pending: boolean; error?: string; complete: boolean; saved: boolean }) {
  if (error) {
    return (
      <p className="flex items-start gap-1.5 text-sm text-destructive" role="alert">
        <CircleAlert className="mt-0.5 size-4 shrink-0" /> Not saved: {error}
      </p>
    );
  }
  if (pending) return <p className="text-sm text-muted-foreground">Saving…</p>;
  return (
    <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
      {saved && <Check className="size-4 text-ok" />}
      {complete ? "All five saved." : saved ? "Saved. Score all five to finish this item." : "Score all five; each click is saved."}
    </p>
  );
}

// ── small parts ──────────────────────────────────────────────────────────────
function DoneCard({ total, onReview }: { total: number; onReview: () => void }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>All {total} items are rated</CardTitle>
        <CardDescription>Thank you. Your scores are saved. You can still go back and change any of them.</CardDescription>
      </CardHeader>
      <CardContent className="flex gap-2">
        <Button variant="outline" onClick={onReview}>
          Review the items
        </Button>
        <Button asChild variant="ghost">
          <Link to="/rate">Back to Rate</Link>
        </Button>
      </CardContent>
    </Card>
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

function Pre({ text }: { text: string }) {
  return <pre className="max-h-64 overflow-auto rounded-md bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere]">{text}</pre>;
}

function Raw({ title, text }: { title: string; text: string }) {
  return (
    <details className="rounded-lg border">
      <summary className="cursor-pointer px-3 py-2 text-sm font-medium select-none">{title}</summary>
      <pre className="max-h-96 overflow-auto border-t bg-muted/40 p-3 font-mono text-xs whitespace-pre-wrap [overflow-wrap:anywhere]">{text}</pre>
    </details>
  );
}

function Problem({ title, text }: { title: string; text: string }) {
  return (
    <Alert variant="destructive" className="mx-auto max-w-xl">
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        {text}{" "}
        <Link to="/rate" className="underline underline-offset-4">
          Back to Rate
        </Link>
      </AlertDescription>
    </Alert>
  );
}
