// The queue (Plan P6 "Queue"): three lanes sorted by the server (escalate →
// needs more info → dismiss, then severity), a format toggle that re-sorts
// by the other format's answers, filters by label, disposition and source,
// and the export links.
import { Download, GitCompare, MessageSquare } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { dateTime } from "@/lib/format";
import { LANE_WORDS, disposition, exportUrl } from "@/lib/triage";
import type { Format, Lane, Queue, QueueItem } from "@/lib/types";
import { cn } from "@/lib/utils";
import { DispositionBadge, InstructionIcon, LabelText, SeverityBadge } from "./badges";

const ALL = "__all";
const LANES: Lane[] = ["queue", "human", "pending"];

export interface QueueState {
  format: Format;
  lane: Lane;
  label: string | null;
  disposition: string | null;
  source: string | null;
  alert: string | null;
}

export function FormatToggle({ formats, value, onChange }: { formats: Format[]; value: Format; onChange: (f: Format) => void }) {
  if (formats.length < 2) return null;
  return (
    <Tabs value={value} onValueChange={(v) => onChange(v as Format)}>
      <TabsList aria-label="Output format">
        {formats.map((f) => (
          <TabsTrigger key={f} value={f}>
            Format {f}
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  );
}

function Filter({ id, label, value, counts, words, onChange }: {
  id: string;
  label: string;
  value: string | null;
  counts: Record<string, number>;
  words?: (v: string) => string;
  onChange: (v: string | null) => void;
}) {
  return (
    <Select value={value ?? ALL} onValueChange={(v) => onChange(v === ALL ? null : v)}>
      <SelectTrigger id={id} size="sm" aria-label={label} className="max-w-full min-w-0">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={ALL}>Any {label.toLowerCase()}</SelectItem>
        {Object.entries(counts).map(([v, n]) => (
          <SelectItem key={v} value={v}>
            {words ? words(v) : v} ({n})
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function QueueView({ jobId, formats, queue, loading, state, update }: {
  jobId: string;
  formats: Format[];
  queue: Queue | undefined;
  loading: boolean;
  state: QueueState;
  update: (patch: Partial<QueueState>) => void;
}) {
  const filtered = queue && (state.label || state.disposition || state.source);
  const items = queue?.lanes[state.lane] ?? [];
  return (
    <section aria-label="Queue" className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <FormatToggle formats={formats} value={state.format} onChange={(format) => update({ format })} />
        <div className="ml-auto flex gap-2">
          <Button asChild variant="outline" size="sm">
            <a href={exportUrl(jobId, "csv")} download>
              <Download /> CSV
            </a>
          </Button>
          <Button asChild variant="outline" size="sm">
            <a href={exportUrl(jobId, "json")} download>
              <Download /> JSON
            </a>
          </Button>
        </div>
      </div>

      <Tabs value={state.lane} onValueChange={(v) => update({ lane: v as Lane, alert: null })}>
        <TabsList className="w-full">
          {LANES.map((lane) => (
            <TabsTrigger key={lane} value={lane} className="text-xs sm:text-sm">
              {LANE_WORDS[lane]} ({queue?.lanes[lane].length ?? "…"})
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {queue && (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          <Filter id="f-label" label="Label" value={state.label} counts={queue.facets.label} onChange={(label) => update({ label })} />
          <Filter id="f-disposition" label="Disposition" value={state.disposition} counts={queue.facets.disposition}
            words={disposition} onChange={(d) => update({ disposition: d })} />
          <Filter id="f-source" label="Source" value={state.source} counts={queue.facets.source} onChange={(source) => update({ source })} />
          {filtered && (
            <Button variant="link" size="sm" className="justify-start px-0 sm:col-span-3"
              onClick={() => update({ label: null, disposition: null, source: null })}>
              Clear filters
            </Button>
          )}
        </div>
      )}

      {loading && !queue && <Skeleton className="h-64" />}
      {queue && items.length === 0 && (
        <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
          {state.lane === "pending" ? "Every alert has an answer." : filtered ? "No alerts match these filters." : "No alerts in this lane."}
        </p>
      )}
      <ol className="space-y-1.5">
        {items.map((item) => (
          <li key={item.alert_id}>
            <QueueRow item={item} format={state.format} selected={item.alert_id === state.alert}
              onSelect={() => update({ alert: item.alert_id })} />
          </li>
        ))}
      </ol>
    </section>
  );
}

const ROW_EDGE: Record<string, string> = {
  escalate: "border-l-fail",
  needs_more_info: "border-l-warn",
  dismiss_false_positive: "border-l-border",
};

function QueueRow({ item, format, selected, onSelect }: { item: QueueItem; format: Format; selected: boolean; onSelect: () => void }) {
  const v = item.verdicts[format] ?? { status: "pending" as const };
  const fb = item.feedback[format];
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-current={selected || undefined}
      className={cn(
        "w-full rounded-lg border border-l-4 bg-card p-2.5 text-left hover:bg-accent/60 focus-visible:outline-2",
        ROW_EDGE[v.disposition ?? ""] ?? "border-l-border",
        selected && "ring-2 ring-ring",
      )}
    >
      <div className="flex flex-wrap items-center gap-1.5">
        {v.status === "ok" ? (
          <>
            <DispositionBadge value={v.disposition} />
            <SeverityBadge value={v.severity} />
            <LabelText value={v.technique_label} />
            <span className="text-xs text-muted-foreground">{v.confidence} confidence</span>
          </>
        ) : (
          <span className="text-xs text-muted-foreground">
            {v.status === "pending" ? "Not triaged yet" : v.status === "api_error" ? "The call failed" : "No usable answer"}
          </span>
        )}
      </div>
      <p className="mt-1 truncate text-sm">{item.rule.description ?? "(no rule description)"}</p>
      <div className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
        <span>{dateTime(item.timestamp)}</span>
        <span className="truncate">{item.source}</span>
        {item.human_reasons.length > 0 && <span className="text-warn">{item.human_reasons.join(", ")}</span>}
        <InstructionIcon flag={item.instruction_like} />
        {item.formats_agree === false && (
          <span className="inline-flex items-center gap-1" title="Format A and B disagree">
            <GitCompare className="size-3.5" aria-hidden /> A and B differ
          </span>
        )}
        {fb && (
          <span className="inline-flex items-center gap-1" title="Your feedback">
            <MessageSquare className="size-3.5" aria-hidden /> you {fb.verdict === "agree" ? "agreed" : "disagreed"}
          </span>
        )}
      </div>
    </button>
  );
}
