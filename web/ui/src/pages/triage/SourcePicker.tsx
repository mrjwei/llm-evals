// The source picker (Plan P6 "Source picker"): a demo session with ground
// truth hidden, an uploaded alerts .jsonl, or a live Wazuh window; the
// bodies toggle; formats and model. Submitting creates a `planned` job:
// alerts captured and the cost estimated, nothing sent to Claude yet.
import { useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { Loader2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SOURCE_NAMES } from "@/components/HealthPanel";
import { useHealth } from "@/lib/queries";
import { ARM_WORDS, FORMAT_WORDS, useCreateJob } from "@/lib/triage";
import type { Arm, Format, NewSource, SourceKind, Sources } from "@/lib/types";

function Field({ label, htmlFor, hint, children }: { label: string; htmlFor: string; hint?: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function Choice<T extends string>({ id, value, onChange, options }: {
  id: string;
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string }[];
}) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as T)}>
      <SelectTrigger id={id} className="w-full">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

const MB = 2 ** 20;

/** A local datetime-local value as an ISO time with its offset (UTC). */
export function localToIso(value: string): string {
  return new Date(value).toISOString();
}

export function SourcePicker({ sources }: { sources: Sources }) {
  const navigate = useNavigate();
  const health = useHealth();
  const create = useCreateJob();

  const [kind, setKind] = useState<SourceKind>("demo");
  const [corpus, setCorpus] = useState(sources.demo.default_corpus);
  const corpusSessions = sources.demo.corpora.find((c) => c.id === corpus)?.sessions ?? [];
  const [session, setSession] = useState(corpusSessions[0]?.name ?? "");
  const [arm, setArm] = useState<Arm>("S1-plain");
  const [alertsFile, setAlertsFile] = useState<File | null>(null);
  const [ingestFile, setIngestFile] = useState<File | null>(null);
  const [windowMode, setWindowMode] = useState<"minutes" | "range">("minutes");
  const [minutes, setMinutes] = useState("60");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [agent, setAgent] = useState("");
  const [limit, setLimit] = useState(String(sources.live.default_limit));
  const [bodies, setBodies] = useState(true);
  const [formats, setFormats] = useState<Format[]>(["A", "B"]);
  const [model, setModel] = useState(sources.default_model);
  const [formError, setFormError] = useState<string | null>(null);

  const ready = health.data?.ready[kind];
  const blocked = ready?.status === "fail";

  function pickCorpus(id: string) {
    setCorpus(id);
    setSession(sources.demo.corpora.find((c) => c.id === id)?.sessions[0]?.name ?? "");
  }

  function toggleFormat(f: Format, on: boolean) {
    setFormats((prev) => (on ? [...prev, f].sort() : prev.filter((x) => x !== f)) as Format[]);
  }

  async function buildSource(): Promise<NewSource> {
    if (kind === "demo") return { kind, corpus, session, arm };
    if (kind === "upload") {
      if (!alertsFile) throw new Error("Choose a Wazuh alerts file (.jsonl) first.");
      for (const f of [alertsFile, ingestFile]) {
        if (f && f.size > sources.max_upload_bytes) {
          throw new Error(`${f.name} is larger than ${sources.max_upload_bytes / MB} MB; split it into smaller files.`);
        }
      }
      return {
        kind,
        content: await alertsFile.text(),
        filename: alertsFile.name,
        ingest_log: bodies && ingestFile ? await ingestFile.text() : null,
      };
    }
    const common = { kind, arm, agent: agent.trim() || null, limit: Number(limit) } as const;
    if (windowMode === "minutes") return { ...common, minutes: Number(minutes) };
    if (!start) throw new Error("Give a start time for the window.");
    return { ...common, start: localToIso(start), end: end ? localToIso(end) : undefined };
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);
    if (formats.length === 0) return setFormError("Pick at least one output format.");
    let source: NewSource;
    try {
      source = await buildSource();
    } catch (err) {
      return setFormError((err as Error).message);
    }
    create.mutate(
      { source, bodies, formats, model },
      { onSuccess: (job) => navigate(`/triage/jobs/${job.id}`) },
    );
  }

  const sessionAlerts = (name: string) => corpusSessions.find((s) => s.name === name)?.alerts?.[arm];

  return (
    <Card>
      <CardHeader>
        <CardTitle>New triage</CardTitle>
        <CardDescription>
          Pick the alerts. The next step shows what the run would cost; nothing is sent to Claude until you approve it.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="space-y-6">
          <Tabs value={kind} onValueChange={(v) => setKind(v as SourceKind)}>
            <TabsList className="w-full sm:w-auto">
              {(Object.keys(SOURCE_NAMES) as SourceKind[]).map((k) => (
                <TabsTrigger key={k} value={k}>
                  {SOURCE_NAMES[k]}
                </TabsTrigger>
              ))}
            </TabsList>

            <TabsContent value="demo" className="grid gap-4 pt-2 sm:grid-cols-3">
              <p className="text-sm text-muted-foreground sm:col-span-3">
                One session of a frozen research corpus. Ground truth stays hidden: only the alerts and their bodies are copied.
              </p>
              <Field label="Corpus" htmlFor="demo-corpus">
                <Choice id="demo-corpus" value={corpus} onChange={pickCorpus}
                  options={sources.demo.corpora.map((c) => ({ value: c.id, label: c.id }))} />
              </Field>
              <Field label="Session" htmlFor="demo-session">
                <Choice id="demo-session" value={session} onChange={setSession}
                  options={corpusSessions.map((s) => ({
                    value: s.name,
                    label: sessionAlerts(s.name) !== undefined ? `${s.name} (${sessionAlerts(s.name)} alerts)` : s.name,
                  }))} />
              </Field>
              <Field label="SIEM log arm" htmlFor="demo-arm">
                <Choice id="demo-arm" value={arm} onChange={setArm} options={sources.arms.map((a) => ({ value: a, label: ARM_WORDS[a] ?? a }))} />
              </Field>
            </TabsContent>

            <TabsContent value="upload" className="grid gap-4 pt-2 sm:grid-cols-2">
              <p className="text-sm text-muted-foreground sm:col-span-2">
                A Wazuh alerts file with one JSON alert per line, up to {sources.max_alerts} alerts and {sources.max_upload_bytes / MB} MB.
              </p>
              <Field label="Alerts (.jsonl)" htmlFor="upload-alerts">
                <Input id="upload-alerts" type="file" accept=".jsonl,.json,.ndjson,application/json"
                  onChange={(e) => setAlertsFile(e.target.files?.[0] ?? null)} />
              </Field>
              <Field label="Ingest log (optional)" htmlFor="upload-ingest" hint="The proxy's ingest_log.jsonl, to attach request bodies by correlation ID.">
                <Input id="upload-ingest" type="file" accept=".jsonl,.json,.ndjson,application/json" disabled={!bodies}
                  onChange={(e) => setIngestFile(e.target.files?.[0] ?? null)} />
              </Field>
            </TabsContent>

            <TabsContent value="live" className="grid gap-4 pt-2 sm:grid-cols-3">
              <p className="text-sm text-muted-foreground sm:col-span-3">
                Alerts Wazuh raised in a time window, read from its indexer.
                {!sources.live.bodies_from_vm && " The VM address is not set, so no request bodies can be attached."}
              </p>
              <Field label="Window" htmlFor="live-window">
                <Choice id="live-window" value={windowMode} onChange={setWindowMode}
                  options={[{ value: "minutes", label: "The last N minutes" }, { value: "range", label: "Between two times" }]} />
              </Field>
              {windowMode === "minutes" ? (
                <Field label="Minutes" htmlFor="live-minutes">
                  <Input id="live-minutes" type="number" min={1} max={sources.live.max_minutes} value={minutes}
                    onChange={(e) => setMinutes(e.target.value)} />
                </Field>
              ) : (
                <>
                  <Field label="From (your time)" htmlFor="live-start">
                    <Input id="live-start" type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
                  </Field>
                  <Field label="To (empty = now)" htmlFor="live-end">
                    <Input id="live-end" type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
                  </Field>
                </>
              )}
              <Field label="SIEM log arm" htmlFor="live-arm">
                <Choice id="live-arm" value={arm} onChange={setArm} options={sources.arms.map((a) => ({ value: a, label: ARM_WORDS[a] ?? a }))} />
              </Field>
              <Field label="Agent (optional)" htmlFor="live-agent" hint="An agent ID like 001, or its name.">
                <Input id="live-agent" value={agent} onChange={(e) => setAgent(e.target.value)} placeholder="all agents" />
              </Field>
              <Field label="At most this many alerts" htmlFor="live-limit">
                <Input id="live-limit" type="number" min={1} max={sources.max_alerts} value={limit} onChange={(e) => setLimit(e.target.value)} />
              </Field>
            </TabsContent>
          </Tabs>

          <div className="grid gap-4 border-t pt-4 sm:grid-cols-3">
            <div className="flex items-start gap-3">
              <Switch id="bodies" checked={bodies} onCheckedChange={setBodies} />
              <Label htmlFor="bodies" className="block leading-snug">
                Attach request bodies when available
                <span className="block text-xs font-normal text-muted-foreground">More evidence for Claude; bodies are shown in each verdict.</span>
              </Label>
            </div>
            <fieldset className="space-y-2">
              <legend className="text-sm font-medium">Output formats</legend>
              {sources.formats.map((f) => (
                <div key={f} className="flex items-center gap-2">
                  <Checkbox id={`format-${f}`} checked={formats.includes(f)} onCheckedChange={(on) => toggleFormat(f, on === true)} />
                  <Label htmlFor={`format-${f}`} className="font-normal">{FORMAT_WORDS[f]}</Label>
                </div>
              ))}
              <p className="text-xs text-muted-foreground">Both lets you compare them on each verdict, and doubles the calls.</p>
            </fieldset>
            <Field label="Model" htmlFor="model">
              <Choice id="model" value={model} onChange={setModel}
                options={Object.entries(sources.models).map(([alias, id]) => ({
                  value: alias,
                  label: `${alias} (${id})${alias === sources.default_model ? ", default" : ""}`,
                }))} />
            </Field>
          </div>

          {blocked && (
            <Alert variant="destructive">
              <AlertTitle>{SOURCE_NAMES[kind]} can't run right now</AlertTitle>
              <AlertDescription>
                <p>
                  Not working: {ready.blocking.join(", ")}. <Link to="/" className="underline underline-offset-4">Home</Link> shows how to fix it.
                </p>
              </AlertDescription>
            </Alert>
          )}
          {(formError || create.error) && (
            <Alert variant="destructive">
              <AlertTitle>Could not prepare the job</AlertTitle>
              <AlertDescription>{formError ?? create.error?.message}</AlertDescription>
            </Alert>
          )}

          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={create.isPending || blocked}>
              {create.isPending && <Loader2 className="animate-spin" />}
              {create.isPending ? "Reading alerts and estimating…" : "Prepare and estimate"}
            </Button>
            <span className="text-sm text-muted-foreground">Nothing is sent to Claude at this step.</span>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
