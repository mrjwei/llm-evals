// The Home page's health tiles (Plan P6 "Home"): `cjp doctor`'s checks,
// green, amber or red, each with what it means and, when it is not ok, the
// fix. The words come from the API (web/api/health.py), so the tiles and
// `cjp doctor` can't disagree.
import { RefreshCw } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { StatusIcon } from "@/components/StatusIcon";
import { useHealth } from "@/lib/queries";
import { clockTime } from "@/lib/format";
import type { Health, HealthCheck, SourceKind } from "@/lib/types";
import { cn } from "@/lib/utils";

export const SOURCE_NAMES: Record<SourceKind, string> = {
  demo: "Demo data",
  upload: "Uploaded alerts",
  live: "Live Wazuh",
};

const TILE = {
  ok: "border-l-ok",
  warn: "border-l-warn bg-warn-soft/40",
  fail: "border-l-fail bg-fail-soft/50",
  skip: "border-l-border",
};

export function summary(health: Health): string {
  const { fail, warn } = health.counts;
  if (fail) return `${fail} ${fail === 1 ? "check is" : "checks are"} failing. Each red tile below says how to fix it.`;
  if (warn) return `Everything needed is working, with ${warn} ${warn === 1 ? "warning" : "warnings"}.`;
  return "Everything is working.";
}

export function HealthTile({ check }: { check: HealthCheck }) {
  return (
    <li className={cn("min-w-0 rounded-lg border border-l-4 bg-card p-3", TILE[check.status])}>
      <div className="flex items-start gap-2">
        <StatusIcon status={check.status} className="mt-0.5" />
        <div className="min-w-0 space-y-1">
          <p className="font-medium leading-tight">{check.name}</p>
          {check.about && <p className="text-sm">{check.about}</p>}
          <p className="font-mono [overflow-wrap:anywhere] text-xs text-muted-foreground">{check.detail}</p>
          {check.fix && check.status !== "ok" && (
            <p className="rounded-md bg-background/80 p-2 text-sm">
              <span className="font-medium">To fix: </span>
              <span className="font-mono [overflow-wrap:anywhere] text-xs">{check.fix}</span>
            </p>
          )}
        </div>
      </div>
    </li>
  );
}

export function Readiness({ health }: { health: Health }) {
  return (
    <ul className="flex flex-wrap gap-2" aria-label="What can run now">
      {(Object.keys(SOURCE_NAMES) as SourceKind[]).map((kind) => {
        const r = health.ready[kind];
        return (
          <li key={kind} className="flex items-center gap-1.5 rounded-full border bg-card px-3 py-1 text-sm">
            <StatusIcon status={r.status} className="size-4" />
            <span className="font-medium">{SOURCE_NAMES[kind]}</span>
            <span className="text-muted-foreground">
              {r.status === "ok" ? "ready" : r.status === "fail" ? "blocked" : "not checked"}
              {r.blocking.length > 0 && ` (${r.blocking.join(", ")})`}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

export function HealthPanel() {
  const health = useHealth();
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-4">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2 text-lg">
            {health.data && <StatusIcon status={health.data.overall} />}
            {health.data ? summary(health.data) : "Checking the pipeline…"}
          </CardTitle>
          <CardDescription>
            {health.data
              ? `Checked at ${clockTime(health.data.checked_at)}. No Claude tokens are used to check.`
              : "This Mac, the Claude API, the lab VM and Wazuh. It takes a few seconds."}
          </CardDescription>
        </div>
        <Button variant="outline" size="sm" onClick={() => health.refetch()} disabled={health.isFetching}>
          <RefreshCw className={cn(health.isFetching && "animate-spin")} />
          Check again
        </Button>
      </CardHeader>
      <CardContent className="space-y-6">
        {health.isError && (
          <Alert variant="destructive">
            <AlertTitle>Could not run the checks</AlertTitle>
            <AlertDescription>{health.error.message}</AlertDescription>
          </Alert>
        )}
        {health.isPending && <HealthSkeleton />}
        {health.data && (
          <>
            <Readiness health={health.data} />
            {health.data.groups.map((group) => (
              <section key={group.id} aria-labelledby={`health-${group.id}`} className="space-y-2">
                <h3 id={`health-${group.id}`} className="text-sm font-semibold text-muted-foreground">
                  {group.title}
                </h3>
                <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {group.checks.map((check) => (
                    <HealthTile key={check.name} check={check} />
                  ))}
                </ul>
              </section>
            ))}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function HealthSkeleton() {
  return (
    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3" aria-hidden>
      {Array.from({ length: 6 }, (_, i) => (
        <Skeleton key={i} className="h-20" />
      ))}
    </div>
  );
}
