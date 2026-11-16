// /triage: start a new triage, or open an earlier job.
import { Link } from "react-router";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { dateTime, usd } from "@/lib/format";
import { sourceSummary, useJobs, useSources } from "@/lib/triage";
import { JobBadge } from "./JobBadge";
import { SourcePicker } from "./SourcePicker";

export function TriagePage() {
  const sources = useSources();
  return (
    <div className="space-y-6">
      {sources.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not load the triage sources</AlertTitle>
          <AlertDescription>{sources.error.message}</AlertDescription>
        </Alert>
      )}
      {sources.isPending ? <Skeleton className="h-80" /> : sources.data && <SourcePicker sources={sources.data} />}
      <JobList />
    </div>
  );
}

function JobList() {
  const jobs = useJobs();
  if (jobs.isError) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Triage jobs</CardTitle>
        <CardDescription>Newest first. Each job keeps its alerts, answers and costs in its own folder on this Mac.</CardDescription>
      </CardHeader>
      <CardContent>
        {jobs.isPending && <Skeleton className="h-24" />}
        {jobs.data?.length === 0 && <p className="text-sm text-muted-foreground">No jobs yet. Start one above.</p>}
        {jobs.data && jobs.data.length > 0 && (
          <ul className="divide-y">
            {jobs.data.map((job) => (
              <li key={job.id}>
                <Link to={`/triage/jobs/${job.id}`} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-3 hover:bg-accent/50">
                  <JobBadge status={job.status} />
                  <span className="min-w-0 flex-1 truncate text-sm font-medium">{sourceSummary(job.source)}</span>
                  <span className="text-sm text-muted-foreground">
                    {job.alerts} alerts · {job.options.formats.join(" + ")} · {job.progress.answered}/{job.progress.total} answered · {usd(job.actual.cost_usd)} billed
                  </span>
                  <span className="w-40 text-right text-xs text-muted-foreground">{dateTime(job.created_at)}</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
