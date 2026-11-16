// Rate (Plan P6 "Rate", WP5′): pick a batch from data/ratings/ and say
// which rater you are. Each rater has their own order and file.
import { ArrowRight } from "lucide-react";
import { Link } from "react-router";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { dateTime } from "@/lib/format";
import { RATERS, useBatches } from "@/lib/rating";
import type { RaterProgress, RatingBatch, Rater } from "@/lib/types";

export function RatePage() {
  const batches = useBatches();
  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Rate</h1>
        <p className="text-sm text-muted-foreground">
          Blind expert rating. You see one alert and the triage answer at a time and score the answer against the rubric. You never see
          which setup produced it or whether it was right. Each click is saved at once, so you can stop and come back.
        </p>
      </div>
      {batches.isPending && <Skeleton className="h-40" />}
      {batches.isError && (
        <Alert variant="destructive">
          <AlertTitle>Could not load the rating batches</AlertTitle>
          <AlertDescription>{batches.error.message}</AlertDescription>
        </Alert>
      )}
      {batches.data?.length === 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">No rating batches yet</CardTitle>
            <CardDescription>
              A batch is a folder in <span className="font-mono">data/ratings/</span>, made by the researcher. When one is there, it shows up here.
            </CardDescription>
          </CardHeader>
        </Card>
      )}
      {batches.data?.map((b) => <BatchCard key={b.id} batch={b} />)}
    </div>
  );
}

function BatchCard({ batch }: { batch: RatingBatch }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="font-mono text-base">{batch.id}</CardTitle>
        <CardDescription>
          {batch.items} items, the first {batch.calibration} a calibration round done together and left out of the analysis
          {batch.created_at && ` · made ${dateTime(batch.created_at)}`}
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3 sm:grid-cols-2">
        {RATERS.map((r) => (
          <RaterTile key={r} batch={batch.id} rater={r} progress={batch.raters[r]} />
        ))}
      </CardContent>
    </Card>
  );
}

function RaterTile({ batch, rater, progress }: { batch: string; rater: Rater; progress: RaterProgress | null }) {
  const done = progress !== null && progress.complete === progress.total;
  return (
    <div className="space-y-2 rounded-lg border p-3">
      <div className="flex items-center gap-2">
        <span className="font-medium">Rater {rater}</span>
        {progress?.via === "pack" && <Badge variant="secondary">from the offline pack</Badge>}
        {done && <Badge variant="outline" className="border-ok/40 text-ok">done</Badge>}
      </div>
      {progress ? (
        <>
          <Progress value={(100 * progress.complete) / Math.max(progress.total, 1)} aria-label={`Rater ${rater} progress`} />
          <p className="text-xs text-muted-foreground">
            {progress.complete} of {progress.total} rated{progress.updated_at && ` · last saved ${dateTime(progress.updated_at)}`}
          </p>
        </>
      ) : (
        <p className="text-xs text-muted-foreground">Not started</p>
      )}
      <Button asChild size="sm" variant={progress ? "outline" : "default"}>
        <Link to={`/rate/${encodeURIComponent(batch)}/${rater}`}>
          {progress ? (done ? "Review" : "Continue") : "Start"} as rater {rater} <ArrowRight />
        </Link>
      </Button>
    </div>
  );
}
