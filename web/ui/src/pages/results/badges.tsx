import { Star } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { STATUS_WORDS } from "@/lib/results";
import type { RunSummary } from "@/lib/types";
import { cn } from "@/lib/utils";

const STATUS_STYLE: Record<string, string> = {
  complete: "border-ok/40 text-ok",
  running: "border-warn/50 text-warn",
  failed: "border-fail/40 text-fail",
  superseded: "text-muted-foreground",
};

export function RunStatusBadge({ run }: { run: Pick<RunSummary, "status" | "superseded_by"> }) {
  const by = run.status === "superseded" && run.superseded_by ? ` by ${run.superseded_by.split("/").pop()}` : "";
  return (
    <Badge variant="outline" className={cn(STATUS_STYLE[run.status])}>
      {STATUS_WORDS[run.status] ?? run.status}
      {by}
    </Badge>
  );
}

export function CanonicalBadge({ keys }: { keys: string[] }) {
  return (
    <Badge className="gap-1">
      <Star className="size-3" aria-hidden /> Canonical · {keys.join(", ")}
    </Badge>
  );
}
