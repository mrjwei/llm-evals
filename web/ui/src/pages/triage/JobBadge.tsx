import { Badge } from "@/components/ui/badge";
import { STATUS_WORDS } from "@/lib/triage";
import type { JobStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

const STYLE: Record<JobStatus, string> = {
  planned: "bg-secondary text-secondary-foreground",
  running: "bg-primary text-primary-foreground",
  complete: "bg-ok-soft text-ok",
  stopped: "bg-warn-soft text-warn",
  interrupted: "bg-warn-soft text-warn",
  failed: "bg-fail-soft text-fail",
};

export function JobBadge({ status }: { status: JobStatus }) {
  return <Badge className={cn(STYLE[status])}>{STATUS_WORDS[status]}</Badge>;
}
