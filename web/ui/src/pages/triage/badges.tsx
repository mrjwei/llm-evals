import { TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { disposition } from "@/lib/triage";
import type { InstructionFlag } from "@/lib/types";
import { cn } from "@/lib/utils";

const DISPOSITION_STYLE: Record<string, string> = {
  escalate: "bg-fail-soft text-fail border-fail/30",
  needs_more_info: "bg-warn-soft text-warn border-warn/30",
  dismiss_false_positive: "bg-secondary text-muted-foreground",
};

const SEVERITY_STYLE: Record<string, string> = {
  critical: "border-fail text-fail",
  high: "border-fail/50 text-fail",
  medium: "border-warn/60 text-warn",
  low: "text-muted-foreground",
};

export function DispositionBadge({ value }: { value?: string }) {
  if (!value) return null;
  return <Badge variant="outline" className={cn(DISPOSITION_STYLE[value])}>{disposition(value)}</Badge>;
}

export function SeverityBadge({ value }: { value?: string }) {
  if (!value) return null;
  return <Badge variant="outline" className={cn("capitalize", SEVERITY_STYLE[value])}>{value}</Badge>;
}

/** A technique label as the model gave it, e.g. sql_injection. */
export function LabelText({ value, className }: { value?: string; className?: string }) {
  if (!value) return null;
  return <span className={cn("font-mono text-sm", value === "uncertain" && "text-warn", className)}>{value}</span>;
}

export function InstructionIcon({ flag }: { flag: InstructionFlag | null }) {
  if (!flag) return null;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-warn" title="Instruction-like text in this alert">
      <TriangleAlert className="size-3.5" aria-hidden />
      instruction-like text
    </span>
  );
}
