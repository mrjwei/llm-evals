import { CircleCheck, CircleHelp, CircleMinus, CircleX, TriangleAlert } from "lucide-react";
import { cn } from "@/lib/utils";

export type Status = "ok" | "warn" | "fail" | "skip" | "unknown";

const ICONS = { ok: CircleCheck, warn: TriangleAlert, fail: CircleX, skip: CircleMinus, unknown: CircleHelp };
const COLOURS = {
  ok: "text-ok",
  warn: "text-warn",
  fail: "text-fail",
  skip: "text-muted-foreground",
  unknown: "text-muted-foreground",
};
export const STATUS_WORDS: Record<Status, string> = {
  ok: "working",
  warn: "warning",
  fail: "not working",
  skip: "not checked",
  unknown: "not checked",
};

export function StatusIcon({ status, className }: { status: Status; className?: string }) {
  const Icon = ICONS[status];
  return <Icon aria-label={STATUS_WORDS[status]} role="img" className={cn("size-5 shrink-0", COLOURS[status], className)} />;
}
