// "Calibration-aware confidence" (Plan P6, decision 015): next to a
// verdict's confidence, how often answers at that level were right in the
// pinned evaluation runs. A track record with its n, never a probability.
import { Gauge } from "lucide-react";
import { calibrationWords } from "@/lib/triage";
import type { Calibration } from "@/lib/types";

export function CalibrationChip({ calibration, note }: { calibration: Calibration | null | undefined; note?: string | null }) {
  if (!calibration) {
    return note ? <p className="text-xs text-muted-foreground">No track record to show: {note}.</p> : null;
  }
  const words = calibrationWords(calibration);
  return (
    <div className="rounded-md border bg-muted/40 p-2.5 text-sm" data-testid="calibration">
      <p className="flex gap-2">
        <Gauge className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden />
        <span>{words.headline}</span>
      </p>
      <p className="mt-1 pl-6 text-xs text-muted-foreground">
        {words.source} {words.caveat} A track record on test data, not a probability for this alert.
      </p>
    </div>
  );
}
