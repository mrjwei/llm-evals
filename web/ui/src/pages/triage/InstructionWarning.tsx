// The instruction-like-text warning (Plan P6, X4, decision 015). A heuristic:
// it says what it found and that text phrased otherwise is not caught.
import { TriangleAlert } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { InstructionFlag } from "@/lib/types";

export function InstructionWarning({ flag }: { flag: InstructionFlag | null }) {
  if (!flag) return null;
  return (
    <Alert className="border-warn/50 bg-warn-soft/60">
      <TriangleAlert className="text-warn" />
      <AlertTitle>Instruction-like text in this alert</AlertTitle>
      <AlertDescription>
        <ul className="list-disc pl-4">
          {flag.found.map((f) => (
            <li key={f.where}>
              In the {f.where}: <q className="font-mono text-xs">{f.phrase}</q>
            </li>
          ))}
        </ul>
        <p>
          Text like this may try to steer the model (prompt injection). Check the verdict against the raw alert below. This is a
          pattern check: text phrased differently is not caught, so no warning does not mean safe.
        </p>
      </AlertDescription>
    </Alert>
  );
}
