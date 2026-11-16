// The Results page's server state (/api/runs) and its path rules. A report
// may only point inside its own run: links to another report.md open in the
// page, charts load through /api/runs/<run>/files/, and anything else is
// shown as plain text (decision 020).
import { useQuery } from "@tanstack/react-query";
import { api, query } from "./api";
import type { RunDetail, RunReport, RunsList, RunStatus } from "./types";

export function useRuns() {
  return useQuery({ queryKey: ["runs"], queryFn: () => api.get<RunsList>("/api/runs") });
}

export function useRun(address: string) {
  return useQuery({ queryKey: ["runs", address], queryFn: () => api.get<RunDetail>(`/api/runs/${address}`) });
}

export function useReport(address: string, doc: string) {
  return useQuery({
    queryKey: ["runs", address, "report", doc],
    queryFn: () => api.get<RunReport>(`/api/runs/${address}/report${query({ doc })}`),
    placeholderData: (previous) => previous,
  });
}

/** `href` from the report at `fromDoc`, as a path inside the run, or null
 * when it is absolute, has a scheme, or climbs out of the run. */
export function resolveInRun(fromDoc: string, href: string): string | null {
  if (!href || /^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith("/") || href.startsWith("#")) return null;
  const parts = fromDoc.split("/").slice(0, -1);
  for (const raw of href.split(/[?#]/)[0].split("/")) {
    let seg: string;
    try {
      seg = decodeURIComponent(raw);
    } catch {
      return null;
    }
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (parts.length === 0) return null;
      parts.pop();
    } else if (seg.includes("/") || seg.includes("\\")) {
      return null;
    } else {
      parts.push(seg);
    }
  }
  return parts.length ? parts.join("/") : null;
}

export const fileUrl = (address: string, path: string) =>
  `/api/runs/${address}/files/${path.split("/").map(encodeURIComponent).join("/")}`;

export const isExternal = (href: string) => /^https?:\/\//i.test(href);

export const STATUS_WORDS: Record<RunStatus, string> = {
  running: "Running",
  complete: "Complete",
  failed: "Failed",
  superseded: "Superseded",
};

/** Which canonical figures and tables read this experiment's pinned run. */
export function figuresFor(list: RunsList, experiment: string): string[] {
  return list.figures.filter((f) => f.from.includes(experiment)).map((f) => f.key.split("_")[0]);
}
