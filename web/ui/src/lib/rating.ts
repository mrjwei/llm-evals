// The Rate page's server state (/api/rating/*) and its rules. Raters see
// the alert and the answer only (rubric `blind: true`): nothing here asks
// for, or shows, a condition, model, format, ground truth or correctness.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";
import type { RatingBatch, RatingItem, RatingSession, Rater, Rubric, RubricId, SaveResult, ScoreRecord } from "./types";

const ROOT = "/api/rating";
export const RUBRIC_IDS: RubricId[] = ["R1", "R2", "R3", "R4", "R5"];
export const RATERS: Rater[] = ["A", "B"];

const batchUrl = (batch: string) => `${ROOT}/batches/${encodeURIComponent(batch)}`;
const raterUrl = (batch: string, rater: Rater) => `${batchUrl(batch)}/raters/${rater}`;

export function useRubric() {
  return useQuery({ queryKey: ["rating", "rubric"], queryFn: () => api.get<Rubric>(`${ROOT}/rubric`), staleTime: Infinity });
}

export function useBatches() {
  return useQuery({ queryKey: ["rating", "batches"], queryFn: () => api.get<RatingBatch[]>(`${ROOT}/batches`) });
}

/** Start or carry on as a rater. A POST, because the first call writes the
 * rater's file with their order; later calls only read it. */
export function useSession(batch: string, rater: Rater) {
  return useQuery({
    queryKey: ["rating", "session", batch, rater],
    queryFn: () => api.post<RatingSession>(raterUrl(batch, rater)),
    staleTime: Infinity,
  });
}

export function useItem(batch: string, item: string | undefined) {
  return useQuery({
    queryKey: ["rating", "item", batch, item],
    queryFn: () => api.get<RatingItem>(`${batchUrl(batch)}/items/${encodeURIComponent(item!)}`),
    enabled: item !== undefined,
    staleTime: Infinity,
  });
}

/** Autosave: every change sends only the scores that changed, and the
 * session in the cache takes the server's record and progress. */
export function useSave(batch: string, rater: Rater) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ item, scores }: { item: string; scores: ScoreRecord }) =>
      api.post<SaveResult>(`${raterUrl(batch, rater)}/items/${encodeURIComponent(item)}`, scores),
    onSuccess: (result) => {
      client.setQueryData<RatingSession>(["rating", "session", batch, rater], (s) =>
        s ? { ...s, ratings: { ...s.ratings, [result.item]: result.record }, progress: result.progress } : s,
      );
      client.invalidateQueries({ queryKey: ["rating", "batches"] });
    },
  });
}

export function isComplete(record: ScoreRecord | undefined): boolean {
  return !!record && RUBRIC_IDS.every((id) => record[id] !== undefined && record[id] !== null);
}

export function firstOpen(session: RatingSession): number | null {
  const n = session.order.findIndex((id) => !isComplete(session.ratings[id]));
  return n < 0 ? null : n;
}

/** The 1-based item position from `?n=`, kept inside the batch. */
export function position(param: string | null, total: number, fallback: number): number {
  const n = Number(param);
  return Number.isInteger(n) && n >= 1 && n <= total ? n - 1 : fallback;
}

// The answer's fields in the Triage page's order, with its words.
export const ANSWER_FIELDS: [string, string][] = [
  ["disposition", "Disposition"],
  ["severity", "Severity"],
  ["technique_label", "Technique"],
  ["candidate_labels", "Could be"],
  ["confidence", "Confidence"],
  ["recommended_action", "Recommended action"],
  ["event_type", "What happened"],
  ["reasoning", "Reasoning"],
  ["evidence", "Evidence"],
  ["cognitive_notes", "Context"],
];
