import { describe, expect, it } from "vitest";
import { job } from "@/test/fixtures";
import { calibrationWords, estimateWords, sourceSummary } from "./triage";
import type { Calibration } from "./types";

const CAL: Calibration = {
  confidence: "medium",
  label: { committed: 50, correct: 37, right_rate: 0.74, enough: true },
  disposition: { committed: 7, correct: 3, right_rate: 0.43, enough: false },
  measured_on: { experiment: "X2", run: "r", condition: "S1-plain__L1-alert+body__FB__sonnet", corpus: "C1" },
  differs: ["bodies"],
  min_n: 20,
};

describe("calibrationWords (decision 015)", () => {
  it("states a track record with n, never a probability", () => {
    const w = calibrationWords(CAL);
    expect(w.headline).toBe(
      "In evaluation on C1, “medium” answers had the right label 37 of 50 times and the right disposition 3 of 7 times (too few to judge).",
    );
    expect(`${w.headline} ${w.source}`).not.toMatch(/%|probab|chance|likel/i);
    expect(w.source).toBe("Measured in X2, condition S1-plain__L1-alert+body__FB__sonnet.");
    expect(w.caveat).toBe("That condition used a different request-bodies setting from this job.");
  });

  it("says when a level had no answers in evaluation", () => {
    const w = calibrationWords({ ...CAL, label: null, disposition: { ...CAL.disposition!, committed: 0, correct: 0 }, differs: [] });
    expect(w.headline).toContain("had no label answers to compare and no disposition answers to compare");
    expect(w.caveat).toBeNull();
  });
});

describe("estimateWords", () => {
  it("states paid calls and the upper bound", () => {
    const w = estimateWords(job());
    expect(w.headline).toBe("61 paid calls to Claude, at most $1.01.");
    expect(w.details[0]).toBe("75 answers come from the cache for free.");
    expect(w.details.join(" ")).toMatch(/real cost is lower/);
  });

  it("says a fully cached job is free", () => {
    const w = estimateWords(job({ estimate: { ...job().estimate, calls: 0, cost_max_usd: 0 } }));
    expect(w.headline).toBe("Free: all 136 answers come from the cache.");
  });
});

it("summarises each source kind", () => {
  expect(sourceSummary(job().source)).toBe("Demo · C1 session_20261002_125210 · S1 · plain access log");
  expect(sourceSummary({ kind: "upload", filename: "a.jsonl", sha256: "x", ingest_log: true })).toBe("Upload · a.jsonl (with ingest log)");
  expect(sourceSummary({ kind: "live", start: "2026-10-04T08:00:00Z", end: "2026-10-04T09:00:00Z", arm: "S3-body-field", agent: "001", limit: 200 }))
    .toMatch(/^Live Wazuh · .* · S3 · body in its own log field · agent 001$/);
});
