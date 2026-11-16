import { screen } from "@testing-library/react";
import { Route, Routes } from "react-router";
import { describe, expect, it } from "vitest";
import { resolveInRun } from "@/lib/results";
import type { RunSummary, RunsList } from "@/lib/types";
import { fakeApi, renderWithApp } from "@/test/render";
import { ReportMarkdown } from "./ReportMarkdown";
import { ResultsPage } from "./ResultsPage";

const ADDR = "X1-evidence/2026-10-04T0851_c60a81";
const COND = "conditions/S1-plain__L1-alert+body__FA__sonnet/report.md";

describe("resolveInRun", () => {
  it("keeps paths inside the run", () => {
    expect(resolveInRun("report.md", "conditions/S1-plain__L1-alert+body__FA__sonnet/report.md")).toBe(COND);
    expect(resolveInRun(COND, "../../report.md")).toBe("report.md");
    expect(resolveInRun(COND, "charts/calibration.png")).toBe("conditions/S1-plain__L1-alert+body__FA__sonnet/charts/calibration.png");
    expect(resolveInRun(COND, "./charts/a.png#x")).toBe("conditions/S1-plain__L1-alert+body__FA__sonnet/charts/a.png");
  });

  it("refuses anything that leaves it", () => {
    for (const href of ["../../../X2-format/report.md", "/etc/passwd", "javascript:alert(1)", "https://example.com/a.png",
                        "data:image/png;base64,AAAA", "#top", "..%2F..%2F..%2Fx.png", "%E0%A4%A"]) {
      expect(resolveInRun(COND, href), href).toBeNull();
    }
  });
});

function report(markdown: string, doc = "report.md") {
  return renderWithApp(<ReportMarkdown address={ADDR} doc={doc} markdown={markdown} />, { route: `/results/${ADDR}` });
}

describe("ReportMarkdown", () => {
  it("renders tables, charts from the run, and report links in the page", () => {
    const { container } = report(`# X1\n\n| Condition | Coverage |\n|---|---:|\n| S1 | 34.5% |\n\n[S1 L1](${COND})\n`);
    expect(screen.getByRole("table")).toHaveTextContent("Coverage");
    expect(screen.getByRole("link", { name: "S1 L1" })).toHaveAttribute("href", `/results/${ADDR}?doc=${encodeURIComponent(COND)}`);
    expect(container.querySelector("h1")).toHaveTextContent("X1");
  });

  it("loads a condition's chart through the run's files route", () => {
    report("![Calibration](charts/calibration.png)\n\n[Run](../../report.md)", COND);
    expect(screen.getByRole("img", { name: "Calibration" })).toHaveAttribute(
      "src", `/api/runs/${ADDR}/files/conditions/S1-plain__L1-alert%2Bbody__FA__sonnet/charts/calibration.png`);
    expect(screen.getByRole("link", { name: "Run" })).toHaveAttribute("href", `/results/${ADDR}`);
  });

  it("never renders raw HTML or a link out of the run", () => {
    const { container } = report([
      '<img src=x onerror="alert(1)">', "<script>alert(2)</script>", "[click](javascript:alert(3))",
      "![remote](https://example.com/x.png)", "[other run](../X2-format/2026-10-04T1247_9bd080/report.md)",
      "[docs](https://example.com/docs)",
    ].join("\n\n"));
    expect(container.querySelector("script, img")).toBeNull();
    expect(container.querySelector('a[href^="javascript"]')).toBeNull();
    expect(screen.getByText("click").closest("a")).toBeNull();
    expect(screen.getByText("other run").closest("a")).toBeNull();
    expect(screen.getByText("[remote]")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "docs" })).toHaveAttribute("rel", "noreferrer noopener");
  });
});

function run(patch: Partial<RunSummary>): RunSummary {
  return {
    address: ADDR, run_id: "2026-10-04T0851_c60a81", experiment: "X1", experiment_slug: "evidence",
    question: "How does evidence change correctness?", rq: ["RQ1", "RQ2"], status: "complete",
    headline: "S1-plain__L0-alert: selective 74.0%", error: null, superseded_by: null, git_describe: "prereg-C1-4-g4e39720",
    created_at: "2026-10-04T08:51:22+10:00", finished_at: "2026-10-04T12:21:14+10:00", model: "claude-sonnet-5-5",
    kind: "triage", reps: 3, corpus: "C1", canonical: [], has_report: true, ...patch,
  };
}

const LIST: RunsList = {
  runs: [
    run({ canonical: ["X1"] }),
    run({ address: "X2-format/2026-10-04T1247_9bd080", run_id: "2026-10-04T1247_9bd080", experiment: "X2", experiment_slug: "format", rq: ["RQ2"], headline: "FA: selective 81.7%" }),
    run({ address: "D1-siem-coverage/2026-10-03T0927_e6115e", run_id: "2026-10-03T0927_e6115e", experiment: "D1", experiment_slug: "siem-coverage", rq: ["RQ1"], status: "superseded", superseded_by: "D1-siem-coverage/2026-10-03T1048_07a1ad" }),
  ],
  experiments: ["D1", "X1", "X2"],
  rqs: ["RQ1", "RQ2"],
  figures: [{ key: "F2_coverage_selective", title: "Coverage", from: ["X1"] }, { key: "F6_format", title: "Format", from: ["X2"] }],
  pin_problems: [],
};

function page(route: string) {
  fakeApi({ "/api/runs": LIST });
  return renderWithApp(
    <Routes>
      <Route path="/results" element={<ResultsPage />} />
    </Routes>,
    { route },
  );
}

describe("ResultsPage", () => {
  it("lists runs with RQ, status, headline and the canonical badge", async () => {
    page("/results");
    expect(await screen.findByText("3 of 3 runs")).toBeInTheDocument();
    expect(screen.getByText("Canonical · X1")).toBeInTheDocument();
    expect(screen.getByText("feeds F2")).toBeInTheDocument();
    expect(screen.getByText("Superseded by 2026-10-03T1048_07a1ad")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "2026-10-04T0851_c60a81" })).toHaveAttribute("href", `/results/${ADDR}`);
  });

  it("filters by experiment and RQ from the URL", async () => {
    page("/results?rq=RQ2");
    expect(await screen.findByText("2 of 3 runs")).toBeInTheDocument();
    expect(screen.queryByText("2026-10-03T0927_e6115e")).toBeNull();
  });

  it("filters by experiment", async () => {
    page("/results?experiment=X2");
    expect(await screen.findByText("1 of 3 runs")).toBeInTheDocument();
    expect(screen.getByText("FA: selective 81.7%")).toBeInTheDocument();
  });
});
