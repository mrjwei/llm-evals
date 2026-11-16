import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Route, Routes } from "react-router";
import { describe, expect, it } from "vitest";
import { position } from "@/lib/rating";
import type { RatingItem, RatingSession as Session, Rubric } from "@/lib/types";
import { HOSTILE } from "@/test/fixtures";
import { fakeApi, renderWithApp } from "@/test/render";
import { RatePage } from "./RatePage";
import { RatingSession } from "./RatingSession";

const RUBRIC: Rubric = {
  version: 1,
  sha256: "abc",
  blind: true,
  items: [
    { id: "R1", name: "Action", question: "Is the recommended action correct?", scale: [1, 5], anchors: { "1": "wrong or harmful", "3": "right but vague", "5": "right and specific" } },
    { id: "R2", name: "Actionability", question: "Could a junior analyst act on this?", scale: [1, 5], anchors: {} },
    { id: "R3", name: "Added value", question: "Does it add anything?", scale: [1, 5], anchors: {} },
    { id: "R4", name: "Confidence fit", question: "Does the confidence match?", scale: [1, 5], anchors: {} },
    { id: "R5", name: "Own decision", question: "Would you escalate?", options: [
      { value: "escalate", label: "Escalate" }, { value: "dismiss_false_positive", label: "Dismiss (false positive)" }, { value: "needs_more_info", label: "Needs more info" },
    ] },
  ],
};

const FULL = { R1: 4, R2: 3, R3: 5, R4: 2, R5: "escalate", saved_at: "2026-10-12T01:00:00Z" };

function session(patch: Partial<Session> = {}): Session {
  return {
    batch: "X5-test", rater: "A", order: ["it03", "it01", "it02"], calibration: ["it03"],
    ratings: {}, rubric: { version: 1, sha256: "abc" },
    progress: { complete: 0, total: 3, next: 0, calibration_complete: 0, started_at: "2026-10-12T00:00:00Z", updated_at: null, via: "app" },
    ...patch,
  };
}

function item(id: string): RatingItem {
  return {
    item: id, calibration: id === "it03",
    alert: { id: "1790945532.836559", timestamp: "2026-10-02T12:52:12.670+0000", rule: { id: "31101", level: 5, description: "Web server 400 error code." },
             full_log: `GET /rest/basket/1 401 ${HOSTILE}` },
    body: { request_body: "<script>alert(2)</script>", response_body: "UnauthorizedError" },
    answer: { technique_label: "uncertain", candidate_labels: ["idor", "forced_browsing"], disposition: "needs_more_info", confidence: "low",
              recommended_action: "Check the access log for other requests." },
  };
}

const BASE = "/api/rating/batches/X5-test";

function routes(s: Session = session()) {
  return {
    "/api/rating/rubric": RUBRIC,
    [`${BASE}/raters/A`]: s,
    ...Object.fromEntries(s.order.map((id) => [`${BASE}/items/${id}`, item(id)])),
  };
}

function renderSession(route = "/rate/X5-test/A") {
  return renderWithApp(
    <Routes>
      <Route path="/rate/:batch/:rater" element={<RatingSession />} />
    </Routes>,
    { route },
  );
}

describe("RatingSession", () => {
  it("shows the alert and answer as text, and nothing that unblinds", async () => {
    fakeApi(routes());
    const { container } = renderSession();
    expect(await screen.findByText("Check the access log for other requests.")).toBeInTheDocument();
    expect(screen.getByText("Item 1 of 3")).toBeInTheDocument();
    expect(screen.getByText("Calibration round")).toBeInTheDocument();
    expect(container.querySelector("img, script")).toBeNull();
    expect(container.textContent).toContain(HOSTILE);
    expect(container.textContent).toContain("<script>alert(2)</script>");
    for (const word of ["Format", "calibration chip", "from cache", "In evaluation", "sonnet", "ground truth", "S1-plain"]) {
      expect(container.textContent).not.toContain(word);
    }
  });

  it("autosaves each click with the guard header and counts a complete item", async () => {
    const saved = { item: "it03", record: FULL, progress: { ...session().progress, complete: 1, next: 1 } };
    const fetch = fakeApi({ ...routes(), [`${BASE}/raters/A/items/it03`]: saved });
    renderSession();
    const r1 = await screen.findByRole("group", { name: "R1 · Action" });
    await userEvent.click(within(r1).getByLabelText(/^4/));
    await waitFor(() => expect(fetch.mock.calls.some((c) => c[0] === `${BASE}/raters/A/items/it03`)).toBe(true));
    const [, init] = fetch.mock.calls.find((c) => c[0] === `${BASE}/raters/A/items/it03`)!;
    expect(JSON.parse(String(init!.body))).toEqual({ R1: 4 });
    expect((init!.headers as Record<string, string>)["X-CJP-Request"]).toBe("1");
    expect(await screen.findByText("1 of 3 rated")).toBeInTheDocument();
    await userEvent.click(within(screen.getByRole("group", { name: "R5 · Own decision" })).getByLabelText("Escalate"));
    const bodies = () => fetch.mock.calls.filter((c) => c[0] === `${BASE}/raters/A/items/it03`).map((c) => JSON.parse(String(c[1]!.body)));
    await waitFor(() => expect(bodies()).toEqual([{ R1: 4 }, { R5: "escalate" }]));
  });

  it("says when a score was not saved", async () => {
    fakeApi({ ...routes(), [`${BASE}/raters/A/items/it03`]: () => new Response(JSON.stringify({ detail: "the rubric changed" }), { status: 409 }) });
    renderSession();
    await userEvent.click(within(await screen.findByRole("group", { name: "R2 · Actionability" })).getByLabelText("2"));
    expect(await screen.findByRole("alert")).toHaveTextContent("Not saved: the rubric changed");
  });

  it("carries on at the first unrated item, and ends on a done screen", async () => {
    fakeApi(routes(session({ ratings: { it03: FULL } })));
    renderSession();
    expect(await screen.findByText("Item 2 of 3")).toBeInTheDocument();
    expect(screen.queryByText("Calibration round")).toBeNull();
  });

  it("shows the done screen when everything is rated", async () => {
    fakeApi(routes(session({ ratings: { it03: FULL, it01: FULL, it02: FULL } })));
    renderSession();
    expect(await screen.findByText("All 3 items are rated")).toBeInTheDocument();
  });

  it("keeps ?n= inside the batch", () => {
    expect(position("2", 3, 0)).toBe(1);
    expect(position("9", 3, 0)).toBe(0);
    expect(position("x", 3, 2)).toBe(2);
    expect(position(null, 3, 1)).toBe(1);
  });
});

describe("RatePage", () => {
  it("lists batches with each rater's progress", async () => {
    fakeApi({ "/api/rating/batches": [{ id: "X5-test", created_at: null, items: 48, calibration: 6, raters: { A: { ...session().progress, complete: 12, total: 48 }, B: null } }] });
    renderWithApp(<RatePage />);
    expect(await screen.findByText("X5-test")).toBeInTheDocument();
    expect(screen.getByText("12 of 48 rated")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Continue as rater A/ })).toHaveAttribute("href", "/rate/X5-test/A");
    expect(screen.getByRole("link", { name: /Start as rater B/ })).toHaveAttribute("href", "/rate/X5-test/B");
  });

  it("explains an empty list", async () => {
    fakeApi({ "/api/rating/batches": [] });
    renderWithApp(<RatePage />);
    expect(await screen.findByText("No rating batches yet")).toBeInTheDocument();
  });
});
