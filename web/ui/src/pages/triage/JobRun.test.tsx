import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { JOB_ID, job } from "@/test/fixtures";
import { fakeApi, renderWithApp } from "@/test/render";
import { JobRun } from "./JobRun";

const START = `/api/triage/jobs/${JOB_ID}/start`;
const ESTIMATE = `/api/triage/jobs/${JOB_ID}/estimate`;
const body = (init?: RequestInit) => JSON.parse(String(init?.body));
const calls = (fetch: ReturnType<typeof fakeApi>, url: string) => fetch.mock.calls.filter((c) => c[0] === url);

describe("JobRun: nothing is spent without approval (decision 014)", () => {
  it("shows the estimate, and Cancel sends nothing", async () => {
    const fetch = fakeApi({ [START]: job({ status: "running" }) });
    renderWithApp(<JobRun job={job()} />);
    expect(screen.getByText(/Before running: 61 paid calls to Claude, at most \$1.01\./)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Run triage" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent("Approve paid calls?");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(calls(fetch, START)).toHaveLength(0);
  });

  it("approves exactly the paid calls the dialog showed", async () => {
    const fetch = fakeApi({ [START]: job({ status: "running" }) });
    renderWithApp(<JobRun job={job()} />);
    await userEvent.click(screen.getByRole("button", { name: "Run triage" }));
    await userEvent.click(await screen.findByRole("button", { name: "Approve 61 paid calls and run" }));
    await waitFor(() => expect(calls(fetch, START)).toHaveLength(1));
    expect(body(calls(fetch, START)[0][1])).toEqual({ max_calls: 61 });
  });

  it("runs a free job with max_calls 0 and no dialog", async () => {
    const fetch = fakeApi({ [START]: job({ status: "running" }) });
    renderWithApp(<JobRun job={job({ estimate: { ...job().estimate, calls: 0, cost_max_usd: 0 } })} />);
    await userEvent.click(screen.getByRole("button", { name: "Run triage" }));
    await waitFor(() => expect(calls(fetch, START)).toHaveLength(1));
    expect(body(calls(fetch, START)[0][1])).toEqual({ max_calls: 0 });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("estimates what is left before a resume, and approves that", async () => {
    const stopped = job({ status: "stopped", progress: { total: 136, answered: 100 } });
    const left = { ...stopped, estimate: { ...stopped.estimate, calls: 12, cached: 24, cost_max_usd: 0.2 } };
    const fetch = fakeApi({ [ESTIMATE]: left, [START]: { ...left, status: "running" } });
    renderWithApp(<JobRun job={stopped} />);
    await userEvent.click(screen.getByRole("button", { name: "Resume" }));
    expect(await screen.findByRole("dialog")).toHaveTextContent("12 paid calls to Claude, at most $0.20.");
    await userEvent.click(screen.getByRole("button", { name: "Approve 12 paid calls and run" }));
    await waitFor(() => expect(calls(fetch, START)).toHaveLength(1));
    expect(body(calls(fetch, START)[0][1])).toEqual({ max_calls: 12 });
  });

  it("explains a refusal for more calls than approved", async () => {
    fakeApi({ [START]: () => new Response(JSON.stringify({ detail: "needs 70 paid call(s), more than the 61 approved" }), { status: 409 }) });
    renderWithApp(<JobRun job={job()} />);
    await userEvent.click(screen.getByRole("button", { name: "Run triage" }));
    await userEvent.click(await screen.findByRole("button", { name: /Approve 61/ }));
    expect(await screen.findByText("This needs more paid calls than you approved")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Estimate again" })).toBeInTheDocument();
  });

  it("shows progress, a Stop button and the actual cost while running", () => {
    fakeApi({});
    const running = job({ status: "running", progress: { total: 136, answered: 34 },
      actual: { ...job().actual, calls: 4, cache_hits: 30, cost_usd: 0.061, answers_cost_usd: 0.4 } });
    renderWithApp(<JobRun job={running} />);
    expect(screen.getByText("34 of 136 answers so far")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Stop" })).toBeInTheDocument();
    expect(screen.getByText("$0.06")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Run triage|Resume/ })).not.toBeInTheDocument();
  });
});
