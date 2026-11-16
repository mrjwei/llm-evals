import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { JOB_ID, item, queue } from "@/test/fixtures";
import { renderWithApp } from "@/test/render";
import { QueueView, type QueueState } from "./QueueView";

const STATE: QueueState = { format: "A", lane: "queue", label: null, disposition: null, source: null, alert: null };

describe("QueueView", () => {
  it("shows lane counts, rows with their flags, and export links", () => {
    const q = queue([
      item({ instruction_like: { found: [{ where: "log line", phrase: "SYSTEM:" }] }, formats_agree: false }),
      item({ alert_id: "2", lane: "human", human_reasons: ["low confidence"] }),
    ]);
    renderWithApp(<QueueView jobId={JOB_ID} formats={["A", "B"]} queue={q} loading={false} state={STATE} update={() => {}} />);
    expect(screen.getByRole("tab", { name: "To act on (1)" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Needs a human (1)" })).toBeInTheDocument();
    expect(screen.getByText("instruction-like text")).toBeInTheDocument();
    expect(screen.getByText("A and B differ")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "CSV" })).toHaveAttribute("href", `/api/triage/jobs/${JOB_ID}/export.csv`);
    expect(screen.getByRole("link", { name: "JSON" })).toHaveAttribute("href", `/api/triage/jobs/${JOB_ID}/export.json`);
  });

  it("opens an alert, switches format and lane through update()", async () => {
    const update = vi.fn();
    renderWithApp(<QueueView jobId={JOB_ID} formats={["A", "B"]} queue={queue()} loading={false} state={STATE} update={update} />);
    await userEvent.click(screen.getByRole("button", { name: /A web attack returned code 200/ }));
    expect(update).toHaveBeenLastCalledWith({ alert: "1790945600.903845" });
    await userEvent.click(screen.getByRole("tab", { name: "Format B" }));
    expect(update).toHaveBeenLastCalledWith({ format: "B" });
    await userEvent.click(screen.getByRole("tab", { name: /Needs a human/ }));
    expect(update).toHaveBeenLastCalledWith({ lane: "human", alert: null });
  });

  it("hides the format toggle for a one-format job", () => {
    renderWithApp(<QueueView jobId={JOB_ID} formats={["A"]} queue={queue()} loading={false} state={STATE} update={() => {}} />);
    expect(screen.queryByRole("tab", { name: "Format B" })).not.toBeInTheDocument();
  });
});
