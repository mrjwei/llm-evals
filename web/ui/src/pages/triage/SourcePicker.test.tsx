import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { HEALTH, job } from "@/test/fixtures";
import { fakeApi, renderWithApp } from "@/test/render";
import type { Sources } from "@/lib/types";
import { SourcePicker } from "./SourcePicker";

const SOURCES: Sources = {
  demo: { corpora: [{ id: "C1", note: null, sessions: [{ name: "session_20261002_125210", alerts: { "S1-plain": 68 } }] }], default_corpus: "C1" },
  arms: ["S1-plain", "S2-body-in-url", "S3-body-field"],
  formats: ["A", "B"],
  models: { sonnet: "claude-sonnet-5-5", haiku: "claude-haiku-4-5-20251001" },
  default_model: "sonnet",
  live: { bodies_from_vm: true, default_limit: 200, max_minutes: 10080 },
  max_alerts: 1000,
  max_upload_bytes: 25 * 2 ** 20,
};

describe("SourcePicker", () => {
  it("prepares a demo job with both formats and bodies by default", async () => {
    const fetch = fakeApi({ "/api/health": HEALTH, "/api/triage/jobs": job() });
    renderWithApp(<SourcePicker sources={SOURCES} />);
    expect(screen.getByRole("combobox", { name: "Session" })).toHaveTextContent("session_20261002_125210 (68 alerts)");
    await userEvent.click(screen.getByRole("button", { name: "Prepare and estimate" }));
    await waitFor(() => expect(fetch.mock.calls.some((c) => c[0] === "/api/triage/jobs")).toBe(true));
    const [, init] = fetch.mock.calls.find((c) => c[0] === "/api/triage/jobs")!;
    expect(JSON.parse(String(init!.body))).toEqual({
      source: { kind: "demo", corpus: "C1", session: "session_20261002_125210", arm: "S1-plain" },
      bodies: true,
      formats: ["A", "B"],
      model: "sonnet",
    });
  });

  it("refuses to prepare without a format", async () => {
    const fetch = fakeApi({ "/api/health": HEALTH });
    renderWithApp(<SourcePicker sources={SOURCES} />);
    await userEvent.click(screen.getByLabelText("Format A · full answer"));
    await userEvent.click(screen.getByLabelText("Format B · decision only"));
    await userEvent.click(screen.getByRole("button", { name: "Prepare and estimate" }));
    expect(await screen.findByText("Pick at least one output format.")).toBeInTheDocument();
    expect(fetch.mock.calls.some((c) => c[0] === "/api/triage/jobs")).toBe(false);
  });

  it("blocks a source the health checks say can't run, and says why", async () => {
    fakeApi({ "/api/health": HEALTH });
    renderWithApp(<SourcePicker sources={SOURCES} />);
    await userEvent.click(screen.getByRole("tab", { name: "Live Wazuh" }));
    expect(await screen.findByText("Live Wazuh can't run right now")).toBeInTheDocument();
    expect(screen.getByText(/Not working: indexer/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Prepare and estimate" })).toBeDisabled();
  });
});
