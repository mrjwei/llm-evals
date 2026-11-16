import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { HEALTH } from "@/test/fixtures";
import { fakeApi, renderWithApp } from "@/test/render";
import { HealthPanel, summary } from "./HealthPanel";


describe("HealthPanel", () => {
  it("shows each check with its plain sentence, and the fix only where something is wrong", async () => {
    fakeApi({ "/api/health": HEALTH });
    renderWithApp(<HealthPanel />);
    expect(await screen.findByText("1 check is failing. Each red tile below says how to fix it.")).toBeInTheDocument();
    expect(screen.getByText("The app can read alerts from Wazuh.")).toBeInTheDocument();
    expect(screen.getByText("open the SSH tunnel")).toBeInTheDocument();
    expect(screen.getAllByText(/To fix:/)).toHaveLength(1);
    expect(screen.getByText("Lab VM and Wazuh")).toBeInTheDocument();
  });

  it("says which triage sources can run", async () => {
    fakeApi({ "/api/health": HEALTH });
    renderWithApp(<HealthPanel />);
    expect(await screen.findByText("(indexer)", { exact: false })).toHaveTextContent("blocked (indexer)");
  });

  it("shows the error when the checks can't run", async () => {
    fakeApi({ "/api/health": () => new Response(JSON.stringify({ detail: "boom" }), { status: 500 }) });
    renderWithApp(<HealthPanel />);
    expect(await screen.findByText("Could not run the checks")).toBeInTheDocument();
    expect(screen.getByText("boom")).toBeInTheDocument();
  });

  it("words the summary for all-green and warnings", () => {
    expect(summary({ ...HEALTH, counts: { ok: 5, warn: 0, fail: 0, skip: 0 } })).toBe("Everything is working.");
    expect(summary({ ...HEALTH, counts: { ok: 5, warn: 2, fail: 0, skip: 0 } })).toMatch(/2 warnings/);
  });
});
