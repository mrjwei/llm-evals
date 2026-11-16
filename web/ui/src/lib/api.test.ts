import { describe, expect, it } from "vitest";
import { fakeApi } from "@/test/render";
import { ApiError, REQUEST_HEADER, api, errorMessage, query } from "./api";

describe("api", () => {
  it("sends the guard header on POST but not on GET (decision 013)", async () => {
    const fetch = fakeApi({ "/api/x": { ok: true } });
    await api.get("/api/x");
    await api.post("/api/x", { a: 1 });
    const [getInit, postInit] = fetch.mock.calls.map((c) => c[1] as RequestInit);
    expect((getInit.headers as Record<string, string>)[REQUEST_HEADER]).toBeUndefined();
    expect((postInit.headers as Record<string, string>)[REQUEST_HEADER]).toBe("1");
    expect(postInit.body).toBe('{"a":1}');
  });

  it("turns an error body into an ApiError with the server's sentence", async () => {
    fakeApi({ "/api/x": () => new Response(JSON.stringify({ detail: "job is running" }), { status: 409 }) });
    const err = await api.post<never>("/api/x").catch((e: ApiError) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(409);
    expect(err.message).toBe("job is running");
  });

  it("says plainly when the app is not answering", async () => {
    fakeApi({ "/api/x": () => Promise.reject(new TypeError("Failed to fetch")) });
    const err = await api.get<never>("/api/x").catch((e: ApiError) => e);
    expect(err.status).toBe(0);
    expect(err.message).toMatch(/not answering/);
  });

  it("reads FastAPI's validation errors", () => {
    const body = { detail: [{ loc: ["body", "max_calls"], msg: "Input should be >= 0" }] };
    expect(errorMessage(422, body)).toBe("max_calls: Input should be >= 0");
    expect(errorMessage(500, null)).toBe("the app answered 500");
  });

  it("builds query strings from set values only", () => {
    expect(query({ format: "B", lane: null, label: undefined, source: "" })).toBe("?format=B");
    expect(query({})).toBe("");
  });
});
