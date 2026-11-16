// Render a component with the app's providers, and fake the API with a
// map from path (and query) to response body.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router";
import { vi } from "vitest";
import { TooltipProvider } from "@/components/ui/tooltip";

export function renderWithApp(ui: ReactElement, { route = "/" }: { route?: string } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <TooltipProvider>{ui}</TooltipProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

export type Responder = (init: RequestInit | undefined, url: string) => unknown;

/** Replace fetch: `routes` maps a path (with its query) to a body or a
 * function of the request. Unknown paths answer 404. Returns the mock. */
export function fakeApi(routes: Record<string, unknown | Responder>) {
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (!(url in routes)) return new Response(JSON.stringify({ detail: "Not Found" }), { status: 404 });
    const value = routes[url];
    const body = typeof value === "function" ? await (value as Responder)(init, url) : value;
    if (body instanceof Response) return body;
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", mock);
  return mock;
}
