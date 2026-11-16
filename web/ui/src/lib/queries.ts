// Server state, through TanStack Query: one cache for the whole app, so
// Home and the Triage page share one health check instead of each running
// the slow network checks again.
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import type { Health, Info } from "./types";

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => api.get<Health>("/api/health"),
    staleTime: 5 * 60_000, // the checks take seconds (SSH, Wazuh); "Check again" refreshes
  });
}

export function useInfo() {
  return useQuery({ queryKey: ["info"], queryFn: () => api.get<Info>("/api/info"), staleTime: Infinity });
}
