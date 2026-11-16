import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router";
import { Skeleton } from "@/components/ui/skeleton";
import { Layout } from "@/components/Layout";
import { Home } from "@/pages/Home";
import { Placeholder } from "@/pages/Placeholder";
import { RatePage } from "@/pages/rate/RatePage";
import { RatingSession } from "@/pages/rate/RatingSession";
import { ResultsPage } from "@/pages/results/ResultsPage";
import { JobPage } from "@/pages/triage/JobPage";
import { TriagePage } from "@/pages/triage/TriagePage";

// The run page carries the Markdown parser, so it loads only when opened.
const RunPage = lazy(() => import("@/pages/results/RunPage").then((m) => ({ default: m.RunPage })));

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="triage" element={<TriagePage />} />
        <Route path="triage/jobs/:jobId" element={<JobPage />} />
        <Route path="rate" element={<RatePage />} />
        <Route path="rate/:batch/:rater" element={<RatingSession />} />
        <Route path="results" element={<ResultsPage />} />
        <Route path="results/:experiment/:run" element={<Suspense fallback={<Skeleton className="h-96" />}><RunPage /></Suspense>} />
        <Route path="*" element={<Placeholder title="Page not found" text="There is nothing at this address." />} />
      </Route>
    </Routes>
  );
}
