import { NavLink, Outlet } from "react-router";
import { useInfo } from "@/lib/queries";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Home", end: true },
  { to: "/triage", label: "Triage" },
  { to: "/rate", label: "Rate" },
  { to: "/results", label: "Results" },
];

export function Layout() {
  const info = useInfo();
  return (
    <div className="flex min-h-svh flex-col">
      <header className="border-b bg-card">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3">
          <NavLink to="/" className="font-semibold tracking-tight">
            cjp <span className="font-normal text-muted-foreground">· alert triage</span>
          </NavLink>
          <nav aria-label="Main" className="flex gap-1 text-sm">
            {NAV.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn("rounded-md px-3 py-1.5 hover:bg-accent", isActive && "bg-accent font-medium")
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6">
        <Outlet />
      </main>
      <footer className="border-t text-xs text-muted-foreground">
        <div className="mx-auto flex max-w-7xl flex-wrap gap-x-4 px-4 py-2">
          <span>Runs on this Mac only (127.0.0.1)</span>
          {info.data && <span>cjp {info.data.version} · {info.data.git_describe}</span>}
        </div>
      </footer>
    </div>
  );
}
