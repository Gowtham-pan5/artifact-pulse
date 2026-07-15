import { Link, useRouterState } from "@tanstack/react-router";
import {
  LayoutDashboard, PlayCircle, Database, Brain, ShieldAlert,
  Link2, FileText, Activity, Terminal,
} from "lucide-react";

type NavItem = {
  to: "/" | "/pipeline" | "/artifacts" | "/anomalies" | "/anti-forensic" | "/chain" | "/reports";
  label: string;
  icon: typeof LayoutDashboard;
  end?: boolean;
};

const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/pipeline", label: "Pipeline Runner", icon: PlayCircle },
  { to: "/artifacts", label: "Artifacts Explorer", icon: Database },
  { to: "/anomalies", label: "Anomaly Detection", icon: Brain },
  { to: "/anti-forensic", label: "Anti-Forensic", icon: ShieldAlert },
  { to: "/chain", label: "Chain of Custody", icon: Link2 },
  { to: "/reports", label: "Reports", icon: FileText },
];

export function AppSidebar() {
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-border/60 bg-background/70 backdrop-blur-xl md:flex">
      <Link to="/" className="flex items-center gap-3 border-b border-border/60 px-5 py-5">
        <div className="relative flex h-9 w-9 items-center justify-center rounded-md bg-primary/10 ring-1 ring-primary/40">
          <Activity className="h-5 w-5 text-primary" />
          <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-primary pulse-dot" />
        </div>
        <div className="flex flex-col leading-tight">
          <span className="font-mono text-[13px] font-bold tracking-tight">
            ARTIFACT<span className="text-primary">-</span>PULSE
          </span>
          <span className="font-mono text-[9px] uppercase tracking-[0.18em] text-muted-foreground">
            v0.9.2 · build 1418
          </span>
        </div>
      </Link>

      <div className="px-3 pt-4 pb-1.5">
        <div className="px-2 font-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
          Triage Modules
        </div>
      </div>

      <nav className="flex flex-1 flex-col gap-0.5 px-3 pb-4">
        {NAV.map(({ to, label, icon: Icon, end }) => {
          const active = end ? pathname === to : pathname.startsWith(to);
          return (
            <Link
              key={to}
              to={to}
              className={
                "group relative flex items-center gap-3 rounded-md border px-3 py-2 text-sm transition-colors " +
                (active
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-transparent text-muted-foreground hover:border-border hover:bg-card/60 hover:text-foreground")
              }
            >
              {active && (
                <span className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-r bg-primary shadow-[0_0_8px_oklch(0.82_0.18_155_/_0.8)]" />
              )}
              <Icon className="h-4 w-4 shrink-0" />
              <span className="truncate font-mono text-[12px] tracking-tight">{label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-border/60 p-4">
        <div className="rounded-md border border-border/60 bg-card/40 p-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-3.5 w-3.5 text-primary" />
            <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              Engine status
            </span>
          </div>
          <div className="mt-2 flex items-baseline justify-between font-mono text-[11px]">
            <span className="text-foreground">workers</span>
            <span className="text-primary">4 / 4</span>
          </div>
          <div className="flex items-baseline justify-between font-mono text-[11px]">
            <span className="text-foreground">queue</span>
            <span className="text-accent">0</span>
          </div>
          <div className="flex items-baseline justify-between font-mono text-[11px]">
            <span className="text-foreground">ledger</span>
            <span className="text-primary">sealed</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
