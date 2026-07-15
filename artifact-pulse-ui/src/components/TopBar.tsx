import { ChevronDown, Search, Bell, ShieldCheck } from "lucide-react";
import { caseInfo } from "../lib/mockData";

export function TopBar() {
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border/60 bg-background/80 px-4 backdrop-blur-xl md:px-6">
      {/* Case selector */}
      <button
        type="button"
        className="group flex items-center gap-2 rounded-md border border-border bg-card/60 px-3 py-1.5 font-mono text-xs hover:border-primary/40"
      >
        <span className="text-muted-foreground">case:</span>
        <span className="text-primary">{caseInfo.caseId}</span>
        <span className="text-muted-foreground">·</span>
        <span className="text-foreground">{caseInfo.hostName}</span>
        <ChevronDown className="h-3.5 w-3.5 text-muted-foreground transition-transform group-hover:translate-y-0.5" />
      </button>

      {/* Search */}
      <div className="relative ml-2 hidden flex-1 max-w-md md:flex">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <input
          type="search"
          placeholder="grep artifacts, hashes, event IDs…"
          className="w-full rounded-md border border-border bg-card/40 py-1.5 pl-9 pr-3 font-mono text-[12px] text-foreground placeholder:text-muted-foreground focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/40"
        />
        <kbd className="absolute right-2 top-1/2 -translate-y-1/2 rounded border border-border bg-background px-1.5 py-0.5 font-mono text-[9px] text-muted-foreground">
          ⌘K
        </kbd>
      </div>

      <div className="ml-auto flex items-center gap-3">
        <div className="hidden items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-3 py-1 sm:flex">
          <ShieldCheck className="h-3 w-3 text-primary" />
          <span className="font-mono text-[10px] uppercase tracking-wider text-primary">
            Chain intact
          </span>
        </div>
        <div className="hidden items-center gap-2 rounded-full border border-border bg-card/40 px-3 py-1 md:flex">
          <span className="h-1.5 w-1.5 rounded-full bg-primary pulse-dot" />
          <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            Engine online
          </span>
        </div>
        <button
          type="button"
          className="relative rounded-md border border-border bg-card/40 p-1.5 hover:border-primary/40"
          aria-label="Notifications"
        >
          <Bell className="h-4 w-4 text-muted-foreground" />
          <span className="absolute right-0.5 top-0.5 h-1.5 w-1.5 rounded-full bg-destructive" />
        </button>
        <div className="flex h-8 w-8 items-center justify-center rounded-full border border-primary/40 bg-primary/10 font-mono text-[11px] font-bold text-primary">
          RS
        </div>
      </div>
    </header>
  );
}
