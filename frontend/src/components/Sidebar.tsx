import { NavLink } from "react-router-dom";
import { ShieldHalf, LayoutDashboard, BarChart3, FileText, UploadCloud, GitCompare } from "lucide-react";

const links = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/upload", label: "Analyze Scan", icon: UploadCloud },
  { to: "/charts", label: "Charts", icon: BarChart3 },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/compare", label: "Compare", icon: GitCompare },
];

export default function Sidebar() {
  return (
    <aside className="w-60 shrink-0 bg-ink-950 border-r border-ink-700 flex flex-col">
      <div className="flex items-center gap-2 px-5 py-6">
        <ShieldHalf className="text-signal-400" size={26} strokeWidth={2.2} />
        <div>
          <div className="font-display font-semibold text-slate-100 text-[15px] leading-none">SecInsight</div>
          <div className="text-[11px] text-slate-500 tracking-wide mt-1">AI SECURITY ANALYSIS</div>
        </div>
      </div>
      <nav className="flex-1 px-3 space-y-1">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
                isActive
                  ? "bg-signal-500/15 text-signal-400 border border-signal-500/30"
                  : "text-slate-400 hover:text-slate-100 hover:bg-ink-800 border border-transparent"
              }`
            }
          >
            <Icon size={17} />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="px-5 py-4 text-[11px] text-slate-600 border-t border-ink-700">
        v0.1.0 &middot; secinsight.dev
      </div>
    </aside>
  );
}
