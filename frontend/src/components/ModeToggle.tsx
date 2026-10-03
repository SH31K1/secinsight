import { useMode } from "../ModeContext";
import { GraduationCap, Briefcase } from "lucide-react";

export default function ModeToggle() {
  const { mode, setMode } = useMode();
  return (
    <div className="inline-flex items-center rounded-full bg-ink-800 border border-ink-600 p-1 text-sm">
      <button
        onClick={() => setMode("student")}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-colors ${
          mode === "student" ? "bg-signal-500 text-white" : "text-slate-400 hover:text-slate-200"
        }`}
      >
        <GraduationCap size={14} /> Student
      </button>
      <button
        onClick={() => setMode("pro")}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full transition-colors ${
          mode === "pro" ? "bg-signal-500 text-white" : "text-slate-400 hover:text-slate-200"
        }`}
      >
        <Briefcase size={14} /> Professional
      </button>
    </div>
  );
}
