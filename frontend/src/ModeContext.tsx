import React, { createContext, useContext, useState } from "react";
import type { Mode } from "./types";

interface ModeContextValue {
  mode: Mode;
  setMode: (m: Mode) => void;
}

const ModeContext = createContext<ModeContextValue | undefined>(undefined);

export function ModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<Mode>(
    (localStorage.getItem("secinsight_mode") as Mode) || "pro"
  );

  const update = (m: Mode) => {
    setMode(m);
    localStorage.setItem("secinsight_mode", m);
  };

  return <ModeContext.Provider value={{ mode, setMode: update }}>{children}</ModeContext.Provider>;
}

export function useMode(): ModeContextValue {
  const ctx = useContext(ModeContext);
  if (!ctx) throw new Error("useMode must be used within a ModeProvider");
  return ctx;
}
