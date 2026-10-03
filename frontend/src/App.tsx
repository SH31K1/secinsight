import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Upload from "./pages/Upload";
import Charts from "./pages/Charts";
import Reports from "./pages/Reports";
import Compare from "./pages/Compare";
import ScanDetail from "./pages/ScanDetail";
import { ModeProvider } from "./ModeContext";

export default function App() {
  return (
    <ModeProvider>
      <div className="flex min-h-screen bg-ink-900">
        <Sidebar />
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/charts" element={<Charts />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/compare" element={<Compare />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
          </Routes>
        </main>
      </div>
    </ModeProvider>
  );
}
