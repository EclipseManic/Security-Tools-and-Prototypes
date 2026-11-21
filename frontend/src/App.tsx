import { Routes, Route } from "react-router-dom";
import { Toaster } from "sonner";
import { Layout } from "@/components/layout";
import ErrorBoundary from "@/components/ErrorBoundary";
import Dashboard from "@/pages/Dashboard";
import Scans from "@/pages/Scans";
import ScanDetail from "@/pages/ScanDetail";
import FileDetailPage from "@/pages/FileDetail";
import SearchPage from "@/pages/SearchPage";
import Reports from "@/pages/Reports";
import SettingsPage from "@/pages/SettingsPage";
import Categories from "@/pages/Categories";
import CategoryFiles from "@/pages/CategoryFiles";

function App() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Layout>
        <ErrorBoundary>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/files/:id" element={<FileDetailPage />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/categories" element={<Categories />} />
            <Route path="/category/:type" element={<CategoryFiles />} />
          </Routes>
        </ErrorBoundary>
      </Layout>
      <Toaster position="bottom-right" theme="dark" />
    </div>
  );
}

export default App;
