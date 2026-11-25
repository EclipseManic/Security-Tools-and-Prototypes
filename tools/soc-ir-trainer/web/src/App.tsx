import type { ReactNode } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { AppShell } from "./components/Layout";
import { Button, ErrorState, Loading } from "./components/ui";
import { useSession } from "./session";
import Dashboard from "./pages/Dashboard";
import Debrief from "./pages/Debrief";
import Library from "./pages/Library";
import Onboarding from "./pages/Onboarding";
import Progress from "./pages/Progress";
import RunWorkspace from "./pages/RunWorkspace";
import Settings from "./pages/Settings";

function FullScreenGate({ children }: { children: ReactNode }) {
  return (
    <div className="onboarding">
      <div className="card onboarding-card" style={{ padding: 24 }}>
        {children}
      </div>
    </div>
  );
}

function ProtectedShell() {
  const { status, error, refresh } = useSession();

  if (status === "loading") {
    return (
      <FullScreenGate>
        <Loading label="Starting your workspace" />
      </FullScreenGate>
    );
  }
  if (status === "error") {
    return (
      <FullScreenGate>
        <ErrorState message={error ?? "Could not load your profile."} onRetry={() => void refresh()} />
      </FullScreenGate>
    );
  }
  if (status === "anonymous") {
    return <Navigate to="/onboarding" replace />;
  }
  return <AppShell />;
}

function NotFound() {
  const navigate = useNavigate();
  return (
    <div className="page page-narrow">
      <div className="card">
        <div className="empty-state">
          <div className="empty-icon">404</div>
          <h3>Page not found</h3>
          <p className="small">That route does not exist in the training range.</p>
          <Button variant="primary" icon="dashboard" onClick={() => navigate("/")}>
            Back to dashboard
          </Button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const { status } = useSession();

  return (
    <Routes>
      <Route
        path="/onboarding"
        element={
          status === "ready" ? (
            <Navigate to="/" replace />
          ) : status === "loading" ? (
            <FullScreenGate>
              <Loading label="Starting your workspace" />
            </FullScreenGate>
          ) : (
            <Onboarding />
          )
        }
      />
      <Route element={<ProtectedShell />}>
        <Route index element={<Dashboard />} />
        <Route path="library" element={<Library />} />
        <Route path="runs/:runId" element={<RunWorkspace />} />
        <Route path="runs/:runId/debrief" element={<Debrief />} />
        <Route path="progress" element={<Progress />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}
