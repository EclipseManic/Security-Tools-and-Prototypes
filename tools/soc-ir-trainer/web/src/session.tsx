import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, UnauthorizedError } from "./api";
import type { SessionInfo } from "./types";

type Status = "loading" | "ready" | "anonymous" | "error";

interface SessionContextValue {
  session: SessionInfo | null;
  status: Status;
  error: string | null;
  refresh: () => Promise<void>;
  setSession: (session: SessionInfo | null) => void;
  logout: () => Promise<void>;
}

const SessionContext = createContext<SessionContextValue>({
  session: null,
  status: "loading",
  error: null,
  refresh: async () => undefined,
  setSession: () => undefined,
  logout: async () => undefined,
});

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSessionState] = useState<SessionInfo | null>(null);
  const [status, setStatus] = useState<Status>("loading");
  const [error, setError] = useState<string | null>(null);

  const setSession = useCallback((next: SessionInfo | null) => {
    setSessionState(next);
    setError(null);
    setStatus(next ? "ready" : "anonymous");
  }, []);

  const refresh = useCallback(async () => {
    try {
      const info = await api.me();
      setSessionState(info);
      setError(null);
      setStatus("ready");
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        setSession(null);
        setError(null);
        setStatus("anonymous");
        return;
      }
      setError(err instanceof Error ? err.message : "Could not load your profile.");
      setStatus("error");
    }
  }, [setSession]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // A 401 from any request (session cookie expired, profile removed) drops the
  // SPA back to onboarding instead of leaving pages half-loaded.
  useEffect(() => {
    const onUnauthorized = () => {
      setSession(null);
      setStatus("anonymous");
    };
    window.addEventListener("soc:unauthorized", onUnauthorized);
    return () => window.removeEventListener("soc:unauthorized", onUnauthorized);
  }, [setSession]);

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // Clearing client state is the important part.
    }
    setSession(null);
  }, [setSession]);

  const value = useMemo(
    () => ({ session, status, error, refresh, setSession, logout }),
    [session, status, error, refresh, setSession, logout],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession() {
  return useContext(SessionContext);
}
