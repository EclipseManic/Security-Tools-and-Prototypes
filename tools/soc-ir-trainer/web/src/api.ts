import type {
  AnswerResult,
  DataActionOut,
  EvaluationResult,
  HintResult,
  Job,
  ModelList,
  ProgressInfo,
  Recommendation,
  RevealResult,
  RunHistoryPage,
  RunState,
  ScenarioDetail,
  ScenarioPage,
  SessionInfo,
  SettingsInfo,
  User,
} from "./types";

const BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  code: string;
  detail: unknown;

  constructor(status: number, code: string, message: string, detail?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

export class UnauthorizedError extends ApiError {}

type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

interface RequestOptions {
  method?: Method;
  body?: unknown;
  signal?: AbortSignal;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { Accept: "application/json" };
  if (method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-Requested-With"] = "SOC-Trainer";
  }

  let response: Response;
  try {
    response = await fetch(`${BASE}${path}`, {
      method,
      headers,
      credentials: "same-origin",
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new ApiError(0, "network_error", "Cannot reach the trainer service. Is the server running?");
  }

  if (response.status === 204) return undefined as T;

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!response.ok) {
    const body = (payload ?? {}) as { code?: string; message?: string; detail?: unknown };
    const message =
      body.message ||
      (typeof payload === "string" ? payload : `Request failed (${response.status}).`);
    if (response.status === 401) {
      window.dispatchEvent(new Event("soc:unauthorized"));
      throw new UnauthorizedError(401, body.code ?? "unauthenticated", message, body.detail);
    }
    throw new ApiError(
      response.status,
      body.code ?? "request_failed",
      message,
      body.detail,
    );
  }

  return payload as T;
}

export const api = {
  // session ---------------------------------------------------------------
  createSession: (name: string, role: string, domains: string[]) =>
    request<SessionInfo>("/session", {
      method: "POST",
      body: { name, role, domains },
    }),
  me: () => request<SessionInfo>("/me"),
  updateMe: (patch: { role?: string; domains?: string[] }) =>
    request<SessionInfo>("/me", { method: "PATCH", body: patch }),
  logout: () => request<void>("/logout", { method: "POST" }),

  // scenarios -------------------------------------------------------------
  scenarios: (params: Record<string, string | number | undefined>, signal?: AbortSignal) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== "" && value !== null) {
        query.set(key, String(value));
      }
    });
    return request<ScenarioPage>(`/scenarios?${query.toString()}`, { signal });
  },
  scenario: (id: string) => request<ScenarioDetail>(`/scenarios/${encodeURIComponent(id)}`),

  // runs ------------------------------------------------------------------
  startRun: (scenarioId: string, role: string, industry = "all") =>
    request<RunState>("/runs", {
      method: "POST",
      body: { scenario_id: scenarioId, role, industry },
    }),
  run: (runId: number) => request<RunState>(`/runs/${runId}`),
  answer: (runId: number, text: string, phaseId: string) =>
    request<AnswerResult>(`/runs/${runId}/answer`, {
      method: "POST",
      body: { text, phase_id: phaseId },
    }),
  hint: (runId: number) =>
    request<HintResult>(`/runs/${runId}/hint`, { method: "POST" }),
  reveal: (runId: number) =>
    request<RevealResult>(`/runs/${runId}/reveal`, { method: "POST" }),
  saveDraft: (runId: number, text: string) =>
    request<{ run_id: number; draft_answer: string }>(`/runs/${runId}/draft`, {
      method: "PATCH",
      body: { text },
    }),
  abandon: (runId: number) =>
    request<{ run_id: number; status: string }>(`/runs/${runId}/abandon`, {
      method: "POST",
    }),
  finish: (runId: number) => request<Job>(`/runs/${runId}/finish`, { method: "POST" }),
  evaluation: (runId: number) => request<Job>(`/runs/${runId}/evaluation`),
  runs: (params: Record<string, string | number | undefined> = {}) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== "") query.set(key, String(value));
    });
    return request<RunHistoryPage>(`/runs?${query.toString()}`);
  },
  reportUrl: (runId: number, format: "html" | "pdf" | "json") =>
    `${BASE}/runs/${runId}/report?format=${format}`,

  // progress / settings ---------------------------------------------------
  progress: () => request<ProgressInfo>("/progress"),
  recommendation: (domains?: string) =>
    request<Recommendation>(
      `/recommendation${domains ? `?domains=${encodeURIComponent(domains)}` : ""}`,
    ),
  settings: () => request<SettingsInfo>("/settings"),
  models: () => request<ModelList>("/settings/models"),
  setModel: (model: string) =>
    request<SettingsInfo>("/settings/model", {
      method: "PUT",
      body: { model },
    }),
  setApiKey: (apiKey: string) =>
    request<SettingsInfo>("/settings/api-key", {
      method: "PUT",
      body: { api_key: apiKey },
    }),
  clearApiKey: () =>
    request<SettingsInfo>("/settings/api-key", { method: "DELETE" }),
  clearHistory: () =>
    request<DataActionOut>("/settings/clear-history", { method: "POST" }),
  deleteProfile: () =>
    request<DataActionOut>("/me", { method: "DELETE" }),
};

export function evaluationFromJob(job: Job): EvaluationResult | null {
  if (job.result && job.result.evaluation) return job.result;
  return null;
}

export function userLabel(user: User | null): string {
  return user?.name ?? "Analyst";
}

export const ROLE_LABELS: Record<string, string> = {
  analyst: "SOC Analyst",
  incident_manager: "Incident Manager",
  ciso: "CISO",
  executive: "Executive",
};

export const PHASE_LABELS: Record<string, string> = {
  triage: "Triage",
  analysis: "Analysis",
  containment: "Containment",
  eradication: "Eradication",
  recovery: "Recovery",
  lessons: "Lessons learned",
};
