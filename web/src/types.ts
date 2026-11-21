export type Role = "analyst" | "incident_manager" | "ciso" | "executive";

export interface User {
  name: string;
  role: Role | string;
  domains: string[];
  created_at?: string | null;
}

export interface LiveRun {
  run_id: number;
  scenario_id: string;
  title: string;
  category: string;
  phase_number: number;
  answered: number;
  updated_at?: string | null;
}

export interface SessionInfo {
  user: User;
  live_run: LiveRun | null;
  scenarios: number;
}

export interface Scenario {
  id: string;
  name: string;
  title: string;
  category: string;
  difficulty: string;
  format_version: number;
  opening: string;
  detected_via: string;
  compromised_assets: string[];
  kill_chain: string[];
  mitre_tactics: string[];
  soc_tier: string;
  roles: string[];
  industries: string[];
  phase_count: number;
  executive_brief: string;
  role: string;
  role_fallback: boolean;
}

export interface ScenarioDetail extends Scenario {
  briefings: Record<string, string>;
  phase_types: string[];
}

export interface ScenarioPage {
  items: Scenario[];
  total: number;
  limit: number;
  offset: number;
  facets: {
    domains?: Record<string, number>;
    difficulties?: Record<string, number>;
    roles?: Record<string, number>;
  };
}

export interface Guidance {
  what: string;
  action: string;
  why: string;
}

export interface PhaseState {
  number: number;
  id: string;
  title: string;
  type: string;
  situation: string;
  prompt: string;
  guidance: Guidance;
  hint: string;
  hints_total: number;
  hints_revealed: number;
  reference_revealed: boolean;
  mitre_tactic: string;
  mitre_technique: string;
}

export interface RunScenarioBrief {
  id: string;
  name: string;
  title: string;
  category: string;
  difficulty: string;
  opening: string;
  compromised_assets: string[];
  detected_via: string;
  kill_chain: string[];
  mitre_tactics: string[];
  soc_tier: string;
  roles: string[];
  role: string;
  role_briefing: string;
  executive_brief: string;
  phase_count: number;
}

export interface RunProgress {
  answered: number;
  visited: string[];
  current_phase_id: string;
  hints_used: number;
  reveals: number;
  draft_answer: string;
}

export interface RunState {
  run_id: number;
  status: string;
  scenario: RunScenarioBrief;
  phase: PhaseState | null;
  progress: RunProgress;
  can_finish: boolean;
  evaluation_available: boolean;
  started_at?: string | null;
  updated_at?: string | null;
  role_fallback: boolean;
  industry: string;
}

export interface AnswerResult {
  run_id: number;
  status: string;
  branch: "good" | "weak";
  followup: string;
  phase: PhaseState | null;
  progress: RunProgress;
  can_finish: boolean;
}

export interface HintResult {
  run_id: number;
  phase_id: string;
  hint: string | null;
  index: number;
  total: number;
  remaining: number;
  exhausted: boolean;
}

export interface RevealResult {
  run_id: number;
  phase_id: string;
  reference_answer: string;
  looked_up: boolean;
  reveals_total: number;
}

export interface RunHistoryItem {
  run_id: number;
  scenario_id: string;
  title: string;
  category: string;
  role_used: string;
  score: number | null;
  grade: string | null;
  started_at: string;
  completed_at?: string | null;
  status: string;
  duration_minutes?: number | null;
}

export interface RunHistoryPage {
  items: RunHistoryItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface Recommendation {
  mode: string;
  technique: string | null;
  reason: string;
  scenario: Scenario | null;
}

export interface DomainMetric {
  domain: string;
  avg_score: number;
  weakest_technique: string | null;
  total_runs: number;
  last_practiced: string | null;
}

export interface MasteryRow {
  technique: string;
  technique_name: string;
  attempts: number;
  avg_score: number;
  best_score: number;
  last_practiced: string;
  level: string;
}

export interface RecentRun {
  run_id: number;
  scenario_id: string;
  score: number | null;
  grade: string | null;
  completed_at: string;
  domain: string;
}

export interface ProgressInfo {
  user: User;
  learner_level: string;
  streak: number;
  run_count: number;
  domains: DomainMetric[];
  mastery: MasteryRow[];
  recent: RecentRun[];
  recommendation: Recommendation;
  live_run: LiveRun | null;
}

export interface ModelInfo {
  id: string;
  name: string;
  context_length?: number | null;
  free: boolean;
}


export interface ModelList {
  models: ModelInfo[];
  source: string;
}


export interface DataActionOut {
  user: string;
  runs_deleted: number;
  actions_deleted: number;
  profile_deleted: boolean;
}


export interface SettingsInfo {
  app: string;
  version: string;
  model: string;
  api_key_configured: boolean;
  ai_disabled: boolean;
  db_available: boolean;
  scenarios: number;
  max_answer_chars: number;
  cookie_secure: boolean;
  report_dir: string;
}

export interface PhaseEvaluation {
  phase_number: number;
  phase_title: string;
  user_action: string;
  user_action_type?: string;
  ideal_action: string;
  correctness: number;
  offline_score?: number;
  what_score?: number;
  action_score?: number;
  why_score?: number;
  analysis: string;
  detailed_analysis?: string;
  what_did_right?: string;
  what_did_wrong?: string;
  how_to_improve?: string;
  mitre_relevance?: string;
}

export interface TighteningRecommendation {
  area: string;
  current_gap: string;
  recommendation: string;
  priority: string;
  reference?: string;
}

export interface Evaluation {
  score: number;
  grade: string;
  overall_assessment: string;
  final_verdict: string;
  phase_evaluations: PhaseEvaluation[];
  strengths: string[];
  weaknesses: string[];
  tightening_recommendations: TighteningRecommendation[];
  missed_opportunities: string[];
  tools_used: string[];
  tools_missing: string[];
  communication_grade: string;
  communication_feedback: string;
  incident_timeline_recommendation?: string;
  next_training: string[];
  offline_avg?: number;
  assist_penalty?: number;
  fallback?: boolean;
}

export interface EvaluationResult {
  run_id: number;
  status: string;
  evaluation: Evaluation | null;
  recommendation: Recommendation | null;
}

export interface Job {
  run_id: number;
  status: "queued" | "running" | "done" | "failed" | "not_started";
  queued_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  result?: EvaluationResult | null;
}
