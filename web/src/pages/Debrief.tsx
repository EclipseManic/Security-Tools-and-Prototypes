import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, PHASE_LABELS, ROLE_LABELS } from "../api";
import { Icon, type IconName } from "../components/Icons";
import {
  Badge,
  Button,
  ErrorState,
  ScoreRing,
  scoreClass,
  scoreTone,
  useToast,
} from "../components/ui";
import type { Evaluation, Job, Recommendation, RunState } from "../types";

function average(values: number[]): number {
  if (!values.length) return 0;
  return Math.round(values.reduce((sum, value) => sum + value, 0) / values.length);
}

function StringList({
  items,
  tone,
  icon,
  empty,
}: {
  items: string[];
  tone: "positive" | "negative" | "neutral";
  icon: IconName;
  empty: string;
}) {
  if (!items.length) return <p className="small dim">{empty}</p>;
  return (
    <ul className={`list-check ${tone}`}>
      {items.map((item, index) => (
        <li key={index}>
          <Icon name={icon} size={14} />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

export default function Debrief() {
  const { runId } = useParams();
  const id = Number(runId);
  const navigate = useNavigate();
  const { push } = useToast();

  const [job, setJob] = useState<Job | null>(null);
  const [run, setRun] = useState<RunState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);
  const [openPhase, setOpenPhase] = useState<number | null>(null);

  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [jobData, runData] = await Promise.all([api.evaluation(id), api.run(id)]);
      setJob(jobData);
      setRun(runData);
      if (jobData.status === "queued" || jobData.status === "running") {
        timer.current = window.setTimeout(() => void load(), 2000);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the debrief.");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    if (!Number.isFinite(id) || id <= 0) {
      setError("Invalid run id.");
      setLoading(false);
      return;
    }
    void load();
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [id, load]);

  async function startScenario(scenarioId: string) {
    setStarting(true);
    try {
      const next = await api.startRun(scenarioId, run?.scenario.role ?? "analyst");
      navigate(`/runs/${next.run_id}`);
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not start the scenario.", "error");
      setStarting(false);
    }
  }

  if (loading) {
    return (
      <div className="page">
        <div className="skeleton" style={{ height: 132, borderRadius: 10 }} />
        <div className="two-col">
          <div className="skeleton" style={{ height: 220 }} />
          <div className="skeleton" style={{ height: 220 }} />
        </div>
        <div className="skeleton" style={{ height: 300 }} />
      </div>
    );
  }
  if (error) {
    return (
      <div className="page page-narrow">
        <div className="card">
          <ErrorState message={error} onRetry={() => void load()} />
        </div>
      </div>
    );
  }
  if (!job) return null;

  const result = job.result ?? null;
  const evaluation: Evaluation | null = result?.evaluation ?? null;
  const recommendation: Recommendation | null = result?.recommendation ?? null;
  const pending = job.status === "queued" || job.status === "running";

  if (pending) {
    return (
      <div className="page page-narrow">
        <div className="page-head">
          <div>
            <div className="eyebrow">Debrief</div>
            <h1>Evaluating your run</h1>
            <p className="page-sub">{run?.scenario.title}</p>
          </div>
        </div>
        <div className="card">
          <div className="empty-state" style={{ padding: "56px 24px" }} role="status" aria-live="polite">
            <span className="spinner" style={{ width: 26, height: 26, borderWidth: 3 }} />
            <h3>{job.status === "queued" ? "Queued for evaluation" : "AI evaluation in progress"}</h3>
            <p className="small" style={{ maxWidth: 460 }}>
              Free-tier inference usually takes 25–40 seconds. This page updates automatically — no
              need to refresh. Your run is safely stored either way.
            </p>
            <div className="row wrap" style={{ justifyContent: "center", marginTop: 6 }}>
              <Badge tone="blue">Score</Badge>
              <Badge tone="blue">Phase analysis</Badge>
              <Badge tone="blue">Recommendations</Badge>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (job.status === "failed") {
    return (
      <div className="page page-narrow">
        <div className="card">
          <ErrorState
            message={job.error ?? "The evaluation job failed."}
            onRetry={() => {
              setLoading(true);
              void load();
            }}
          />
        </div>
        <div className="row" style={{ justifyContent: "center" }}>
          <Button icon="arrowLeft" onClick={() => navigate(`/runs/${id}`)}>
            Back to run
          </Button>
          <Button variant="primary" icon="library" onClick={() => navigate("/library")}>
            Scenario library
          </Button>
        </div>
      </div>
    );
  }

  if (!evaluation) {
    return (
      <div className="page page-narrow">
        <div className="card">
          <div className="empty-state">
            <div className="empty-icon">
              <Icon name="alertCircle" size={19} />
            </div>
            <h3>No debrief is available yet</h3>
            <p className="small">
              {run?.status === "in_progress"
                ? "This run is still open. Finish all phases to generate the debrief."
                : "The evaluation for this run was not saved."}
            </p>
            <div className="row">
              <Button variant="primary" onClick={() => navigate(`/runs/${id}`)}>
                {run?.status === "in_progress" ? "Continue run" : "Open run"}
              </Button>
              <Button icon="library" onClick={() => navigate("/library")}>
                Library
              </Button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const phases = evaluation.phase_evaluations ?? [];
  const whatAvg = average(phases.map((phase) => phase.what_score ?? phase.correctness ?? 0));
  const actionAvg = average(phases.map((phase) => phase.action_score ?? phase.correctness ?? 0));
  const whyAvg = average(phases.map((phase) => phase.why_score ?? phase.correctness ?? 0));
  const techniques = Array.from(
    new Set(
      phases
        .map((phase) => phase.mitre_relevance)
        .filter((value): value is string => Boolean(value)),
    ),
  );
  const offline = Boolean(evaluation.fallback);
  const progress = run?.progress;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Debrief</div>
          <h1>{run?.scenario.title ?? "Run debrief"}</h1>
          <div className="row wrap" style={{ marginTop: 6 }}>
            {run ? <Badge tone="cyan">{run.scenario.category}</Badge> : null}
            {run ? <Badge>{run.scenario.difficulty}</Badge> : null}
            {run ? <Badge tone="blue">{ROLE_LABELS[run.scenario.role] ?? run.scenario.role}</Badge> : null}
            <Badge tone={offline ? "amber" : "green"} icon="sparkles">
              {offline ? "Offline debrief" : "AI debrief"}
            </Badge>
          </div>
        </div>
        <div className="row wrap">
          <Button size="sm" icon="refresh" onClick={() => navigate("/library")}>
            New scenario
          </Button>
          {run ? (
            <Button
              size="sm"
              variant="primary"
              icon="play"
              loading={starting}
              onClick={() => void startScenario(run.scenario.id)}
            >
              Run again
            </Button>
          ) : null}
        </div>
      </div>

      <section className="card debrief-hero">
        <ScoreRing score={evaluation.score} grade={evaluation.grade} />
        <div>
          <div className="row wrap">
            <Badge tone={scoreTone(evaluation.score) === "good" ? "green" : scoreTone(evaluation.score) === "mid" ? "amber" : "red"}>
              {evaluation.grade}
            </Badge>
            <span className="tiny dim">
              {phases.length} phases scored{progress ? ` · ${progress.hints_used} hints · ${progress.reveals} reveals` : ""}
            </span>
          </div>
          <p className="verdict">{evaluation.final_verdict}</p>
          <p className="assessment">{evaluation.overall_assessment}</p>
          <div className="row wrap" style={{ marginTop: 12 }}>
            <a className="btn btn-sm" href={api.reportUrl(id, "html")} target="_blank" rel="noreferrer">
              <Icon name="fileText" size={14} /> HTML report
            </a>
            <a className="btn btn-sm" href={api.reportUrl(id, "pdf")} target="_blank" rel="noreferrer">
              <Icon name="download" size={14} /> PDF
            </a>
            <a className="btn btn-sm btn-ghost" href={api.reportUrl(id, "json")} target="_blank" rel="noreferrer">
              JSON
            </a>
          </div>
        </div>
      </section>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">What · detection</div>
          <div className="stat-value" style={{ color: scoreTone(whatAvg) === "good" ? "var(--green-400)" : scoreTone(whatAvg) === "mid" ? "var(--amber-400)" : "var(--red-400)" }}>
            {whatAvg}<span className="small dim">/10</span>
          </div>
          <div className="stat-note">Recognizing what happened</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Action · response</div>
          <div className="stat-value" style={{ color: scoreTone(actionAvg) === "good" ? "var(--green-400)" : scoreTone(actionAvg) === "mid" ? "var(--amber-400)" : "var(--red-400)" }}>
            {actionAvg}<span className="small dim">/10</span>
          </div>
          <div className="stat-note">Effectiveness of the response</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Why · justification</div>
          <div className="stat-value" style={{ color: scoreTone(whyAvg) === "good" ? "var(--green-400)" : scoreTone(whyAvg) === "mid" ? "var(--amber-400)" : "var(--red-400)" }}>
            {whyAvg}<span className="small dim">/10</span>
          </div>
          <div className="stat-note">Reasoning and prioritization</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Communication</div>
          <div className="stat-value">{evaluation.communication_grade}</div>
          <div className="stat-note truncate" title={evaluation.communication_feedback}>
            {evaluation.communication_feedback || "—"}
          </div>
        </div>
      </div>

      <div className="two-col">
        <section className="card">
          <div className="card-head">
            <div className="row" style={{ gap: 7 }}>
              <Icon name="checkCircle" size={15} style={{ color: "var(--green-400)" }} />
              <span className="card-title">What you did right</span>
            </div>
          </div>
          <div className="card-body">
            <StringList items={evaluation.strengths ?? []} tone="positive" icon="checkCircle" empty="No strengths were recorded." />
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div className="row" style={{ gap: 7 }}>
              <Icon name="alertTriangle" size={15} style={{ color: "var(--red-400)" }} />
              <span className="card-title">What to tighten</span>
            </div>
          </div>
          <div className="card-body">
            <StringList items={evaluation.weaknesses ?? []} tone="negative" icon="alertTriangle" empty="No weaknesses were recorded." />
          </div>
        </section>
      </div>

      <div className="two-col">
        <section className="card">
          <div className="card-head">
            <span className="card-title">Missed opportunities</span>
          </div>
          <div className="card-body">
            <StringList items={evaluation.missed_opportunities ?? []} tone="neutral" icon="info" empty="Nothing flagged." />
          </div>
        </section>
        <section className="card">
          <div className="card-head">
            <span className="card-title">Next training</span>
          </div>
          <div className="card-body">
            <StringList items={evaluation.next_training ?? []} tone="neutral" icon="target" empty="No follow-up topics suggested." />
          </div>
        </section>
      </div>

      {recommendation?.scenario ? (
        <section className="card">
          <div className="card-head">
            <div className="row" style={{ gap: 7 }}>
              <Icon name="compass" size={15} style={{ color: "var(--blue-400)" }} />
              <span className="card-title">Recommended next drill</span>
            </div>
            <Badge tone="blue">Adaptive</Badge>
          </div>
          <div className="card-body">
            <div className="row-between wrap" style={{ alignItems: "flex-start" }}>
              <div style={{ maxWidth: 680 }}>
                <h3>{recommendation.scenario.title}</h3>
                <div className="row wrap" style={{ marginTop: 5 }}>
                  <Badge tone="cyan">{recommendation.scenario.category}</Badge>
                  <Badge>{recommendation.scenario.difficulty}</Badge>
                  <Badge>{recommendation.scenario.phase_count} phases</Badge>
                </div>
                <p className="small muted" style={{ marginTop: 8 }}>
                  {recommendation.reason}
                </p>
              </div>
              <Button
                variant="primary"
                icon="play"
                loading={starting}
                onClick={() => void startScenario(recommendation.scenario!.id)}
              >
                Start next drill
              </Button>
            </div>
          </div>
        </section>
      ) : null}

      <section className="card">
        <div className="card-head">
          <span className="card-title">Phase-by-phase analysis</span>
          <Badge>{phases.length} phases</Badge>
        </div>
        {phases.length === 0 ? (
          <p className="card-body small dim">The evaluation did not include per-phase detail.</p>
        ) : (
          <div className="phase-accordion">
            {phases.map((phase) => {
              const open = openPhase === phase.phase_number;
              const tone = scoreTone(phase.correctness);
              return (
                <div key={phase.phase_number} className="acc-item">
                  <button
                    className="acc-head"
                    onClick={() => setOpenPhase(open ? null : phase.phase_number)}
                    aria-expanded={open}
                  >
                    <span className="acc-num">{phase.phase_number}</span>
                    <span className="grow" style={{ minWidth: 0 }}>
                      <span className="acc-title" style={{ display: "block" }}>
                        {phase.phase_title}
                      </span>
                      <span className="acc-sub">
                        {PHASE_LABELS[phase.user_action_type ?? ""] ?? phase.mitre_relevance ?? "Phase review"}
                      </span>
                    </span>
                    <span className={`acc-score ${scoreClass(phase.correctness)}`} style={{ color: tone === "good" ? "var(--green-400)" : tone === "mid" ? "var(--amber-400)" : "var(--red-400)" }}>
                      {phase.correctness}/10
                    </span>
                    <Icon name={open ? "chevronDown" : "chevronRight"} size={15} />
                  </button>
                  {open ? (
                    <div className="acc-body">
                      <div className="acc-block user">
                        <div className="ak">Your response</div>
                        <p style={{ whiteSpace: "pre-wrap" }}>{phase.user_action}</p>
                      </div>
                      <div className="acc-block">
                        <div className="ak">Ideal response</div>
                        <p style={{ whiteSpace: "pre-wrap" }}>{phase.ideal_action}</p>
                      </div>
                      <div className="acc-block">
                        <div className="ak">Analysis</div>
                        <p>{phase.analysis}</p>
                      </div>
                      <div className="score-bars">
                        {[
                          ["What", phase.what_score],
                          ["Action", phase.action_score],
                          ["Why", phase.why_score],
                        ].map(([label, value]) => (
                          <div key={String(label)} className="score-bar-cell">
                            <div className="sb-head">
                              <span>{label}</span>
                              <span className="mono">{value ?? phase.correctness}/10</span>
                            </div>
                            <div className="bar">
                              <div
                                className={`bar-fill ${scoreTone(Number(value ?? phase.correctness))}`}
                                style={{ width: `${Math.min(100, Number(value ?? phase.correctness) * 10)}%` }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>
                      <div className="two-col" style={{ gap: 10 }}>
                        {phase.what_did_right ? (
                          <div className="acc-block">
                            <div className="ak">Worked</div>
                            <p>{phase.what_did_right}</p>
                          </div>
                        ) : null}
                        {phase.what_did_wrong ? (
                          <div className="acc-block">
                            <div className="ak">Did not land</div>
                            <p>{phase.what_did_wrong}</p>
                          </div>
                        ) : null}
                      </div>
                      {phase.how_to_improve ? (
                        <div className="acc-block">
                          <div className="ak">Next time</div>
                          <p>{phase.how_to_improve}</p>
                        </div>
                      ) : null}
                      {phase.mitre_relevance ? (
                        <div className="tiny dim mono">{phase.mitre_relevance}</div>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {(evaluation.tightening_recommendations ?? []).length ? (
        <section className="card">
          <div className="card-head">
            <span className="card-title">Tightening recommendations</span>
            <Badge>{evaluation.tightening_recommendations.length}</Badge>
          </div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Area</th>
                  <th>Gap</th>
                  <th>Recommendation</th>
                  <th>Priority</th>
                  <th>Reference</th>
                </tr>
              </thead>
              <tbody>
                {evaluation.tightening_recommendations.map((item, index) => (
                  <tr key={index}>
                    <td style={{ fontWeight: 550 }}>{item.area}</td>
                    <td className="muted small">{item.current_gap}</td>
                    <td className="muted small">{item.recommendation}</td>
                    <td>
                      <Badge
                        tone={
                          item.priority === "Critical"
                            ? "red"
                            : item.priority === "High"
                              ? "amber"
                              : item.priority === "Medium"
                                ? "blue"
                                : "default"
                        }
                      >
                        {item.priority}
                      </Badge>
                    </td>
                    <td className="tiny dim">{item.reference ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {techniques.length || (evaluation.tools_used ?? []).length || (evaluation.tools_missing ?? []).length ? (
        <div className="two-col">
          <section className="card">
            <div className="card-head">
              <span className="card-title">MITRE coverage</span>
            </div>
            <div className="card-body context-tags">
              {techniques.length ? (
                techniques.map((technique) => (
                  <span key={technique} className="chip mono">
                    {technique}
                  </span>
                ))
              ) : (
                <span className="small dim">No technique detail recorded.</span>
              )}
            </div>
          </section>
          <section className="card">
            <div className="card-head">
              <span className="card-title">Tools & frameworks</span>
            </div>
            <div className="card-body stack-sm">
              {(evaluation.tools_used ?? []).length ? (
                <div className="context-tags">
                  {evaluation.tools_used.map((tool) => (
                    <span key={tool} className="chip">
                      {tool}
                    </span>
                  ))}
                </div>
              ) : null}
              {(evaluation.tools_missing ?? []).length ? (
                <div className="context-tags">
                  {evaluation.tools_missing.map((tool) => (
                    <span key={tool} className="chip" style={{ borderColor: "rgba(251,191,36,0.3)" }}>
                      missing: {tool}
                    </span>
                  ))}
                </div>
              ) : null}
              {!(evaluation.tools_used ?? []).length && !(evaluation.tools_missing ?? []).length ? (
                <span className="small dim">No tooling detail recorded.</span>
              ) : null}
            </div>
          </section>
        </div>
      ) : null}

      {evaluation.incident_timeline_recommendation ? (
        <section className="card">
          <div className="card-head">
            <span className="card-title">Timeline recommendation</span>
          </div>
          <div className="card-body small muted">{evaluation.incident_timeline_recommendation}</div>
        </section>
      ) : null}

      <div className="row" style={{ justifyContent: "center", paddingBottom: 12 }}>
        <Button icon="arrowLeft" onClick={() => navigate("/progress")}>
          Progress report
        </Button>
        <Button variant="primary" icon="library" onClick={() => navigate("/library")}>
          Back to library
        </Button>
      </div>
    </div>
  );
}
