import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ROLE_LABELS } from "../api";
import { Icon } from "../components/Icons";
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  PageSkeleton,
  formatDate,
  levelTone,
  relativeTime,
  scoreClass,
  scoreTone,
  titleCase,
} from "../components/ui";
import { useSession } from "../session";
import type { ProgressInfo, RunHistoryPage } from "../types";

export default function Dashboard() {
  const { session } = useSession();
  const navigate = useNavigate();
  const [progress, setProgress] = useState<ProgressInfo | null>(null);
  const [runs, setRuns] = useState<RunHistoryPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [starting, setStarting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [progressData, runData] = await Promise.all([
        api.progress(),
        api.runs({ limit: 6 }),
      ]);
      setProgress(progressData);
      setRuns(runData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the dashboard.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function startScenario(scenarioId: string) {
    setStarting(true);
    try {
      const run = await api.startRun(scenarioId, session?.user.role ?? "analyst");
      navigate(`/runs/${run.run_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start the scenario.");
      setStarting(false);
    }
  }

  if (loading) {
    return (
      <div className="page">
        <PageSkeleton />
      </div>
    );
  }
  if (error) {
    return (
      <div className="page">
        <div className="card">
          <ErrorState message={error} onRetry={() => void load()} />
        </div>
      </div>
    );
  }
  if (!progress) return null;

  const user = progress.user;
  const recommendation = progress.recommendation;
  const live = progress.live_run;
  const history = runs?.items ?? [];
  const domains = progress.domains;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Operations dashboard</div>
          <h1>Good to see you, {user.name.split(" ")[0]}</h1>
          <p className="page-sub">
            {ROLE_LABELS[user.role] ?? user.role} · {domains.length || progress.user.domains.length}{" "}
            domains in scope · {progress.run_count} completed run{progress.run_count === 1 ? "" : "s"}
          </p>
        </div>
        <Button variant="primary" icon="library" onClick={() => navigate("/library")}>
          Browse scenarios
        </Button>
      </div>

      {live ? (
        <div className="resume-card">
          <span className="resume-icon">
            <Icon name="clock" size={18} />
          </span>
          <div className="grow">
            <div className="row" style={{ gap: 8 }}>
              <strong style={{ fontSize: "0.9rem" }}>Resume the open incident</strong>
              <Badge tone="blue">Phase {live.phase_number}</Badge>
            </div>
            <div className="small muted">
              {live.title} · {live.category} · {relativeTime(live.updated_at)}
            </div>
          </div>
          <Button variant="primary" iconRight="arrowRight" onClick={() => navigate(`/runs/${live.run_id}`)}>
            Continue
          </Button>
        </div>
      ) : null}

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">
            <Icon name="award" size={13} className="stat-icon" /> Readiness
          </div>
          <div className="stat-value">{progress.learner_level}</div>
          <div className="stat-note">Grade band from completed runs</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <Icon name="flame" size={13} className="stat-icon" /> Practice streak
          </div>
          <div className="stat-value">{progress.streak}<span className="small muted"> day{progress.streak === 1 ? "" : "s"}</span></div>
          <div className="stat-note">{progress.streak > 0 ? "Keep the chain alive" : "Complete a run to start"}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <Icon name="checkCircle" size={13} className="stat-icon" /> Completed runs
          </div>
          <div className="stat-value">{progress.run_count}</div>
          <div className="stat-note">{progress.mastery.length} techniques practiced</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <Icon name="layers" size={13} className="stat-icon" /> Range size
          </div>
          <div className="stat-value">{session?.scenarios ?? 0}</div>
          <div className="stat-note">Across {progress.user.domains.length} curated domains</div>
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="stack">
          <section className="card">
            <div className="card-head">
              <div className="row" style={{ gap: 7 }}>
                <Icon name="target" size={15} style={{ color: "var(--blue-400)" }} />
                <span className="card-title">Next drill</span>
              </div>
              <Badge tone={recommendation.mode === "none" ? "default" : "blue"}>
                Adaptive
              </Badge>
            </div>
            <div className="card-body">
              {recommendation.scenario ? (
                <div className="stack">
                  <div>
                    <h2 style={{ fontSize: "1rem" }}>{recommendation.scenario.title}</h2>
                    <div className="row wrap" style={{ marginTop: 6 }}>
                      <Badge tone="cyan">{recommendation.scenario.category}</Badge>
                      <Badge tone={recommendation.scenario.difficulty === "Hard" ? "red" : recommendation.scenario.difficulty === "Easy" ? "green" : "amber"}>
                        {recommendation.scenario.difficulty}
                      </Badge>
                      <Badge>{recommendation.scenario.phase_count} phases</Badge>
                      <Badge>{recommendation.scenario.soc_tier}</Badge>
                    </div>
                  </div>
                  <p className="small muted">{recommendation.reason}</p>
                  <div className="row">
                    <Button
                      variant="primary"
                      icon="play"
                      loading={starting}
                      onClick={() => void startScenario(recommendation.scenario!.id)}
                    >
                      Start drill
                    </Button>
                    <Button variant="ghost" size="sm" onClick={() => navigate("/library")}>
                      Choose another
                    </Button>
                  </div>
                </div>
              ) : (
                <EmptyState
                  icon="target"
                  title="No recommendation yet"
                  action={
                    <Button variant="primary" size="sm" icon="play" onClick={() => navigate("/library")}>
                      Pick your first scenario
                    </Button>
                  }
                >
                  {recommendation.reason}
                </EmptyState>
              )}
            </div>
          </section>

          <section className="card">
            <div className="card-head">
              <span className="card-title">Recent runs</span>
              <Button variant="ghost" size="sm" onClick={() => navigate("/progress")}>
                View all
              </Button>
            </div>
            {history.length === 0 ? (
              <EmptyState icon="fileText" title="No runs yet">
                Your completed incidents and debriefs will appear here.
              </EmptyState>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Incident</th>
                      <th>Domain</th>
                      <th>Score</th>
                      <th>Status</th>
                      <th>When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((run) => {
                      const isLive = run.status === "in_progress";
                      return (
                        <tr
                          key={run.run_id}
                          style={{ cursor: "pointer" }}
                          onClick={() =>
                            navigate(isLive ? `/runs/${run.run_id}` : `/runs/${run.run_id}/debrief`)
                          }
                        >
                          <td>
                            <div className="truncate" style={{ maxWidth: 280, fontWeight: 550 }}>
                              {run.title}
                            </div>
                            <div className="tiny dim">{titleCase(run.status)}</div>
                          </td>
                          <td className="muted small">{run.category}</td>
                          <td>
                            {run.score !== null ? (
                              <span className={`mono ${scoreClass(run.score)}`} style={{ color: scoreTone(run.score) === "good" ? "var(--green-400)" : scoreTone(run.score) === "mid" ? "var(--amber-400)" : "var(--red-400)" }}>
                                {run.score}
                              </span>
                            ) : (
                              <span className="dim">—</span>
                            )}
                          </td>
                          <td>
                            {isLive ? (
                              <Badge tone="blue">In progress</Badge>
                            ) : run.status === "abandoned" ? (
                              <Badge>Abandoned</Badge>
                            ) : (
                              <Badge tone={levelTone(run.grade ?? "")}>{run.grade ?? "Completed"}</Badge>
                            )}
                          </td>
                          <td className="tiny muted nowrap">
                            {formatDate(run.completed_at ?? run.started_at)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>

        <div className="stack">
          <section className="card">
            <div className="card-head">
              <span className="card-title">Domain readiness</span>
              {domains.length > 0 ? <Badge>{domains.length}</Badge> : null}
            </div>
            <div className="card-body">
              {domains.length === 0 ? (
                <EmptyState icon="chart" title="No domain data yet">
                  Complete a run in each domain to build a readiness picture.
                </EmptyState>
              ) : (
                <div>
                  {domains.map((domain) => (
                    <div key={domain.domain} className="domain-row">
                      <div className="domain-row-head">
                        <span className="truncate">{domain.domain}</span>
                        <span className={`mono ${scoreClass(domain.avg_score)}`}>
                          {Math.round(domain.avg_score)}
                        </span>
                      </div>
                      <div className="bar">
                        <div
                          className={`bar-fill ${scoreTone(domain.avg_score)}`}
                          style={{ width: `${Math.max(2, Math.min(100, domain.avg_score))}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {domains.length > 0 ? (
              <div className="card-foot">
                <Button variant="ghost" size="sm" block iconRight="arrowRight" onClick={() => navigate("/progress")}>
                  Open progress report
                </Button>
              </div>
            ) : null}
          </section>

          <section className="card">
            <div className="card-head">
              <span className="card-title">How scoring works</span>
            </div>
            <div className="card-body stack-sm">
              <p className="small muted">
                Every phase is scored offline 0–10 against the reference concepts. At the end, a
                single evaluation turns the run into a 0–100 debrief.
              </p>
              <div className="row wrap" style={{ marginTop: 4 }}>
                <Badge tone="green">Good · 75+</Badge>
                <Badge tone="amber">Developing · 50–74</Badge>
                <Badge tone="red">Needs work · below 50</Badge>
              </div>
              <p className="tiny dim" style={{ marginTop: 4 }}>
                Hints cost 3 points and a reference reveal costs 10, capped at 15 per run.
              </p>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
