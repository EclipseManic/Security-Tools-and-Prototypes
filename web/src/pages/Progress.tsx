import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
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
  scoreTone,
  titleCase,
  useToast,
} from "../components/ui";
import type { ProgressInfo, RunHistoryPage } from "../types";

function TrendChart({ points }: { points: { label: string; score: number }[] }) {
  const width = 680;
  const height = 190;
  const padX = 34;
  const padY = 18;

  if (!points.length) {
    return <div className="chart-empty">Complete a run to plot your score trend.</div>;
  }

  const max = 100;
  const stepX = points.length > 1 ? (width - padX * 2) / (points.length - 1) : 0;
  const y = (score: number) => padY + (1 - score / max) * (height - padY * 2);
  const coords = points.map((point, index) => ({
    x: padX + index * stepX,
    y: y(point.score),
    ...point,
  }));
  const line = coords.map((point) => `${point.x},${point.y}`).join(" ");
  const area = `${padX},${height - padY} ${line} ${padX + (points.length - 1) * stepX},${height - padY}`;

  return (
    <div>
      <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Score trend over recent runs">
        {[0, 25, 50, 75, 100].map((tick) => (
          <g key={tick}>
            <line
              x1={padX}
              x2={width - padX}
              y1={y(tick)}
              y2={y(tick)}
              stroke="var(--border-subtle)"
              strokeWidth={1}
            />
            <text x={padX - 8} y={y(tick) + 3} textAnchor="end" fill="var(--text-dim)" fontSize={9} fontFamily="var(--font-mono)">
              {tick}
            </text>
          </g>
        ))}
        <polygon points={area} fill="rgba(59,130,246,0.10)" />
        <polyline points={line} fill="none" stroke="var(--blue-500)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {coords.map((point, index) => (
          <circle key={index} cx={point.x} cy={point.y} r={3.2} fill="var(--slate-900)" stroke="var(--blue-400)" strokeWidth={1.8}>
            <title>{`${point.label}: ${point.score}`}</title>
          </circle>
        ))}
      </svg>
      <div className="row-between tiny dim" style={{ padding: "0 6px" }}>
        <span>{points[0].label}</span>
        <span>{points[points.length - 1].label}</span>
      </div>
    </div>
  );
}

export default function Progress() {
  const navigate = useNavigate();
  const { push } = useToast();
  const [progress, setProgress] = useState<ProgressInfo | null>(null);
  const [runs, setRuns] = useState<RunHistoryPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [progressData, runData] = await Promise.all([
        api.progress(),
        api.runs({ limit: 20 }),
      ]);
      setProgress(progressData);
      setRuns(runData);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load progress.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function loadMore() {
    if (!runs) return;
    setLoadingMore(true);
    try {
      const next = await api.runs({ limit: 20, offset: runs.items.length });
      setRuns({ ...next, items: [...runs.items, ...next.items] });
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not load more history.", "error");
    } finally {
      setLoadingMore(false);
    }
  }

  const trend = useMemo(() => {
    const completed = (runs?.items ?? [])
      .filter((run) => run.status === "completed" && run.score !== null)
      .slice(0, 20)
      .reverse();
    return completed.map((run) => ({
      label: formatDate(run.completed_at ?? run.started_at),
      score: run.score as number,
    }));
  }, [runs]);

  if (loading) {
    return (
      <div className="page">
        <PageSkeleton />
      </div>
    );
  }
  if (error && !progress) {
    return (
      <div className="page">
        <div className="card">
          <ErrorState message={error} onRetry={() => void load()} />
        </div>
      </div>
    );
  }
  if (!progress) return null;

  const mastery = progress.mastery;
  const weak = mastery.filter((row) => row.avg_score < 60);
  const hasRuns = (runs?.total ?? 0) > 0;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Learning record</div>
          <h1>Progress</h1>
          <p className="page-sub">
            {progress.user.name} · {progress.learner_level} · {progress.run_count} completed run
            {progress.run_count === 1 ? "" : "s"}
          </p>
        </div>
        <Button variant="primary" icon="play" onClick={() => navigate("/library")}>
          Start a drill
        </Button>
      </div>

      <div className="stat-grid">
        <div className="stat-card">
          <div className="stat-label">
            <Icon name="award" size={13} /> Readiness
          </div>
          <div className="stat-value">{progress.learner_level}</div>
          <div className="stat-note">Average run grade band</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <Icon name="flame" size={13} /> Streak
          </div>
          <div className="stat-value">
            {progress.streak}<span className="small muted"> day{progress.streak === 1 ? "" : "s"}</span>
          </div>
          <div className="stat-note">Consecutive practice days</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <Icon name="checkCircle" size={13} /> Completed
          </div>
          <div className="stat-value">{progress.run_count}</div>
          <div className="stat-note">Runs with a debrief</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">
            <Icon name="layers" size={13} /> Techniques
          </div>
          <div className="stat-value">{mastery.length}</div>
          <div className="stat-note">{weak.length} below 60%</div>
        </div>
      </div>

      <div className="two-col">
        <section className="card">
          <div className="card-head">
            <div className="row" style={{ gap: 7 }}>
              <Icon name="chart" size={15} style={{ color: "var(--blue-400)" }} />
              <span className="card-title">Score trend</span>
            </div>
            <Badge>Last {trend.length || 0} runs</Badge>
          </div>
          <div className="card-body">
            <TrendChart points={trend} />
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <span className="card-title">Domain performance</span>
            <Badge>{progress.domains.length}</Badge>
          </div>
          <div className="card-body">
            {progress.domains.length === 0 ? (
              <EmptyState icon="chart" title="No domain data yet">
                Complete a run to start measuring domain readiness.
              </EmptyState>
            ) : (
              progress.domains.map((domain) => (
                <div key={domain.domain} className="domain-row">
                  <div className="domain-row-head">
                    <span className="truncate">{domain.domain}</span>
                    <span className={`mono ${scoreTone(domain.avg_score)}`}>{Math.round(domain.avg_score)}</span>
                  </div>
                  <div className="bar">
                    <div
                      className={`bar-fill ${scoreTone(domain.avg_score)}`}
                      style={{ width: `${Math.max(2, Math.min(100, domain.avg_score))}%` }}
                    />
                  </div>
                  <div className="tiny dim">
                    {domain.total_runs} run{domain.total_runs === 1 ? "" : "s"}
                    {domain.weakest_technique ? ` · weakest ${domain.weakest_technique}` : ""}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      <section className="card">
        <div className="card-head">
          <span className="card-title">Technique mastery</span>
          <Badge>{mastery.length}</Badge>
        </div>
        {mastery.length === 0 ? (
          <EmptyState icon="target" title="No mastery buckets yet">
            Each phase you answer is tracked against its MITRE technique.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Technique</th>
                  <th>Name</th>
                  <th>Level</th>
                  <th>Avg</th>
                  <th>Best</th>
                  <th>Attempts</th>
                  <th>Last practiced</th>
                </tr>
              </thead>
              <tbody>
                {mastery.map((row) => (
                  <tr key={row.technique}>
                    <td className="mono">{row.technique}</td>
                    <td className="truncate" style={{ maxWidth: 260 }}>
                      {row.technique_name || "—"}
                    </td>
                    <td>
                      <Badge tone={levelTone(row.level)}>{row.level}</Badge>
                    </td>
                    <td>
                      <span className="mono">{Math.round(row.avg_score)}</span>
                    </td>
                    <td className="mono muted">{Math.round(row.best_score)}</td>
                    <td className="mono muted">{row.attempts}</td>
                    <td className="tiny dim nowrap">{relativeTime(row.last_practiced)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <span className="card-title">Run history</span>
          <Badge>{runs?.total ?? 0}</Badge>
        </div>
        {!hasRuns ? (
          <EmptyState
            icon="fileText"
            title="No runs recorded"
            action={
              <Button variant="primary" size="sm" icon="play" onClick={() => navigate("/library")}>
                Start your first run
              </Button>
            }
          >
            Your incident history will collect here.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Incident</th>
                    <th>Domain</th>
                    <th>Role</th>
                    <th>Score</th>
                    <th>Grade</th>
                    <th>Status</th>
                    <th>Completed</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {(runs?.items ?? []).map((run) => {
                    const live = run.status === "in_progress";
                    return (
                      <tr key={run.run_id}>
                        <td style={{ fontWeight: 550, maxWidth: 300 }}>
                          <div className="truncate">{run.title}</div>
                        </td>
                        <td className="muted small">{run.category}</td>
                        <td className="tiny dim">
                          {titleCase(run.role_used)}
                        </td>
                        <td>
                          {run.score !== null ? (
                            <span
                              className="mono"
                              style={{
                                color:
                                  scoreTone(run.score) === "good"
                                    ? "var(--green-400)"
                                    : scoreTone(run.score) === "mid"
                                      ? "var(--amber-400)"
                                      : "var(--red-400)",
                              }}
                            >
                              {run.score}
                            </span>
                          ) : (
                            <span className="dim">—</span>
                          )}
                        </td>
                        <td>
                          {run.grade ? (
                            <Badge tone={levelTone(run.grade)}>{run.grade}</Badge>
                          ) : (
                            <span className="dim">—</span>
                          )}
                        </td>
                        <td>
                          <Badge tone={live ? "blue" : run.status === "abandoned" ? "default" : "green"}>
                            {titleCase(run.status)}
                          </Badge>
                        </td>
                        <td className="tiny dim nowrap">{formatDate(run.completed_at ?? run.started_at)}</td>
                        <td>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() =>
                              navigate(live ? `/runs/${run.run_id}` : `/runs/${run.run_id}/debrief`)
                            }
                          >
                            {live ? "Resume" : "Debrief"}
                          </Button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {runs && runs.items.length < runs.total ? (
              <div className="card-foot">
                <Button size="sm" loading={loadingMore} onClick={() => void loadMore()}>
                  Load more
                </Button>
              </div>
            ) : null}
          </>
        )}
      </section>
    </div>
  );
}
