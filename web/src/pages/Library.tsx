import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ROLE_LABELS } from "../api";
import { Icon } from "../components/Icons";
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  difficultyTone,
  useToast,
} from "../components/ui";
import { useSession } from "../session";
import type { Scenario, ScenarioPage } from "../types";

const PAGE_SIZE = 24;
const TIERS = ["L1", "L2", "L3"];

export default function Library() {
  const { session } = useSession();
  const { push } = useToast();
  const navigate = useNavigate();

  const [page, setPage] = useState<ScenarioPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [domain, setDomain] = useState("");
  const [difficulty, setDifficulty] = useState("");
  const [role, setRole] = useState("");
  const [tier, setTier] = useState("");
  const [offset, setOffset] = useState(0);

  const controller = useRef<AbortController | null>(null);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setDebounced(query.trim());
      setOffset(0);
    }, 300);
    return () => window.clearTimeout(timer);
  }, [query]);

  const load = useCallback(async () => {
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setLoading(true);
    setError(null);
    try {
      const data = await api.scenarios(
        {
          q: debounced,
          domain: domain || undefined,
          difficulty: difficulty || undefined,
          role: role || undefined,
          tier: tier || undefined,
          limit: PAGE_SIZE,
          offset,
        },
        next.signal,
      );
      setPage(data);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setError(err instanceof Error ? err.message : "Could not load scenarios.");
    } finally {
      if (!next.signal.aborted) setLoading(false);
    }
  }, [debounced, domain, difficulty, role, tier, offset]);

  useEffect(() => {
    void load();
    return () => controller.current?.abort();
  }, [load]);

  async function start(scenario: Scenario) {
    setStarting(scenario.id);
    try {
      const run = await api.startRun(scenario.id, session?.user.role ?? "analyst");
      navigate(`/runs/${run.run_id}`);
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not start the scenario.", "error");
      setStarting(null);
    }
  }

  const items = page?.items ?? [];
  const total = page?.total ?? 0;
  const facets = page?.facets ?? {};
  const filtersActive = Boolean(debounced || domain || difficulty || role || tier);

  function clearFilters() {
    setQuery("");
    setDebounced("");
    setDomain("");
    setDifficulty("");
    setRole("");
    setTier("");
    setOffset(0);
  }

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">Incident library</div>
          <h1>Scenario library</h1>
          <p className="page-sub">
            {total} simulated incidents · pick a domain, difficulty, or role to narrow the range.
          </p>
        </div>
        {filtersActive ? (
          <Button variant="ghost" size="sm" icon="x" onClick={clearFilters}>
            Clear filters
          </Button>
        ) : null}
      </div>

      <div className="card">
        <div className="card-body tight">
          <div className="filter-bar">
            <div className="search-wrap">
              <Icon name="search" size={15} />
              <input
                className="input"
                placeholder="Search incidents, tactics, assets…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                aria-label="Search scenarios"
              />
            </div>
            <select className="select" value={domain} onChange={(event) => { setDomain(event.target.value); setOffset(0); }} aria-label="Filter by domain">
              <option value="">All domains</option>
              {Object.keys(facets.domains ?? {}).map((name) => (
                <option key={name} value={name}>
                  {name} ({facets.domains?.[name]})
                </option>
              ))}
            </select>
            <select className="select" value={difficulty} onChange={(event) => { setDifficulty(event.target.value); setOffset(0); }} aria-label="Filter by difficulty">
              <option value="">Any difficulty</option>
              {Object.keys(facets.difficulties ?? {}).map((name) => (
                <option key={name} value={name}>
                  {name} ({facets.difficulties?.[name]})
                </option>
              ))}
            </select>
            <select className="select" value={role} onChange={(event) => { setRole(event.target.value); setOffset(0); }} aria-label="Filter by role">
              <option value="">Any role</option>
              {Object.keys(facets.roles ?? {}).map((name) => (
                <option key={name} value={name}>
                  {ROLE_LABELS[name] ?? name} ({facets.roles?.[name]})
                </option>
              ))}
            </select>
            <select className="select" value={tier} onChange={(event) => { setTier(event.target.value); setOffset(0); }} aria-label="Filter by SOC tier">
              <option value="">Any tier</option>
              {TIERS.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {error ? (
        <div className="card">
          <ErrorState message={error} onRetry={() => void load()} />
        </div>
      ) : loading && items.length === 0 ? (
        <div className="scenario-grid" aria-busy="true">
          {Array.from({ length: 6 }).map((_, index) => (
            <div key={index} className="skeleton" style={{ height: 210 }} />
          ))}
        </div>
      ) : items.length === 0 ? (
        <div className="card">
          <EmptyState
            icon="search"
            title="No scenarios match"
            action={
              <Button size="sm" onClick={clearFilters}>
                Clear filters
              </Button>
            }
          >
            Try a broader search or a different domain.
          </EmptyState>
        </div>
      ) : (
        <>
          <div className="scenario-grid" style={{ opacity: loading ? 0.6 : 1, transition: "opacity 150ms" }}>
            {items.map((scenario) => {
              const supported = scenario.roles.includes(session?.user.role ?? "analyst");
              return (
                <article key={scenario.id} className="scenario-card">
                  <div className="scenario-meta">
                    <Badge tone="cyan">{scenario.category}</Badge>
                    <Badge tone={difficultyTone(scenario.difficulty)}>{scenario.difficulty}</Badge>
                    <Badge>{scenario.soc_tier}</Badge>
                    {!supported && session?.user.role !== "analyst" ? (
                      <Badge tone="amber">Analyst view</Badge>
                    ) : null}
                  </div>
                  <h3>{scenario.title}</h3>
                  <p className="opening">{scenario.opening}</p>
                  <div className="scenario-meta">
                    <span className="tiny dim">
                      {scenario.phase_count} phases · detected via {scenario.detected_via || "—"}
                    </span>
                  </div>
                  <div className="scenario-foot">
                    <Button
                      variant="primary"
                      size="sm"
                      icon="play"
                      loading={starting === scenario.id}
                      onClick={() => void start(scenario)}
                    >
                      Start
                    </Button>
                    <span className="tiny dim truncate" title={scenario.mitre_tactics.join(", ")}>
                      {scenario.mitre_tactics.slice(0, 2).join(" · ")}
                    </span>
                  </div>
                </article>
              );
            })}
          </div>

          <div className="pagination">
            <span className="tiny dim">
              Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total}
            </span>
            <div className="row">
              <Button
                size="sm"
                icon="chevronLeft"
                disabled={offset === 0 || loading}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                Previous
              </Button>
              <Button
                size="sm"
                iconRight="chevronRight"
                disabled={offset + PAGE_SIZE >= total || loading}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
