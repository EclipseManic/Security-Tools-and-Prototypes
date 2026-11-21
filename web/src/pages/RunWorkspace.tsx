import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, PHASE_LABELS, ROLE_LABELS } from "../api";
import { Icon } from "../components/Icons";
import {
  Badge,
  Button,
  Drawer,
  ErrorState,
  Loading,
  Modal,
  difficultyTone,
  useToast,
} from "../components/ui";
import type { RunState } from "../types";

type Followup = { text: string; branch: "good" | "weak" } | null;

interface HintState {
  total: number;
  remaining: number;
  exhausted: boolean;
}

export default function RunWorkspace() {
  const { runId } = useParams();
  const id = Number(runId);
  const navigate = useNavigate();
  const { push } = useToast();

  const [run, setRun] = useState<RunState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [draft, setDraft] = useState("");
  const [answerError, setAnswerError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [followup, setFollowup] = useState<Followup>(null);

  const [hints, setHints] = useState<string[]>([]);
  const [hintState, setHintState] = useState<HintState>({ total: 0, remaining: 0, exhausted: true });
  const [hintLoading, setHintLoading] = useState(false);
  const [hintDrawer, setHintDrawer] = useState(false);

  const [reference, setReference] = useState<string | null>(null);
  const [revealConfirm, setRevealConfirm] = useState(false);
  const [revealLoading, setRevealLoading] = useState(false);
  const [abandonConfirm, setAbandonConfirm] = useState(false);
  const [finishing, setFinishing] = useState(false);
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "saved">("idle");

  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const composerRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const state = await api.run(id);
      if (state.status === "completed") {
        navigate(`/runs/${id}/debrief`, { replace: true });
        return;
      }
      setRun(state);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load this run.");
    } finally {
      setLoading(false);
    }
  }, [id, navigate]);

  useEffect(() => {
    if (!Number.isFinite(id) || id <= 0) {
      setError("Invalid run id.");
      setLoading(false);
      return;
    }
    void load();
  }, [id, load]);

  const phase = run?.phase ?? null;
  const phaseId = phase?.id ?? "";

  /* Draft + per-phase assist state when the phase changes. */
  useEffect(() => {
    if (!run || !run.phase) return;
    const key = `soc:draft:${run.run_id}:${run.phase.id}`;
    const local = localStorage.getItem(key) ?? "";
    setDraft(run.progress.draft_answer || local);
    setAnswerError("");
    setHints([]);
    setReference(null);
    setHintState({
      total: run.phase.hints_total,
      remaining: Math.max(0, run.phase.hints_total - run.phase.hints_revealed),
      exhausted: run.phase.hints_revealed >= run.phase.hints_total,
    });
    // Focus the composer when a new phase opens.
    window.setTimeout(() => textareaRef.current?.focus(), 60);
  }, [run?.run_id, run?.phase?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  /* Debounced draft autosave (local backup + server). */
  useEffect(() => {
    if (!run || !run.phase) return;
    const key = `soc:draft:${run.run_id}:${run.phase.id}`;
    if (draft) localStorage.setItem(key, draft);
    else localStorage.removeItem(key);

    if (!draft.trim()) {
      setSaveStatus("idle");
      return;
    }
    setSaveStatus("saving");
    const timer = window.setTimeout(() => {
      api
        .saveDraft(run.run_id, draft)
        .then(() => setSaveStatus("saved"))
        .catch(() => setSaveStatus("idle"));
    }, 1200);
    return () => window.clearTimeout(timer);
  }, [draft, run?.run_id, run?.phase?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
        event.preventDefault();
        void submit();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const elapsed = useMemo(() => {
    if (!run?.started_at) return "—";
    const start = new Date(run.started_at).getTime();
    if (Number.isNaN(start)) return "—";
    const minutes = Math.max(0, Math.round((Date.now() - start) / 60000));
    return minutes < 1 ? "under a minute" : `${minutes} min`;
  }, [run?.started_at]);

  if (loading) {
    return (
      <div className="page">
        <div className="card">
          <Loading label="Opening the incident" />
        </div>
      </div>
    );
  }
  if (error || !run) {
    return (
      <div className="page page-narrow">
        <div className="card">
          <ErrorState message={error ?? "Run not found."} onRetry={() => void load()} />
        </div>
        <div className="row" style={{ justifyContent: "center" }}>
          <Button icon="arrowLeft" onClick={() => navigate("/library")}>
            Back to library
          </Button>
        </div>
      </div>
    );
  }

  if (run.status === "abandoned") {
    return (
      <div className="page page-narrow">
        <div className="card">
          <div className="empty-state">
            <div className="empty-icon">
              <Icon name="alertCircle" size={19} />
            </div>
            <h3>This run was abandoned</h3>
            <p className="small">Start a fresh attempt from the scenario library.</p>
            <Button variant="primary" icon="library" onClick={() => navigate("/library")}>
              Browse scenarios
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const scenario = run.scenario;
  const total = scenario.phase_count;
  const answered = run.progress.answered;
  const number = phase?.number ?? answered;
  const scenarioKey = `soc:draft:${run.run_id}:${phaseId}`;

  async function submit() {
    if (!phase || submitting) return;
    const text = draft.trim();
    const words = text.split(/\s+/).filter(Boolean).length;
    if (text.length < 8 || words < 2) {
      setAnswerError("Describe a concrete action in at least a few words.");
      textareaRef.current?.focus();
      return;
    }
    setSubmitting(true);
    setAnswerError("");
    try {
      const result = await api.answer(run!.run_id, text, phase.id);
      localStorage.removeItem(scenarioKey);
      setRun((prev) =>
        prev
          ? {
              ...prev,
              status: result.status,
              phase: result.phase,
              progress: result.progress,
              can_finish: result.can_finish,
            }
          : prev,
      );
      setFollowup({ text: result.followup, branch: result.branch });
      setDraft("");
      setSaveStatus("idle");
      setHintDrawer(false);
    } catch (err) {
      setAnswerError(err instanceof Error ? err.message : "Could not record the answer.");
    } finally {
      setSubmitting(false);
    }
  }

  async function requestHint() {
    if (!phase) return;
    setHintLoading(true);
    try {
      const result = await api.hint(run!.run_id);
      if (result.hint) setHints((current) => [...current, result.hint as string]);
      setHintState({
        total: result.total,
        remaining: result.remaining,
        exhausted: result.exhausted,
      });
      setRun((prev) =>
        prev && prev.phase
          ? {
              ...prev,
              phase: { ...prev.phase, hints_revealed: result.index },
              progress: { ...prev.progress, hints_used: prev.progress.hints_used + 1 },
            }
          : prev,
      );
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not load a hint.", "error");
    } finally {
      setHintLoading(false);
    }
  }

  async function revealReference() {
    setRevealLoading(true);
    try {
      const result = await api.reveal(run!.run_id);
      setReference(result.reference_answer);
      setRevealConfirm(false);
      setRun((prev) =>
        prev && prev.phase
          ? {
              ...prev,
              phase: { ...prev.phase, reference_revealed: true },
              progress: { ...prev.progress, reveals: result.reveals_total },
            }
          : prev,
      );
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not reveal the reference.", "error");
    } finally {
      setRevealLoading(false);
    }
  }

  async function finish() {
    setFinishing(true);
    try {
      await api.finish(run!.run_id);
      navigate(`/runs/${run!.run_id}/debrief`);
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not finish the run.", "error");
      setFinishing(false);
    }
  }

  async function abandon() {
    try {
      await api.abandon(run!.run_id);
      push("Run abandoned.", "info");
      navigate("/library");
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not abandon the run.", "error");
    }
  }

  function continueRun() {
    setFollowup(null);
    window.setTimeout(() => {
      composerRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      textareaRef.current?.focus();
    }, 50);
  }

  return (
    <div className="page run-page">
      <header className="run-head">
        <div className="run-head-bar">
          <Button variant="ghost" size="sm" icon="arrowLeft" onClick={() => navigate("/library")}>
            Scenario library
          </Button>
          <span className="run-head-sep" aria-hidden="true" />
          <span className="eyebrow">Incident run · Case #{String(run.run_id).padStart(4, "0")}</span>
          <span className="spacer" />
          <span className="saved-ind" aria-live="polite">
            <Icon name={saveStatus === "saving" ? "refresh" : "save"} size={13} />
            {saveStatus === "saving" ? "Saving…" : saveStatus === "saved" ? "Draft saved" : "Autosave on"}
          </span>
        </div>
        <div className="run-head-main">
          <div className="run-head-title">
            <h1>{scenario.title}</h1>
            <div className="run-meta">
              <Badge tone="cyan">{scenario.category}</Badge>
              <Badge tone={difficultyTone(scenario.difficulty)}>{scenario.difficulty}</Badge>
              <Badge>{scenario.soc_tier}</Badge>
              <Badge tone="blue">{ROLE_LABELS[scenario.role] ?? scenario.role}</Badge>
              <span className="run-meta-sep" aria-hidden="true" />
              <span className="tiny dim">Elapsed {elapsed}</span>
            </div>
          </div>
          <div className="run-head-actions">
            {run.can_finish ? (
              <Button
                variant="primary"
                icon="sparkles"
                loading={finishing}
                onClick={() => void finish()}
              >
                Finish run
              </Button>
            ) : (
              <span className="run-finish-note tiny dim">Finish unlocks after the final phase</span>
            )}
            <Button
              variant="ghost"
              size="sm"
              icon="x"
              className="btn-danger"
              onClick={() => setAbandonConfirm(true)}
            >
              Abandon
            </Button>
          </div>
        </div>
      </header>

      <section className="run-strip" aria-label="Run progress">
        <div className="run-strip-block">
          <span className="strip-label">Phase map</span>
          <div
            className="phase-track"
            title="Branching means the path length can differ from the estimate"
          >
            {Array.from({ length: total }).map((_, index) => {
              const n = index + 1;
              const state = n < number ? "done" : n === number && phase ? "current" : "";
              return (
                <span key={n} className={`phase-dot ${state}`} title={`Phase ${n}`}>
                  {n}
                </span>
              );
            })}
          </div>
        </div>
        <div className="run-strip-stats">
          <div className="strip-stat">
            <span>Current phase</span>
            <strong>{phase ? `${number} of ${total}` : "—"}</strong>
          </div>
          <div className="strip-stat">
            <span>Answered</span>
            <strong>{answered}</strong>
          </div>
          <div className="strip-stat">
            <span>Hints used</span>
            <strong>{run.progress.hints_used}</strong>
          </div>
          <div className="strip-stat">
            <span>Reveals</span>
            <strong>{run.progress.reveals}</strong>
          </div>
        </div>
      </section>

      {run.role_fallback ? (
        <div className="alert alert-warn">
          <Icon name="info" size={15} />
          <span>
            This scenario has no role-specific content for your profile, so it is running from
            the SOC Analyst perspective.
          </span>
        </div>
      ) : null}

      <div className="run-body">
        {/* Incident context ------------------------------------------------ */}
        <aside className="panel context-panel">
          <div className="panel-head">
            <span>Incident context</span>
            <Icon name="fileText" size={14} />
          </div>
          <div className="panel-body">
            <div className="context-list">
              <div className="context-item">
                <div className="context-label">What happened</div>
                <p style={{ whiteSpace: "pre-wrap" }}>{scenario.opening}</p>
              </div>
              {scenario.compromised_assets.length ? (
                <div className="context-item">
                  <div className="context-label">Compromised assets</div>
                  <div className="context-tags">
                    {scenario.compromised_assets.map((asset) => (
                      <span key={asset} className="chip mono">
                        {asset}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
              <div className="context-item">
                <div className="context-label">Detected via</div>
                <p>{scenario.detected_via || "—"}</p>
              </div>
              {scenario.kill_chain.length ? (
                <div className="context-item">
                  <div className="context-label">Kill chain</div>
                  <div className="context-tags">
                    {scenario.kill_chain.map((stage) => (
                      <span key={stage} className="chip">
                        {stage}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
              {scenario.mitre_tactics.length ? (
                <div className="context-item">
                  <div className="context-label">MITRE tactics</div>
                  <div className="context-tags">
                    {scenario.mitre_tactics.map((tactic) => (
                      <span key={tactic} className="chip">
                        {tactic}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
              {scenario.role_briefing ? (
                <div className="context-item">
                  <div className="context-label">Role briefing</div>
                  <p>{scenario.role_briefing}</p>
                </div>
              ) : null}
              {scenario.executive_brief && scenario.role !== "analyst" ? (
                <div className="context-item">
                  <div className="context-label">Executive brief</div>
                  <p>{scenario.executive_brief}</p>
                </div>
              ) : null}
            </div>
          </div>
        </aside>

        {/* Phase ----------------------------------------------------------- */}
        <section className="panel phase-panel" ref={composerRef}>
          {phase ? (
            <>
              <div className="phase-top">
                <div className="phase-kicker">
                  <Badge tone="blue">Phase {number} of {total}</Badge>
                  <Badge>{PHASE_LABELS[phase.type] ?? (phase.type || "Response")}</Badge>
                  {phase.mitre_technique ? (
                    <span className="chip mono" style={{ fontSize: "0.7rem" }}>
                      {phase.mitre_technique}
                    </span>
                  ) : null}
                </div>
                <h2 className="phase-title">{phase.title}</h2>
                <div className="phase-section">
                  <div className="section-label">Situation</div>
                  <div className="phase-situation">{phase.situation}</div>
                </div>
                <div className="phase-section">
                  <div className="section-label">Your task</div>
                  <div className="phase-prompt">{phase.prompt}</div>
                </div>
                {phase.guidance.what || phase.guidance.action || phase.guidance.why ? (
                  <div className="phase-section">
                    <div className="section-label">Guidance</div>
                    <div className="guidance-grid">
                      {phase.guidance.what ? (
                        <div className="guidance-cell">
                          <div className="gk">What</div>
                          <div className="gv">{phase.guidance.what}</div>
                        </div>
                      ) : null}
                      {phase.guidance.action ? (
                        <div className="guidance-cell">
                          <div className="gk">Action</div>
                          <div className="gv">{phase.guidance.action}</div>
                        </div>
                      ) : null}
                      {phase.guidance.why ? (
                        <div className="guidance-cell">
                          <div className="gk">Why</div>
                          <div className="gv">{phase.guidance.why}</div>
                        </div>
                      ) : null}
                    </div>
                  </div>
                ) : null}
              </div>

              {followup ? (
                <div className="followup" aria-live="polite">
                  <h4>{followup.branch === "good" ? "Where things stand" : "Consequence"}</h4>
                  {followup.text}
                  <div>
                    <Button
                      variant="primary"
                      size="sm"
                      iconRight="arrowRight"
                      onClick={continueRun}
                    >
                      {run.phase ? "Continue to next phase" : "Continue"}
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="composer">
                  <div className="composer-top">
                    <span className="section-label">Your response</span>
                    <span className="composer-meta">
                      {draft.trim() ? `${draft.trim().split(/\s+/).length} words · ` : ""}
                      <span className="mono">{draft.length}/8000</span>
                    </span>
                  </div>
                  <textarea
                    ref={textareaRef}
                    className="textarea composer-input"
                    value={draft}
                    onChange={(event) => {
                      setDraft(event.target.value);
                      if (answerError) setAnswerError("");
                    }}
                    maxLength={8000}
                    placeholder="Type the action you would take, the evidence you would pull, and why. Be specific — name tools and data sources."
                    aria-label="Your response"
                  />
                  {answerError ? (
                    <div className="composer-error" role="alert">
                      {answerError}
                    </div>
                  ) : null}
                  <div className="composer-foot">
                    <div className="composer-tools">
                      <Button
                        size="sm"
                        icon="lightbulb"
                        onClick={() => setHintDrawer(true)}
                        disabled={phase.hints_total === 0}
                      >
                        Hints
                        {phase.hints_total > 0 ? (
                          <span className="badge" style={{ height: 18 }}>
                            {hintState.remaining}
                          </span>
                        ) : null}
                      </Button>
                      <Button size="sm" icon="eye" onClick={() => setRevealConfirm(true)}>
                        {reference || phase.reference_revealed ? "Reference" : "Reveal reference"}
                      </Button>
                    </div>
                    <div className="composer-submit">
                      <span className="composer-kbd">Ctrl/⌘ + Enter</span>
                      <Button
                        variant="primary"
                        icon="send"
                        loading={submitting}
                        onClick={() => void submit()}
                      >
                        Submit response
                      </Button>
                    </div>
                  </div>

                  {hints.length ? (
                    <div className="hint-list">
                      {hints.map((hint, index) => (
                        <div key={index} className="hint-item">
                          {hint}
                        </div>
                      ))}
                    </div>
                  ) : null}

                  {reference ? (
                    <div className="reference-box">
                      <div className="tiny dim" style={{ marginBottom: 4 }}>
                        Reference answer
                      </div>
                      {reference}
                    </div>
                  ) : phase.reference_revealed ? (
                    <div className="reference-box">
                      You revealed the reference answer for this phase earlier.
                      <div style={{ marginTop: 8 }}>
                        <Button size="sm" variant="ghost" icon="eye" onClick={() => setRevealConfirm(true)}>
                          Show it again
                        </Button>
                      </div>
                    </div>
                  ) : null}
                </div>
              )}
            </>
          ) : followup ? (
            <div className="empty-state" style={{ padding: "40px 24px" }}>
              <div className="empty-icon" style={{ color: "var(--cyan-400)" }}>
                <Icon name="checkCircle" size={19} />
              </div>
              <h3>Path complete</h3>
              <p className="small" style={{ maxWidth: 520, whiteSpace: "pre-wrap" }}>
                {followup.text}
              </p>
              <Button variant="primary" icon="sparkles" loading={finishing} onClick={() => void finish()}>
                Finish and get debrief
              </Button>
            </div>
          ) : (
            <div className="empty-state" style={{ padding: "48px 24px" }}>
              <div className="empty-icon">
                <Icon name="checkCircle" size={19} />
              </div>
              <h3>All phases answered</h3>
              <p className="small">
                Submit the run to generate your evaluation and debrief.
              </p>
              <Button variant="primary" icon="sparkles" loading={finishing} onClick={() => void finish()}>
                Finish and get debrief
              </Button>
            </div>
          )}
        </section>
      </div>

      {hintDrawer ? (
        <Drawer title="Hints" onClose={() => setHintDrawer(false)}>
          <p className="small muted">
            Hints reveal one at a time and cost 3 points each in the final debrief, capped at 15.
          </p>
          {phase && phase.hints_revealed > hints.length ? (
            <div className="alert alert-warn">
              <Icon name="lightbulb" size={15} />
              <span>
                {phase.hints_revealed} hint{phase.hints_revealed === 1 ? "" : "s"} already revealed
                for this phase.
              </span>
            </div>
          ) : null}
          {hints.length ? (
            <div className="hint-list">
              {hints.map((hint, index) => (
                <div key={index} className="hint-item">
                  <span className="tiny dim mono" style={{ display: "block", marginBottom: 3 }}>
                    Hint {index + 1}
                  </span>
                  {hint}
                </div>
              ))}
            </div>
          ) : (
            <p className="small dim">No hints revealed yet.</p>
          )}
          <Button
            icon="lightbulb"
            loading={hintLoading}
            disabled={hintState.exhausted || !phase}
            onClick={() => void requestHint()}
          >
            {hintState.exhausted ? "No hints remaining" : `Reveal hint (${hintState.remaining} left)`}
          </Button>
          <p className="tiny dim">
            Prefer to work without hints? Close this panel and submit your own approach.
          </p>
        </Drawer>
      ) : null}

      {revealConfirm ? (
        <Modal
          title="Reveal the reference answer?"
          onClose={() => setRevealConfirm(false)}
          footer={
            <>
              <Button variant="ghost" onClick={() => setRevealConfirm(false)}>
                Keep working
              </Button>
              <Button variant="primary" icon="eye" loading={revealLoading} onClick={() => void revealReference()}>
                Reveal reference
              </Button>
            </>
          }
        >
          The reference answer is what an experienced analyst would do. Revealing it is recorded for
          this phase and can cost up to 10 points in the final debrief.
        </Modal>
      ) : null}

      {abandonConfirm ? (
        <Modal
          title="Abandon this run?"
          onClose={() => setAbandonConfirm(false)}
          footer={
            <>
              <Button variant="ghost" onClick={() => setAbandonConfirm(false)}>
                Keep running
              </Button>
              <Button className="btn-danger" icon="trash" onClick={() => void abandon()}>
                Abandon run
              </Button>
            </>
          }
        >
          The incident will close without a debrief. You can start it again from the library.
        </Modal>
      ) : null}
    </div>
  );
}
