import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, ROLE_LABELS } from "../api";
import { Icon } from "../components/Icons";
import { Badge, Button, ErrorState, Loading, Modal, useToast } from "../components/ui";
import { useSession } from "../session";
import type { ModelInfo, SettingsInfo } from "../types";

const ROLES = ["analyst", "incident_manager", "ciso", "executive"];

export default function Settings() {
  const { session, setSession, logout } = useSession();
  const { push } = useToast();
  const navigate = useNavigate();

  const [settings, setSettings] = useState<SettingsInfo | null>(null);
  const [available, setAvailable] = useState<string[]>([]);
  const [role, setRole] = useState(session?.user.role ?? "analyst");
  const [domains, setDomains] = useState<string[]>(session?.user.domains ?? []);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [modelSource, setModelSource] = useState("");
  const [modelDraft, setModelDraft] = useState("");
  const [modelSaving, setModelSaving] = useState(false);
  const [keySaving, setKeySaving] = useState(false);
  const [keyClearing, setKeyClearing] = useState(false);
  const [confirm, setConfirm] = useState<null | "history" | "profile">(null);
  const [dataBusy, setDataBusy] = useState(false);

  useEffect(() => {
    Promise.all([api.settings(), api.scenarios({ limit: 1 })])
      .then(([settingsData, page]) => {
        setSettings(settingsData);
        setAvailable(Object.keys(page.facets.domains ?? {}));
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load settings."))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (session) {
      setRole(session.user.role);
      setDomains(session.user.domains);
    }
  }, [session]);

  useEffect(() => {
    if (settings) setModelDraft(settings.model);
  }, [settings]);

  useEffect(() => {
    api
      .models()
      .then((result) => {
        setModels(result.models);
        setModelSource(result.source);
      })
      .catch(() => setModels([]));
  }, []);

  function toggleDomain(domain: string) {
    setDomains((current) =>
      current.includes(domain) ? current.filter((item) => item !== domain) : [...current, domain],
    );
  }

  async function save() {
    setSaving(true);
    try {
      const updated = await api.updateMe({ role, domains });
      setSession(updated);
      push("Profile updated.", "success");
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not save the profile.", "error");
    } finally {
      setSaving(false);
    }
  }

  async function saveModel() {
    const value = modelDraft.trim();
    if (!value || value === settings?.model) return;
    setModelSaving(true);
    try {
      const updated = await api.setModel(value);
      setSettings(updated);
      push(`Evaluator model set to ${updated.model}.`, "success");
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not save the model.", "error");
    } finally {
      setModelSaving(false);
    }
  }

  async function saveKey(event: FormEvent) {
    event.preventDefault();
    const value = apiKey.trim();
    if (!value) return;
    setKeySaving(true);
    try {
      const updated = await api.setApiKey(value);
      setSettings(updated);
      setApiKey("");
      push("API key saved. New runs will use AI evaluation.", "success");
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not save the API key.", "error");
    } finally {
      setKeySaving(false);
    }
  }

  async function clearKey() {
    setKeyClearing(true);
    try {
      const updated = await api.clearApiKey();
      setSettings(updated);
      push("AI disabled. Runs will use the offline debrief.", "info");
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not clear the API key.", "error");
    } finally {
      setKeyClearing(false);
    }
  }

  async function runDataAction() {
    if (!confirm) return;
    setDataBusy(true);
    try {
      if (confirm === "history") {
        const result = await api.clearHistory();
        push(
          `Cleared ${result.runs_deleted} run${result.runs_deleted === 1 ? "" : "s"} and ${result.actions_deleted} recorded actions.`,
          "success",
        );
        setConfirm(null);
      } else {
        const result = await api.deleteProfile();
        setConfirm(null);
        setSession(null);
        push(
          `Profile deleted with ${result.runs_deleted} run${result.runs_deleted === 1 ? "" : "s"}.`,
          "success",
        );
        navigate("/onboarding", { replace: true });
      }
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not delete the data.", "error");
    } finally {
      setDataBusy(false);
    }
  }

  if (loading) {
    return (
      <div className="page page-narrow">
        <div className="card">
          <Loading label="Loading settings" />
        </div>
      </div>
    );
  }
  if (error) {
    return (
      <div className="page page-narrow">
        <div className="card">
          <ErrorState message={error} />
        </div>
      </div>
    );
  }

  const dirty =
    session !== null &&
    (role !== session.user.role ||
      domains.length !== session.user.domains.length ||
      domains.some((domain) => !session.user.domains.includes(domain)));
  const aiEnabled = Boolean(settings?.api_key_configured);
  const aiDisabled = Boolean(settings?.ai_disabled);

  return (
    <div className="page page-narrow">
      <div className="page-head">
        <div>
          <div className="eyebrow">Configuration</div>
          <h1>Settings</h1>
          <p className="page-sub">Profile, scoring, and local instance details.</p>
        </div>
      </div>

      <section className="card">
        <div className="card-head">
          <div className="row" style={{ gap: 7 }}>
            <Icon name="user" size={15} />
            <span className="card-title">Profile</span>
          </div>
          <Badge>{session?.user.name}</Badge>
        </div>
        <div className="card-body stack">
          <div className="field">
            <span className="label">Practice role</span>
            <div className="role-grid">
              {ROLES.map((value) => (
                <button
                  key={value}
                  type="button"
                  className={`role-option${role === value ? " on" : ""}`}
                  onClick={() => setRole(value)}
                >
                  <div className="role-name">{ROLE_LABELS[value]}</div>
                  <div className="role-desc">
                    {value === "analyst"
                      ? "Triage and hands-on response."
                      : value === "incident_manager"
                        ? "Coordination and escalation."
                        : value === "ciso"
                          ? "Regulatory and legal decisions."
                          : "Business impact and communication."}
                  </div>
                </button>
              ))}
            </div>
            {role !== "analyst" ? (
              <span className="tiny dim">
                Scenarios without role-specific content run from the analyst perspective and flag it.
              </span>
            ) : null}
          </div>

          <div className="field">
            <span className="label">Domains in scope</span>
            <div className="domain-grid">
              {available.map((domain) => (
                <button
                  key={domain}
                  type="button"
                  className={`domain-chip${domains.includes(domain) ? " on" : ""}`}
                  onClick={() => toggleDomain(domain)}
                  aria-pressed={domains.includes(domain)}
                >
                  {domains.includes(domain) ? <Icon name="check" size={11} /> : null}
                  {domain}
                </button>
              ))}
            </div>
            <span className="tiny dim">
              {domains.length === 0
                ? "At least one domain is required."
                : `${domains.length} of ${available.length} selected.`}
            </span>
          </div>

          <div className="row">
            <Button
              variant="primary"
              icon="save"
              loading={saving}
              disabled={!dirty || domains.length === 0}
              onClick={() => void save()}
            >
              Save profile
            </Button>
            {dirty ? <span className="tiny dim">Unsaved changes</span> : null}
          </div>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <div className="row" style={{ gap: 7 }}>
            <Icon name="sparkles" size={15} />
            <span className="card-title">AI & scoring</span>
          </div>
          <Badge tone={aiEnabled ? "green" : aiDisabled ? "red" : "amber"}>
            {aiEnabled ? "AI enabled" : aiDisabled ? "AI disabled" : "Offline mode"}
          </Badge>
        </div>
        <div className="card-body" style={{ paddingBottom: 0 }}>
          <div className="stack-sm" style={{ marginBottom: 18 }}>
            <label className="label" htmlFor="model-id">
              Evaluator model
            </label>
            <div className="row wrap">
              <input
                id="model-id"
                className="input mono"
                list="model-options"
                value={modelDraft}
                onChange={(event) => setModelDraft(event.target.value)}
                placeholder="nvidia/nemotron-3.5-lightning:free"
                spellCheck={false}
                autoComplete="off"
                style={{ flex: "1 1 320px" }}
              />
              <datalist id="model-options">
                {models.map((model) => (
                  <option key={model.id} value={model.id}>
                    {model.name} · {model.context_length ? `${Math.round(model.context_length / 1000)}k ctx` : ""}
                  </option>
                ))}
              </datalist>
              <Button
                variant="primary"
                icon="save"
                loading={modelSaving}
                disabled={!modelDraft.trim() || modelDraft.trim() === settings?.model}
                onClick={() => void saveModel()}
              >
                Save model
              </Button>
            </div>
            <span className="tiny dim">
              {models.length > 0
                ? `${models.length} models ${modelSource === "openrouter" ? "loaded from OpenRouter" : "from the built-in list (OpenRouter unreachable)"}. Pick one or type any model id.`
                : "Loading the OpenRouter model list — you can type any model id."}
            </span>
          </div>

          <form className="stack-sm" onSubmit={saveKey}>
            <label className="label" htmlFor="api-key">
              OpenRouter API key
            </label>
            <div className="row wrap">
              <input
                id="api-key"
                className="input"
                type="password"
                value={apiKey}
                onChange={(event) => setApiKey(event.target.value)}
                placeholder={aiEnabled ? "Paste a new key to replace the current one" : "sk-or-v1-…"}
                autoComplete="off"
                spellCheck={false}
                style={{ flex: "1 1 280px" }}
              />
              <Button
                type="submit"
                variant="primary"
                icon="save"
                loading={keySaving}
                disabled={!apiKey.trim()}
              >
                Save key
              </Button>
              {aiEnabled || !aiDisabled ? (
                <Button
                  type="button"
                  variant="ghost"
                  className="btn-danger"
                  icon="lock"
                  loading={keyClearing}
                  onClick={() => void clearKey()}
                >
                  Disable AI
                </Button>
              ) : null}
            </div>
            <span className="tiny dim">
              Saved to <span className="mono">.env</span> on this machine and applied immediately.
              The key is never returned to the browser. Disabling AI also overrides a key set in
              the Windows system environment.
            </span>
          </form>
        </div>
        <div className="table-wrap">
          <table className="table">
            <tbody>
              <tr>
                <td className="muted">OpenRouter key</td>
                <td>
                  {aiEnabled ? (
                    <span className="row" style={{ gap: 6 }}>
                      <span className="status-dot" /> Configured server-side
                    </span>
                  ) : aiDisabled ? (
                    <span className="row" style={{ gap: 6 }}>
                      <span className="status-dot warn" /> Disabled in Settings — runs use the offline
                      debrief
                    </span>
                  ) : (
                    <span className="row" style={{ gap: 6 }}>
                      <span className="status-dot warn" /> Not set — runs use the offline debrief
                    </span>
                  )}
                </td>
              </tr>
              <tr>
                <td className="muted">Session database</td>
                <td>
                  {settings?.db_available ? (
                    <Badge tone="green">Available</Badge>
                  ) : (
                    <Badge tone="red">Unavailable</Badge>
                  )}
                </td>
              </tr>
              <tr>
                <td className="muted">Scenarios loaded</td>
                <td className="mono">{settings?.scenarios}</td>
              </tr>
              <tr>
                <td className="muted">Max answer length</td>
                <td className="mono">{settings?.max_answer_chars} chars</td>
              </tr>
              <tr>
                <td className="muted">Report directory</td>
                <td className="mono tiny">{settings?.report_dir}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className="card-foot">
          <p className="tiny dim">
            AI evaluation is a single OpenRouter request per completed run. If the key is missing,
            disabled, or the model call fails, the run produces the offline debrief instead.
          </p>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <div className="row" style={{ gap: 7 }}>
            <Icon name="trash" size={15} />
            <span className="card-title">Data management</span>
          </div>
          <Badge tone="amber">Local only</Badge>
        </div>
        <div className="card-body stack">
          <div className="row-between wrap" style={{ alignItems: "flex-start" }}>
            <div style={{ maxWidth: 560 }}>
              <strong style={{ fontSize: "0.86rem" }}>Clear run history</strong>
              <p className="small muted" style={{ marginTop: 3 }}>
                Deletes every run, answer, hint/reveal record, mastery score and domain metric for
                this profile. Your name, role and domain choices stay.
              </p>
            </div>
            <Button
              className="btn-danger"
              icon="trash"
              onClick={() => setConfirm("history")}
              disabled={dataBusy}
            >
              Clear history
            </Button>
          </div>

          <hr className="divider" />

          <div className="row-between wrap" style={{ alignItems: "flex-start" }}>
            <div style={{ maxWidth: 560 }}>
              <strong style={{ fontSize: "0.86rem" }}>Delete profile and all data</strong>
              <p className="small muted" style={{ marginTop: 3 }}>
                Also removes the profile itself and signs you out. Generated files already written
                to the reports folder stay on disk.
              </p>
            </div>
            <Button
              className="btn-danger"
              icon="user"
              onClick={() => setConfirm("profile")}
              disabled={dataBusy}
            >
              Delete profile
            </Button>
          </div>
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <div className="row" style={{ gap: 7 }}>
            <Icon name="shield" size={15} />
            <span className="card-title">Local instance</span>
          </div>
          <Badge tone="green">Single user</Badge>
        </div>
        <div className="card-body stack-sm">
          <p className="small muted">
            {settings?.app} v{settings?.version}. Runs are stored in a local SQLite database; reports
            are written to the report directory above. Nothing is uploaded except the evaluation
            prompt when an API key is configured.
          </p>
          <div className="row wrap" style={{ marginTop: 4 }}>
            <a className="btn btn-sm" href="/api/docs" target="_blank" rel="noreferrer">
              <Icon name="fileText" size={14} /> API documentation
            </a>
            <a className="btn btn-sm" href="/health" target="_blank" rel="noreferrer">
              <Icon name="activity" size={14} /> Health check
            </a>
            <Button
              size="sm"
              variant="ghost"
              icon="logout"
              onClick={async () => {
                await logout();
                navigate("/onboarding");
              }}
            >
              Sign out
            </Button>
          </div>
        </div>
      </section>

      {confirm ? (
        <Modal
          title={confirm === "history" ? "Clear all run history?" : "Delete profile and all data?"}
          onClose={() => setConfirm(null)}
          footer={
            <>
              <Button variant="ghost" onClick={() => setConfirm(null)} disabled={dataBusy}>
                Cancel
              </Button>
              <Button
                className="btn-danger"
                icon="trash"
                loading={dataBusy}
                onClick={() => void runDataAction()}
              >
                {confirm === "history" ? "Clear history" : "Delete everything"}
              </Button>
            </>
          }
        >
          {confirm === "history" ? (
            <>
              This permanently deletes every run, recorded answer, mastery score and domain metric
              for <strong>{session?.user.name}</strong>. Your profile and settings remain. This
              cannot be undone.
            </>
          ) : (
            <>
              This permanently deletes the profile <strong>{session?.user.name}</strong>, every
              run and all derived learning data, then signs you out. This cannot be undone.
            </>
          )}
        </Modal>
      ) : null}
    </div>
  );
}
