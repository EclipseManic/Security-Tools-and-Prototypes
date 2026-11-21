import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, ROLE_LABELS } from "../api";
import { Icon } from "../components/Icons";
import { Button, useToast } from "../components/ui";
import { useSession } from "../session";

const ROLES: { id: string; name: string; desc: string }[] = [
  {
    id: "analyst",
    name: ROLE_LABELS.analyst,
    desc: "Triage, investigate, contain. Every scenario supports this role.",
  },
  {
    id: "incident_manager",
    name: ROLE_LABELS.incident_manager,
    desc: "Coordinate the response and manage escalation.",
  },
  {
    id: "ciso",
    name: ROLE_LABELS.ciso,
    desc: "Regulatory, legal, and stakeholder decisions.",
  },
  {
    id: "executive",
    name: ROLE_LABELS.executive,
    desc: "Business impact, resources, and communications.",
  },
];

export default function Onboarding() {
  const { setSession } = useSession();
  const { push } = useToast();
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [role, setRole] = useState("analyst");
  const [domains, setDomains] = useState<string[]>([]);
  const [available, setAvailable] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .scenarios({ limit: 1 })
      .then((page) => {
        const names = Object.keys(page.facets.domains ?? {});
        setAvailable(names);
        setDomains(names);
      })
      .catch(() => setAvailable([]));
  }, []);

  const allSelected = available.length > 0 && domains.length === available.length;

  function toggleDomain(domain: string) {
    setDomains((current) =>
      current.includes(domain) ? current.filter((item) => item !== domain) : [...current, domain],
    );
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const clean = name.trim();
    if (clean.length < 2) {
      setError("Enter a name with at least two characters.");
      return;
    }
    setSubmitting(true);
    setError("");
    try {
      const session = await api.createSession(clean, role, domains);
      setSession(session);
      push(`Welcome, ${clean}. Your range is ready.`, "success");
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the session.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="onboarding">
      <div className="card onboarding-card">
        <div className="onboarding-brand" style={{ paddingTop: 26, paddingInline: 24 }}>
          <span className="brand-mark">
            <Icon name="shield" size={24} />
          </span>
          <h1>SOC Incident Response Range</h1>
          <p>
            The breach has already happened. Read the briefing, make the calls, and get a
            detailed debrief on your decisions.
          </p>
        </div>

        <form className="onboarding-body stack" onSubmit={submit}>
          <div className="field">
            <label className="label" htmlFor="profile-name">
              Your name
            </label>
            <input
              id="profile-name"
              className="input"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="e.g. Alex Chen"
              maxLength={64}
              autoFocus
              autoComplete="off"
            />
            <span className="tiny dim">
              Local profile only. No password, no account, no data leaves this machine.
            </span>
          </div>

          <div className="field">
            <span className="label">Practice role</span>
            <div className="role-grid" role="radiogroup" aria-label="Practice role">
              {ROLES.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={`role-option${role === item.id ? " on" : ""}`}
                  onClick={() => setRole(item.id)}
                  role="radio"
                  aria-checked={role === item.id}
                >
                  <div className="role-name">{item.name}</div>
                  <div className="role-desc">{item.desc}</div>
                </button>
              ))}
            </div>
            {role !== "analyst" ? (
              <span className="tiny dim">
                Scenarios that do not support this role will run as SOC Analyst and say so.
              </span>
            ) : null}
          </div>

          <div className="field">
            <div className="row-between">
              <span className="label">Domains</span>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setDomains(allSelected ? [] : available)}
                disabled={available.length === 0}
              >
                {allSelected ? "Clear" : "Select all"}
              </button>
            </div>
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
              {available.length === 0 ? (
                <span className="tiny dim">Loading domains…</span>
              ) : null}
            </div>
            <span className="tiny dim">
              {domains.length === 0
                ? "No filter — every domain is in scope."
                : `${domains.length} of ${available.length} domains selected.`}
            </span>
          </div>

          {error ? (
            <div className="alert alert-error" role="alert">
              <Icon name="alertCircle" size={15} />
              <span>{error}</span>
            </div>
          ) : null}

          <Button type="submit" variant="primary" size="lg" block loading={submitting} iconRight="arrowRight">
            Enter the range
          </Button>

          <div className="alert">
            <Icon name="info" size={15} />
            <span>
              Simulation only. Every incident is a decision-tree walkthrough — no exploits are
              executed.
            </span>
          </div>
        </form>
      </div>
    </div>
  );
}
