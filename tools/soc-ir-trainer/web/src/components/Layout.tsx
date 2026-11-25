import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api, ROLE_LABELS } from "../api";
import { useSession } from "../session";
import type { SettingsInfo } from "../types";
import { Icon, type IconName } from "./Icons";
import { Badge } from "./ui";

const NAV: { to: string; label: string; icon: IconName; end?: boolean }[] = [
  { to: "/", label: "Dashboard", icon: "dashboard", end: true },
  { to: "/library", label: "Scenario library", icon: "library" },
  { to: "/progress", label: "Progress", icon: "chart" },
  { to: "/settings", label: "Settings", icon: "settings" },
];

const TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/library": "Scenario library",
  "/progress": "Progress",
  "/settings": "Settings",
  "/onboarding": "Onboarding",
};

export function AppShell() {
  const { session, logout } = useSession();
  const navigate = useNavigate();
  const location = useLocation();
  const [menuOpen, setMenuOpen] = useState(false);
  const [settings, setSettings] = useState<SettingsInfo | null>(null);

  useEffect(() => {
    api.settings().then(setSettings).catch(() => setSettings(null));
  }, []);

  useEffect(() => {
    setMenuOpen(false);
  }, [location.pathname]);

  const section = location.pathname.startsWith("/runs")
    ? location.pathname.endsWith("/debrief")
      ? "Debrief"
      : "Run workspace"
    : TITLES[location.pathname] ?? "SOC Trainer";
  const user = session?.user;
  const initials = (user?.name ?? "A")
    .split(/\s+/)
    .map((part) => part[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="app-shell">
      {menuOpen ? (
        <div className="sidebar-backdrop" onClick={() => setMenuOpen(false)} aria-hidden="true" />
      ) : null}
      <aside className={`sidebar${menuOpen ? " open" : ""}`} aria-label="Main navigation">
        <div className="brand">
          <span className="brand-mark">
            <Icon name="shield" size={19} />
          </span>
          <div className="stack-sm" style={{ gap: 0 }}>
            <span className="brand-name">SOC Trainer</span>
            <span className="brand-sub">IR Range</span>
          </div>
        </div>

        <nav className="nav">
          <span className="nav-label">Workspace</span>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) => `nav-item${isActive ? " active" : ""}`}
            >
              <span className="nav-icon">
                <Icon name={item.icon} size={16} />
              </span>
              {item.label}
              {item.to === "/library" && settings ? (
                <span className="badge">{settings.scenarios}</span>
              ) : null}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="profile-chip">
            <span className="avatar">{initials}</span>
            <div className="grow" style={{ minWidth: 0 }}>
              <div className="truncate" style={{ fontSize: "0.82rem", fontWeight: 550 }}>
                {user?.name ?? "Analyst"}
              </div>
              <div className="truncate tiny dim">{ROLE_LABELS[user?.role ?? "analyst"] ?? user?.role}</div>
            </div>
            <button
              className="btn btn-ghost btn-icon btn-sm"
              title="Sign out"
              aria-label="Sign out"
              onClick={async () => {
                await logout();
                navigate("/onboarding");
              }}
            >
              <Icon name="logout" size={15} />
            </button>
          </div>
          <div className="tiny dim" style={{ padding: "0 6px" }}>
            Simulated incidents only. Local instance.
          </div>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <button
            className="btn btn-ghost btn-icon menu-btn"
            aria-label="Open navigation"
            onClick={() => setMenuOpen(true)}
          >
            <Icon name="menu" size={18} />
          </button>
          <div className="topbar-title">
            SOC Trainer <span className="dim">/</span> <strong>{section}</strong>
          </div>
          <div className="topbar-spacer" />
          {settings ? (
            <Badge tone={settings.api_key_configured ? "green" : "amber"} icon="sparkles">
              {settings.api_key_configured ? "AI debrief enabled" : "Offline debrief"}
            </Badge>
          ) : null}
          <a className="btn btn-ghost btn-sm" href="/api/docs" target="_blank" rel="noreferrer">
            API
            <Icon name="external" size={12} />
          </a>
        </header>
        <Outlet context={{ settings }} />
      </div>
    </div>
  );
}
