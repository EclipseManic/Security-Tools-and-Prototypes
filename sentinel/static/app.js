/* ServiceSentinel Web - single page console.
   Vanilla JS, no build step. Every value from the API is escaped before it is
   inserted into HTML so service metadata can never inject markup. */
(() => {
  "use strict";

  const TOKEN = document.querySelector('meta[name="sentinel-token"]').content;
  const view = document.getElementById("view");
  const drawer = document.getElementById("drawer");
  const scrim = document.getElementById("scrim");
  const toasts = document.getElementById("toasts");

  const ROUTES = [
    ["overview", "Overview"],
    ["inventory", "Inventory"],
    ["hunt", "Hunt"],
    ["timeline", "Timeline"],
    ["baseline", "Baseline"],
    ["triage", "Triage"],
    ["reports", "Reports"],
    ["manage", "Management"],
    ["help", "Help"],
  ];

  const state = {
    status: null,
    route: (location.hash || "#overview").slice(1),
    inventory: null,
    inventoryEvidence: false,
    hunt: null,
    huntHours: 168,
    huntLevel: "",
    huntOpen: new Set(),
    timeline: null,
    timelineHours: 168,
    timelineName: "",
    timelineBucket: "day",
    baseline: null,
    triage: null,
    manage: null,
    help: null,
    serviceNames: [],
    baselineConfirm: "",
    manageResult: null,
    preflight: null,
    drawer: null,
    filters: {
      q: "", st: "", start: "", cat: "",
      unsigned: false, missing: false, writable: false, unquoted: false, unknown: false,
      page: 0, sort: "category", dir: 1,
    },
    baselineFilter: { severity: "", type: "" },
  };

  /* ------------------------------------------------------------------ */
  /* helpers                                                             */
  /* ------------------------------------------------------------------ */
  const esc = (value) =>
    String(value === null || value === undefined ? "" : value).replace(/[&<>"']/g, (ch) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
    ));

  const num = (value) => Number(value || 0).toLocaleString();
  const pct = (value) => Math.max(0, Math.min(100, Number(value || 0)));

  function when(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return esc(value);
    return date.toLocaleString();
  }

  function toast(message, kind = "info") {
    const node = document.createElement("div");
    node.className = `toast ${kind === "info" ? "" : kind}`;
    node.textContent = message;
    toasts.appendChild(node);
    setTimeout(() => node.remove(), kind === "error" ? 9000 : 5000);
  }

  async function api(path, options = {}) {
    const method = options.method || "GET";
    const headers = { "X-Sentinel-Token": TOKEN };
    if (options.body) headers["Content-Type"] = "application/json";
    const response = await fetch(path, {
      method,
      headers,
      body: options.body ? JSON.stringify(options.body) : null,
    });
    let payload = null;
    try {
      payload = await response.json();
    } catch {
      throw new Error(`Server returned an unreadable response (${response.status}).`);
    }
    if (!response.ok || payload.ok === false) {
      const error = new Error(payload && payload.error ? payload.error : `Request failed (${response.status}).`);
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  function levelBadge(level) {
    const key = String(level || "informational").toLowerCase();
    return `<span class="badge ${esc(key)}">${esc(level || "Informational")}</span>`;
  }

  function pill(text, cls) {
    return `<span class="badge ${esc(cls || "info")}">${esc(text)}</span>`;
  }

  function severityPill(severity) {
    const key = String(severity || "").toLowerCase();
    const cls = key === "error" || key === "high" ? "bad" : key === "warning" || key === "medium" ? "warn" : "info";
    return pill(severity, cls);
  }

  function decisionPill(decision) {
    const map = {
      Contain: "bad",
      Investigate: "warn",
      Monitor: "info",
      Allow: "good",
      FalsePositive: "info",
      Resolved: "good",
    };
    return pill(decision, map[decision] || "info");
  }

  function scoreCell(score, level, label) {
    const key = String(level || "informational").toLowerCase();
    return `<div class="score" title="${esc(label)}: ${num(score)} (${esc(level)})">
      <div class="bar bar-${esc(key)}"><span style="width:${pct(score)}%"></span></div>
      <span class="val">${num(score)}</span></div>`;
  }

  function statCard(label, value, hint, tone = "") {
    return `<div class="card ${tone}">
      <div class="label">${esc(label)}</div>
      <div class="value">${value}</div>
      ${hint ? `<div class="hint">${esc(hint)}</div>` : ""}
    </div>`;
  }

  function panel(title, body, extra = "") {
    return `<section class="panel">
      <h3>${esc(title)}${extra ? ` <span class="pill">${extra}</span>` : ""}</h3>
      ${body}
    </section>`;
  }

  function emptyPanel(message) {
    return `<div class="empty">${esc(message)}</div>`;
  }

  function serviceDatalist() {
    return `<datalist id="service-names">${state.serviceNames
      .map((name) => `<option value="${esc(name)}"></option>`)
      .join("")}</datalist>`;
  }

  function rememberServiceNames(services) {
    state.serviceNames = services.map((item) => item.name).filter(Boolean);
  }

  /* ------------------------------------------------------------------ */
  /* chrome                                                              */
  /* ------------------------------------------------------------------ */
  function renderTabs() {
    document.getElementById("tabs").innerHTML = ROUTES.map(
      ([id, label]) =>
        `<button class="tab ${state.route === id ? "active" : ""}" data-action="nav" data-route="${id}">${esc(label)}</button>`
    ).join("");
  }

  async function loadStatus(refresh = false) {
    if (state.status && !refresh) return state.status;
    state.status = await api("/api/status");
    renderTopMeta();
    return state.status;
  }

  function renderTopMeta() {
    const status = state.status;
    if (!status) return;
    const admin = status.admin
      ? `<span class="pill ok">Administrator</span>`
      : `<span class="pill warn" title="Some service metadata cannot be read without elevation">Standard user</span>`;
    document.getElementById("topmeta").innerHTML = `
      <span class="pill"><strong>${esc(status.hostname)}</strong></span>
      ${admin}
      <span class="pill">PowerShell <strong>${esc(status.powershell)}</strong></span>
      <span class="pill" title="${esc(status.data_root)}">Evidence: <strong>${esc(shorten(status.data_root, 34))}</strong></span>
      <span class="pill">Triage: <strong>${num(status.triage_count)}</strong></span>
      ${status.auth_enabled ? `<a class="pill" href="/logout" title="Sign out of this console">Sign out</a>` : ""}`;
  }

  function shorten(text, limit) {
    const value = String(text || "");
    return value.length > limit ? `…${value.slice(-limit + 1)}` : value;
  }

  function setLoading(label) {
    view.innerHTML = `<div class="loading"><span class="spinner"></span> ${esc(label)}</div>`;
  }

  function errorPanel(message) {
    return `<div class="banner bad"><strong>Unable to load:</strong> ${esc(message)}
      <div style="margin-top:10px"><button data-action="retry">Try again</button></div></div>`;
  }

  /* ------------------------------------------------------------------ */
  /* router                                                              */
  /* ------------------------------------------------------------------ */
  const VIEWS = {
    overview: viewOverview,
    inventory: viewInventory,
    hunt: viewHunt,
    timeline: viewTimeline,
    baseline: viewBaseline,
    triage: viewTriage,
    reports: viewReports,
    manage: viewManage,
    help: viewHelp,
  };

  async function render(force = false) {
    const route = ROUTES.some(([id]) => id === state.route) ? state.route : "overview";
    state.route = route;
    renderTabs();
    setLoading("Loading " + route + "…");
    try {
      await loadStatus();
      const handler = VIEWS[route] || viewOverview;
      const html = await handler(force);
      view.innerHTML = html;
      window.scrollTo(0, 0);
    } catch (error) {
      view.innerHTML = errorPanel(error.message || String(error));
    }
  }

  /* ------------------------------------------------------------------ */
  /* overview                                                            */
  /* ------------------------------------------------------------------ */
  async function viewOverview(force) {
    if (!state.inventory || force) {
      state.inventory = await api(`/api/inventory?evidence=${state.inventoryEvidence ? 1 : 0}`);
      rememberServiceNames(state.inventory.services);
    }
    if (!state.baseline) state.baseline = await api("/api/baseline");
    if (!state.maintenance) state.maintenance = await api("/api/maintenance");
    const inv = state.inventory;
    const stats = inv.stats;
    const hunt = state.hunt;
    const baseline = state.baseline;

    const categoryBars = stats.categories
      .slice(0, 10)
      .map((row) => {
        const share = stats.total ? Math.round((row.count / stats.total) * 100) : 0;
        return `<div class="row">
          <span>${esc(row.name)}</span>
          <span class="track"><span class="fill" style="width:${share}%"></span></span>
          <span class="n">${num(row.count)}</span>
        </div>`;
      })
      .join("");

    const notable = hunt
      ? hunt.findings.filter((item) => item.threat_score > 0).slice(0, 6)
      : [];

    const findingsBody = notable.length
      ? `<div class="table-wrap"><table>
          <thead><tr><th class="nosort">Service</th><th class="nosort">Threat</th><th class="nosort">Level</th>
          <th class="nosort">Primary reason</th></tr></thead>
          <tbody>${notable
            .map(
              (item) => `<tr class="clickable" data-action="open-service" data-name="${esc(item.service_name)}">
                <td><strong>${esc(item.service_name)}</strong><div class="muted smalltext">${esc(item.display_name)}</div></td>
                <td>${scoreCell(item.threat_score, item.threat_level, "Threat")}</td>
                <td>${levelBadge(item.threat_level)}</td>
                <td class="truncate">${esc((item.threat_reasons[0] || {}).text || "—")}</td>
              </tr>`
            )
            .join("")}</tbody></table></div>
        <p class="hint" style="margin-top:10px">Open the Hunt page for every finding, reasons and exports.</p>`
      : emptyPanel("No hunt has been run in this session. Start with a 7-day hunt on the Hunt page.");

    const baselineBody = baseline
      ? `<div class="kv">
          <div><span class="k">Captured</span><span class="v">${when(baseline.baseline && baseline.baseline.created_at)}</span></div>
          <div><span class="k">Services</span><span class="v">${num(baseline.baseline && baseline.baseline.services)}</span></div>
          <div><span class="k">Changes now</span><span class="v">${num(baseline.summary && baseline.summary.total)}</span></div>
          <div><span class="k">Unverifiable</span><span class="v">${num(baseline.summary && baseline.summary.unverifiable)}</span></div>
        </div>
        <button class="small" data-action="nav" data-route="baseline">Open baseline</button>`
      : `<p class="hint">No baseline exists yet. Create one while this computer is known to be clean.</p>
         <button class="small" data-action="nav" data-route="baseline">Create a baseline</button>`;

    const logTail = (state.status.log_tail || [])
      .slice(-12)
      .map((line) => `<div class="mono smalltext muted">${esc(line)}</div>`)
      .join("");

    const store = state.maintenance;
    const storageBody = store
      ? `<div class="kv">
          <div><span class="k">Evidence</span><span class="v">${num(store.usage.mb)} MB · ${num(store.usage.files)} files</span></div>
          <div><span class="k">Free disk</span><span class="v">${store.usage.free_mb === null ? "unknown" : num(store.usage.free_mb) + " MB"}</span></div>
          <div><span class="k">Retention</span><span class="v">${num(store.retention_days)} days</span></div>
          <div><span class="k">Exports kept</span><span class="v">${num(store.max_exports)}</span></div>
          <div><span class="k">Evidence cache</span><span class="v">${num(store.cache_entries)} entries</span></div>
          <div><span class="k">Baseline history</span><span class="v">${num(store.baseline_history)}</span></div>
        </div>
        <button class="small" data-action="prune">Prune expired evidence</button>`
      : emptyPanel("Maintenance information unavailable.");

    const unknownNote = stats.unknown_path
      ? `<div class="banner info">${num(stats.unknown_path)} service(s) reported no readable executable path.
          Those are treated as <strong>unknown</strong>, not as suspicious. Run the console as Administrator for complete metadata.</div>`
      : "";

    return `
      <div class="view-head">
        <div>
          <h2>Overview</h2>
          <div class="sub">Collected ${when(inv.collected_at)} · ${num(inv.event_count)} SCM events in the last ${num(inv.event_window_hours)}h</div>
        </div>
        <div class="view-actions">
          <button data-action="nav" data-route="hunt">Run a hunt</button>
          <button data-action="nav" data-route="inventory">Browse inventory</button>
        </div>
      </div>

      ${unknownNote}

      <div class="cards">
        ${statCard("Services", num(stats.total), "installed on this host")}
        ${statCard("Running", num(stats.running), "of " + num(stats.total), "good")}
        ${statCard("Automatic", num(stats.auto), "start at boot", "accent")}
        ${statCard(
          "Unsigned",
          num(stats.unsigned),
          stats.signature_unknown ? `${num(stats.signature_unknown)} not checked` : "signature verified",
          stats.unsigned ? "warn" : ""
        )}
        ${statCard("Missing binary", num(stats.missing_binary), "configured file is gone", stats.missing_binary ? "bad" : "")}
        ${statCard("User-writable path", num(stats.user_writable), "Downloads / Temp / profile", stats.user_writable ? "bad" : "")}
        ${statCard("Unquoted path", num(stats.unquoted), "space in unquoted image", stats.unquoted ? "warn" : "")}
        ${statCard("Notable findings", hunt ? num(hunt.notable) : "—", hunt ? "scored above zero" : "run a hunt")}
      </div>

      <div class="panel-grid">
        ${panel("Service categories", `<div class="bars">${categoryBars || emptyPanel("No services")}</div>`)}
        ${panel("Baseline", baselineBody)}
        ${panel("Storage and retention", storageBody)}
      </div>

      ${panel("Top findings", findingsBody)}
      ${panel("Application log", logTail || emptyPanel("No log entries for today."))}`;
  }

  /* ------------------------------------------------------------------ */
  /* inventory                                                           */
  /* ------------------------------------------------------------------ */
  function filteredInventory() {
    const f = state.filters;
    let rows = state.inventory.services.slice();
    const query = f.q.trim().toLowerCase();
    if (query) {
      rows = rows.filter((row) =>
        [row.name, row.display_name, row.command_line, row.company, row.account, row.category, row.exe_path]
          .some((value) => String(value || "").toLowerCase().includes(query))
      );
    }
    if (f.st) rows = rows.filter((row) => row.state === f.st);
    if (f.start) rows = rows.filter((row) => row.start_mode === f.start);
    if (f.cat) rows = rows.filter((row) => row.category === f.cat);
    if (f.unsigned) rows = rows.filter((row) => row.signature === "NotSigned");
    if (f.missing) rows = rows.filter((row) => row.path_known && !row.file_exists);
    if (f.writable) rows = rows.filter((row) => row.user_writable);
    if (f.unquoted) rows = rows.filter((row) => row.unquoted_path);
    if (f.unknown) rows = rows.filter((row) => !row.path_known);

    const key = f.sort;
    rows.sort((a, b) => {
      const left = key === "triage" ? (a.triage ? a.triage.decision : "") : a[key];
      const right = key === "triage" ? (b.triage ? b.triage.decision : "") : b[key];
      return String(left || "").localeCompare(String(right || ""), undefined, { numeric: true }) * f.dir;
    });
    return rows;
  }

  function sortHeader(key, label) {
    const active = state.filters.sort === key;
    const arrow = active ? (state.filters.dir === 1 ? " ▲" : " ▼") : "";
    return `<th data-action="sort-inventory" data-sort="${key}">${esc(label)}${arrow}</th>`;
  }

  async function viewInventory(force) {
    if (!state.inventory || force) {
      state.inventory = await api(`/api/inventory?evidence=${state.inventoryEvidence ? 1 : 0}`);
      rememberServiceNames(state.inventory.services);
    }
    const inv = state.inventory;
    const rows = filteredInventory();
    const pageSize = 50;
    const pages = Math.max(1, Math.ceil(rows.length / pageSize));
    state.filters.page = Math.min(state.filters.page, pages - 1);
    const page = state.filters.page;
    const slice = rows.slice(page * pageSize, page * pageSize + pageSize);

    const categories = state.inventory.stats.categories
      .map((row) => `<option value="${esc(row.name)}" ${state.filters.cat === row.name ? "selected" : ""}>${esc(row.name)}</option>`)
      .join("");

    const body = slice
      .map((row) => {
        const triage = row.triage
          ? `<span class="badge ${row.triage.decision === "Contain" ? "bad" : "info"}">${esc(row.triage.decision)}</span>`
          : `<span class="muted smalltext">—</span>`;
        const signature = row.path_known
          ? `<span class="badge ${row.signature === "Valid" ? "good" : row.signature === "NotSigned" ? "warn" : "info"}">${esc(row.signature)}</span>`
          : `<span class="badge unknown" title="Not readable without elevation">unknown</span>`;
        return `<tr class="clickable" data-action="open-service" data-name="${esc(row.name)}">
          <td><strong>${esc(row.name)}</strong></td>
          <td class="truncate" title="${esc(row.display_name)}">${esc(row.display_name)}</td>
          <td>${esc(row.category)}</td>
          <td>${row.state === "Running" ? `<span class="badge good">Running</span>` : `<span class="muted">${esc(row.state)}</span>`}</td>
          <td>${row.start_mode === "Auto" ? `<span class="badge warn">Auto</span>` : esc(row.start_mode)}</td>
          <td class="truncate" title="${esc(row.account)}">${esc(row.account)}${row.account_known ? "" : " <span class=\"badge unknown\">?</span>"}</td>
          <td>${signature}</td>
          <td>${esc(row.runtime)}</td>
          <td class="truncate">${esc(row.last_activity)}</td>
          <td>${triage}</td>
        </tr>`;
      })
      .join("");

    return `
      <div class="view-head">
        <div>
          <h2>Inventory</h2>
          <div class="sub">${num(inv.stats.total)} services · ${num(inv.stats.running)} running · collected ${when(inv.collected_at)}
            ${inv.evidence ? "· file evidence included" : "· file evidence off"}</div>
        </div>
        <div class="view-actions">
          <button data-action="toggle-evidence">${inv.evidence ? "Hide file evidence" : "Collect file evidence"}</button>
          <button data-action="refresh-inventory" class="ghost">Refresh</button>
          <button data-action="export" data-report="inventory" data-format="Csv" class="ghost">Export CSV</button>
        </div>
      </div>

      <form class="toolbar" data-form="inventory-filter">
        <label class="field grow">Search name, display name, path, company or account
          <input type="text" name="q" value="${esc(state.filters.q)}" placeholder="e.g. updater, svchost, C:\\Program Files" autocomplete="off">
        </label>
        <label class="field">State
          <select name="st">
            <option value="">All</option>
            <option value="Running" ${state.filters.st === "Running" ? "selected" : ""}>Running</option>
            <option value="Stopped" ${state.filters.st === "Stopped" ? "selected" : ""}>Stopped</option>
          </select>
        </label>
        <label class="field">Startup
          <select name="start">
            <option value="">All</option>
            <option value="Auto" ${state.filters.start === "Auto" ? "selected" : ""}>Auto</option>
            <option value="Manual" ${state.filters.start === "Manual" ? "selected" : ""}>Manual</option>
            <option value="Disabled" ${state.filters.start === "Disabled" ? "selected" : ""}>Disabled</option>
          </select>
        </label>
        <label class="field">Category
          <select name="cat"><option value="">All</option>${categories}</select>
        </label>
        <button type="submit" class="primary">Apply</button>
        <button type="button" data-action="reset-filters" class="ghost">Reset</button>
      </form>

      <div class="checkline">
        <label><input type="checkbox" data-flag="unsigned" ${state.filters.unsigned ? "checked" : ""}> Unsigned only</label>
        <label><input type="checkbox" data-flag="missing" ${state.filters.missing ? "checked" : ""}> Missing binary</label>
        <label><input type="checkbox" data-flag="writable" ${state.filters.writable ? "checked" : ""}> User-writable path</label>
        <label><input type="checkbox" data-flag="unquoted" ${state.filters.unquoted ? "checked" : ""}> Unquoted path</label>
        <label><input type="checkbox" data-flag="unknown" ${state.filters.unknown ? "checked" : ""}> Metadata unknown</label>
      </div>

      <div class="table-wrap">
        <table>
          <thead><tr>
            ${sortHeader("name", "Name")}
            ${sortHeader("display_name", "Display name")}
            ${sortHeader("category", "Category")}
            ${sortHeader("state", "State")}
            ${sortHeader("start_mode", "Startup")}
            ${sortHeader("account", "Account")}
            ${sortHeader("signature", "Signature")}
            ${sortHeader("runtime", "Runtime")}
            ${sortHeader("last_activity", "Last activity")}
            <th data-action="sort-inventory" data-sort="triage">Triage</th>
          </tr></thead>
          <tbody>${body || `<tr><td colspan="10">${emptyPanel("No services match these filters.")}</td></tr>`}</tbody>
        </table>
      </div>

      <div class="pager">
        <span>${num(rows.length)} match${rows.length === 1 ? "" : "es"} · page ${page + 1} of ${pages}</span>
        <button class="small" data-action="page" data-dir="-1" ${page === 0 ? "disabled" : ""}>Previous</button>
        <button class="small" data-action="page" data-dir="1" ${page >= pages - 1 ? "disabled" : ""}>Next</button>
      </div>
      ${serviceDatalist()}`;
  }

  /* ------------------------------------------------------------------ */
  /* hunt                                                                */
  /* ------------------------------------------------------------------ */
  async function viewHunt(force) {
    if (!state.hunt || force) {
      state.hunt = await api(`/api/hunt?hours=${state.huntHours}${force ? "&refresh=1" : ""}`);
    }
    const hunt = state.hunt;
    const counts = hunt.counts || {};
    const list = hunt.findings.filter(
      (item) =>
        (item.threat_score > 0 || item.reliability_score > 0) &&
        (!state.huntLevel || item.threat_level === state.huntLevel || item.reliability_level === state.huntLevel)
    );

    const rows = list
      .map((item) => {
        const open = state.huntOpen.has(item.service_name);
        const reasons = item.threat_reasons
          .map((reason) => `<li>${esc(reason.text)}</li>`)
          .join("");
        const reliability = item.reliability_reasons.map((reason) => `<li>${esc(reason.text)}</li>`).join("");
        const notes = item.notes && item.notes.length
          ? `<div class="notes"><strong>Data gaps (not scored)</strong><ul>${item.notes.map((note) => `<li>${esc(note)}</li>`).join("")}</ul></div>`
          : "";
        return `<tr class="clickable" data-action="toggle-finding" data-name="${esc(item.service_name)}">
            <td><strong>${esc(item.service_name)}</strong>
              <div class="muted smalltext">${esc(item.display_name)}</div></td>
            <td>${scoreCell(item.threat_score, item.threat_level, "Threat")}</td>
            <td>${levelBadge(item.threat_level)}</td>
            <td>${scoreCell(item.reliability_score, item.reliability_level, "Reliability")}</td>
            <td>${esc(item.state)}</td>
            <td>${esc(item.start_mode)}</td>
            <td class="truncate" title="${esc(item.account)}">${esc(item.account)}</td>
            <td class="truncate" title="${esc(item.exe_path)}">${esc(item.exe_path || "unknown")}</td>
            <td class="truncate">${esc((item.threat_reasons[0] || {}).text || (item.notes || [])[0] || "—")}</td>
          </tr>
          ${open ? `<tr class="expand"><td colspan="9"><div class="expand-inner">
            <div class="section-title">Threat reasons</div>
            ${reasons ? `<ul class="reasons">${reasons}</ul>` : `<p class="hint">No threat indicator contributed points.</p>`}
            ${reliability ? `<div class="section-title">Reliability</div><ul class="reasons">${reliability}</ul>` : ""}
            ${notes}
            <p><strong>Recommended next step.</strong> ${esc(item.recommendation)}</p>
            <div class="kv">
              <div><span class="k">Category</span><span class="v">${esc(item.category)}</span></div>
              <div><span class="k">Signature</span><span class="v">${esc(item.signature)}</span></div>
              <div><span class="k">Signer</span><span class="v">${esc(item.signer || "—")}</span></div>
              <div><span class="k">SHA-256</span><span class="v mono">${esc(item.sha256 || "not collected")}</span></div>
            </div>
            <div class="view-actions">
              <button class="small" data-action="open-service" data-name="${esc(item.service_name)}">Full evidence</button>
              <button class="small" data-action="triage-quick" data-name="${esc(item.service_name)}">Triage…</button>
            </div>
          </div></td></tr>` : ""}`;
      })
      .join("");

    const option = (hours, label) =>
      `<option value="${hours}" ${state.huntHours === hours ? "selected" : ""}>${esc(label)}</option>`;

    return `
      <div class="view-head">
        <div>
          <h2>Hunt</h2>
          <div class="sub">${num(hunt.scored_services)} services scored · ${num(hunt.event_count)} events in the last ${num(hunt.hours)}h
            · ${num(hunt.notable)} notable</div>
        </div>
        <div class="view-actions">
          <button data-action="export" data-report="assessment" data-format="Html">Export HTML</button>
          <button data-action="export" data-report="assessment" data-format="Csv" class="ghost">CSV</button>
          <button data-action="export" data-report="assessment" data-format="Json" class="ghost">JSON</button>
        </div>
      </div>

      <form class="toolbar" data-form="hunt-run">
        <label class="field">Lookback
          <select name="hours">
            ${option(24, "24 hours")}${option(72, "3 days")}${option(168, "7 days")}${option(720, "30 days")}
          </select>
        </label>
        <label class="field">Level
          <select name="level">
            <option value="">All levels</option>
            ${["Critical", "High", "Medium", "Low"].map((level) => `<option value="${level}" ${state.huntLevel === level ? "selected" : ""}>${level}</option>`).join("")}
          </select>
        </label>
        <button type="submit" class="primary">Run hunt</button>
      </form>

      <div class="cards">
        ${statCard("Critical", num(counts.Critical), "75-100", counts.Critical ? "bad" : "")}
        ${statCard("High", num(counts.High), "50-74", counts.High ? "warn" : "")}
        ${statCard("Medium", num(counts.Medium), "25-49")}
        ${statCard("Low", num(counts.Low), "1-24")}
        ${statCard("Informational", num(counts.Informational), "score 0")}
      </div>

      ${hunt.events_truncated ? `<div class="banner warn">The event query hit the record cap; older events were skipped. Narrow the window for complete coverage.</div>` : ""}

      <div class="table-wrap">
        <table>
          <thead><tr>
            <th class="nosort">Service</th><th class="nosort">Threat</th><th class="nosort">Level</th>
            <th class="nosort">Reliability</th><th class="nosort">State</th><th class="nosort">Startup</th>
            <th class="nosort">Account</th><th class="nosort">Executable</th><th class="nosort">Primary reason</th>
          </tr></thead>
          <tbody>${rows || `<tr><td colspan="9">${emptyPanel("No findings for this window. That is a result, not an error.")}</td></tr>`}</tbody>
        </table>
      </div>
      <p class="hint" style="margin-top:10px">Click any row to expand its scored reasons. Scores prioritise investigation; they are not a malware verdict.</p>`;
  }

  /* ------------------------------------------------------------------ */
  /* timeline                                                            */
  /* ------------------------------------------------------------------ */
  async function viewTimeline(force) {
    const query = new URLSearchParams({
      hours: String(state.timelineHours),
      name: state.timelineName,
      bucket: state.timelineBucket,
    });
    if (force) query.set("refresh", "1");
    state.timeline = await api(`/api/timeline?${query.toString()}`);
    const timeline = state.timeline;
    const summary = timeline.summary;

    const activity = summary.by_activity
      .map(
        (row) => `<div class="row"><span>${esc(row.name)}</span>
          <span class="track"><span class="fill" style="width:${summary.total ? Math.round((row.count / summary.total) * 100) : 0}%"></span></span>
          <span class="n">${num(row.count)}</span></div>`
      )
      .join("");

    const buckets = summary.by_bucket
      .slice(0, 20)
      .map(
        (row) => `<tr><td>${esc(row.key)}</td><td class="num">${num(row.events)}</td>
          <td class="num">${num(row.created)}</td><td class="num">${num(row.started)}</td>
          <td class="num">${num(row.stopped)}</td>
          <td class="num">${row.failures ? `<span class="badge bad">${num(row.failures)}</span>` : "0"}</td></tr>`
      )
      .join("");

    const events = timeline.events
      .slice(0, 400)
      .map(
        (event) => `<tr>
          <td class="mono smalltext">${esc(when(event.time))}</td>
          <td class="mono">${esc(event.event_id)}</td>
          <td>${esc(event.activity)}</td>
          <td>${severityPill(event.severity)}</td>
          <td>${esc(event.service_name)}</td>
          <td class="truncate" title="${esc(event.detail)}">${esc(event.detail)}</td>
        </tr>`
      )
      .join("");

    const unrecognised = summary.unrecognised_state_words || [];
    const localisationNote = unrecognised.length
      ? `<div class="banner warn"><strong>Unrecognised service state wording:</strong>
          ${unrecognised.map((word) => `“${esc(word)}”`).join(", ")}.
          These events are counted but their state cannot be classified yet. Restart the service once while
          ServiceSentinel is running, or open a service page, so the wording can be learned from its current state.</div>`
      : `<div class="banner info">State wording learned for this host: ${Object.entries(timeline.state_words || {})
          .slice(0, 8)
          .map(([word, meaning]) => `<strong>${esc(word)}</strong> → ${esc(meaning)}`)
          .join(" · ")}</div>`;

    return `
      <div class="view-head">
        <div>
          <h2>Timeline</h2>
          <div class="sub">Service Control Manager activity · ${num(timeline.events.length)} events${state.timelineName ? ` for ${esc(state.timelineName)}` : ""}</div>
        </div>
        <div class="view-actions">
          <button data-action="export" data-report="timeline" data-format="Html">Export HTML</button>
          <button data-action="export" data-report="timeline" data-format="Csv" class="ghost">CSV</button>
        </div>
      </div>

      <form class="toolbar" data-form="timeline-run">
        <label class="field">Lookback (hours)
          <input type="number" name="hours" min="1" max="2160" value="${state.timelineHours}">
        </label>
        <label class="field grow">Service (optional)
          <input type="text" name="name" list="service-names" value="${esc(state.timelineName)}" placeholder="exact internal name or display name">
        </label>
        <label class="field">Group by
          <select name="bucket">
            <option value="day" ${state.timelineBucket === "day" ? "selected" : ""}>Day</option>
            <option value="week" ${state.timelineBucket === "week" ? "selected" : ""}>Week</option>
          </select>
        </label>
        <button type="submit" class="primary">Apply</button>
      </form>

      <div class="cards">
        ${statCard("Events", num(summary.total), "in this window")}
        ${statCard("Created", num(summary.created), "7045 service creation", summary.created ? "warn" : "")}
        ${statCard("Started", num(summary.started), "7036 running")}
        ${statCard("Failures", num(summary.failures), "error severity", summary.failures ? "bad" : "")}
      </div>

      ${localisationNote}

      <div class="panel-grid">
        ${panel("Activity totals", `<div class="bars">${activity || emptyPanel("No events")}</div>`)}
        ${panel(
          state.timelineBucket === "week" ? "Weekly activity" : "Daily activity",
          `<div class="table-wrap"><table>
            <thead><tr><th class="nosort">${state.timelineBucket === "week" ? "Week" : "Day"}</th><th class="nosort">Events</th>
            <th class="nosort">Created</th><th class="nosort">Started</th><th class="nosort">Stopped</th><th class="nosort">Failures</th></tr></thead>
            <tbody>${buckets || `<tr><td colspan="6">${emptyPanel("No events")}</td></tr>`}</tbody></table></div>`
        )}
      </div>

      ${panel(
        "Events",
        `<div class="table-wrap"><table>
          <thead><tr><th class="nosort">Time</th><th class="nosort">Event</th><th class="nosort">Activity</th>
          <th class="nosort">Severity</th><th class="nosort">Service</th><th class="nosort">Detail</th></tr></thead>
          <tbody>${events || `<tr><td colspan="6">${emptyPanel("No Service Control Manager events in this window.")}</td></tr>`}</tbody>
        </table></div>${timeline.events.length > 400 ? `<p class="hint" style="margin-top:8px">Showing the newest 400 of ${num(timeline.events.length)} events. Export for the full set.</p>` : ""}`
      )}
      ${serviceDatalist()}`;
  }

  /* ------------------------------------------------------------------ */
  /* baseline                                                            */
  /* ------------------------------------------------------------------ */
  async function viewBaseline(force) {
    if (!state.baseline || force) state.baseline = await api("/api/baseline");
    const data = state.baseline;

    const createCard = `<form class="toolbar" data-form="baseline-create">
        <label class="field grow">Type BASELINE to snapshot the current configuration
          <input type="text" name="confirm" value="${esc(state.baselineConfirm)}" placeholder="BASELINE" autocomplete="off">
        </label>
        <button type="submit" class="primary">${data.exists ? "Replace baseline" : "Create baseline"}</button>
      </form>
      <p class="hint">Only create a baseline when this computer is known to be clean and correctly configured.
      Replacing it discards the trusted reference.</p>`;

    if (!data.exists) {
      return `<div class="view-head"><div><h2>Baseline</h2>
        <div class="sub">No trusted snapshot yet</div></div></div>
        <div class="banner info">A baseline records the service configuration you trust. Later comparisons then
        show what appeared, disappeared or changed.</div>
        ${panel("Create the first baseline", createCard)}`;
    }

    const summary = data.summary;
    const filters = state.baselineFilter;
    let changes = data.changes.slice();
    if (filters.severity) changes = changes.filter((row) => row.severity === filters.severity);
    if (filters.type) changes = changes.filter((row) => row.change_type === filters.type);

    const rows = changes
      .map(
        (row) => `<tr>
          <td>${levelBadge(row.severity)}</td>
          <td>${esc(row.change_type)}</td>
          <td><strong>${esc(row.service_name)}</strong></td>
          <td>${esc(row.field)}</td>
          <td class="truncate mono smalltext" title="${esc(row.old_value || "")}">${esc(row.old_value || "—")}</td>
          <td class="truncate mono smalltext" title="${esc(row.new_value || "")}">${esc(row.new_value || "—")}</td>
          <td class="truncate">${esc(row.reason)}</td>
        </tr>`
      )
      .join("");

    const unverifiable = (data.unverifiable || [])
      .slice(0, 40)
      .map((row) => `<li><strong>${esc(row.service_name)}</strong> · ${esc(row.field)} — ${esc(row.reason)}</li>`)
      .join("");

    const history = (data.history || [])
      .map(
        (row) => `<tr><td class="mono smalltext">${esc(row.file)}</td><td>${when(row.created_at)}</td>
          <td class="num">${num(row.services)}</td><td class="num">${num(row.size)}</td></tr>`
      )
      .join("");

    return `
      <div class="view-head">
        <div><h2>Baseline</h2>
          <div class="sub">Captured ${when(data.baseline.created_at)} on ${esc(data.baseline.hostname)} · ${num(data.baseline.services)} services</div>
        </div>
        <div class="view-actions">
          <button data-action="baseline-compare" class="ghost">Re-run comparison</button>
          <button data-action="export" data-report="baseline" data-format="Html">Export HTML</button>
          <button data-action="export" data-report="baseline" data-format="Csv" class="ghost">CSV</button>
        </div>
      </div>

      <div class="cards">
        ${statCard("Changes", num(summary.total), "since the baseline", summary.total ? "warn" : "good")}
        ${statCard("Created", num(summary.created), "services that appeared", summary.created ? "bad" : "")}
        ${statCard("Deleted", num(summary.deleted), "services that vanished", summary.deleted ? "bad" : "")}
        ${statCard("Modified", num(summary.modified), "configuration changes")}
        ${statCard("Version rotation", num(summary.versioned), "expected after updates", "good")}
        ${statCard("Unverifiable", num(summary.unverifiable), "value unreadable in a snapshot")}
      </div>

      <form class="toolbar" data-form="baseline-filter">
        <label class="field">Severity
          <select name="severity">
            <option value="">All</option>
            ${["High", "Medium", "Low"].map((level) => `<option value="${level}" ${filters.severity === level ? "selected" : ""}>${level}</option>`).join("")}
          </select>
        </label>
        <label class="field">Change type
          <select name="type">
            <option value="">All</option>
            ${["Created since baseline", "Deleted since baseline", "Configuration changed", "Versioned replacement"]
              .map((type) => `<option value="${type}" ${filters.type === type ? "selected" : ""}>${type}</option>`)
              .join("")}
          </select>
        </label>
        <button type="submit" class="primary">Filter</button>
        <button type="button" data-action="reset-baseline-filter" class="ghost">Reset</button>
      </form>

      <div class="table-wrap">
        <table>
          <thead><tr><th class="nosort">Severity</th><th class="nosort">Change</th><th class="nosort">Service</th>
          <th class="nosort">Field</th><th class="nosort">Old</th><th class="nosort">New</th><th class="nosort">Why it matters</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="7">${emptyPanel("No changes match these filters. That is a clean result.")}</td></tr>`}</tbody>
        </table>
      </div>

      ${unverifiable ? panel("Unverifiable values", `<p class="hint">These were empty or unreadable in one snapshot, so they are reported instead of being scored as tampering.</p><ul class="reasons">${unverifiable}</ul>`) : ""}
      ${panel("Replace the baseline", createCard)}
      ${panel("Baseline history", `<div class="table-wrap"><table>
        <thead><tr><th class="nosort">File</th><th class="nosort">Captured</th><th class="nosort">Services</th><th class="nosort">Bytes</th></tr></thead>
        <tbody>${history || `<tr><td colspan="4">${emptyPanel("No history yet")}</td></tr>`}</tbody></table></div>`)}`;
  }

  /* ------------------------------------------------------------------ */
  /* triage                                                              */
  /* ------------------------------------------------------------------ */
  async function viewTriage(force) {
    if (!state.triage || force) state.triage = await api("/api/triage");
    const data = state.triage;
    const counts = data.counts || {};
    const decisions = data.decisions || ["Investigate", "Monitor", "Allow", "Contain", "FalsePositive", "Resolved"];

    const rows = data.records
      .slice(0, 200)
      .map(
        (row) => `<tr>
          <td class="mono smalltext">${esc(row.id)}</td>
          <td class="mono smalltext">${esc(when(row.timestamp))}</td>
          <td><strong>${esc(row.service_name)}</strong></td>
          <td>${decisionPill(row.decision)}</td>
          <td>${esc(row.analyst || "—")}</td>
          <td class="num">${row.threat_score === null || row.threat_score === undefined ? "—" : num(row.threat_score)}</td>
          <td>${esc(row.threat_level || "—")}</td>
          <td class="truncate mono smalltext" title="${esc(row.executable_path || "")}">${esc(row.executable_path || "—")}</td>
          <td class="truncate mono smalltext" title="${esc(row.sha256 || "")}">${esc(row.sha256 ? row.sha256.slice(0, 16) + "…" : "no hash")}</td>
          <td class="truncate" title="${esc(row.notes || "")}">${esc(row.notes || "—")}</td>
        </tr>`
      )
      .join("");

    return `
      <div class="view-head">
        <div><h2>Triage</h2>
          <div class="sub">${num(data.records.length)} decision(s) recorded · evidence snapshot attached to every entry</div>
        </div>
        <div class="view-actions">
          <button data-action="export" data-report="triage" data-format="Html">Export HTML</button>
          <button data-action="export" data-report="triage" data-format="Csv" class="ghost">CSV</button>
        </div>
      </div>

      <div class="cards">
        ${["Investigate", "Monitor", "Allow", "Contain", "FalsePositive", "Resolved"]
          .map((decision) => statCard(decision, num(counts[decision] || 0), "", decision === "Contain" ? "bad" : ""))
          .join("")}
      </div>

      ${panel(
        "Record a decision",
        `<form data-form="triage-save">
          <div class="toolbar">
            <label class="field grow">Service
              <input type="text" name="service" list="service-names" placeholder="exact internal service name" autocomplete="off">
            </label>
            <label class="field">Decision
              <select name="decision">${decisions.map((decision) => `<option value="${esc(decision)}">${esc(decision)}</option>`).join("")}</select>
            </label>
            <label class="field">Analyst
              <input type="text" name="analyst" placeholder="your name">
            </label>
          </div>
          <label class="field">Notes
            <textarea name="notes" placeholder="What did you verify? Owner, business purpose, signer, hash, recent activity."></textarea>
          </label>
          <button type="submit" class="primary">Save decision</button>
          <p class="hint" style="margin-top:8px">Choosing Contain records intent only. It does not change the service.</p>
        </form>`
      )}

      <div class="table-wrap">
        <table>
          <thead><tr><th class="nosort">ID</th><th class="nosort">When</th><th class="nosort">Service</th>
          <th class="nosort">Decision</th><th class="nosort">Analyst</th><th class="nosort">Threat</th>
          <th class="nosort">Level</th><th class="nosort">Path</th><th class="nosort">SHA-256</th><th class="nosort">Notes</th></tr></thead>
          <tbody>${rows || `<tr><td colspan="10">${emptyPanel("No decisions recorded yet.")}</td></tr>`}</tbody>
        </table>
      </div>
      ${serviceDatalist()}`;
  }

  /* ------------------------------------------------------------------ */
  /* reports                                                             */
  /* ------------------------------------------------------------------ */
  async function viewReports() {
    const reports = [
      ["inventory", "Service inventory", "Every installed service with the evidence that was collected."],
      ["assessment", "Threat and reliability assessment", "Full scored inventory including services that scored zero."],
      ["timeline", "Service event timeline", "Service Control Manager events for the window you choose."],
      ["baseline", "Baseline changes", "Created, deleted and modified services against the trusted snapshot."],
      ["triage", "Triage decisions", "Analyst decisions with their evidence snapshots."],
    ];

    const cards = reports
      .map(
        ([id, title, description]) => `<form class="panel" data-form="report" data-report="${id}">
          <h3>${esc(title)}</h3>
          <p class="hint">${esc(description)}</p>
          <div class="toolbar">
            <label class="field">Format
              <select name="format">
                <option value="Csv">CSV</option><option value="Json">JSON</option><option value="Html">HTML</option>
              </select>
            </label>
            ${id === "assessment" || id === "timeline" ? `<label class="field">Lookback (hours)
              <input type="number" name="hours" min="1" max="2160" value="${state.timelineHours}"></label>` : ""}
            ${id === "timeline" ? `<label class="field grow">Service (optional)
              <input type="text" name="service" list="service-names" placeholder="all services"></label>` : ""}
            <button type="submit" class="primary">Generate</button>
          </div>
          <div class="report-result smalltext muted" data-result></div>
        </form>`
      )
      .join("");

    return `<div class="view-head"><div><h2>Reports</h2>
      <div class="sub">Exports are written to the evidence folder and downloaded from this page</div></div></div>
      ${cards}${serviceDatalist()}`;
  }

  /* ------------------------------------------------------------------ */
  /* management                                                          */
  /* ------------------------------------------------------------------ */
  async function viewManage(force) {
    if (!state.manage || force) state.manage = await api("/api/manage");
    const manage = state.manage;
    const status = state.status;
    const actions = manage.actions || [];
    const preflight = state.preflight;
    const result = state.manageResult;

    const preflightHTML = preflight
      ? `<div class="banner ${preflight.protected ? "bad" : "info"}">
          <strong>${esc(preflight.name)}</strong> · ${esc(preflight.display)}<br>
          Status: ${esc(preflight.status)} · Startup: ${esc(preflight.start_type)} ·
          Dependents: ${preflight.dependents && preflight.dependents.length ? esc(preflight.dependents.join(", ")) : "none"}
          ${preflight.protected ? "<br>This is a core Windows service. Disruptive actions are refused." : ""}
        </div>`
      : "";

    const resultHTML = result
      ? `<div class="banner ${result.ok ? "info" : "bad"}">
          <strong>${esc(result.action)} on ${esc(result.service)}: ${result.ok ? "completed" : "FAILED"}</strong>
          <ul class="reasons" style="margin-top:8px">
            ${(result.steps || [])
              .map((step) => `<li>${step.ok ? "✔" : "✖"} <strong>${esc(step.step)}</strong> — ${esc(step.message)}</li>`)
              .join("")}
          </ul>
          ${result.backup ? `<div class="smalltext" style="margin-top:8px">Configuration backup: <span class="mono">${esc(result.backup.file)}</span></div>` : ""}
        </div>`
      : "";

    const backups = (manage.backups || [])
      .map(
        (row) => `<tr><td class="mono smalltext">${esc(row.service)}</td><td>${when(row.captured_at)}</td>
          <td>${esc(row.start_mode || "—")}</td><td class="truncate mono smalltext">${esc(row.exe_path || "—")}</td>
          <td><button class="small" data-action="restore" data-file="${esc(row.file)}">Restore</button></td></tr>`
      )
      .join("");

    return `
      <div class="view-head">
        <div><h2>Management</h2><div class="sub">Guarded service actions with per-step results</div></div>
      </div>

      <div class="banner ${status.admin ? "warn" : "bad"}">
        <strong>${status.admin ? "Elevated session" : "Not elevated"}.</strong>
        ${status.admin
          ? "Service changes will take effect immediately. Every action needs the exact service name typed as confirmation."
          : "Windows will refuse most service changes. Restart the console from an elevated prompt to manage services."}
      </div>

      ${preflightHTML}
      ${resultHTML}

      ${panel(
        "Perform an action",
        `<form data-form="manage">
          <div class="toolbar">
            <label class="field grow">Service
              <input type="text" name="service" list="service-names" value="${esc(preflight ? preflight.name : "")}" placeholder="exact internal service name" autocomplete="off">
            </label>
            <label class="field">Action
              <select name="action">${actions
                .map((item) => `<option value="${esc(item.action)}">${esc(item.label)}</option>`)
                .join("")}</select>
            </label>
            <label class="field">Startup type (for change startup)
              <select name="startup">${(manage.startup_types || ["Automatic", "Manual", "Disabled"])
                .map((type) => `<option value="${esc(type)}">${esc(type)}</option>`)
                .join("")}</select>
            </label>
            <button type="button" data-action="preflight" class="ghost">Check service</button>
          </div>
          <div class="checkline">
            <label><input type="checkbox" name="force"> Force (stop dependent services)</label>
          </div>
          <label class="field">Type the exact service name to confirm (case-sensitive)
            <input type="text" name="confirm" placeholder="copy the name exactly" autocomplete="off">
          </label>
          <label class="field">Analyst (recorded in the log)
            <input type="text" name="analyst" placeholder="your name">
          </label>
          <button type="submit" class="danger">Execute action</button>
          <p class="hint" style="margin-top:8px">Contain and Delete save the configuration first.
          Core services (${(manage.protected || []).slice(0, 6).map(esc).join(", ")}…) are refused.</p>
        </form>`
      )}

      ${panel("Containment backups", backups
        ? `<div class="table-wrap"><table>
            <thead><tr><th class="nosort">Service</th><th class="nosort">Captured</th><th class="nosort">Original startup</th>
            <th class="nosort">Executable</th><th class="nosort"></th></tr></thead>
            <tbody>${backups}</tbody></table></div>
          <p class="hint" style="margin-top:8px">Restore sets the startup type back to the captured value. Start the service afterwards if it was running.</p>`
        : emptyPanel("No containment backups yet."))}
      ${serviceDatalist()}`;
  }

  /* ------------------------------------------------------------------ */
  /* help                                                                */
  /* ------------------------------------------------------------------ */
  async function viewHelp(force) {
    if (!state.help || force) state.help = await api("/api/help");
    const sections = state.help.sections
      .map(
        (section) => `<details class="help-section" ${section.id === "services" ? "open" : ""}>
          <summary><strong>${esc(section.title)}</strong></summary>
          <div class="body">${section.body.map((paragraph) => `<p>${esc(paragraph)}</p>`).join("")}</div>
        </details>`
      )
      .join("");

    return `<div class="view-head"><div><h2>Help</h2>
      <div class="sub">How the console collects evidence, scores findings and protects the host</div></div></div>
      <div class="panel">${sections}</div>
      <div class="panel">
        <h3>Keyboard and navigation</h3>
        <p>Use the tabs to move between pages, click any table row for details, and press <span class="keys">Esc</span>
        to close the evidence drawer. Export buttons write into
        <span class="mono">${esc(state.status.data_root)}</span>.</p>
      </div>`;
  }

  /* ------------------------------------------------------------------ */
  /* service drawer                                                      */
  /* ------------------------------------------------------------------ */
  async function openService(name) {
    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
    scrim.hidden = false;
    drawer.innerHTML = `<div class="loading"><span class="spinner"></span> Collecting evidence for ${esc(name)}…</div>`;
    try {
      const detail = await api(`/api/service/${encodeURIComponent(name)}`);
      state.drawer = detail;
      drawer.innerHTML = drawerHTML(detail);
    } catch (error) {
      drawer.innerHTML = `<button class="close small" data-action="close-drawer">Close</button>
        <div class="banner bad">${esc(error.message)}</div>`;
    }
  }

  function drawerHTML(detail) {
    const service = detail.service;
    const assessment = detail.assessment;
    const triage = detail.triage;
    const events = (detail.events || [])
      .map(
        (event) => `<tr><td class="mono smalltext">${esc(when(event.time))}</td><td class="mono">${esc(event.event_id)}</td>
          <td>${esc(event.activity)}</td><td class="truncate" title="${esc(event.detail)}">${esc(event.detail)}</td></tr>`
      )
      .join("");

    const reasons = assessment.threat_reasons
      .map((reason) => `<li>${esc(reason.text)}</li>`)
      .join("") || `<li class="muted">No threat indicator contributed points.</li>`;
    const reliability = assessment.reliability_reasons.map((reason) => `<li>${esc(reason.text)}</li>`).join("");
    const notes = (assessment.notes || []).length
      ? `<div class="notes"><strong>Data gaps (not scored)</strong><ul>${assessment.notes.map((note) => `<li>${esc(note)}</li>`).join("")}</ul></div>`
      : "";

    return `
      <button class="close small" data-action="close-drawer">Close</button>
      <h3>${esc(service.name)}</h3>
      <p class="hint" style="margin-top:4px">${esc(service.display_name)} · ${esc(service.category)}</p>

      <div class="cards" style="grid-template-columns:repeat(2,1fr)">
        <div class="card"><div class="label">Threat</div>
          <div class="value">${num(assessment.threat_score)}
            <span class="badge ${esc(assessment.threat_level.toLowerCase())}">${esc(assessment.threat_level)}</span></div></div>
        <div class="card"><div class="label">Reliability</div>
          <div class="value">${num(assessment.reliability_score)}
            <span class="badge ${esc(assessment.reliability_level.toLowerCase())}">${esc(assessment.reliability_level)}</span></div></div>
      </div>

      <div class="section-title">Identity</div>
      <div class="kv">
        <div><span class="k">State</span><span class="v">${esc(service.state)}</span></div>
        <div><span class="k">Startup</span><span class="v">${esc(service.start_mode)}</span></div>
        <div><span class="k">Account</span><span class="v">${esc(service.account)}${service.account_known ? "" : " (unreadable)"}</span></div>
        <div><span class="k">Service type</span><span class="v">${esc(service.service_type)}</span></div>
        <div><span class="k">Process ID</span><span class="v">${num(service.process_id)}</span></div>
        <div><span class="k">Category</span><span class="v">${esc(service.category)}</span></div>
        <div><span class="k">Runtime</span><span class="v">${esc(service.runtime)} <span class="muted">(${esc(service.runtime_source || "n/a")})</span></span></div>
        <div><span class="k">Runs in window</span><span class="v">${num(service.run_count)}</span></div>
      </div>

      <div class="section-title">Binary evidence</div>
      <div class="kv">
        <div><span class="k">Command line</span><span class="v mono">${esc(service.command_line || "unreadable")}</span></div>
        <div><span class="k">Path</span><span class="v mono">${esc(service.exe_path || "unreadable")}</span></div>
        <div><span class="k">Exists</span><span class="v">${service.path_known ? (service.file_exists ? "yes" : "no") : "unknown"}</span></div>
        <div><span class="k">Signature</span><span class="v">${esc(service.signature)}</span></div>
        <div><span class="k">Signer</span><span class="v">${esc(service.signer || "—")}</span></div>
        <div><span class="k">Company</span><span class="v">${esc(service.company || "—")}</span></div>
        <div><span class="k">Version</span><span class="v">${esc(service.version || "—")}</span></div>
        <div><span class="k">SHA-256</span><span class="v mono">${esc(service.sha256 || "not collected")}</span></div>
        <div><span class="k">User-writable</span><span class="v">${service.user_writable ? "yes" : "no"}</span></div>
        <div><span class="k">Unquoted path</span><span class="v">${service.unquoted_path ? "yes" : "no"}</span></div>
        <div><span class="k">Outside protected roots</span><span class="v">${service.path_known ? (service.outside_protected ? "yes" : "no") : "unknown"}</span></div>
      </div>

      <div class="section-title">Threat reasons</div>
      <ul class="reasons">${reasons}</ul>
      ${reliability ? `<div class="section-title">Reliability reasons</div><ul class="reasons">${reliability}</ul>` : ""}
      ${notes}
      <p><strong>Next step.</strong> ${esc(assessment.recommendation)}</p>

      ${triage
        ? `<div class="notes"><strong>Latest triage:</strong> ${esc(triage.decision)} by ${esc(triage.analyst || "unknown")} · ${esc(when(triage.timestamp))}
            ${triage.notes ? `<br>${esc(triage.notes)}` : ""}</div>`
        : ""}

      ${panel(
        "Recent service events",
        `<div class="table-wrap"><table>
          <thead><tr><th class="nosort">Time</th><th class="nosort">Event</th><th class="nosort">Activity</th><th class="nosort">Detail</th></tr></thead>
          <tbody>${events || `<tr><td colspan="4">${emptyPanel("No events for this service in the window.")}</td></tr>`}</tbody></table></div>`
      )}

      <div class="section-title">Record a triage decision</div>
      <form data-form="drawer-triage" data-name="${esc(service.name)}">
        <div class="toolbar">
          <label class="field">Decision
            <select name="decision">${["Investigate", "Monitor", "Allow", "Contain", "FalsePositive", "Resolved"]
              .map((value) => `<option value="${esc(value)}">${esc(value)}</option>`)
              .join("")}</select>
          </label>
          <label class="field grow">Analyst
            <input type="text" name="analyst" placeholder="your name">
          </label>
        </div>
        <label class="field">Notes
          <textarea name="notes" placeholder="Evidence reviewed, business purpose, verification steps"></textarea>
        </label>
        <button type="submit" class="primary">Save decision</button>
      </form>`;
  }

  function closeDrawer() {
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
    scrim.hidden = true;
  }

  /* ------------------------------------------------------------------ */
  /* actions                                                             */
  /* ------------------------------------------------------------------ */
  async function exportReport(report, format) {
    try {
      const result = await api("/api/export", {
        method: "POST",
        body: { report, format, hours: state.huntHours },
      });
      toast(`${result.rows} rows exported as ${result.format}`);
      const link = document.createElement("a");
      link.href = result.url;
      link.textContent = `Download ${result.file}`;
      link.className = "badge good";
      link.style.marginLeft = "8px";
      link.style.textDecoration = "none";
      toasts.lastElementChild.appendChild(link);
      link.click();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  document.addEventListener("click", async (event) => {
    const trigger = event.target.closest("[data-action]");
    if (!trigger) return;
    const action = trigger.dataset.action;

    try {
      switch (action) {
        case "nav": {
          const route = trigger.dataset.route;
          if (state.route === route) return;
          state.route = route;
          location.hash = `#${route}`;
          await render(false);
          break;
        }
        case "retry":
          await render(true);
          break;
        case "refresh-all":
          state.inventory = null;
          state.hunt = null;
          state.baseline = null;
          state.triage = null;
          state.manage = null;
          await loadStatus(true);
          await render(true);
          toast("Data refreshed");
          break;
        case "refresh-inventory":
          state.inventory = null;
          await render(true);
          break;
        case "toggle-evidence":
          state.inventoryEvidence = !state.inventoryEvidence;
          state.inventory = null;
          await render(true);
          break;
        case "sort-inventory": {
          const key = trigger.dataset.sort;
          if (state.filters.sort === key) state.filters.dir *= -1;
          else {
            state.filters.sort = key;
            state.filters.dir = 1;
          }
          await render(false);
          break;
        }
        case "page":
          state.filters.page = Math.max(0, state.filters.page + Number(trigger.dataset.dir));
          await render(false);
          break;
        case "reset-filters":
          state.filters = { q: "", st: "", start: "", cat: "", unsigned: false, missing: false, writable: false, unquoted: false, unknown: false, page: 0, sort: "category", dir: 1 };
          await render(false);
          break;
        case "open-service":
          await openService(trigger.dataset.name);
          break;
        case "close-drawer":
          closeDrawer();
          break;
        case "toggle-finding": {
          const name = trigger.dataset.name;
          if (state.huntOpen.has(name)) state.huntOpen.delete(name);
          else state.huntOpen.add(name);
          await render(false);
          break;
        }
        case "export":
          await exportReport(trigger.dataset.report, trigger.dataset.format);
          break;
        case "baseline-compare":
          state.baseline = null;
          await render(true);
          break;
        case "reset-baseline-filter":
          state.baselineFilter = { severity: "", type: "" };
          await render(false);
          break;
        case "preflight": {
          const form = document.querySelector('form[data-form="manage"]');
          const name = form.elements.service.value.trim();
          if (!name) return toast("Enter a service name first.", "warn");
          state.preflight = await api(`/api/manage/preflight?service=${encodeURIComponent(name)}`);
          await render(false);
          break;
        }
        case "restore": {
          const file = trigger.dataset.file;
          if (!window.confirm("Restore the startup configuration from this backup?")) return;
          const result = await api("/api/manage/restore", { method: "POST", body: { file } });
          toast(result.ok ? `Restored ${result.service} to ${result.startup}` : `Restore failed for ${result.service}`, result.ok ? "info" : "error");
          state.manage = null;
          state.inventory = null;
          await render(true);
          break;
        }
        case "triage-quick": {
          const name = trigger.dataset.name;
          await openService(name);
          break;
        }
        case "prune": {
          const result = await api("/api/maintenance/prune", { method: "POST", body: {} });
          toast(
            `Pruned ${result.removed_files} file(s) and ${result.cache_entries_removed} cache entr(ies), ` +
              `${result.freed_mb} MB freed`
          );
          state.maintenance = null;
          state.baseline = null;
          await render(false);
          break;
        }
        default:
          break;
      }
    } catch (error) {
      toast(error.message, "error");
    }
  });

  document.addEventListener("submit", async (event) => {
    const form = event.target.closest("form[data-form]");
    if (!form) return;
    event.preventDefault();
    const kind = form.dataset.form;

    try {
      if (kind === "inventory-filter") {
        state.filters.q = form.elements.q.value;
        state.filters.st = form.elements.st.value;
        state.filters.start = form.elements.start.value;
        state.filters.cat = form.elements.cat.value;
        state.filters.page = 0;
        await render(false);
        return;
      }
      if (kind === "hunt-run") {
        state.huntHours = Number(form.elements.hours.value) || 168;
        state.huntLevel = form.elements.level.value;
        state.hunt = null;
        await render(true);
        return;
      }
      if (kind === "timeline-run") {
        state.timelineHours = Math.min(2160, Math.max(1, Number(form.elements.hours.value) || 168));
        state.timelineName = form.elements.name.value.trim();
        state.timelineBucket = form.elements.bucket.value;
        await render(true);
        return;
      }
      if (kind === "baseline-create") {
        const confirm = form.elements.confirm.value;
        if (confirm.trim().toUpperCase() !== "BASELINE") return toast("Type BASELINE to confirm.", "warn");
        const result = await api("/api/baseline", { method: "POST", body: { confirm } });
        toast(`Baseline saved with ${result.services} services`);
        state.baselineConfirm = "";
        state.baseline = null;
        await render(true);
        return;
      }
      if (kind === "baseline-filter") {
        state.baselineFilter = { severity: form.elements.severity.value, type: form.elements.type.value };
        await render(false);
        return;
      }
      if (kind === "triage-save" || kind === "drawer-triage") {
        const service = kind === "drawer-triage" ? form.dataset.name : form.elements.service.value.trim();
        if (!service) return toast("Enter a service name.", "warn");
        const entry = await api("/api/triage", {
          method: "POST",
          body: {
            service,
            decision: form.elements.decision.value,
            analyst: form.elements.analyst.value,
            notes: form.elements.notes.value,
          },
        });
        toast(`${entry.record.decision} recorded for ${entry.record.service_name}`);
        if (kind === "drawer-triage") closeDrawer();
        state.inventory = null;
        state.triage = null;
        await render(false);
        return;
      }
      if (kind === "report") {
        const result = await api("/api/export", {
          method: "POST",
          body: {
            report: form.dataset.report,
            format: form.elements.format.value,
            hours: form.elements.hours ? Number(form.elements.hours.value) : state.huntHours,
            service: form.elements.service ? form.elements.service.value : "",
          },
        });
        const box = form.querySelector("[data-result]");
        box.innerHTML = `${result.rows} rows · <a href="${esc(result.url)}">download ${esc(result.file)}</a>`;
        toast(`Report generated: ${result.file}`);
        window.location.href = result.url;
        return;
      }
      if (kind === "manage") {
        const payload = {
          service: form.elements.service.value.trim(),
          action: form.elements.action.value,
          startup: form.elements.startup.value,
          force: form.elements.force.checked,
          confirm: form.elements.confirm.value,
          analyst: form.elements.analyst.value,
        };
        if (!payload.service) return toast("Enter a service name.", "warn");
        if (payload.action === "delete" && !window.confirm(`Permanently delete ${payload.service}?`)) return;
        const result = await api("/api/manage", { method: "POST", body: payload });
        state.manageResult = result;
        state.manage = null;
        state.inventory = null;
        await render(true);
        toast(result.ok ? `${payload.action} completed` : `${payload.action} failed`, result.ok ? "info" : "error");
        return;
      }
    } catch (error) {
      toast(error.message, "error");
    }
  });

  document.addEventListener("change", async (event) => {
    const flag = event.target.dataset ? event.target.dataset.flag : null;
    if (flag) {
      state.filters[flag] = event.target.checked;
      state.filters.page = 0;
      await render(false);
    }
  });

  scrim.addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });
  window.addEventListener("hashchange", () => {
    const route = (location.hash || "#overview").slice(1);
    if (ROUTES.some(([id]) => id === route) && route !== state.route) {
      state.route = route;
      render(false);
    }
  });

  render(true);
})();
