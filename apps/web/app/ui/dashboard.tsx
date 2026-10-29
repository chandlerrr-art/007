"use client";

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";

type DashboardData = {
  summary: { active_scans: number; verified_findings: number; endpoints: number; targets: number };
  severity: Record<string, number>;
  targets: { id: number; name: string; base_url: string; environment: string; status: string }[];
  findings: { id: number; title: string; category: string; severity: string; confidence: string; verified: boolean; status: string; path: string; target: string }[];
  scans: { id: number; target: string; status: string; trigger: string; started_at: string; summary: string }[];
  changes: { id: number; target: string; source: string; detail: string; created_at: string }[];
  safety: { kill_switch_engaged: boolean; reason: string };
};

type Health = { status: string; database: string };

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const DEMO_ORIGIN = "http://demo-app:8080";
const empty: DashboardData = {
  summary: { active_scans: 0, verified_findings: 0, endpoints: 0, targets: 0 },
  severity: {}, targets: [], findings: [], scans: [], changes: [],
  safety: { kill_switch_engaged: false, reason: "" },
};

function supportsDemoScan(target: DashboardData["targets"][number]) {
  try {
    const url = new URL(target.base_url);
    return target.status === "authorized" && target.environment === "local-demo" &&
      url.origin === DEMO_ORIGIN && url.pathname === "/" && !url.search && !url.hash;
  } catch {
    return false;
  }
}

function messageFrom(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

async function responseError(response: Response) {
  try {
    const payload = await response.json();
    return typeof payload.detail === "string" ? payload.detail : `Request failed (${response.status}).`;
  } catch {
    return `Request failed (${response.status}).`;
  }
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Time unavailable" : date.toLocaleString();
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardData>(empty);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [actionError, setActionError] = useState("");
  const [notice, setNotice] = useState("");
  const [health, setHealth] = useState<Health | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [targetFormOpen, setTargetFormOpen] = useState(false);
  const [targetName, setTargetName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [targetEnvironment, setTargetEnvironment] = useState("staging");
  const [selectedTargetId, setSelectedTargetId] = useState<number | null>(null);

  const scanTargets = useMemo(() => data.targets.filter(supportsDemoScan), [data.targets]);
  const selectedTarget = scanTargets.find((target) => target.id === selectedTargetId) ?? scanTargets[0];

  const refreshDashboard = useCallback(async (manual = false, signal?: AbortSignal) => {
    if (manual) setRefreshing(true);
    try {
      const [dashboardResponse, healthResponse] = await Promise.all([
        fetch(`${API}/api/dashboard`, { cache: "no-store", signal }),
        fetch(`${API}/api/health`, { cache: "no-store", signal }),
      ]);
      if (!dashboardResponse.ok) throw new Error(await responseError(dashboardResponse));
      const body = await dashboardResponse.json() as DashboardData;
      setData(body);
      setLoaded(true);
      setLoadError("");
      setLastUpdated(new Date());
      if (healthResponse.ok) setHealth(await healthResponse.json() as Health);
      else setHealth(null);
    } catch (error) {
      if (signal?.aborted) return;
      setLoadError(messageFrom(error, "The dashboard could not connect to the API."));
      setHealth(null);
    } finally {
      if (manual) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    const load = async () => {
      if (pending || controller.signal.aborted) return;
      pending = true;
      try { await refreshDashboard(false, controller.signal); }
      finally { pending = false; }
    };
    void load();
    const timer = window.setInterval(() => { void load(); }, 5000);
    return () => { window.clearInterval(timer); controller.abort(); };
  }, [refreshDashboard]);

  useEffect(() => {
    if (selectedTargetId === null && scanTargets.length) setSelectedTargetId(scanTargets[0].id);
    if (selectedTargetId !== null && !scanTargets.some((target) => target.id === selectedTargetId)) {
      setSelectedTargetId(scanTargets[0]?.id ?? null);
    }
  }, [scanTargets, selectedTargetId]);

  async function startScan() {
    if (!selectedTarget || busy || data.safety.kill_switch_engaged) return;
    setBusy(true);
    setActionError("");
    setNotice("");
    try {
      const response = await fetch(`${API}/api/scans`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_id: selectedTarget.id }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      const scan = await response.json() as { id: number };
      setNotice(`Scan #${scan.id} queued for ${selectedTarget.name}.`);
      await refreshDashboard();
    } catch (error) {
      setActionError(messageFrom(error, "Could not start the scan."));
    } finally {
      setBusy(false);
    }
  }

  async function cancelScan(scanId: number) {
    setActionError("");
    try {
      const response = await fetch(`${API}/api/scans/${scanId}/cancel`, { method: "POST" });
      if (!response.ok) throw new Error(await responseError(response));
      setNotice(`Cancellation requested for scan #${scanId}.`);
      await refreshDashboard();
    } catch (error) {
      setActionError(messageFrom(error, "Could not cancel the scan."));
    }
  }

  async function toggleKillSwitch() {
    const engaging = !data.safety.kill_switch_engaged;
    if (engaging && !window.confirm("Stop all active scan work and block new scans?")) return;
    setActionError("");
    setNotice("");
    try {
      const response = await fetch(`${API}/api/safety/kill-switch`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ engaged: engaging, reason: engaging ? "Manually halted from the dashboard." : "" }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      setNotice(engaging ? "Safety stop engaged. No new scan requests will run." : "Safety stop cleared.");
      await refreshDashboard();
    } catch (error) {
      setActionError(messageFrom(error, "Could not update the safety stop."));
    }
  }

  async function createTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setActionError("");
    setNotice("");
    try {
      const response = await fetch(`${API}/api/targets`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: targetName, base_url: targetUrl, environment: targetEnvironment, scope_note: "Registered from 007 dashboard." }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      const result = await response.json() as { name: string };
      await refreshDashboard();
      setTargetName(""); setTargetUrl(""); setTargetEnvironment("staging"); setTargetFormOpen(false);
      setNotice(`Target “${result.name}” added to authorized scope.`);
    } catch (error) {
      setActionError(messageFrom(error, "Could not add the target."));
    }
  }

  async function importHar(targetId: number, file?: File) {
    if (!file) return;
    setActionError(""); setNotice("");
    if (file.size > 5_000_000) {
      setActionError("HAR files must be smaller than 5 MB.");
      return;
    }
    try {
      const response = await fetch(`${API}/api/targets/${targetId}/har-import`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: await file.text() }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      const result = await response.json() as { inserted: number };
      await refreshDashboard();
      setNotice(`HAR imported: ${result.inserted} new endpoints added. Sensitive request data is discarded.`);
    } catch (error) {
      setActionError(messageFrom(error, "Could not import the HAR file."));
    }
  }

  async function retestFinding(findingId: number) {
    setActionError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/findings/${findingId}/retest`, { method: "POST" });
      if (!response.ok) throw new Error(await responseError(response));
      setNotice(`Retest queued for SF-${String(findingId).padStart(4, "0")}.`);
      await refreshDashboard();
    } catch (error) {
      setActionError(messageFrom(error, "Could not start the retest."));
    }
  }

  const apiConnected = health?.status === "healthy";
  const databaseConnected = health?.database === "connected";
  const updatedLabel = lastUpdated
    ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}`
    : "Connecting to workspace…";

  return <main className="shell">
    <aside className="sidebar">
      <a className="brand" href="#overview" aria-label="007 dashboard home"><span className="brand-mark">0</span><span>007</span></a>
      <div className="nav-label">WORKSPACE</div>
      <a className="nav-item active" href="#overview" title="Overview"><span aria-hidden="true">◫</span> Overview</a>
      <a className="nav-item" href="#scans" title="Scans"><span aria-hidden="true">◉</span> Scans <span className="nav-count">{data.summary.active_scans}</span></a>
      <a className="nav-item" href="#findings" title="Findings"><span aria-hidden="true">⚑</span> Findings</a>
      <a className="nav-item" href="#targets" title="Targets"><span aria-hidden="true">◎</span> Targets</a>
      <a className="nav-item" href="#changes" title="Changes"><span aria-hidden="true">↻</span> Changes</a>
      <div className="sidebar-bottom">
        <div className={`safety-chip ${data.safety.kill_switch_engaged ? "halted" : ""}`}>
          <span className="pulse"/> SAFETY ENGINE <b>{data.safety.kill_switch_engaged ? "HALTED" : "READY"}</b>
        </div>
        <div className="user-row"><div className="avatar">SF</div><div><strong>Security team</strong><small>Local workspace</small></div><span className="dots">•••</span></div>
      </div>
    </aside>

    <section className="content" id="overview">
      <header className="topbar">
        <div className="breadcrumbs">Workspace <span>/</span> <b>Overview</b></div>
        <div className="top-actions">
          <span className="env-pill"><i/> LOCAL WORKSPACE</span>
          <span className={`api-pill ${apiConnected ? "connected" : loaded ? "disconnected" : "checking"}`}><i/>{apiConnected ? "API ONLINE" : loaded ? "API OFFLINE" : "CONNECTING"}</span>
          <span className={`api-pill db-pill ${databaseConnected ? "connected" : loaded && health ? "disconnected" : "checking"}`}><i/>{databaseConnected ? "DB ONLINE" : health ? "DB OFFLINE" : "DB CHECKING"}</span>
          <button className={`kill-button ${data.safety.kill_switch_engaged ? "engaged" : ""}`} onClick={toggleKillSwitch} aria-pressed={data.safety.kill_switch_engaged}>
            <span aria-hidden="true">{data.safety.kill_switch_engaged ? "■" : "Ⅱ"}</span>{data.safety.kill_switch_engaged ? "Resume scans" : "Stop scans"}
          </button>
          <div className="avatar small" aria-label="Security team">SF</div>
        </div>
      </header>

      <div className="page-wrap">
        <div className="welcome">
          <div><div className="eyebrow">LOCAL SECURITY OPERATIONS <span className={`live-dot ${apiConnected ? "" : "offline"}`}/> SYSTEM STATUS</div>
            <h1>Security overview</h1>
            <p>Monitor authorized scan activity and application risk in your local workspace.</p>
          </div>
          <div className="scan-controls">
            {scanTargets.length > 1 && <label className="scan-target-select"><span>Scan target</span><select aria-label="Select a local demo scan target" value={selectedTarget?.id ?? ""} onChange={(event) => setSelectedTargetId(Number(event.target.value))}>{scanTargets.map((target) => <option value={target.id} key={target.id}>{target.name}</option>)}</select></label>}
            <button className="primary-button" onClick={startScan} disabled={busy || !selectedTarget || data.safety.kill_switch_engaged} title={data.safety.kill_switch_engaged ? "Clear the safety stop to start a scan" : selectedTarget ? `Run the bounded local demo check against ${selectedTarget.name}` : "Add or authorize the local synthetic demo target to enable scans"}>
              <span aria-hidden="true">＋</span>{busy ? "Starting…" : "New scan"}
            </button>
          </div>
        </div>

        {loadError && <div className="alert" role="alert"><span className="alert-icon">!</span><div><b>Workspace connection issue</b><p>{loadError} Check that the API and database services are running.</p></div><button className="inline-button" onClick={() => void refreshDashboard(true)}>Retry</button></div>}
        {actionError && <div className="alert" role="alert"><span className="alert-icon">!</span><div><b>Action could not be completed</b><p>{actionError}</p></div><button className="dismiss-button" aria-label="Dismiss error" onClick={() => setActionError("")}>×</button></div>}
        {notice && <div className="notice" role="status"><span aria-hidden="true">✓</span><p>{notice}</p><button className="dismiss-button" aria-label="Dismiss notice" onClick={() => setNotice("")}>×</button></div>}
        {data.safety.kill_switch_engaged && <div className="halt-banner" role="status"><span aria-hidden="true">Ⅱ</span><div><b>Safety stop is engaged</b><p>{data.safety.reason || "New scans are blocked until you resume scan activity."}</p></div></div>}

        <div className="section-heading"><div><h2>At a glance</h2><p>Live summary from your 007 workspace</p></div><div className="heading-actions"><span className="refresh-note"><i className={refreshing ? "spin" : ""} aria-hidden="true">↻</i>{updatedLabel}</span><button className="refresh-button" onClick={() => void refreshDashboard(true)} disabled={refreshing} aria-label="Refresh dashboard" title="Refresh dashboard">↻</button></div></div>

        <div className="metric-grid">
          <Metric label="ACTIVE SCANS" value={data.summary.active_scans} icon="◉" tone="blue" detail="Queued or running" />
          <Metric label="VERIFIED FINDINGS" value={data.summary.verified_findings} icon="⚑" tone="red" detail="Independently confirmed" />
          <Metric label="ENDPOINTS TRACKED" value={data.summary.endpoints} icon="⌘" tone="violet" detail="From HAR inventory" />
          <Metric label="AUTHORIZED TARGETS" value={data.summary.targets} icon="◎" tone="green" detail="Allowlist validated" />
        </div>

        {!selectedTarget && <div className="scope-callout"><span aria-hidden="true">ⓘ</span><div><b>No supported demo scan target</b><p>New scans run only against the authorized local synthetic demo. Other targets can be used for inventory and HAR import.</p></div><a href="#targets">Review targets</a></div>}

        <div className="main-grid">
          <section className="card findings-card" id="findings"><div className="card-head"><div><h2>Recent findings</h2><p>Review confidence, lifecycle, and safe retest actions</p></div><span className="period-label">LATEST</span></div>
            <div className="table-wrap"><table><thead><tr><th>FINDING</th><th>TARGET / ENDPOINT</th><th>SEVERITY</th><th>CONFIDENCE</th><th>LIFECYCLE</th><th>ACTION</th></tr></thead><tbody>
              {data.findings.map((finding) => <tr key={finding.id}><td><div className="finding-title">{finding.title}</div><div className="muted">SF-{String(finding.id).padStart(4, "0")} · {finding.category.replaceAll("_", " ")}</div></td><td><div className="target-name">{finding.target}</div><code>{finding.path}</code></td><td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td><td><span className={`confidence ${finding.confidence}`}>{finding.confidence}</span></td><td><span className={`lifecycle ${finding.status}`}><i/>{finding.status.replaceAll("_", " ")}</span><small className={`verification ${finding.verified ? "verified" : "review"}`}>{finding.verified ? "Verified" : "Needs review"}</small></td><td>{finding.verified && finding.status === "open" && <button className="text-button" onClick={() => retestFinding(finding.id)} disabled={data.safety.kill_switch_engaged}>Retest</button>}</td></tr>)}
              {!data.findings.length && <tr><td colSpan={6} className="empty">{loaded ? "No findings yet. Results appear after an authorized scan." : "Loading findings…"}</td></tr>}
            </tbody></table></div>
          </section>
          <section className="card severity-card"><div className="card-head"><div><h2>Severity breakdown</h2><p>Unresolved findings by severity</p></div><span className="period-label">OPEN</span></div><div className="severity-total"><strong>{Object.values(data.severity).reduce((total, value) => total + value, 0)}</strong><span>open findings</span></div>
            <div className="bars">{[["Critical", "critical"], ["High", "high"], ["Medium", "medium"], ["Low", "low"], ["Info", "info"]].map(([name, key]) => { const value = data.severity[key] ?? 0; const total = Math.max(1, ...Object.values(data.severity)); return <div className="bar-row" key={key}><span>{name}</span><div className="bar-track"><i className={key} style={{ width: `${Math.max(value ? 8 : 0, value / total * 100)}%` }}/></div><b>{value}</b></div>; })}</div>
          </section>
        </div>

        <div className="lower-grid">
          <section className="card" id="scans"><div className="card-head"><div><h2>Recent scan activity</h2><p>Latest runs against supported, authorized targets</p></div><span className="period-label">LATEST 6</span></div><div className="scan-list">
            {data.scans.map((scan) => <div className="scan-row" key={scan.id}><span className={`scan-icon ${scan.status}`} aria-hidden="true">{scan.status === "failed" || scan.status === "halted" ? "!" : scan.status === "completed" ? "✓" : "⌕"}</span><div className="scan-info"><b>{scan.target}</b><span>{scan.trigger.replaceAll("_", " ")} · {formatDate(scan.started_at)}</span></div><span className={`scan-state ${scan.status}`}>{scan.status.replaceAll("_", " ")}</span>{["queued", "running", "cancel_requested"].includes(scan.status) && <button className="cancel-button" onClick={() => cancelScan(scan.id)}>Stop</button>}<span className="scan-summary">{scan.summary}{scan.status === "completed" && <> · <a href={`${API}/api/scans/${scan.id}/report`} target="_blank" rel="noreferrer">View report ↗</a></>}</span></div>)}
            {!data.scans.length && <div className="empty scan-empty">{loaded ? "No scan activity yet. Start a local demo scan to see progress here." : "Loading scan activity…"}</div>}
          </div></section>

          <section className="card targets-card" id="targets"><div className="card-head"><div><h2>Authorized targets</h2><p>Registered application origins</p></div><button className="text-link button-link" onClick={() => setTargetFormOpen((open) => !open)}>{targetFormOpen ? "Close" : "＋ Add target"}</button></div>
            {targetFormOpen && <form className="target-form" onSubmit={createTarget}><label>Target name<input required minLength={2} maxLength={160} value={targetName} onChange={(event) => setTargetName(event.target.value)} placeholder="Local travel demo"/></label><label>Base URL<input required type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="http://demo-app:8080"/></label><label>Purpose<select value={targetEnvironment} onChange={(event) => setTargetEnvironment(event.target.value)}><option value="staging">Inventory only</option><option value="local-demo">Local synthetic demo scan</option></select></label><button className="primary-button form-submit" type="submit">Add to scope</button><small>Only allowlisted origins are accepted. Active checks are currently limited to the local synthetic demo.</small></form>}
            <div className="target-list">{data.targets.map((target) => <div className="target-row" key={target.id}><div className="target-icon">{target.name.slice(0, 1).toUpperCase()}</div><div className="target-info"><b>{target.name}</b><span>{target.base_url}</span></div><label className="import-button">Import HAR<input type="file" accept=".har,application/json" onChange={(event) => { void importHar(target.id, event.target.files?.[0]); event.currentTarget.value = ""; }}/></label><span className={`authorized ${target.status}`}><i/>{target.status}</span></div>)}{!data.targets.length && <div className="empty">{loaded ? "No targets configured. Add an allowlisted origin to begin." : "Loading targets…"}</div>}</div>
            <div className="scope-note"><span aria-hidden="true">ⓘ</span><div><b>Scope is checked by the backend</b><p>HAR import keeps endpoint paths only. Active scanning runs only against the synthetic demo app.</p></div></div>
          </section>
        </div>

        <section className="card changes-card" id="changes"><div className="card-head"><div><h2>Change events</h2><p>Deploy notifications and endpoint inventory changes</p></div><span className="period-label">LATEST</span></div><div className="change-list">
          {data.changes.map((change) => <div className="change-row" key={change.id}><span className="change-icon" aria-hidden="true">↻</span><div className="change-info"><b>{change.target}</b><span>{change.source.replaceAll("_", " ")} · {formatDate(change.created_at)}</span></div><p>{change.detail}</p></div>)}
          {!data.changes.length && <div className="empty">{loaded ? "No change events yet. New deploys and inventory differences will appear here." : "Loading change events…"}</div>}
        </div></section>

        <footer><span>007 <b>·</b> Local demo workspace</span><span><i className={`live-dot ${data.safety.kill_switch_engaged || !apiConnected ? "offline" : ""}`}/>{data.safety.kill_switch_engaged ? "Safety stop engaged" : apiConnected && databaseConnected ? "API and database operational" : "Checking service health"}</span></footer>
      </div>
    </section>
  </main>;
}

function Metric({ label, value, icon, tone, detail }: { label: string; value: number; icon: string; tone: string; detail: string }) {
  return <article className="metric-card"><div className={`metric-icon ${tone}`} aria-hidden="true">{icon}</div><div className="metric-label">{label}</div><div className="metric-value">{value.toLocaleString()}</div><div className="metric-detail">{detail}</div><div className={`metric-accent ${tone}`}/></article>;
}
