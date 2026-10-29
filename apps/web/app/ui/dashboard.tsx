"use client";

import { useEffect, useState, type FormEvent } from "react";

type DashboardData = {
  summary: { active_scans: number; verified_findings: number; endpoints: number; targets: number };
  severity: Record<string, number>;
  targets: { id: number; name: string; base_url: string; environment: string; status: string }[];
  findings: { id: number; title: string; category: string; severity: string; confidence: string; verified: boolean; status: string; path: string; target: string }[];
  scans: { id: number; target: string; status: string; trigger: string; started_at: string; summary: string }[];
};

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const empty: DashboardData = { summary: { active_scans: 0, verified_findings: 0, endpoints: 0, targets: 0 }, severity: {}, targets: [], findings: [], scans: [] };

export default function Dashboard() {
  const [data, setData] = useState<DashboardData>(empty);
  const [error, setError] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [targetFormOpen, setTargetFormOpen] = useState(false);
  const [targetName, setTargetName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [targetEnvironment, setTargetEnvironment] = useState("local-demo");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let live = true;
    const load = () => fetch(`${API}/api/dashboard`, { cache: "no-store" })
      .then((response) => { if (!response.ok) throw new Error(`API returned ${response.status}`); return response.json(); })
      .then((body: DashboardData) => { if (live) { setData(body); setLoaded(true); setError(""); } })
      .catch(() => { if (live) { setError("Dashboard API is unavailable. Start the services and seed the demo database."); setLoaded(true); } });
    void load();
    const timer = window.setInterval(load, 4000);
    return () => { live = false; window.clearInterval(timer); };
  }, []);

  async function startScan() {
    const target = data.targets[0];
    if (!target || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(`${API}/api/scans`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target_id: target.id }) });
      if (!response.ok) throw new Error((await response.json()).detail ?? `API returned ${response.status}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start scan.");
    } finally { setBusy(false); }
  }

  async function cancelScan(scanId: number) {
    try {
      const response = await fetch(`${API}/api/scans/${scanId}/cancel`, { method: "POST" });
      if (!response.ok) throw new Error("Could not cancel scan.");
    } catch (err) { setError(err instanceof Error ? err.message : "Could not cancel scan."); }
  }

  async function refreshDashboard() {
    const response = await fetch(`${API}/api/dashboard`, { cache: "no-store" });
    if (!response.ok) throw new Error(`API returned ${response.status}`);
    setData(await response.json() as DashboardData);
  }

  async function createTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setNotice("");
    try {
      const response = await fetch(`${API}/api/targets`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name: targetName, base_url: targetUrl, environment: targetEnvironment, scope_note: "Registered from SentinelFlow dashboard." }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? `API returned ${response.status}`);
      await refreshDashboard();
      setTargetName(""); setTargetUrl(""); setTargetFormOpen(false);
      setNotice(`Target “${result.name}” added to the authorized scope.`);
    } catch (err) { setError(err instanceof Error ? err.message : "Could not add target."); }
  }

  async function importHar(targetId: number, file?: File) {
    if (!file) return;
    setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/targets/${targetId}/har-import`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content: await file.text() }) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? `API returned ${response.status}`);
      await refreshDashboard();
      setNotice(`HAR imported: ${result.inserted} new endpoints added.`);
    } catch (err) { setError(err instanceof Error ? err.message : "Could not import HAR file."); }
  }

  async function retestFinding(findingId: number) {
    setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/findings/${findingId}/retest`, { method: "POST" });
      const result = await response.json();
      if (!response.ok) throw new Error(result.detail ?? `API returned ${response.status}`);
      setNotice(`Retest started for SF-${String(findingId).padStart(4, "0")}.`);
      await refreshDashboard();
    } catch (err) { setError(err instanceof Error ? err.message : "Could not start retest."); }
  }

  return <main className="shell">
    <aside className="sidebar">
      <a className="brand" href="#overview"><span className="brand-mark">S</span><span>Sentinel<span className="brand-light">Flow</span></span></a>
      <div className="nav-label">WORKSPACE</div>
      <a className="nav-item active" href="#overview"><span>◫</span> Overview</a>
      <a className="nav-item" href="#scans"><span>◉</span> Scans <span className="nav-count">{data.summary.active_scans}</span></a>
      <a className="nav-item" href="#findings"><span>⚑</span> Findings</a>
      <a className="nav-item" href="#targets"><span>◎</span> Targets</a>
      <div className="sidebar-bottom"><div className="safety-chip"><span className="pulse"/> SAFETY ENGINE <b>READY</b></div><div className="user-row"><div className="avatar">SF</div><div><strong>Security team</strong><small>Local workspace</small></div><span className="dots">•••</span></div></div>
    </aside>

    <section className="content" id="overview">
      <header className="topbar"><div className="breadcrumbs">Workspace <span>/</span> <b>Overview</b></div><div className="top-actions"><span className="env-pill"><i/> LOCAL DEMO</span><span className={`api-pill ${loaded && !error ? "connected" : "disconnected"}`}><i/>{loaded && !error ? "API CONNECTED" : "API OFFLINE"}</span><div className="avatar small">SF</div></div></header>
      <div className="page-wrap">
        <div className="welcome"><div><div className="eyebrow">LOCAL WORKSPACE <span className="live-dot"/> SYSTEM STATUS</div><h1>Security overview</h1><p>Track authorized scan activity and application risk across your targets.</p></div><button className="primary-button" onClick={startScan} disabled={busy || !data.targets.length} title="Runs the bounded local demo access-control check"><span>＋</span> {busy ? "Starting…" : "New scan"}</button></div>
        {error && <div className="alert" role="alert">{error}</div>}{notice && <div className="notice" role="status">{notice}</div>}
        <div className="section-heading"><div><h2>At a glance</h2><p>Live summary from your 007 workspace</p></div><span className="refresh-note">{loaded ? "Updated just now" : "Connecting to API…"}</span></div>

        <div className="metric-grid">
          <Metric label="ACTIVE SCANS" value={data.summary.active_scans} icon="◉" tone="blue" detail="Across all targets" />
          <Metric label="VERIFIED FINDINGS" value={data.summary.verified_findings} icon="⚑" tone="red" detail="Deterministic evidence only" />
          <Metric label="ENDPOINTS TRACKED" value={data.summary.endpoints} icon="⌘" tone="violet" detail="From captured traffic" />
          <Metric label="AUTHORIZED TARGETS" value={data.summary.targets} icon="◎" tone="green" detail="Scope validated" />
        </div>

        <div className="main-grid">
          <section className="card findings-card" id="findings"><div className="card-head"><div><h2>Recent findings</h2><p>Review, retest, and triage security issues</p></div><span className="period-label">LATEST</span></div>
            <div className="table-wrap"><table><thead><tr><th>FINDING</th><th>TARGET / ENDPOINT</th><th>SEVERITY</th><th>CONFIDENCE</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody>
              {data.findings.map((f) => <tr key={f.id}><td><div className="finding-title">{f.title}</div><div className="muted">SF-{String(f.id).padStart(4, "0")} · {f.category.replaceAll("_", " ")}</div></td><td><div className="target-name">{f.target}</div><code>{f.path}</code></td><td><span className={`severity ${f.severity}`}>{f.severity}</span></td><td><span className={`confidence ${f.confidence}`}>{f.confidence}</span></td><td><span className={`status ${f.verified ? "verified" : "review"}`}><i/>{f.verified ? "Verified" : "Needs review"}</span></td><td>{f.verified && <button className="text-button" onClick={() => retestFinding(f.id)}>Retest</button>}</td></tr>)}
              {!data.findings.length && <tr><td colSpan={6} className="empty">{loaded ? "No findings yet. Results will appear here after a scan." : "Loading findings…"}</td></tr>}
            </tbody></table></div>
          </section>
          <section className="card severity-card"><div className="card-head"><div><h2>Severity breakdown</h2><p>Open findings by severity</p></div><span className="period-label">ALL TIME</span></div><div className="severity-total"><strong>{Object.values(data.severity).reduce((a, b) => a + b, 0)}</strong><span>total findings</span></div>
            <div className="bars">{[["Critical","critical"],["High","high"],["Medium","medium"],["Low","low"],["Info","info"]].map(([name,key]) => { const value = data.severity[key] ?? 0; const total = Math.max(1, ...Object.values(data.severity)); return <div className="bar-row" key={key}><span>{name}</span><div className="bar-track"><i className={key} style={{ width: `${Math.max(value ? 8 : 0, value / total * 100)}%` }}/></div><b>{value}</b></div>; })}</div>
          </section>
        </div>

        <div className="lower-grid">
          <section className="card" id="scans"><div className="card-head"><div><h2>Recent scan activity</h2><p>Latest runs across your authorized targets</p></div><span className="period-label">LATEST 6</span></div><div className="scan-list">{data.scans.map((scan) => <div className="scan-row" key={scan.id}><span className={`scan-icon ${scan.status}`}>⌕</span><div className="scan-info"><b>{scan.target}</b><span>{scan.trigger} scan · {new Date(scan.started_at).toLocaleString()}</span></div><span className={`scan-state ${scan.status}`}>{scan.status}</span>{["queued", "running", "cancel_requested"].includes(scan.status) && <button className="cancel-button" onClick={() => cancelScan(scan.id)}>Stop</button>}<span className="scan-summary">{scan.summary}{scan.status === "completed" && <> · <a href={`${API}/api/scans/${scan.id}/report`} target="_blank" rel="noreferrer">Report</a></>}</span></div>)}{!data.scans.length && <div className="empty scan-empty">{loaded ? "No scan activity yet." : "Loading scan activity…"}</div>}</div></section>
          <section className="card targets-card" id="targets"><div className="card-head"><div><h2>Authorized targets</h2><p>In-scope applications</p></div><button className="text-link button-link" onClick={() => setTargetFormOpen((open) => !open)}>{targetFormOpen ? "Close" : "＋ Add target"}</button></div>
            {targetFormOpen && <form className="target-form" onSubmit={createTarget}><label>Target name<input required minLength={2} maxLength={160} value={targetName} onChange={(event) => setTargetName(event.target.value)} placeholder="Local travel demo"/></label><label>Base URL<input required type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="http://demo-app:8080"/></label><label>Environment<select value={targetEnvironment} onChange={(event) => setTargetEnvironment(event.target.value)}><option value="local-demo">Local demo</option><option value="staging">Staging inventory only</option></select></label><button className="primary-button form-submit" type="submit">Add to scope</button><small>Only origins in the backend allowlist are accepted. The current security check runs against the local demo fixture only.</small></form>}
            <div className="target-list">{data.targets.map((target) => <div className="target-row" key={target.id}><div className="target-icon">{target.name.slice(0, 1)}</div><div className="target-info"><b>{target.name}</b><span>{target.base_url}</span></div><label className="import-button">Import HAR<input type="file" accept=".har,application/json" onChange={(event) => { void importHar(target.id, event.target.files?.[0]); event.currentTarget.value = ""; }}/></label><span className="authorized"><i/>{target.status}</span></div>)}{!data.targets.length && <div className="empty">{loaded ? "No targets configured." : "Loading targets…"}</div>}</div><div className="scope-note"><span>ⓘ</span><div><b>Scope is enforced by the backend</b><p>Only allowlisted origins can be registered. Scanning is limited to the synthetic demo.</p></div></div></section>
        </div>
        <footer><span>007 <b>·</b> Local demo workspace</span><span><i className="live-dot"/> All systems operational</span></footer>
      </div>
    </section>
  </main>;
}

function Metric({ label, value, icon, tone, detail }: { label: string; value: number; icon: string; tone: string; detail: string }) {
  return <article className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><div className="metric-label">{label}</div><div className="metric-value">{value.toString().padStart(2, "0")}</div><div className="metric-detail">{detail}</div><div className={`metric-accent ${tone}`}/></article>;
}
