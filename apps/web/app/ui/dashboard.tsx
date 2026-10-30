"use client";

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import Link from "next/link";
import {
  Activity, AlertTriangle, Bell, ChevronDown, CircleDot, Crosshair, Database,
  FileSearch, Gauge, LayoutDashboard, Radar, RefreshCw, ScanLine, ShieldCheck,
  Square, Target, UsersRound, Zap,
} from "lucide-react";

type PendingTest = {
  id: number;
  scan_id: number;
  target_id: number;
  name: string;
  test_type: string;
  is_risky: boolean;
  risk_level: string;
  risk_rationale: string;
  status: string;
  reviewer_notes: string;
  created_at: string;
};

type DashboardData = {
  summary: { active_scans: number; verified_findings: number; endpoints: number; targets: number; pending_reviews?: number };
  severity: Record<string, number>;
  targets: { id: number; name: string; base_url: string; environment: string; status: string }[];
  findings: { id: number; title: string; category: string; severity: string; confidence: string; verified: boolean; status: string; path: string; target: string }[];
  scans: { id: number; target: string; status: string; trigger: string; started_at: string; summary: string }[];
  changes: { id: number; target: string; source: string; detail: string; created_at: string }[];
  safety: { kill_switch_engaged: boolean; reason: string };
  pending_tests?: PendingTest[];
};

type Health = { status: string; database: string };

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const DEMO_ORIGIN = "http://demo-app:8080";
const empty: DashboardData = {
  summary: { active_scans: 0, verified_findings: 0, endpoints: 0, targets: 0, pending_reviews: 0 },
  severity: {}, targets: [], findings: [], scans: [], changes: [],
  safety: { kill_switch_engaged: false, reason: "" },
  pending_tests: [],
};

function supportsScan(target: DashboardData["targets"][number]) {
  try {
    const url = new URL(target.base_url);
    if (target.status !== "authorized" && target.status !== "approved") return false;
    if (url.pathname !== "/" && url.pathname !== "") return false;
    if (url.search || url.hash) return false;
    if (target.environment === "local-demo") {
      return url.origin === DEMO_ORIGIN;
    }
    return target.environment === "staging";
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

  const scanTargets = useMemo(() => data.targets.filter(supportsScan), [data.targets]);
  const selectedTarget = scanTargets.find((target) => target.id === selectedTargetId) ?? scanTargets[0];

  const refreshDashboard = useCallback(async (manual = false, signal?: AbortSignal) => {
    if (manual) setRefreshing(true);
    try {
      const [dashboardResponse, healthResponse] = await Promise.all([
        fetch(`${API}/api/dashboard`, { cache: "no-store", signal }),
        fetch(`${API}/api/health`, { cache: "no-store", signal }).catch(() => null),
      ]);
      if (!dashboardResponse.ok) throw new Error(await responseError(dashboardResponse));
      const body = await dashboardResponse.json() as DashboardData;
      setData(body);
      setLoaded(true);
      setLoadError("");
      setLastUpdated(new Date());
      if (healthResponse?.ok) setHealth(await healthResponse.json() as Health);
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

  // --- Human Reviewer Actions (Phase 0) ---

  async function approveTest(testId: number) {
    setActionError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/reviews/tests/${testId}/approve`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: "Approved from reviewer dashboard." }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      setNotice(`Risky test #${testId} approved for execution.`);
      await refreshDashboard();
    } catch (error) {
      setActionError(messageFrom(error, "Could not approve test."));
    }
  }

  async function rejectTest(testId: number) {
    setActionError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/reviews/tests/${testId}/reject`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: "Rejected from reviewer dashboard." }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      setNotice(`Risky test #${testId} rejected.`);
      await refreshDashboard();
    } catch (error) {
      setActionError(messageFrom(error, "Could not reject test."));
    }
  }

  async function approveFinding(findingId: number) {
    setActionError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/reviews/findings/${findingId}/approve`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: "Approved from reviewer dashboard." }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      setNotice(`Finding SF-${String(findingId).padStart(4, "0")} approved and verified.`);
      await refreshDashboard();
    } catch (error) {
      setActionError(messageFrom(error, "Could not approve finding."));
    }
  }

  async function rejectFinding(findingId: number) {
    setActionError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/reviews/findings/${findingId}/reject`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ notes: "Rejected from reviewer dashboard." }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      setNotice(`Finding SF-${String(findingId).padStart(4, "0")} rejected.`);
      await refreshDashboard();
    } catch (error) {
      setActionError(messageFrom(error, "Could not reject finding."));
    }
  }

  const apiConnected = health?.status === "healthy";
  const databaseConnected = health?.database === "connected";
  const updatedLabel = lastUpdated
    ? `Updated ${lastUpdated.toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}`
    : "Connecting to workspace…";

  const pendingFindings = data.findings.filter((f) => f.status === "pending_review");
  const pendingTests = data.pending_tests ?? [];
  const hasReviewQueue = pendingFindings.length > 0 || pendingTests.length > 0;
  const openFindings = Object.values(data.severity).reduce((total, value) => total + value, 0);
  const riskScore = Math.max(12, 100 - (data.severity.critical ?? 0) * 18 - (data.severity.high ?? 0) * 9 - (data.severity.medium ?? 0) * 4 - (data.severity.low ?? 0));
  const postureLabel = riskScore >= 85 ? "Strong" : riskScore >= 65 ? "Guarded" : "At risk";

  return <main className="shell operations-shell">
    <aside className="sidebar">
      <a className="brand" href="#overview" aria-label="007 command center home">
        <span className="brand-mark">007</span>
        <span className="brand-copy"><strong>007</strong><small>SECURITY OPS</small></span>
      </a>
      <div className="workspace-switcher"><span className="workspace-logo">A</span><span><small>WORKSPACE</small><b>Acme Security</b></span><ChevronDown size={14} /></div>
      <nav className="primary-nav" aria-label="Workspace navigation">
        <div className="nav-label">COMMAND</div>
        <a className="nav-item active" href="#overview"><LayoutDashboard size={17} /> Overview</a>
        <a className="nav-item" href="#scans"><Radar size={17} /> Scans <span className="nav-count">{data.summary.active_scans}</span></a>
        <a className="nav-item" href="#findings"><FileSearch size={17} /> Findings <span className="nav-count">{openFindings}</span></a>
        {hasReviewQueue && <a className="nav-item review-nav" href="#review-queue"><UsersRound size={17} /> Review queue <span className="nav-count alert-count">{pendingFindings.length + pendingTests.length}</span></a>}
        <div className="nav-label second">MANAGE</div>
        <a className="nav-item" href="#targets"><Target size={17} /> Attack surface</a>
        <a className="nav-item" href="#changes"><Activity size={17} /> Change events</a>
      </nav>
      <div className="sidebar-bottom">
        <div className={`engine-card ${data.safety.kill_switch_engaged ? "halted" : ""}`}>
          <div className="engine-card-head"><ShieldCheck size={16} /><span>Safety engine</span><i /></div>
          <p>{data.safety.kill_switch_engaged ? "All scanning activity is paused." : "Policy guardrails are enforced."}</p>
          <div className="engine-meter"><span /></div>
        </div>
        <div className="user-row"><div className="avatar">SF</div><div><strong>Security team</strong><small>Authorized reviewer</small></div><ChevronDown className="user-chevron" size={14} /></div>
      </div>
    </aside>

    <section className="content" id="overview">
      <header className="topbar">
        <div className="topbar-title"><span>Command center</span><b>Overview</b></div>
        <div className="top-actions">
          <div className="service-health">
            <span className={apiConnected ? "online" : "offline"}><i /> API</span>
            <span className={databaseConnected ? "online" : "offline"}><i /> DATABASE</span>
          </div>
          <button className="icon-button" aria-label="Notifications"><Bell size={16} /><span className="notification-dot" /></button>
          <button className={`kill-button ${data.safety.kill_switch_engaged ? "engaged" : ""}`} onClick={toggleKillSwitch} aria-pressed={data.safety.kill_switch_engaged}>
            {data.safety.kill_switch_engaged ? <Zap size={14} /> : <Square size={13} />}{data.safety.kill_switch_engaged ? "Resume engine" : "Emergency stop"}
          </button>
        </div>
      </header>

      <div className="page-wrap">
        <section className="command-hero">
          <div className="hero-copy">
            <div className="eyebrow"><span className={`live-dot ${apiConnected ? "" : "offline"}`} /> LIVE SECURITY POSTURE</div>
            <h1>Know what changed.<br /><em>Act before it matters.</em></h1>
            <p>One operational view across your attack surface, verified findings, and human approval gates.</p>
            <div className="hero-actions">
              <div className="scan-controls">
                {scanTargets.length > 1 && <label className="scan-target-select"><span>SCAN TARGET</span><select aria-label="Select an authorized scan target" value={selectedTarget?.id ?? ""} onChange={(event) => setSelectedTargetId(Number(event.target.value))}>{scanTargets.map((target) => <option value={target.id} key={target.id}>{target.name}</option>)}</select></label>}
                <button className="primary-button hero-scan" onClick={startScan} disabled={busy || !selectedTarget || data.safety.kill_switch_engaged} title={data.safety.kill_switch_engaged ? "Clear the safety stop to start a scan" : selectedTarget ? `Run bounded checks against ${selectedTarget.name}` : "Add or authorize an allowlisted target to enable scans"}>
                  <ScanLine size={16} />{busy ? "Launching scan…" : "Launch new scan"}
                </button>
              </div>
              <span className="hero-scope"><ShieldCheck size={14} /> Authorized scope only</span>
            </div>
          </div>
          <div className="posture-card">
            <div className="posture-card-head"><span><Gauge size={15} /> POSTURE SCORE</span><b>LIVE</b></div>
            <div className="posture-gauge" style={{ background: `conic-gradient(var(--blue) ${riskScore * 3.6}deg, #243037 0deg)` }}>
              <div><strong>{riskScore}</strong><span>/ 100</span><small>{postureLabel}</small></div>
            </div>
            <div className="posture-stats">
              <div><AlertTriangle size={14} /><span><b>{data.severity.critical ?? 0}</b>Critical</span></div>
              <div><CircleDot size={14} /><span><b>{openFindings}</b>Open</span></div>
              <div><Crosshair size={14} /><span><b>{data.summary.targets}</b>In scope</span></div>
            </div>
          </div>
        </section>

        {loadError && <div className="alert" role="alert"><span className="alert-icon">!</span><div><b>Workspace connection issue</b><p>{loadError} Check that the API and database services are running.</p></div><button className="inline-button" onClick={() => void refreshDashboard(true)}>Retry</button></div>}
        {actionError && <div className="alert" role="alert"><span className="alert-icon">!</span><div><b>Action could not be completed</b><p>{actionError}</p></div><button className="dismiss-button" aria-label="Dismiss error" onClick={() => setActionError("")}>×</button></div>}
        {notice && <div className="notice" role="status"><span aria-hidden="true">✓</span><p>{notice}</p><button className="dismiss-button" aria-label="Dismiss notice" onClick={() => setNotice("")}>×</button></div>}
        {data.safety.kill_switch_engaged && <div className="halt-banner" role="status"><span aria-hidden="true">Ⅱ</span><div><b>Safety stop is engaged</b><p>{data.safety.reason || "New scans are blocked until you resume scan activity."}</p></div></div>}

        <div className="section-heading command-section-heading"><div><span className="section-index">01</span><h2>Operational pulse</h2><p>What needs your attention right now</p></div><div className="heading-actions"><span className="refresh-note">{updatedLabel}</span><button className="refresh-button" onClick={() => void refreshDashboard(true)} disabled={refreshing} aria-label="Refresh dashboard"><RefreshCw className={refreshing ? "spin" : ""} size={14} /></button></div></div>

        <div className="metric-grid command-metrics">
          <Metric label="ACTIVE SCANS" value={data.summary.active_scans} icon={<Radar size={18} />} tone="blue" detail="Running now" bars={[42, 68, 48, 82, 58]} />
          <Metric label="VERIFIED RISKS" value={data.summary.verified_findings} icon={<AlertTriangle size={18} />} tone="red" detail="Confirmed findings" bars={[70, 58, 76, 45, 62]} />
          <Metric label="REVIEW QUEUE" value={(data.summary.pending_reviews ?? 0)} icon={<UsersRound size={18} />} tone="violet" detail="Awaiting decision" bars={[28, 45, 38, 60, 72]} />
          <Metric label="ENDPOINTS" value={data.summary.endpoints} icon={<Database size={18} />} tone="green" detail={`${data.summary.targets} authorized targets`} bars={[32, 44, 57, 68, 86]} />
        </div>

        {/* Human Review Queue Card */}
        {hasReviewQueue && (
          <section className="card review-card" id="review-queue" style={{ borderColor: "#f59e0b", background: "rgba(245, 158, 11, 0.03)" }}>
            <div className="card-head">
              <div>
                <h2 style={{ color: "#d97706" }}>⚖ Human Review Queue (Phase 0 Guardrails)</h2>
                <p>Risky test executions and high-severity findings blocked until explicitly reviewed</p>
              </div>
              <span className="period-label" style={{ background: "#fef3c7", color: "#b45309" }}>ACTION REQUIRED</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>TYPE / ITEM</th>
                    <th>RISK / RATIONALE</th>
                    <th>STATE</th>
                    <th>REVIEW DECISION</th>
                  </tr>
                </thead>
                <tbody>
                  {pendingTests.map((test) => (
                    <tr key={`test-${test.id}`}>
                      <td>
                        <div className="finding-title">{test.name}</div>
                        <div className="muted">Test #{test.id} · Type: {test.test_type}</div>
                      </td>
                      <td>
                        <span className={`severity ${test.risk_level}`} style={{ marginRight: 8 }}>{test.risk_level}</span>
                        <small>{test.risk_rationale}</small>
                      </td>
                      <td>
                        <span className="lifecycle pending_review"><i/>Pending review</span>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: "8px" }}>
                          <button className="primary-button" style={{ padding: "4px 10px", fontSize: "12px", background: "#059669" }} onClick={() => approveTest(test.id)}>Approve</button>
                          <button className="cancel-button" style={{ padding: "4px 10px", fontSize: "12px" }} onClick={() => rejectTest(test.id)}>Reject</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {pendingFindings.map((finding) => (
                    <tr key={`finding-${finding.id}`}>
                      <td>
                        <div className="finding-title">{finding.title}</div>
                        <div className="muted">SF-{String(finding.id).padStart(4, "0")} · {finding.category}</div>
                      </td>
                      <td>
                        <span className={`severity ${finding.severity}`} style={{ marginRight: 8 }}>{finding.severity}</span>
                        <small>High-severity candidate finding requires reviewer sign-off before escalation</small>
                      </td>
                      <td>
                        <span className="lifecycle pending_review"><i/>Pending review</span>
                      </td>
                      <td>
                        <div style={{ display: "flex", gap: "8px" }}>
                          <button className="primary-button" style={{ padding: "4px 10px", fontSize: "12px", background: "#059669" }} onClick={() => approveFinding(finding.id)}>Approve</button>
                          <button className="cancel-button" style={{ padding: "4px 10px", fontSize: "12px" }} onClick={() => rejectFinding(finding.id)}>Reject</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        <div className="main-grid">
          <section className="card findings-card" id="findings"><div className="card-head"><div><h2>Recent findings</h2><p>Review confidence, lifecycle, and safe retest actions</p></div><span className="period-label">LATEST</span></div>
            <div className="table-wrap"><table><thead><tr><th>FINDING</th><th>TARGET / ENDPOINT</th><th>SEVERITY</th><th>CONFIDENCE</th><th>LIFECYCLE</th><th>ACTION</th></tr></thead><tbody>
              {data.findings.map((finding) => <tr key={finding.id}><td><div className="finding-title">{finding.title}</div><div className="muted">SF-{String(finding.id).padStart(4, "0")} · {finding.category.replaceAll("_", " ")}</div></td><td><div className="target-name">{finding.target}</div><code>{finding.path}</code></td><td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td><td><span className={`confidence ${finding.confidence}`}>{finding.confidence}</span></td><td><span className={`lifecycle ${finding.status}`}><i/>{finding.status.replaceAll("_", " ")}</span><small className={`verification ${finding.verified ? "verified" : "review"}`}>{finding.verified ? "Verified" : "Needs review"}</small></td><td>
                {finding.status === "pending_review" && (
                  <div style={{ display: "flex", gap: "6px" }}>
                    <button className="text-button" style={{ color: "#059669" }} onClick={() => approveFinding(finding.id)}>Approve</button>
                    <button className="text-button" style={{ color: "#dc2626" }} onClick={() => rejectFinding(finding.id)}>Reject</button>
                  </div>
                )}
                {finding.verified && (finding.status === "open" || finding.status === "approved") && <button className="text-button" onClick={() => retestFinding(finding.id)} disabled={data.safety.kill_switch_engaged}>Retest</button>}
              </td></tr>)}
              {!data.findings.length && <tr><td colSpan={6} className="empty">{loaded ? "No findings yet. Results appear after an authorized scan." : "Loading findings…"}</td></tr>}
            </tbody></table></div>
          </section>
          <section className="card severity-card"><div className="card-head"><div><h2>Severity breakdown</h2><p>Unresolved findings by severity</p></div><span className="period-label">OPEN</span></div><div className="severity-total"><strong>{Object.values(data.severity).reduce((total, value) => total + value, 0)}</strong><span>open findings</span></div>
            <div className="bars">{[["Critical", "critical"], ["High", "high"], ["Medium", "medium"], ["Low", "low"], ["Info", "info"]].map(([name, key]) => { const value = data.severity[key] ?? 0; const total = Math.max(1, ...Object.values(data.severity)); return <div className="bar-row" key={key}><span>{name}</span><div className="bar-track"><i className={key} style={{ width: `${Math.max(value ? 8 : 0, value / total * 100)}%` }}/></div><b>{value}</b></div>; })}</div>
          </section>
        </div>

        <div className="lower-grid">
          <section className="card" id="scans"><div className="card-head"><div><h2>Recent scan activity</h2><p>Latest runs against supported, authorized targets</p></div><span className="period-label">LATEST 6</span></div><div className="scan-list">
            {data.scans.map((scan) => <div className="scan-row" key={scan.id}><span className={`scan-icon ${scan.status}`} aria-hidden="true">{scan.status === "failed" || scan.status === "halted" ? "!" : scan.status === "completed" ? "✓" : "⌕"}</span><div className="scan-info"><b>{scan.target}</b><span>{scan.trigger.replaceAll("_", " ")} · {formatDate(scan.started_at)}</span></div><span className={`scan-state ${scan.status}`}>{scan.status.replaceAll("_", " ")}</span>{["queued", "running", "cancel_requested"].includes(scan.status) && <button className="cancel-button" onClick={() => cancelScan(scan.id)}>Stop</button>}<span className="scan-summary">{scan.summary}{scan.status === "completed" && <> · <a href={`${API}/api/scans/${scan.id}/report`} target="_blank" rel="noreferrer">Download PDF ↓</a></>}</span></div>)}
            {!data.scans.length && <div className="empty scan-empty">{loaded ? "No scan activity yet. Start a scan to see progress here." : "Loading scan activity…"}</div>}
          </div></section>

          <section className="card targets-card" id="targets"><div className="card-head"><div><h2>Authorized targets</h2><p>Registered application origins</p></div><button className="text-link button-link" onClick={() => setTargetFormOpen((open) => !open)}>{targetFormOpen ? "Close" : "＋ Add target"}</button></div>
            {targetFormOpen && <form className="target-form" onSubmit={createTarget}><label>Target name<input required minLength={2} maxLength={160} value={targetName} onChange={(event) => setTargetName(event.target.value)} placeholder="Staging environment"/></label><label>Base URL<input required type="url" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="http://staging-app:8080"/></label><label>Purpose<select value={targetEnvironment} onChange={(event) => setTargetEnvironment(event.target.value)}><option value="staging">Staging target (Authorized scan)</option><option value="local-demo">Local synthetic demo scan</option></select></label><button className="primary-button form-submit" type="submit">Add to scope</button><small>Only allowlisted origins are accepted. Staging targets enforce independent request budgets and review gates.</small></form>}
            <div className="target-list">{data.targets.map((target) => <div className="target-row" key={target.id}><div className="target-icon">{target.name.slice(0, 1).toUpperCase()}</div><div className="target-info"><b>{target.name}</b><span>{target.base_url} ({target.environment})</span></div><label className="import-button">Import HAR<input type="file" accept=".har,application/json" onChange={(event) => { void importHar(target.id, event.target.files?.[0]); event.currentTarget.value = ""; }}/></label><Link className="import-button" href={`/targets/${target.id}/import`}>Import OpenAPI</Link><span className={`authorized ${target.status}`}><i/>{target.status}</span></div>)}{!data.targets.length && <div className="empty">{loaded ? "No targets configured. Add an allowlisted origin to begin." : "Loading targets…"}</div>}</div>
            <div className="scope-note"><span aria-hidden="true">ⓘ</span><div><b>Scope is checked by the backend</b><p>Only explicitly allowlisted origins can be registered and scanned. Staging credentials and review states are strictly enforced.</p></div></div>
          </section>
        </div>

        <section className="card changes-card" id="changes"><div className="card-head"><div><h2>Change events</h2><p>Deploy notifications and endpoint inventory changes</p></div><span className="period-label">LATEST</span></div><div className="change-list">
          {data.changes.map((change) => <div className="change-row" key={change.id}><span className="change-icon" aria-hidden="true">↻</span><div className="change-info"><b>{change.target}</b><span>{change.source.replaceAll("_", " ")} · {formatDate(change.created_at)}</span></div><p>{change.detail}</p></div>)}
          {!data.changes.length && <div className="empty">{loaded ? "No change events yet. New deploys and inventory differences will appear here." : "Loading change events…"}</div>}
        </div></section>

        <footer><span>007 <b>·</b> Local &amp; Staging Security Operations</span><span><i className={`live-dot ${data.safety.kill_switch_engaged || !apiConnected ? "offline" : ""}`}/>{data.safety.kill_switch_engaged ? "Safety stop engaged" : apiConnected && databaseConnected ? "API and database operational" : "Checking service health"}</span></footer>
      </div>
    </section>
  </main>;
}

function Metric({ label, value, icon, tone, detail, bars }: { label: string; value: number; icon: React.ReactNode; tone: string; detail: string; bars: number[] }) {
  return <article className={`metric-card metric-${tone}`}>
    <div className="metric-top"><div className={`metric-icon ${tone}`} aria-hidden="true">{icon}</div><div className="metric-label">{label}</div><button aria-label={`View ${label.toLowerCase()}`}>↗</button></div>
    <div className="metric-body"><div><div className="metric-value">{value.toLocaleString()}</div><div className="metric-detail">{detail}</div></div><div className="metric-spark" aria-hidden="true">{bars.map((height, index) => <i key={index} style={{ height: `${height}%` }} />)}</div></div>
  </article>;
}
