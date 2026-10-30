"use client";

import { useEffect, useState } from "react";
import { Activity, AlertTriangle, CheckCircle2, Clock3, LoaderCircle, Radar, XCircle } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type ScanStatus = {
  id: number;
  target_id: number;
  status: "pending" | "running" | "completed" | "failed" | string;
  profile: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  progress_percentage: number;
  findings_count: number;
  findings_by_severity: Record<string, number>;
  metrics: Record<string, number | string | null>;
};

type Props = { targetId: number; scanId: number; authorization?: string };

function authHeaders(value?: string) {
  if (!value) return undefined;
  return { Authorization: value.startsWith("Bearer ") ? value : `Bearer ${value}` };
}

function statusStyle(status: string) {
  if (status === "completed") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (status === "failed") return "border-rose-200 bg-rose-50 text-rose-700";
  if (status === "running") return "border-blue-200 bg-blue-50 text-blue-700";
  return "border-slate-200 bg-slate-50 text-slate-600";
}

function formatDuration(seconds: number | null, startedAt: string | null, running: boolean) {
  const value = seconds ?? (running && startedAt ? Math.max(0, Math.floor((Date.now() - new Date(startedAt).getTime()) / 1000)) : 0);
  if (!Number.isFinite(value)) return "—";
  const minutes = Math.floor(value / 60);
  return `${minutes}m ${Math.floor(value % 60)}s`;
}

function Metric({ icon: Icon, label, value, tone }: { icon: typeof Activity; label: string; value: string | number; tone: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className={`mb-3 flex h-9 w-9 items-center justify-center rounded-lg ${tone}`}><Icon size={18} /></div>
      <div className="text-2xl font-semibold tracking-tight text-slate-900">{value}</div>
      <div className="mt-1 text-xs font-medium uppercase tracking-wider text-slate-500">{label}</div>
    </div>
  );
}

export default function ScanProgress({ targetId, scanId, authorization }: Props) {
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    const poll = async () => {
      try {
        const response = await fetch(`${API}/api/targets/${targetId}/scans/${scanId}`, {
          cache: "no-store", signal: controller.signal,
          headers: authHeaders(authorization),
        });
        if (!response.ok) {
          const payload = await response.json().catch(() => null) as { detail?: string } | null;
          throw new Error(payload?.detail || `Could not load scan status (${response.status}).`);
        }
        const data = await response.json() as ScanStatus;
        setScan(data);
        setError("");
        setLoading(false);
        if (!stopped && !["completed", "failed"].includes(data.status)) timer = setTimeout(poll, 3000);
      } catch (reason) {
        if (controller.signal.aborted) return;
        setLoading(false);
        setError(reason instanceof Error ? reason.message : "Scan status could not be refreshed.");
        if (!stopped) timer = setTimeout(poll, 3000);
      }
    };
    void poll();
    return () => { stopped = true; controller.abort(); if (timer) clearTimeout(timer); };
  }, [targetId, scanId, authorization]);

  const status = scan?.status ?? "pending";
  const progress = Math.max(0, Math.min(100, scan?.progress_percentage ?? 0));
  const metrics = scan?.metrics ?? {};
  const endpointsScanned = Number(metrics.endpoints_scanned ?? 0);
  const severity = scan?.findings_by_severity ?? {};

  return (
    <section aria-live="polite" className="w-full rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:p-7">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="rounded-xl bg-slate-900 p-3 text-white"><Radar size={21} /></div>
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-600">Live scan monitor</div>
            <div className="mt-1 text-xl font-semibold text-slate-900">Scan #{scanId}</div>
            <div className="mt-1 text-sm text-slate-500">Target {targetId}{scan?.profile ? ` · ${scan.profile} profile` : ""}</div>
          </div>
        </div>
        <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold uppercase tracking-wide ${statusStyle(status)}`}>
          {status === "running" || status === "pending" ? <LoaderCircle className="animate-spin" size={14} /> : status === "completed" ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
          {status.replaceAll("_", " ")}
        </span>
      </div>

      <div className="mt-7">
        <div className="mb-2 flex items-center justify-between text-xs font-medium text-slate-500">
          <span>Execution progress</span><span className="tabular-nums">{loading ? "Loading" : `${progress}%`}</span>
        </div>
        <div className="h-2.5 overflow-hidden rounded-full bg-slate-100" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress}>
          <div className={`h-full rounded-full transition-all duration-700 ${status === "failed" ? "bg-rose-500" : status === "completed" ? "bg-emerald-500" : "bg-blue-600"}`} style={{ width: `${progress}%` }} />
        </div>
        {error && <div role="status" className="mt-3 flex items-center gap-2 text-sm text-amber-700"><AlertTriangle size={15} />{error} Retrying automatically.</div>}
      </div>

      <div className="mt-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric icon={AlertTriangle} label="Critical findings" value={severity.critical ?? 0} tone="bg-rose-50 text-rose-600" />
        <Metric icon={AlertTriangle} label="High findings" value={severity.high ?? 0} tone="bg-orange-50 text-orange-600" />
        <Metric icon={Activity} label="Endpoints scanned" value={endpointsScanned} tone="bg-blue-50 text-blue-600" />
        <Metric icon={Clock3} label="Execution time" value={formatDuration(scan?.duration_seconds ?? null, scan?.started_at ?? null, status === "running")} tone="bg-violet-50 text-violet-600" />
      </div>
      {status === "failed" && <p className="mt-5 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">The scan ended with an error. Review the scan record and worker logs for details.</p>}
      {status === "completed" && <p className="mt-5 rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">Scan complete. {scan?.findings_count ?? 0} finding{scan?.findings_count === 1 ? "" : "s"} recorded.</p>}
    </section>
  );
}
