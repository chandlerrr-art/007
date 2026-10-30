"use client";

import { useEffect, useRef, useState } from "react";
import { Check, CheckCheck, Clipboard, Code2, FileCode2, LoaderCircle, ShieldCheck, WandSparkles } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Patch = {
  id: number;
  vulnerability_id: number;
  target_file_path: string;
  unified_diff: string;
  ai_confidence_score: number;
  status: string;
  application_mode?: string | null;
};
type TaskStatus = { status: string; result?: { patch_id?: number; rationale?: string; strategy?: string }; error?: string };
type Props = {
  vulnerabilityId: number;
  authorization?: string;
  initialFilePath?: string;
  initialSourceCode?: string;
  dbDialect?: "sqlite" | "postgresql" | "mysql";
};

function authHeaders(value?: string) {
  if (!value) return undefined;
  return { Authorization: value.startsWith("Bearer ") ? value : `Bearer ${value}` };
}

async function errorMessage(response: Response) {
  const body = await response.json().catch(() => null) as { detail?: string } | null;
  return body?.detail ?? `Request failed (${response.status}).`;
}

function DiffLine({ line, index }: { line: string; index: number }) {
  let style = "text-slate-300";
  let marker = " ";
  if (line.startsWith("+++ ") || line.startsWith("--- ") || line.startsWith("@@")) style = "text-sky-300";
  else if (line.startsWith("+")) { style = "bg-emerald-950/70 text-emerald-200"; marker = "+"; }
  else if (line.startsWith("-")) { style = "bg-rose-950/70 text-rose-200"; marker = "−"; }
  return <div key={`${index}-${line}`} className={`grid min-h-6 grid-cols-[2.5rem_1fr] whitespace-pre ${style}`}><span className="select-none border-r border-white/10 px-2 text-right text-slate-500">{index + 1}</span><span className="px-3"><span className="mr-1 inline-block w-3 text-center">{marker}</span>{line || " "}</span></div>;
}

export default function PatchReview({ vulnerabilityId, authorization, initialFilePath = "", initialSourceCode = "", dbDialect }: Props) {
  const [filePath, setFilePath] = useState(initialFilePath);
  const [sourceCode, setSourceCode] = useState(initialSourceCode);
  const [patch, setPatch] = useState<Patch | null>(null);
  const [rationale, setRationale] = useState("");
  const [strategy, setStrategy] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [copyLabel, setCopyLabel] = useState("Copy diff");
  const [applyMode, setApplyMode] = useState<"simulate" | "record">("simulate");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const headers = authHeaders(authorization);

  useEffect(() => {
    if (!patch || patch.status !== "generated") return;
    const patchId = patch.id;
    const timer = window.setInterval(async () => {
      try {
        const response = await fetch(`${API}/api/vulnerabilities/${vulnerabilityId}/patches`, { cache: "no-store", headers });
        if (!response.ok) return;
        const rows = await response.json() as Patch[];
        const latest = rows.find((row) => row.id === patchId);
        if (latest) setPatch(latest);
      } catch { /* Keep the review visible; the next poll retries. */ }
    }, 2500);
    return () => window.clearInterval(timer);
  }, [patch?.id, patch?.status, vulnerabilityId, authorization]);

  async function generate() {
    if (!filePath.trim() || !sourceCode.trim() || busy) return;
    setBusy(true); setError(""); setNotice(""); setPatch(null); setRationale(""); setStrategy("");
    try {
      const response = await fetch(`${API}/api/vulnerabilities/${vulnerabilityId}/patch`, {
        method: "POST", headers: { "Content-Type": "application/json", ...(headers ?? {}) },
        body: JSON.stringify({ target_file_path: filePath, source_code: sourceCode, ...(dbDialect ? { db_dialect: dbDialect } : {}) }),
      });
      if (!response.ok) throw new Error(await errorMessage(response));
      const task = await response.json() as { task_id?: string; patch_id?: number; ai_confidence_score?: number; status?: string };
      let completed = task;
      if (task.task_id && !task.patch_id) {
        for (let attempt = 0; attempt < 90; attempt += 1) {
          await new Promise((resolve) => window.setTimeout(resolve, 2000));
          const statusResponse = await fetch(`${API}/api/tasks/${encodeURIComponent(task.task_id)}`, { cache: "no-store", headers });
          if (!statusResponse.ok) throw new Error(await errorMessage(statusResponse));
          const result = await statusResponse.json() as TaskStatus;
          if (result.status === "failure") throw new Error(result.error || "Patch generation failed.");
          if (result.result?.patch_id) { completed = { ...task, patch_id: result.result.patch_id }; setRationale(result.result.rationale ?? ""); setStrategy(result.result.strategy ?? ""); break; }
        }
      }
      if (!completed.patch_id) throw new Error("Patch generation is taking longer than expected. Check the vulnerability's patch list in a moment.");
      const listResponse = await fetch(`${API}/api/vulnerabilities/${vulnerabilityId}/patches`, { cache: "no-store", headers });
      if (!listResponse.ok) throw new Error(await errorMessage(listResponse));
      const patches = await listResponse.json() as Patch[];
      const generated = patches.find((item) => item.id === completed.patch_id);
      if (!generated) throw new Error("Patch generation completed, but the patch details are not available yet.");
      setPatch(generated);
      setNotice("Patch candidate generated. Review the diff before approving it.");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not generate a patch candidate.");
    } finally { setBusy(false); }
  }

  async function approve() {
    if (!patch || busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/patches/${patch.id}/review`, {
        method: "POST", headers: { "Content-Type": "application/json", ...(headers ?? {}) },
        body: JSON.stringify({ decision: "approved" }),
      });
      if (!response.ok) throw new Error(await errorMessage(response));
      setPatch(await response.json() as Patch);
      setNotice("Patch approved. Apply it when you are ready.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not approve this patch."); }
    finally { setBusy(false); }
  }

  async function apply() {
    if (!patch || patch.status !== "reviewed" || busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await fetch(`${API}/api/patches/${patch.id}/apply`, {
        method: "POST", headers: { "Content-Type": "application/json", ...(headers ?? {}) },
        body: JSON.stringify({ mode: applyMode }),
      });
      if (!response.ok) throw new Error(await errorMessage(response));
      const result = await response.json() as Patch & { message?: string };
      setPatch(result);
      setNotice(result.message || `Patch application recorded in ${applyMode} mode.`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Could not apply this patch."); }
    finally { setBusy(false); }
  }

  async function copyDiff() {
    if (!patch) return;
    try {
      await navigator.clipboard.writeText(patch.unified_diff);
      setCopyLabel("Copied"); window.setTimeout(() => setCopyLabel("Copy diff"), 1800);
    } catch { setError("Clipboard access was blocked by the browser."); }
  }

  const canGenerate = filePath.trim().length > 0 && sourceCode.trim().length > 0;
  const confidence = patch ? Math.max(0, Math.min(100, Math.round(patch.ai_confidence_score * 100))) : 0;
  const diffLines = patch?.unified_diff.split("\n") ?? [];

  return (
    <section className="w-full overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 px-5 py-5 sm:px-7">
        <div className="flex items-start gap-3"><div className="rounded-xl bg-violet-100 p-3 text-violet-700"><WandSparkles size={20} /></div><div>
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-violet-700">AI remediation</div>
          <h2 className="mt-1 text-xl font-semibold text-slate-900">Patch review</h2>
          <p className="mt-1 text-sm text-slate-500">Vulnerability #{vulnerabilityId} · human approval required</p>
        </div></div>
        {patch && <span className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-slate-600">{patch.status.replaceAll("_", " ")}</span>}
      </div>

      {!patch && <div className="grid gap-5 p-5 sm:p-7 lg:grid-cols-[minmax(0,1fr)_minmax(260px,.8fr)]">
        <div className="space-y-4">
          <label className="block text-sm font-medium text-slate-700">Target file path
            <div className="relative mt-2"><FileCode2 className="absolute left-3 top-3 text-slate-400" size={16} /><input value={filePath} onChange={(event) => setFilePath(event.target.value)} maxLength={1000} placeholder="src/routes/bookings.ts" className="w-full rounded-lg border border-slate-300 py-2.5 pl-10 pr-3 font-mono text-sm outline-none transition focus:border-blue-500 focus:ring-4 focus:ring-blue-100" /></div>
          </label>
          <label className="block text-sm font-medium text-slate-700">Current source code
            <textarea ref={textareaRef} value={sourceCode} onChange={(event) => setSourceCode(event.target.value)} maxLength={200000} rows={11} placeholder="Paste the relevant source file or function for analysis..." className="mt-2 w-full resize-y rounded-lg border border-slate-300 p-3 font-mono text-xs leading-6 text-slate-700 outline-none transition focus:border-blue-500 focus:ring-4 focus:ring-blue-100" />
          </label>
          <div className="flex flex-wrap items-center justify-between gap-3"><span className="text-xs text-slate-500">{sourceCode.length.toLocaleString()} / 200,000 characters · Only the source you enter is sent to the API.</span>
            <button onClick={generate} disabled={!canGenerate || busy} className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50">
              {busy ? <LoaderCircle className="animate-spin" size={16} /> : <WandSparkles size={16} />}{busy ? "Generating patch…" : "Generate patch"}
            </button>
          </div>
        </div>
        <aside className="rounded-xl border border-violet-100 bg-violet-50/70 p-5">
          <div className="flex items-center gap-2 font-semibold text-violet-950"><ShieldCheck size={17} />Safe review workflow</div>
          <ol className="mt-4 space-y-4 text-sm text-violet-900/75">
            <li className="flex gap-3"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-white text-xs font-bold text-violet-700">1</span><span>Generate a candidate from the vulnerability details and source you provide.</span></li>
            <li className="flex gap-3"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-white text-xs font-bold text-violet-700">2</span><span>Review the unified diff, rationale, and confidence score.</span></li>
            <li className="flex gap-3"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-white text-xs font-bold text-violet-700">3</span><span>Approve and record or simulate application. The API does not modify a repository.</span></li>
          </ol>
        </aside>
      </div>}

      {patch && <div className="space-y-5 p-5 sm:p-7">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="rounded-xl border border-slate-200 p-4"><div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500"><Code2 size={15} />File</div><div className="mt-2 break-all font-mono text-sm text-slate-800">{patch.target_file_path}</div></div>
          <div className="rounded-xl border border-slate-200 p-4"><div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-slate-500"><span>Model confidence</span><span className="text-slate-800">{confidence}%</span></div><div className="mt-3 h-2 overflow-hidden rounded-full bg-slate-100"><div className={`h-full rounded-full ${confidence >= 80 ? "bg-emerald-500" : confidence >= 55 ? "bg-amber-500" : "bg-rose-500"}`} style={{ width: `${confidence}%` }} /></div><p className="mt-2 text-xs text-slate-500">Confidence supports review; it is not an approval.</p></div>
          <div className="rounded-xl border border-slate-200 p-4"><div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Generation strategy</div><div className="mt-2 text-sm font-medium capitalize text-slate-800">{strategy || "Security remediation"}</div></div>
        </div>
        {rationale && <div className="rounded-xl border border-blue-100 bg-blue-50 p-4 text-sm text-blue-900"><div className="font-semibold">Remediation rationale</div><p className="mt-1 leading-6">{rationale}</p></div>}
        <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-950">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-slate-900 px-4 py-3"><div className="flex items-center gap-2 text-xs font-medium text-slate-200"><Code2 size={15} />Unified diff</div><button onClick={copyDiff} className="inline-flex items-center gap-1.5 rounded-md border border-white/15 px-2.5 py-1.5 text-xs text-slate-300 hover:bg-white/10"><Clipboard size={13} />{copyLabel}</button></div>
          <div className="max-h-[440px] overflow-auto py-2 font-mono text-[11px] leading-6" role="region" aria-label="Syntax highlighted unified diff">{diffLines.map((line, index) => <DiffLine key={`${index}-${line}`} line={line} index={index} />)}</div>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-200 bg-amber-50 p-4">
          <div className="flex min-w-0 items-start gap-2 text-sm text-amber-900"><ShieldCheck className="mt-0.5 shrink-0" size={17} /><span>Review the complete change before approval. Patch application is recorded by the backend and does not edit repository files.</span></div>
          <div className="flex w-full flex-wrap justify-end gap-2 sm:w-auto">
            {patch.status === "generated" && <button onClick={approve} disabled={busy} className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-emerald-600 px-4 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-50">{busy ? <LoaderCircle className="animate-spin" size={15} /> : <Check size={15} />}Approve patch</button>}
            {patch.status === "reviewed" && <><label className="flex items-center gap-1 rounded-lg border border-slate-300 bg-white px-2 text-xs text-slate-600">Mode<select value={applyMode} onChange={(event) => setApplyMode(event.target.value as "simulate" | "record")} className="ml-1 rounded border-0 bg-transparent py-2 text-xs font-semibold text-slate-800 outline-none"><option value="simulate">Simulate</option><option value="record">Record</option></select></label><button onClick={apply} disabled={busy} className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50">{busy ? <LoaderCircle className="animate-spin" size={15} /> : <CheckCheck size={15} />}Apply patch</button></>}
            {patch.status === "applied" && <span className="inline-flex items-center gap-2 rounded-lg bg-emerald-100 px-4 py-2 text-sm font-semibold text-emerald-800"><CheckCheck size={16} />Application recorded</span>}
          </div>
        </div>
      </div>}

      {(error || (notice && patch)) && <div role="status" className={`mx-5 mb-5 rounded-lg border p-3 text-sm sm:mx-7 ${error ? "border-rose-200 bg-rose-50 text-rose-800" : "border-emerald-200 bg-emerald-50 text-emerald-800"}`}>{error || notice}</div>}
    </section>
  );
}
