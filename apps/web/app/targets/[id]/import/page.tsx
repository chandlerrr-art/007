"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useRef, useState, type DragEvent, type ChangeEvent } from "react";
import { ArrowLeft, CheckCircle2, FileCode2, FileUp, LockKeyhole, ShieldCheck, UploadCloud, X, XCircle } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const MAX_SIZE = 5_000_000;
const ACCEPTED = [".json", ".yaml", ".yml"];

type ImportResult = {
  target_id: number;
  discovered: number;
  inserted: number;
  updated: number;
  parameters_added: number;
  classification_counts: Record<string, number>;
  note: string;
};

async function responseMessage(response: Response) {
  const body = await response.json().catch(() => null) as { detail?: string } | null;
  return body?.detail ?? `Import failed (${response.status}).`;
}

export default function OpenAPIImportPage() {
  const params = useParams<{ id: string }>();
  const targetId = Number(params.id);
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);

  function chooseFile(candidate?: File) {
    setError(""); setResult(null);
    if (!candidate) return;
    const extension = candidate.name.toLowerCase().slice(candidate.name.lastIndexOf("."));
    if (!ACCEPTED.includes(extension)) { setFile(null); setError("Choose an OpenAPI JSON or YAML file (.json, .yaml, or .yml)."); return; }
    if (candidate.size > MAX_SIZE) { setFile(null); setError("Specification files must be 5 MB or smaller."); return; }
    setFile(candidate);
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault(); setDragging(false); chooseFile(event.dataTransfer.files?.[0]);
  }

  function onFileInput(event: ChangeEvent<HTMLInputElement>) {
    chooseFile(event.target.files?.[0]);
    event.target.value = "";
  }

  async function importSpec() {
    if (!file || !Number.isSafeInteger(targetId) || targetId <= 0 || busy) return;
    setBusy(true); setError(""); setResult(null);
    try {
      const body = new FormData();
      body.append("file", file, file.name);
      const response = await fetch(`${API}/api/targets/${targetId}/openapi-import`, { method: "POST", body });
      if (!response.ok) throw new Error(await responseMessage(response));
      setResult(await response.json() as ImportResult);
      setFile(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not import this specification.");
    } finally { setBusy(false); }
  }

  return (
    <main className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-5 py-4 sm:px-8">
          <Link href="/" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 transition hover:text-slate-900"><ArrowLeft size={16} />Back to command center</Link>
          <div className="flex items-center gap-2 text-sm font-bold tracking-tight text-slate-800"><span className="grid h-8 w-8 place-items-center rounded-lg bg-blue-600 text-xs text-white">007</span>Security Scanner</div>
        </div>
      </header>

      <div className="mx-auto max-w-6xl px-5 py-10 sm:px-8 sm:py-14">
        <div className="mb-8 flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
          <div><div className="mb-3 inline-flex items-center gap-2 rounded-full border border-blue-100 bg-blue-50 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-blue-700"><FileCode2 size={14} />Shift-left inventory</div>
            <div className="text-3xl font-semibold tracking-tight text-slate-950 sm:text-4xl">Import an API specification</div>
            <p className="mt-3 max-w-2xl text-sm leading-6 text-slate-600">Bring documented routes into your inventory before the next scan. We validate the specification, infer parameter shapes, and classify routes against observed traffic.</p>
          </div>
          <div className="rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600 shadow-sm"><span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Target</span><div className="mt-1 font-semibold text-slate-900">#{Number.isSafeInteger(targetId) ? targetId : "Invalid ID"}</div></div>
        </div>

        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.6fr)_minmax(270px,.75fr)]">
          <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm sm:p-7">
            <div className="mb-5 flex items-center justify-between gap-3"><div><div className="text-lg font-semibold text-slate-900">Specification source</div><p className="mt-1 text-sm text-slate-500">OpenAPI 3.0 or Swagger 2.0 in JSON or YAML format.</p></div><span className="rounded-md bg-slate-100 px-2 py-1 font-mono text-xs text-slate-500">MAX 5 MB</span></div>
            <div onDragEnter={(event) => { event.preventDefault(); setDragging(true); }} onDragOver={(event) => event.preventDefault()} onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false); }} onDrop={onDrop}
              className={`relative flex min-h-[270px] flex-col items-center justify-center rounded-xl border-2 border-dashed px-5 py-9 text-center transition ${dragging ? "border-blue-500 bg-blue-50" : "border-slate-300 bg-slate-50/70 hover:border-blue-300 hover:bg-blue-50/40"}`}>
              <input ref={inputRef} type="file" accept=".json,.yaml,.yml,application/json,application/yaml,text/yaml" onChange={onFileInput} className="sr-only" aria-label="Choose OpenAPI specification file" />
              {file ? <><div className="mb-4 rounded-2xl bg-blue-100 p-4 text-blue-700"><FileCode2 size={28} /></div><div className="max-w-full truncate font-semibold text-slate-900">{file.name}</div><div className="mt-1 text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB · Ready to validate</div><button type="button" onClick={() => setFile(null)} className="absolute right-3 top-3 rounded-lg p-2 text-slate-400 hover:bg-white hover:text-slate-700" aria-label="Remove selected file"><X size={16} /></button></> : <><div className="mb-4 rounded-2xl bg-blue-100 p-4 text-blue-700"><UploadCloud size={29} /></div><div className="text-base font-semibold text-slate-900">Drop your API specification here</div><div className="mt-2 text-sm text-slate-500">or select a file from your computer</div><button type="button" onClick={() => inputRef.current?.click()} className="mt-5 inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 shadow-sm transition hover:border-blue-300 hover:text-blue-700"><FileUp size={16} />Browse files</button><div className="mt-5 flex flex-wrap justify-center gap-2">{[".json", ".yaml", ".yml"].map((ext) => <span key={ext} className="rounded-md border border-slate-200 bg-white px-2 py-1 font-mono text-[11px] text-slate-500">{ext}</span>)}</div></>}
            </div>
            {error && <div role="alert" className="mt-4 flex items-start gap-2 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800"><XCircle className="mt-0.5 shrink-0" size={16} />{error}</div>}
            {result && <div role="status" className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-emerald-900"><div className="flex items-center gap-2 font-semibold"><CheckCircle2 size={18} />Specification imported successfully</div><div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">{[["Endpoints", result.discovered], ["New", result.inserted], ["Updated", result.updated], ["Parameters", result.parameters_added]].map(([label, value]) => <div key={label} className="rounded-lg border border-emerald-200/80 bg-white/70 p-3"><div className="text-xl font-semibold">{value}</div><div className="mt-1 text-xs text-emerald-800/75">{label}</div></div>)}</div><p className="mt-3 text-xs leading-5 text-emerald-800/80">{result.note}</p></div>}
            <div className="mt-5 flex flex-wrap items-center justify-between gap-3"><div className="inline-flex items-center gap-2 text-xs text-slate-500"><LockKeyhole size={14} />Parameter values are never imported.</div><button onClick={importSpec} disabled={!file || busy || !Number.isSafeInteger(targetId) || targetId <= 0} className="inline-flex min-h-11 items-center gap-2 rounded-lg bg-blue-600 px-5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50">{busy ? <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/40 border-t-white" /> : <FileUp size={16} />}{busy ? "Validating and importing…" : "Import specification"}</button></div>
          </section>

          <aside className="space-y-4">
            <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm"><div className="flex items-center gap-2 font-semibold text-slate-900"><ShieldCheck size={18} className="text-emerald-600" />What gets imported</div><ul className="mt-4 space-y-3 text-sm leading-5 text-slate-600"><li className="flex gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0 text-emerald-600" />Path templates and supported HTTP methods</li><li className="flex gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0 text-emerald-600" />Path, query, header, and body parameter names and inferred types</li><li className="flex gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0 text-emerald-600" />Security scheme names and authentication requirements</li><li className="flex gap-2"><CheckCircle2 size={16} className="mt-0.5 shrink-0 text-emerald-600" />Owner and business-flow hints from route prefixes</li></ul></div>
            <div className="rounded-2xl border border-blue-100 bg-blue-50 p-5"><div className="text-sm font-semibold text-blue-950">After import</div><p className="mt-2 text-sm leading-6 text-blue-900/75">Routes are classified as active, zombie, or shadow using observed traffic. Documented routes with no recent traffic are highlighted for review.</p></div>
            <div className="rounded-xl border border-slate-200 bg-white p-4 text-xs leading-5 text-slate-500"><strong className="text-slate-700">URL imports</strong> are available through the API for specifications hosted on the target’s authorized origin.</div>
          </aside>
        </div>
      </div>
    </main>
  );
}
