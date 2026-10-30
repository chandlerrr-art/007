"use client";

import { useEffect, useState, type FormEvent } from "react";
import { ArrowRight, Eye, EyeOff, Fingerprint, LockKeyhole, ShieldCheck } from "lucide-react";
import Dashboard from "./dashboard";

type Stage = "opening" | "login" | "dashboard";

const ACCESS_KEY = "007-workspace-access";

export default function ExperienceGate() {
  const [stage, setStage] = useState<Stage>("opening");
  const [showPassword, setShowPassword] = useState(false);
  const [identity, setIdentity] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (window.sessionStorage.getItem(ACCESS_KEY) === "granted") {
      setStage("dashboard");
      return;
    }

    const timer = window.setTimeout(() => setStage("login"), 3800);
    return () => window.clearTimeout(timer);
  }, []);

  function enterWorkspace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!identity.trim() || !password) {
      setError("Enter your workspace identity and access key.");
      return;
    }

    window.sessionStorage.setItem(ACCESS_KEY, "granted");
    setStage("dashboard");
  }

  if (stage === "dashboard") return <Dashboard />;

  if (stage === "opening") {
    return (
      <main className="opening-screen" aria-label="007 security operations loading">
        <div className="opening-grid" aria-hidden="true" />
        <div className="opening-glow opening-glow-one" aria-hidden="true" />
        <div className="opening-glow opening-glow-two" aria-hidden="true" />
        <button className="skip-opening" onClick={() => setStage("login")}>Skip intro</button>

        <section className="opening-content">
          <div className="opening-orbit" aria-hidden="true">
            <span className="orbit-ring orbit-ring-one" />
            <span className="orbit-ring orbit-ring-two" />
            <span className="opening-brand-mark">007</span>
          </div>
          <p className="opening-kicker"><span /> Authorized security operations</p>
          <h1 className="opening-title">See the risk.<br /><em>Control the response.</em></h1>
          <p className="opening-copy">Initializing your protected operations workspace.</p>
          <div className="opening-progress" aria-label="Loading workspace">
            <span className="opening-progress-bar" />
          </div>
          <div className="opening-status"><span>SECURE CHANNEL</span><span className="opening-status-value">ESTABLISHING</span></div>
        </section>
      </main>
    );
  }

  return (
    <main className="login-screen">
      <div className="login-visual" aria-hidden="true">
        <div className="login-grid" />
        <div className="login-visual-content">
          <div className="login-wordmark"><span>007</span> SECURITY OPERATIONS</div>
          <div className="login-message">
            <p>AUTHORIZED ENVIRONMENTS ONLY</p>
            <h1>Clarity at every<br />attack surface.</h1>
            <div className="login-feature"><ShieldCheck size={20} /><span><b>Guardrails active</b>Bounded scans and human review by default</span></div>
            <div className="login-feature"><Fingerprint size={20} /><span><b>Evidence you can trust</b>Deterministic verification and redacted output</span></div>
          </div>
          <div className="login-visual-footer"><span className="live-signal" /> SYSTEMS NOMINAL <b>v0.7</b></div>
        </div>
      </div>

      <section className="login-panel">
        <div className="mobile-wordmark"><span>007</span> SECURITY OPERATIONS</div>
        <div className="login-form-wrap">
          <div className="login-icon"><LockKeyhole size={22} /></div>
          <p className="login-kicker">SECURE WORKSPACE</p>
          <h2>Welcome back</h2>
          <p className="login-subtitle">Enter your workspace details to continue to the operations console.</p>

          <form onSubmit={enterWorkspace} noValidate>
            <label htmlFor="workspace-identity">Workspace identity</label>
            <input id="workspace-identity" autoComplete="username" value={identity} onChange={(event) => { setIdentity(event.target.value); setError(""); }} placeholder="name@organization.com" />

            <div className="password-label"><label htmlFor="workspace-key">Access key</label><button type="button">Need help?</button></div>
            <div className="password-field">
              <input id="workspace-key" type={showPassword ? "text" : "password"} autoComplete="current-password" value={password} onChange={(event) => { setPassword(event.target.value); setError(""); }} placeholder="Enter your access key" />
              <button type="button" aria-label={showPassword ? "Hide access key" : "Show access key"} onClick={() => setShowPassword((visible) => !visible)}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button>
            </div>

            {error && <p className="login-error" role="alert">{error}</p>}
            <button className="login-submit" type="submit">Enter workspace <ArrowRight size={17} /></button>
          </form>

          <p className="login-disclaimer">Local interface gate only. Production access must still be protected by the configured enterprise identity gateway.</p>
        </div>
        <footer className="login-footer"><span>Protected by 007 Safety Engine</span><span>Privacy&nbsp;&nbsp;·&nbsp;&nbsp;Security</span></footer>
      </section>
    </main>
  );
}
