import React, { useState } from "react";
import { CheckCircle2, Clock3, KeyRound, ShieldCheck } from "lucide-react";
import { Modal } from "./common.js";
import { api, csrf } from "./ui-helpers.js";

type LoginPasswordResponse =
  | { ok: true; csrfToken: string; trustedDeviceExpiresAt?: string | null }
  | { ok: false; mfaRequired: true; challengeExpiresAt: string; trustedDeviceWindowHours: number };

type LoginMfaResponse = { ok: true; csrfToken: string; trustedDeviceExpiresAt?: string | null };

export function Login({ notice, onLogin }: { notice?: string; onLogin: () => void }) {
  const [step, setStep] = useState<"password" | "mfa">("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [trustedWindowHours, setTrustedWindowHours] = useState<number | null>(null);
  const [error, setError] = useState("");

  async function submitPassword(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    try {
      const result = await api<LoginPasswordResponse>("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
      if (!result.ok && result.mfaRequired) {
        setStep("mfa");
        setCode("");
        setTrustedWindowHours(result.trustedDeviceWindowHours);
        return;
      }
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Přihlášení selhalo");
    }
  }

  async function submitMfa(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api<LoginMfaResponse>("/api/login/mfa", { method: "POST", body: JSON.stringify({ code }) });
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : "MFA ověření selhalo");
    }
  }

  return <main className="login-shell"><section className="login-panel">
    <div className="brand-row"><ShieldCheck size={28} /><strong>KCML</strong></div>
    <h1>Správce komponent</h1>
    {notice ? <div className="login-notice" role="status"><Clock3 size={18} /><span><strong>Je nutné se znovu přihlásit</strong>{notice}</span></div> : null}
    {step === "password" ? <form onSubmit={(event) => { void submitPassword(event); }}>
      <label>Uživatel<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label>
      <label>Heslo<input value={password} onChange={(event) => setPassword(event.target.value)} type="password" autoComplete="current-password" /></label>
      {error ? <p className="error">{error}</p> : null}
      <button type="submit"><KeyRound size={18} /> Pokračovat</button>
    </form> : <form onSubmit={(event) => { void submitMfa(event); }}>
      <div className="login-notice" role="status">
        <ShieldCheck size={18} />
        <span><strong>Vyžadováno MFA ověření</strong>Tento počítač si po úspěšném ověření zapamatujeme na {trustedWindowHours ?? 48} hodin.</span>
      </div>
      <label>MFA nebo recovery kód<input value={code} onChange={(event) => setCode(event.target.value)} autoComplete="one-time-code" /></label>
      {error ? <p className="error">{error}</p> : null}
      <div className="modal-actions">
        <button type="button" className="secondary" onClick={() => { setStep("password"); setCode(""); setError(""); }}>Zpět</button>
        <button type="submit"><ShieldCheck size={18} /> Ověřit a přihlásit</button>
      </div>
    </form>}
  </section></main>;
}

export function BootstrapPage({ onComplete }: { onComplete: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [bootstrapSecret, setBootstrapSecret] = useState("");
  const [completed, setCompleted] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api("/api/bootstrap", {
        method: "POST",
        body: JSON.stringify({ username, password, bootstrapSecret: bootstrapSecret || undefined })
      });
      setCompleted(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "První nastavení selhalo.");
    }
  }

  return <main className="login-shell"><section className="login-panel">
    <div className="brand-row"><ShieldCheck size={28} /><strong>KCML</strong></div>
    <h1>První bezpečné nastavení</h1>
    {completed ? <div className="security-stack">
      <div className="notice success"><CheckCircle2 size={18} /><span>Vlastník byl vytvořen. MFA si můžete zapnout hned po přihlášení v sekci Bezpečnost.</span></div>
      <button onClick={onComplete}>Pokračovat k přihlášení</button>
    </div> : <form onSubmit={(event) => { void submit(event); }}>
      <label>Uživatelské jméno vlastníka<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label>
      <label>Heslo<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /></label>
      <label>Bootstrap secret pro vzdálené nastavení (volitelné)<input type="password" value={bootstrapSecret} onChange={(event) => setBootstrapSecret(event.target.value)} autoComplete="off" /></label>
      {error ? <p className="error">{error}</p> : null}
      <button type="submit"><ShieldCheck size={18} /> Vytvořit vlastníka</button>
    </form>}
  </section></main>;
}

export function ReauthModal({ onClose }: { onClose: () => void }) {
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    try {
      await api("/api/reauth", { method: "POST", headers: { "x-csrf-token": csrf() }, body: JSON.stringify({ password, totp }) });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Opětovné ověření selhalo.");
    }
  }
  return <Modal title="Potvrdit citlivou operaci" onClose={onClose}><form className="modal-form" onSubmit={(event) => { void submit(event); }}>
    <p>Zadejte znovu heslo a MFA kód. Ověření bude platit deset minut.</p>
    <label>Heslo<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label>
    <label>MFA kód nebo recovery kód<input value={totp} onChange={(event) => setTotp(event.target.value)} autoComplete="one-time-code" /></label>
    {error ? <p className="error">{error}</p> : null}
    <footer className="modal-actions"><button type="button" className="secondary" onClick={onClose}>Zrušit</button><button type="submit">Ověřit</button></footer>
  </form></Modal>;
}
