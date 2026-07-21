import React from "react";
import {
  Activity,
  AlertTriangle,
  Boxes,
  KeyRound,
  Lock,
  LockKeyhole,
  LogOut,
  Plus,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Workflow
} from "lucide-react";
import { pageNames, type AdminRole, type Page } from "./types.js";

export function PageRouter({ page, routes }: { page: Page; routes: Partial<Record<Page, React.ReactNode>> }) {
  return routes[page] ?? null;
}

export function AppLayout({
  page,
  role,
  accountName,
  error,
  onPageChange,
  onLogout,
  children,
  overlays,
  releaseLabel,
  buildLabel
}: {
  page: Page;
  role: AdminRole;
  accountName: string | null;
  error: string;
  onPageChange: (page: Page) => void;
  onLogout: () => void;
  children: React.ReactNode;
  overlays?: React.ReactNode;
  releaseLabel: string;
  buildLabel: string;
}) {
  const navigationButton = (target: Page, label: string, icon: React.ReactNode) => (
    <button aria-pressed={page === target} className={page === target ? "active" : ""} onClick={() => onPageChange(target)}>
      {icon}<span>{label}</span>
    </button>
  );
  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand-row"><span className="brand-mark"><ShieldCheck size={22} /></span><div><strong>KCML</strong><span>{releaseLabel}</span></div></div>
        <nav>
          {navigationButton("components", "Katalog komponent", <Boxes size={18} />)}
          {navigationButton("monitoring", "Monitoring komponent", <Activity size={18} />)}
          {role !== "AUDITOR" ? navigationButton("integration", "Integrační tokeny", <Workflow size={18} />) : null}
          {role !== "AUDITOR" ? navigationButton("secrets", "Secrets", <Lock size={18} />) : null}
          {role !== "AUDITOR" ? navigationButton("tokens", "Přístupové tokeny", <KeyRound size={18} />) : null}
          {role !== "AUDITOR" ? navigationButton("permissions", "Správa oprávnění", <LockKeyhole size={18} />) : null}
          {navigationButton("audit", "Audit", <Terminal size={18} />)}
          {role !== "AUDITOR" ? navigationButton("config", "Konfigurace", <SlidersHorizontal size={18} />) : null}
          {navigationButton("security", "Bezpečnost", <ShieldCheck size={18} />)}
          {role === "OWNER" ? navigationButton("admins", "Administrátoři", <Plus size={18} />) : null}
        </nav>
        <div className="sidebar-footer"><div className="environment"><span className="status-dot neutral" /><span>{buildLabel}</span></div><div className="account"><span className="avatar">{(accountName ?? "AD").slice(0, 2).toUpperCase()}</span><span><strong>{accountName ?? "Administrátor"}</strong><small>{role}</small></span></div><button onClick={onLogout}><LogOut size={16} /> Odhlásit se</button></div>
      </aside>
      <section className="workspace">
        <div className="mobile-topbar"><div className="brand-row"><span className="brand-mark"><ShieldCheck size={20} /></span><strong>KCML</strong></div><span>{pageNames[page]}</span></div>
        {error ? <div className="notice error"><AlertTriangle size={18} /> {error}</div> : null}
        {children}
      </section>
      {overlays}
    </main>
  );
}
