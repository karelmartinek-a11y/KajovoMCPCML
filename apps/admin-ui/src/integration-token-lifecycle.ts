const NEAR_MAXIMUM_MS = 2 * 60 * 60 * 1000;

export type IntegrationTokenLifecycleInput = {
  issuedAt: string;
  expiresAt: string;
  maxExpiresAt: string;
  revokedAt: string | null;
  jobId: string | null;
  jobState: string | null;
  heartbeatAt: string | null;
};

export type IntegrationRunState = "waiting" | "running" | "starting" | "paused" | "completed" | "inactive";

export type IntegrationTokenLifecycle = {
  currentRemainingMs: number;
  maximumRemainingMs: number;
  maximumProgressPercent: number;
  nearMaximum: boolean;
  tokenValid: boolean;
  runState: IntegrationRunState;
  runLabel: string;
  protectionLabel: string;
  protectionActive: boolean;
};

function timestamp(value: string | null): number | null {
  if (!value) return null;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : null;
}

export function getIntegrationTokenLifecycle(token: IntegrationTokenLifecycleInput, nowMs: number): IntegrationTokenLifecycle {
  const issuedAtMs = timestamp(token.issuedAt) ?? nowMs;
  const expiresAtMs = timestamp(token.expiresAt) ?? 0;
  const maxExpiresAtMs = timestamp(token.maxExpiresAt) ?? issuedAtMs;
  const currentRemainingMs = Math.max(0, expiresAtMs - nowMs);
  const maximumRemainingMs = Math.max(0, maxExpiresAtMs - nowMs);
  const maximumDurationMs = Math.max(1, maxExpiresAtMs - issuedAtMs);
  const maximumProgressPercent = Math.min(100, Math.max(0, ((nowMs - issuedAtMs) / maximumDurationMs) * 100));
  const tokenValid = !token.revokedAt && currentRemainingMs > 0;

  let runState: IntegrationRunState;
  let runLabel: string;
  let protectionLabel: string;

  if (!tokenValid) {
    runState = "inactive";
    runLabel = token.revokedAt ? "Token revokován" : "Platnost skončila";
    protectionLabel = "Integrační token není použitelný";
  } else if (!token.jobId) {
    runState = "waiting";
    runLabel = "Integrace nezahájena";
    protectionLabel = "Token čeká na první upload";
  } else if (token.jobState === "ACTIVE") {
    runState = "completed";
    runLabel = "Integrace dokončena";
    protectionLabel = "Token byl spotřebován úspěšnou integrací";
  } else if (token.jobState && ["FAILED", "QUARANTINED", "CANCELLED"].includes(token.jobState)) {
    runState = "paused";
    runLabel = "Integrace nedokončena";
    protectionLabel = "Nedokončený runtime stav bude uklizen";
  } else {
    runState = "running";
    runLabel = "Integrace běží";
    protectionLabel = "Platí pevné 24hodinové okno bez prodlužování";
  }

  return {
    currentRemainingMs,
    maximumRemainingMs,
    maximumProgressPercent,
    nearMaximum: maximumRemainingMs > 0 && maximumRemainingMs <= NEAR_MAXIMUM_MS,
    tokenValid,
    runState,
    runLabel,
    protectionLabel,
    protectionActive: false
  };
}

export function formatMinuteSecondCountdown(remainingMs: number): string {
  const totalSeconds = Math.max(0, Math.ceil(remainingMs / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${formatCzNumber(minutes)} min ${String(seconds).padStart(2, "0")} s`;
}
import { formatCzNumber } from "./ui-helpers.js";
