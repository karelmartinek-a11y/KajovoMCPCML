// @vitest-environment jsdom
import React from "react";
import axe from "axe-core";
import { cleanup, render, screen } from "@testing-library/react";
import { userEvent } from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ExternalComponentsPage } from "./external-components-page.js";
import type { ExternalTarget } from "./types.js";

afterEach(() => cleanup());

describe("external component administration", () => {
  it("renders circuit policy, accepts keyboard input and has no axe violations", async () => {
    const target: ExternalTarget = { id: "target-1", targetKey: "payroll", displayName: "Payroll", baseUrl: "https://api.example.com", auditRequired: true, allowedPathPrefixes: ["/mcp"], connectTimeoutMs: 5000, requestTimeoutMs: 15000, maxRetries: 1, circuitState: "CLOSED", circuitFailureCount: 0, circuitFailureThreshold: 5, circuitOpenSeconds: 60, status: "ACTIVE", createdAt: "2026-07-21T00:00:00Z", revokedAt: null };
    const { container } = render(<ExternalComponentsPage principals={[]} targets={[target]} permissions={[]} components={[]} role="ADMIN" onRefresh={vi.fn()} onCreatePrincipal={vi.fn()} onCreateTarget={vi.fn()} onRotatePrincipal={vi.fn()} onSetPrincipalStatus={vi.fn()} onSetTargetStatus={vi.fn()} onSetPermission={vi.fn()} />);
    expect(screen.getByText("CLOSED")).toBeTruthy();
    expect(screen.getByText("0/5, cooldown 60s")).toBeTruthy();
    const threshold = screen.getByLabelText("Circuit threshold");
    await userEvent.setup().clear(threshold);
    await userEvent.setup().type(threshold, "8");
    expect((threshold as HTMLInputElement).value).toBe("8");
    expect((await axe.run(container)).violations).toEqual([]);
  });
});
