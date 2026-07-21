// @vitest-environment jsdom
import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { userEvent } from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AppLayout, PageRouter } from "./app-layout.js";

afterEach(() => cleanup());

describe("application layout and router", () => {
  it("keeps auditor navigation read-only and routes the selected page", async () => {
    const onPageChange = vi.fn();
    render(
      <AppLayout
        page="audit"
        role="AUDITOR"
        accountName="auditor"
        error=""
        onPageChange={onPageChange}
        onLogout={vi.fn()}
        releaseLabel="Release 2026.07.22"
        buildLabel="Build 35754cf"
      >
        <PageRouter page="audit" routes={{ audit: <h1>Auditní události</h1>, monitoring: <h1>Monitoring</h1> }} />
      </AppLayout>
    );
    expect(screen.getByRole("heading", { name: "Auditní události" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Přístupové tokeny/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Konfigurace/ })).toBeNull();
    await userEvent.click(screen.getByRole("button", { name: /Monitoring komponent/ }));
    expect(onPageChange).toHaveBeenCalledWith("monitoring");
  });

  it("renders release and build metadata supplied by the server", () => {
    render(
      <AppLayout
        page="components"
        role="OWNER"
        accountName="owner"
        error=""
        onPageChange={vi.fn()}
        onLogout={vi.fn()}
        releaseLabel="Release 2026.07.22"
        buildLabel="Build 35754cf"
      >
        <PageRouter page="components" routes={{ components: <h1>Katalog komponent</h1> }} />
      </AppLayout>
    );
    expect(screen.getByText("Release 2026.07.22")).toBeTruthy();
    expect(screen.getByText("Build 35754cf")).toBeTruthy();
    expect(screen.queryByText("Release 2026.07.21")).toBeNull();
    expect(screen.queryByText("Production")).toBeNull();
  });
});
