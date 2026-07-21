// @vitest-environment jsdom
import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CredentialsPage } from "./credential-pages.js";
import type { AccessTokenCredential } from "./types.js";

afterEach(() => cleanup());

describe("credential terminology", () => {
  it("uses access token terminology for the long-lived access token registry", () => {
    const credential: AccessTokenCredential = {
      id: "credential-1",
      publicId: "Kaja0001",
      label: "CI klient",
      fingerprint: "fingerprint",
      active: true,
      revokedAt: null,
      deletedAt: null,
      createdAt: "2026-07-16T00:00:00.000Z",
      updatedAt: "2026-07-16T00:00:00.000Z",
      expiresAt: null,
      permissionCount: 1,
      activeAccessTokenCount: 1,
      lastTokenIssuedAt: "2026-07-16T00:01:00.000Z",
      lastTokenExpiresAt: "2026-07-16T01:01:00.000Z",
      lastUsedAt: "2026-07-16T00:02:00.000Z"
    };
    render(
      <CredentialsPage
        credentials={[credential]}
        onOpenCreate={vi.fn()}
        onEditPermissions={vi.fn()}
        onRename={vi.fn()}
        onConfirm={vi.fn()}
        onRefresh={vi.fn()}
      />
    );
    expect(screen.getByRole("heading", { name: "Přístupové tokeny" })).toBeTruthy();
    expect(screen.getByText(/dlouhodobých přístupových tokenů/i)).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Poslední vydání krátkodobého tokenu" })).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Poslední použití" })).toBeTruthy();
  });
});
