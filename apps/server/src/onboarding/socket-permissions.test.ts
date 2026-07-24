import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listenEgressProxy } from "./egress-proxy.js";
import { listenSecretBroker } from "./secret-broker.js";

const cleanupPaths: string[] = [];
const cleanupServers: http.Server[] = [];

afterEach(async () => {
  await Promise.all(cleanupServers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  await Promise.all(cleanupPaths.splice(0).map((target) => fs.rm(target, { recursive: true, force: true })));
});

async function verifyListener(
  listen: (server: http.Server, socketPath: string) => Promise<void>
): Promise<{ directoryMode: number; socketMode: number }> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "kcml-socket-permissions-"));
  cleanupPaths.push(directory);
  const socketPath = path.join(directory, "proxy.sock");
  const server = http.createServer((_request, reply) => reply.writeHead(200).end());
  cleanupServers.push(server);
  await listen(server, socketPath);
  const directoryStat = await fs.stat(directory);
  const socketStat = await fs.stat(socketPath);
  return {
    directoryMode: directoryStat.mode & 0o777,
    socketMode: socketStat.mode & 0o777
  };
}

describe("broker socket permissions", () => {
  it("keeps the egress proxy socket connectable for rootless repository runtimes", async () => {
    const result = await verifyListener(listenEgressProxy);
    expect(result.directoryMode).toBe(0o711);
    expect(result.socketMode).toBe(0o666);
  });

  it("keeps the secret broker socket connectable for rootless repository runtimes", async () => {
    const result = await verifyListener(listenSecretBroker);
    expect(result.directoryMode).toBe(0o711);
    expect(result.socketMode).toBe(0o666);
  });
});
