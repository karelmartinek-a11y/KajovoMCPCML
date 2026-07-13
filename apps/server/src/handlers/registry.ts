import type { McpServer } from "../domain/types.js";
import { ociHandler } from "./oci-client.js";

export type HandlerContext = {
  correlationId: string;
  server: McpServer;
  logger: { info: (obj: object, msg?: string) => void | Promise<void>; error: (obj: object, msg?: string) => void | Promise<void> };
};

export type KcmlHandler = {
  key: string;
  version: string;
  invoke(input: unknown, ctx: HandlerContext): Promise<unknown>;
};

const handlers = new Map<string, KcmlHandler>();

export function registerHandler(handler: KcmlHandler): void {
  const id = `${handler.key}@${handler.version}`;
  if (handlers.has(id)) throw new Error(`duplicate handler ${id}`);
  handlers.set(id, handler);
}

export function getHandler(server: McpServer): KcmlHandler | null {
  if (server.runtimeSocket && server.imageDigest) return ociHandler();
  return handlers.get(`${server.handlerKey}@${server.handlerVersion}`) ?? null;
}

export function registeredHandlerIds(): string[] {
  return [...handlers.keys()].sort();
}
