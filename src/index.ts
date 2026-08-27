import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { config as loadDotEnv } from "dotenv";

import { loadConfig } from "./config.js";
import { createRuntime } from "./runtime.js";

export interface StartableRuntime {
  start(): Promise<void>;
  close(): Promise<void>;
}

export interface ShutdownTarget {
  once(signal: string, listener: () => void): unknown;
}

export function installShutdownHandlers(
  runtime: Pick<StartableRuntime, "close">,
  target: ShutdownTarget = process,
  onError: (error: unknown) => void = (error) => console.error(error),
): () => Promise<void> {
  let closePromise: Promise<void> | undefined;
  const shutdown = (): Promise<void> => {
    if (!closePromise) {
      closePromise = runtime.close().catch((error: unknown) => {
        onError(error);
      });
    }
    return closePromise;
  };

  for (const signal of ["SIGINT", "SIGTERM"]) {
    target.once(signal, () => {
      void shutdown();
    });
  }
  return shutdown;
}

export async function startRuntime(
  runtime: StartableRuntime,
  target: ShutdownTarget = process,
  onError: (error: unknown) => void = (error) => console.error(error),
): Promise<void> {
  const shutdown = installShutdownHandlers(runtime, target, onError);
  try {
    await runtime.start();
  } catch (error) {
    await shutdown();
    throw error;
  }
}

export async function main(): Promise<void> {
  loadDotEnv();
  const config = loadConfig();
  const runtime = await createRuntime(config, {
    onBotError: async (error) => {
      console.error("Telegram bot polling failed", error);
      await runtime.close();
    },
  });
  await startRuntime(runtime);
}

function isMainModule(): boolean {
  const entrypoint = process.argv[1];
  return (
    entrypoint !== undefined &&
    resolve(entrypoint) === fileURLToPath(import.meta.url)
  );
}

if (isMainModule()) {
  void main().catch((error: unknown) => {
    console.error("Failed to start authentication server", error);
    process.exitCode = 1;
  });
}
