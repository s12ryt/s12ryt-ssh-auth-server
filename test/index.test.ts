import assert from "node:assert/strict";
import test from "node:test";

import {
  installShutdownHandlers,
  startRuntime,
  type ShutdownTarget,
  type StartableRuntime,
} from "../src/index.js";

class FakeTarget implements ShutdownTarget {
  readonly listeners = new Map<string, () => void>();

  once(signal: string, listener: () => void): void {
    this.listeners.set(signal, listener);
  }
}

class FakeRuntime implements StartableRuntime {
  startCount = 0;
  closeCount = 0;
  shouldFail = false;

  async start(): Promise<void> {
    this.startCount += 1;
    if (this.shouldFail) throw new Error("listen failed");
  }

  async close(): Promise<void> {
    this.closeCount += 1;
  }
}

test("startRuntime starts the service and shutdown handlers close it once", async () => {
  const runtime = new FakeRuntime();
  const target = new FakeTarget();

  await startRuntime(runtime, target);
  assert.equal(runtime.startCount, 1);
  assert.deepEqual([...target.listeners.keys()], ["SIGINT", "SIGTERM"]);

  target.listeners.get("SIGTERM")?.();
  target.listeners.get("SIGINT")?.();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(runtime.closeCount, 1);
});

test("startRuntime closes the service when startup fails", async () => {
  const runtime = new FakeRuntime();
  runtime.shouldFail = true;

  await assert.rejects(
    startRuntime(runtime, new FakeTarget()),
    /listen failed/,
  );
  assert.equal(runtime.closeCount, 1);
});

test("installShutdownHandlers is idempotent for repeated signals", async () => {
  const runtime = new FakeRuntime();
  const target = new FakeTarget();
  installShutdownHandlers(runtime, target);

  target.listeners.get("SIGINT")?.();
  target.listeners.get("SIGINT")?.();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(runtime.closeCount, 1);
});
