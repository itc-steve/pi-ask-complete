/**
 * Alert Herdr only when this pane is NOT being viewed.
 * Emitting herdr:blocked always was dinging even on the focused pane
 * (Herdr's "background only" sound did not hold for us).
 * Fail-safe: if we can't tell, treat as focused → no ding.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type EventsLike = {
  emit: (name: string, data?: unknown) => void;
};

let bus: EventsLike | undefined;

/** Injectable for tests. Resolves true when the user is looking at this pane. */
let isViewed: () => Promise<boolean> = defaultIsViewed;

export function bindHerdrAttention(events: EventsLike): void {
  bus = events;
  // Clear a stuck blocked count from earlier races / reloads.
  bus.emit("herdr:blocked", { active: false });
}

/** @internal test seam */
export function _setIsViewedForTest(fn: (() => Promise<boolean>) | undefined): void {
  isViewed = fn ?? defaultIsViewed;
}

async function defaultIsViewed(): Promise<boolean> {
  const paneId = process.env.HERDR_PANE_ID;
  if (process.env.HERDR_ENV !== "1" || !paneId) return true;

  try {
    const { stdout } = await execFileAsync("herdr", ["api", "snapshot"], {
      timeout: 800,
      maxBuffer: 4_000_000,
      env: process.env,
    });
    const snap = JSON.parse(stdout)?.result?.snapshot;
    const focused = snap?.focused_pane_id;
    // No focused id → don't guess; stay quiet.
    if (typeof focused !== "string") return true;
    return focused === paneId;
  } catch {
    return true;
  }
}

export async function withHerdrBlocked<T>(
  label: string,
  fn: () => Promise<T>,
): Promise<T> {
  // Only ping Herdr when the user is elsewhere.
  const alert = !(await isViewed());
  if (alert) {
    bus?.emit("herdr:blocked", { active: true, label });
  }
  try {
    return await fn();
  } finally {
    if (alert) {
      bus?.emit("herdr:blocked", { active: false });
    }
  }
}
