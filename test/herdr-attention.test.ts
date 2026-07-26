import assert from "node:assert/strict";
import { test } from "node:test";
import {
  _setIsViewedForTest,
  bindHerdrAttention,
  withHerdrBlocked,
} from "../src/herdr-attention.ts";

function capture() {
  const events: Array<{ name: string; data: unknown }> = [];
  bindHerdrAttention({
    emit(name, data) {
      events.push({ name, data });
    },
  });
  // bind clears with one false — drop it so tests see only panel traffic
  events.length = 0;
  return events;
}

test("unviewed: emits active true then false around fn", async () => {
  _setIsViewedForTest(async () => false);
  const events = capture();

  const out = await withHerdrBlocked("Permission needed", async () => {
    assert.equal(events.length, 1);
    assert.deepEqual(events[0], {
      name: "herdr:blocked",
      data: { active: true, label: "Permission needed" },
    });
    return 42;
  });

  assert.equal(out, 42);
  assert.deepEqual(events, [
    { name: "herdr:blocked", data: { active: true, label: "Permission needed" } },
    { name: "herdr:blocked", data: { active: false } },
  ]);
  _setIsViewedForTest(undefined);
});

test("viewed: no emit (no ding while looking)", async () => {
  _setIsViewedForTest(async () => true);
  const events = capture();

  const out = await withHerdrBlocked("Permission needed", async () => "ok");
  assert.equal(out, "ok");
  assert.deepEqual(events, []);
  _setIsViewedForTest(undefined);
});

test("unviewed: still clears on throw", async () => {
  _setIsViewedForTest(async () => false);
  const events = capture();

  await assert.rejects(
    () =>
      withHerdrBlocked("x", async () => {
        throw new Error("boom");
      }),
    /boom/,
  );
  assert.deepEqual(
    events.map((e) => e.data),
    [{ active: true, label: "x" }, { active: false }],
  );
  _setIsViewedForTest(undefined);
});

test("bind emits a clear to unstick prior blocked", () => {
  const events: unknown[] = [];
  bindHerdrAttention({
    emit(_n, data) {
      events.push(data);
    },
  });
  assert.deepEqual(events, [{ active: false }]);
});
