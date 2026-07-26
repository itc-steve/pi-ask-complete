import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PermissionStore } from "../src/permission-store.ts";

/** Fixture matching the yolo contract: path/bash/tool denies + some allows. */
function fixtureStore(): {
  dir: string;
  path: string;
  fixtureBody: string;
  store: PermissionStore;
} {
  const dir = mkdtempSync(join(tmpdir(), "pi-yolo-"));
  const path = join(dir, "permission.json");
  const fixtureBody =
    JSON.stringify(
      {
        paths: {
          "**/.env": "deny",
          "**/.ssh/**": "deny",
          "Projects/**": "allow",
        },
        bash: {
          ls: "allow",
          rm: "deny",
        },
        tools: {
          some_tool: "deny",
        },
      },
      null,
      2,
    ) + "\n";
  writeFileSync(path, fixtureBody);
  return { dir, path, fixtureBody, store: new PermissionStore(path) };
}

function cleanup(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

test("yolo: ask → allow only under yolo (curl has no rule)", () => {
  const { dir, store } = fixtureStore();
  try {
    assert.equal(store.yolo, false);
    const off = store.planBash("curl https://x");
    assert.equal(off.action, "ask");

    store.setYolo(true);
    assert.equal(store.yolo, true);
    const on = store.planBash("curl https://x");
    assert.equal(on.action, "allow");
    assert.equal(store.checkUnit("curl https://x"), "allow");
  } finally {
    cleanup(dir);
  }
});

test("yolo: bash deny stays deny (rm)", () => {
  const { dir, store } = fixtureStore();
  try {
    const off = store.planBash("rm -rf /tmp/x");
    assert.equal(off.action, "deny");
    if (off.action === "deny") {
      assert.equal(off.kind, "bash");
      assert.equal(off.label, "rm");
    }
    assert.equal(store.checkUnit("rm -rf /tmp/x"), "deny");

    store.setYolo(true);
    const on = store.planBash("rm -rf /tmp/x");
    assert.equal(on.action, "deny");
    if (on.action === "deny") {
      assert.equal(on.kind, "bash");
      assert.equal(on.label, "rm");
    }
    assert.equal(store.checkUnit("rm -rf /tmp/x"), "deny");
  } finally {
    cleanup(dir);
  }
});

test("yolo: deny wins inside a chain (ls; rm -rf /tmp/x)", () => {
  const { dir, store } = fixtureStore();
  try {
    // ls is allow; rm is deny → whole plan must deny, not ask/allow the chain
    const off = store.planBash("ls; rm -rf /tmp/x");
    assert.equal(off.action, "deny");
    if (off.action === "deny") {
      assert.equal(off.kind, "bash");
      assert.equal(off.label, "rm");
    }

    store.setYolo(true);
    const on = store.planBash("ls; rm -rf /tmp/x");
    assert.equal(on.action, "deny");
    if (on.action === "deny") {
      assert.equal(on.kind, "bash");
      assert.equal(on.label, "rm");
    }
  } finally {
    cleanup(dir);
  }
});

test("yolo: path deny stays deny for bash path args and decide(read)", () => {
  const { dir, store } = fixtureStore();
  try {
    for (const cmd of ["cat .env", "cat ~/.ssh/id_rsa"]) {
      const off = store.planBash(cmd);
      assert.equal(off.action, "deny", `off ${cmd}`);
      if (off.action === "deny") assert.equal(off.kind, "path", `off kind ${cmd}`);

      store.setYolo(true);
      const on = store.planBash(cmd);
      assert.equal(on.action, "deny", `on ${cmd}`);
      if (on.action === "deny") assert.equal(on.kind, "path", `on kind ${cmd}`);
      store.setYolo(false);
    }

    // via decide("read", …) for secret paths
    const envOff = store.decide("read", "read", ".env");
    assert.equal(envOff.state, "deny");
    const sshOff = store.decide("read", "read", "~/.ssh/id_rsa");
    assert.equal(sshOff.state, "deny");

    store.setYolo(true);
    assert.equal(store.decide("read", "read", ".env").state, "deny");
    assert.equal(store.decide("read", "read", "~/.ssh/id_rsa").state, "deny");
  } finally {
    cleanup(dir);
  }
});

test("yolo: sudo redirect survives (leading and mid-chain)", () => {
  const { dir, store } = fixtureStore();
  try {
    for (const cmd of ["sudo apt install x", "ls && sudo rm x"]) {
      const off = store.planBash(cmd);
      assert.equal(off.action, "deny", `off ${cmd}`);
      if (off.action === "deny") {
        assert.equal(off.kind, "sudo_redirect", `off kind ${cmd}`);
      }

      store.setYolo(true);
      const on = store.planBash(cmd);
      assert.equal(on.action, "deny", `on ${cmd}`);
      if (on.action === "deny") {
        assert.equal(on.kind, "sudo_redirect", `on kind ${cmd}`);
      }
      store.setYolo(false);
    }
  } finally {
    cleanup(dir);
  }
});

test("yolo: tool deny stays deny; unknown tool ask → allow", () => {
  const { dir, store } = fixtureStore();
  try {
    assert.equal(store.checkTool("some_tool"), "deny");
    assert.equal(store.decide("some_tool", "some_tool").state, "deny");
    assert.equal(store.checkTool("unknown_tool"), "ask");
    assert.equal(store.decide("unknown_tool", "unknown_tool").state, "ask");

    store.setYolo(true);
    assert.equal(store.checkTool("some_tool"), "deny");
    assert.equal(store.decide("some_tool", "some_tool").state, "deny");
    assert.equal(store.checkTool("unknown_tool"), "allow");
    assert.equal(store.decide("unknown_tool", "unknown_tool").state, "allow");
  } finally {
    cleanup(dir);
  }
});

test("yolo: setYolo(true) then clearSession() clears yolo and restores ask", () => {
  const { dir, store } = fixtureStore();
  try {
    store.setYolo(true);
    assert.equal(store.yolo, true);
    assert.equal(store.planBash("curl https://x").action, "allow");
    assert.equal(store.checkTool("unknown_tool"), "allow");

    store.clearSession();
    assert.equal(store.yolo, false);
    assert.equal(store.planBash("curl https://x").action, "ask");
    assert.equal(store.checkTool("unknown_tool"), "ask");
    // denies still deny after clear
    assert.equal(store.planBash("rm -rf /tmp/x").action, "deny");
  } finally {
    cleanup(dir);
  }
});

test("yolo: unresolved expansion asks off, allows on (denies still deny)", () => {
  const { dir, store } = fixtureStore();
  try {
    // Fail-closed without yolo (can't prove target isn't a secret).
    // Under yolo, user opted out of asks — upgrade like any other ask.
    // Resolved path denies still block either way (`cat .env`).
    const globs = [
      "cat .*",
      "cat .en*",
      "cat {.env,x}",
      "cat ~/.ss?/id_rsa",
      "cat $SECRET",
      "find . -name '*.md'",
    ];

    for (const cmd of globs) {
      assert.equal(store.planBash(cmd).action, "ask", `off ${cmd}`);
    }

    store.setYolo(true);
    for (const cmd of globs) {
      assert.equal(store.planBash(cmd).action, "allow", `on ${cmd}`);
      assert.equal(store.checkBash(cmd), "allow", `on checkBash ${cmd}`);
      assert.equal(store.decide("bash", cmd).state, "allow", `on decide ${cmd}`);
    }

    // Resolved denies never upgrade under yolo.
    assert.equal(store.planBash("cat .env").action, "deny");
    assert.equal(store.planBash("rm -rf /tmp/x").action, "deny");
    // Plain rule-less ask still upgrades.
    assert.equal(store.planBash("curl https://x").action, "allow");
  } finally {
    cleanup(dir);
  }
});

test("yolo: does NOT write to disk (fixture bytes identical after yolo allow)", () => {
  const { dir, path, fixtureBody, store } = fixtureStore();
  try {
    const before = readFileSync(path);
    assert.equal(before.toString("utf-8"), fixtureBody);

    store.setYolo(true);
    assert.equal(store.planBash("curl https://x").action, "allow");
    assert.equal(store.checkTool("unknown_tool"), "allow");
    // also exercise checkUnit / decide under yolo
    assert.equal(store.checkUnit("whoami"), "allow");
    assert.equal(store.decide("bash", "curl https://x").state, "allow");

    const after = readFileSync(path);
    assert.equal(Buffer.compare(before, after), 0, "permission.json must be byte-identical");
    assert.equal(after.toString("utf-8"), fixtureBody);
  } finally {
    cleanup(dir);
  }
});
