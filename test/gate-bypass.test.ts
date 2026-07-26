import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { baseCommand, stripWrappers } from "../src/base-command.ts";
import { PermissionStore } from "../src/permission-store.ts";

/** Fixture: allow-listed wrappers + denies that C1/C2/C4 must hit. */
function fixtureStore(): { dir: string; store: PermissionStore } {
  const dir = mkdtempSync(join(tmpdir(), "pi-gate-bypass-"));
  const path = join(dir, "permission.json");
  writeFileSync(
    path,
    JSON.stringify(
      {
        bash: {
          env: "allow",
          strace: "allow",
          ltrace: "allow",
          echo: "allow",
          cat: "allow",
          grep: "allow",
          "git status*": "allow",
          dd: "deny",
          rm: "deny",
        },
        paths: {
          "**/.env": "deny",
          "/etc/shadow": "deny",
        },
      },
      null,
      2,
    ) + "\n",
  );
  return { dir, store: new PermissionStore(path) };
}

function cleanup(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

test("stripWrappers peels env/strace/timeout flags to the inner binary", () => {
  assert.equal(stripWrappers("env dd if=/dev/zero of=/dev/sda"), "dd if=/dev/zero of=/dev/sda");
  assert.equal(stripWrappers("env -i rm -rf /tmp/x"), "rm -rf /tmp/x");
  assert.equal(stripWrappers("strace -f rm -rf /tmp/x"), "rm -rf /tmp/x");
  assert.equal(stripWrappers("ltrace rm -rf /tmp/x"), "rm -rf /tmp/x");
  assert.equal(stripWrappers("env sudo rm -rf /"), "sudo rm -rf /");
  assert.equal(stripWrappers("timeout 5 npm test"), "npm test");
  assert.equal(stripWrappers("xargs echo"), "echo");
  assert.equal(stripWrappers("env"), "");
  assert.equal(baseCommand("strace -f rm -rf /tmp/x"), "rm");
  assert.equal(baseCommand("env -i rm -rf /tmp/x"), "rm");
  assert.equal(baseCommand("env"), "env");
});

test("C1: wrapper laundering — env/strace/ltrace cannot allow a denied inner", () => {
  const { dir, store } = fixtureStore();
  try {
    for (const cmd of [
      "env dd if=/dev/zero of=/dev/sda",
      "env rm -rf /tmp/x",
      "strace -f rm -rf /tmp/x",
      "ltrace rm -rf /tmp/x",
      "env -i rm -rf /tmp/x",
    ]) {
      const plan = store.planBash(cmd);
      assert.equal(plan.action, "deny", cmd);
      if (plan.action === "deny") {
        assert.equal(plan.kind, "bash", cmd);
      }
    }
  } finally {
    cleanup(dir);
  }
});

test("C2: env/strace sudo → sudo_redirect (not allow)", () => {
  const { dir, store } = fixtureStore();
  try {
    for (const cmd of [
      "env sudo rm -rf /",
      "env doas rm -rf /",
      "strace -f sudo -n true",
    ]) {
      const plan = store.planBash(cmd);
      assert.equal(plan.action, "deny", cmd);
      if (plan.action === "deny") {
        assert.equal(plan.kind, "sudo_redirect", cmd);
      }
    }
    // Leading sudo still redirects the same way.
    const plain = store.planBash("sudo rm -rf /");
    assert.equal(plain.action, "deny");
    if (plain.action === "deny") assert.equal(plain.kind, "sudo_redirect");
  } finally {
    cleanup(dir);
  }
});

test("C4: ../ traversal + cwd resolve hits absolute path denies", () => {
  const { dir, store } = fixtureStore();
  try {
    // cwd depth matches the ../ count in each string so resolve → /etc/shadow.
    const cat = store.planBash("cat ../../../etc/shadow", { cwd: "/a/b/c" });
    assert.equal(cat.action, "deny");
    if (cat.action === "deny") assert.equal(cat.kind, "path");

    const grep = store.planBash("grep -r x ../../etc/shadow", { cwd: "/a/b" });
    assert.equal(grep.action, "deny");
    if (grep.action === "deny") assert.equal(grep.kind, "path");

    // Absolute still denies (and cwd is optional).
    const abs = store.planBash("cat /etc/shadow");
    assert.equal(abs.action, "deny");
    if (abs.action === "deny") assert.equal(abs.kind, "path");

    // Raw-token path check kept: $HOME/.env still denies literally.
    const home = store.planBash("cat $HOME/.env");
    assert.equal(home.action, "deny");
    if (home.action === "deny") assert.equal(home.kind, "path");
  } finally {
    cleanup(dir);
  }
});

test("no over-block: bare env, timeout/xargs/npm/git still allow or ask", () => {
  const { dir, store } = fixtureStore();
  try {
    // Bare wrapper — its own allow still works.
    assert.equal(store.planBash("env").action, "allow");

    // Wrappers resolving to unruled/allow binaries: ask or allow, never deny.
    for (const cmd of [
      "timeout 5 npm test",
      "xargs echo",
      "npm test",
      "git status",
    ]) {
      const plan = store.planBash(cmd);
      assert.notEqual(plan.action, "deny", cmd);
    }
    // xargs echo → echo is allow
    assert.equal(store.planBash("xargs echo").action, "allow");
    // git status* allow
    assert.equal(store.planBash("git status").action, "allow");
    // npm has no rule → ask
    assert.equal(store.planBash("npm test").action, "ask");
    assert.equal(store.planBash("timeout 5 npm test").action, "ask");
  } finally {
    cleanup(dir);
  }
});
