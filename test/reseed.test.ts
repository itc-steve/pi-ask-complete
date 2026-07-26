import assert from "node:assert/strict";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  examplePermissionPath,
  PermissionStore,
} from "../src/permission-store.ts";

function tempPermissionPath(): { dir: string; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "pi-reseed-"));
  return { dir, path: join(dir, "permission.json") };
}

function cleanup(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

/** Assert example defaults are live (secrets denied, explore allowed). */
function assertExampleDefaults(store: PermissionStore): void {
  assert.equal(store.checkPath(".env"), "deny");
  assert.equal(store.checkPath("/home/u/.env"), "deny");
  assert.equal(store.checkPath("/home/u/.ssh/id_rsa"), "deny");
  assert.equal(store.checkPath("/etc/shadow"), "deny");
  assert.equal(store.checkBash("dd if=/dev/zero of=/tmp/x"), "deny");
  assert.equal(store.checkBash("ls"), "allow");
}

test("missing permission.json loads example defaults (secrets denied)", () => {
  const { dir, path } = tempPermissionPath();
  try {
    assert.equal(existsSync(path), false);
    const store = new PermissionStore(path);
    assertExampleDefaults(store);
  } finally {
    cleanup(dir);
  }
});

test("missing permission.json is re-created with example bytes", () => {
  const { dir, path } = tempPermissionPath();
  try {
    const store = new PermissionStore(path);
    assert.equal(existsSync(path), true);
    const written = readFileSync(path, "utf-8");
    const example = readFileSync(examplePermissionPath(), "utf-8");
    assert.equal(written, example);
    // touch store so it is not unused if asserts above pass via side effects
    assert.ok(store.filePath === path);
  } finally {
    cleanup(dir);
  }
});

test("anti-merge: one-entry file is obeyed verbatim (no example injection)", () => {
  const { dir, path } = tempPermissionPath();
  try {
    writeFileSync(path, JSON.stringify({ bash: { foo: "deny" } }) + "\n");
    const store = new PermissionStore(path);
    assert.equal(store.checkBash("foo"), "deny");
    // .env is NOT denied — example paths must not be merged in
    assert.equal(store.checkPath(".env"), undefined);
    assert.equal(store.checkPath("/home/u/.ssh/id_rsa"), undefined);
    assert.equal(store.checkPath("/etc/shadow"), undefined);
    assert.equal(store.checkBash("dd if=/dev/zero of=/tmp/x"), "ask");
    assert.equal(store.checkBash("ls"), "ask");
  } finally {
    cleanup(dir);
  }
});

test("empty present file {} is obeyed — no example injection", () => {
  const { dir, path } = tempPermissionPath();
  try {
    writeFileSync(path, JSON.stringify({ bash: {}, paths: {} }) + "\n");
    const store = new PermissionStore(path);
    assert.equal(store.checkPath(".env"), undefined);
    assert.equal(store.checkPath("/etc/shadow"), undefined);
    assert.equal(store.checkBash("ls"), "ask");
    assert.equal(store.checkBash("dd if=/dev/zero of=/tmp/x"), "ask");
  } finally {
    cleanup(dir);
  }
});

test("corrupt file keeps last-good rules", () => {
  const { dir, path } = tempPermissionPath();
  try {
    writeFileSync(
      path,
      JSON.stringify({
        bash: { ls: "allow", dd: "deny" },
        paths: { "**/.env": "deny" },
      }) + "\n",
    );
    const store = new PermissionStore(path);
    assert.equal(store.checkBash("ls"), "allow");
    assert.equal(store.checkBash("cat .env"), "deny");
    assert.equal(store.checkBash("dd if=/dev/zero of=/tmp/x"), "deny");

    writeFileSync(path, "{not json\n");
    store.reload();
    assert.equal(store.checkBash("ls"), "allow");
    assert.equal(store.checkBash("cat .env"), "deny");
    assert.equal(store.checkBash("dd if=/dev/zero of=/tmp/x"), "deny");
  } finally {
    cleanup(dir);
  }
});

test("M2: non-object JSON ([\"hi\"], \"x\") treated as corrupt (keep last-good)", () => {
  const { dir, path } = tempPermissionPath();
  try {
    writeFileSync(
      path,
      JSON.stringify({
        bash: { ls: "allow", dd: "deny" },
        paths: { "**/.env": "deny", "/etc/shadow": "deny" },
      }) + "\n",
    );
    const store = new PermissionStore(path);
    assert.equal(store.checkPath(".env"), "deny");
    assert.equal(store.checkBash("dd if=/dev/zero of=/tmp/x"), "deny");

    writeFileSync(path, '["hi"]\n');
    store.reload();
    assert.equal(store.checkPath(".env"), "deny");
    assert.equal(store.checkPath("/etc/shadow"), "deny");
    assert.equal(store.checkBash("ls"), "allow");
    assert.equal(store.checkBash("dd if=/dev/zero of=/tmp/x"), "deny");

    writeFileSync(path, '"x"\n');
    store.reload();
    assert.equal(store.checkPath(".env"), "deny");
    assert.equal(store.checkBash("dd if=/dev/zero of=/tmp/x"), "deny");
  } finally {
    cleanup(dir);
  }
});

test("delete-then-reload mid-session restores example defaults", () => {
  const { dir, path } = tempPermissionPath();
  try {
    // Start with a narrow custom ruleset (not the example).
    writeFileSync(
      path,
      JSON.stringify({ bash: { foo: "deny" }, paths: {} }) + "\n",
    );
    const store = new PermissionStore(path);
    assert.equal(store.checkBash("foo"), "deny");
    assert.equal(store.checkPath(".env"), undefined);

    // session_start path: file vanished, reload must restore defaults.
    unlinkSync(path);
    assert.equal(existsSync(path), false);
    store.reload();

    assertExampleDefaults(store);
    assert.equal(existsSync(path), true);
    assert.equal(
      readFileSync(path, "utf-8"),
      readFileSync(examplePermissionPath(), "utf-8"),
    );
  } finally {
    cleanup(dir);
  }
});
