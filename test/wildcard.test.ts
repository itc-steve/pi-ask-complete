import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { describeToolCall } from "../src/describe-tool.ts";
import { PermissionStore } from "../src/permission-store.ts";
import { compileGlob, matchGlob, resolveRules } from "../src/wildcard.ts";

const SAMPLE_CONFIG = {
  bash: {
    ls: "allow",
    sudo: "deny",
  },
  tools: {
    write: "ask",
    edit: "ask",
  },
  paths: {
    "**/.env.example": "allow",
    "**/*.env.example": "allow",
    "**/.env": "deny",
    "**/*.env": "deny",
    "**/.ssh/**": "deny",
  },
};

test("*.env matches .env and foo.env but NOT .env.example", () => {
  assert.equal(matchGlob("*.env", ".env"), true);
  assert.equal(matchGlob("*.env", "foo.env"), true);
  assert.equal(matchGlob("*.env", "/proj/foo.env"), true);
  assert.equal(matchGlob("*.env", ".env.example"), false);
  assert.equal(matchGlob("*.env", "/proj/.env.example"), false);
});

test("**/.env matches nested .env only", () => {
  assert.equal(matchGlob("**/.env", "/home/u/proj/.env"), true);
  assert.equal(matchGlob("**/.env", "/home/u/proj/.env.example"), false);
});

test("most-specific path rule wins when both match (.env.example over *.env)", () => {
  const rules = [
    { pattern: "**/*.env", state: "deny" as const },
    { pattern: "**/.env.example", state: "allow" as const },
    { pattern: "**/*.env.example", state: "allow" as const },
  ];
  assert.equal(resolveRules(rules, "/proj/.env.example"), "allow");
  assert.equal(resolveRules(rules, "/proj/foo.env"), "deny");
  assert.equal(resolveRules(rules, "/proj/readme.md"), undefined);
});

test("PermissionStore reads rules only from JSON (no code defaults)", () => {
  const dir = mkdtempSync(join(tmpdir(), "pi-ask-wc-"));
  const path = join(dir, "permission.json");
  writeFileSync(path, JSON.stringify(SAMPLE_CONFIG, null, 2));
  try {
    const store = new PermissionStore(path);
    assert.equal(store.checkPath("/home/u/app/.env"), "deny");
    assert.equal(store.checkPath("/home/u/app/prod.env"), "deny");
    assert.equal(store.checkPath("/home/u/app/.env.example"), "allow");
    assert.equal(store.checkPath("/home/u/app/.ssh/id_rsa"), "deny");
    assert.equal(store.checkPath("/home/u/app/src/main.ts"), undefined);

    // empty config → nothing path-denied; plain bins ask
    const emptyPath = join(dir, "empty.json");
    writeFileSync(emptyPath, "{}\n");
    const empty = new PermissionStore(emptyPath);
    assert.equal(empty.checkPath("/home/u/app/.env"), undefined);
    assert.equal(empty.decide("bash", "ls -la").state, "ask");
    // sudo/doas are hard-gated (redirect), not JSON policy
    assert.equal(empty.decide("bash", "sudo rm").state, "deny");

    store.allowPermanently("write", "write", "/home/u/app/.env");
    assert.equal(store.checkPath("/home/u/app/.env"), "allow");
    const disk = JSON.parse(readFileSync(path, "utf-8"));
    assert.equal(disk.paths["/home/u/app/.env"], "allow");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("decide uses JSON bash + path rules", () => {
  const dir = mkdtempSync(join(tmpdir(), "pi-ask-wc2-"));
  const path = join(dir, "permission.json");
  writeFileSync(path, JSON.stringify(SAMPLE_CONFIG, null, 2));
  try {
    const store = new PermissionStore(path);
    assert.equal(store.decide("write", "write", "/x/.env").state, "deny");
    assert.equal(store.decide("write", "write", "/x/.env.example").state, "allow");
    assert.equal(store.decide("write", "write", "/x/main.ts").state, "ask");
    assert.equal(store.decide("bash", "ls -la").state, "allow");
    assert.equal(store.decide("bash", "sudo rm -rf /").state, "deny");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("describeToolCall resolves write path", () => {
  const d = describeToolCall("write", { path: "/tmp/a.txt", content: "hi" });
  assert.equal(d.filePath, "/tmp/a.txt");
  assert.equal(d.prompt.base, "/tmp/a.txt");
});

test("compileGlob rejects empty", () => {
  assert.equal(compileGlob("").test("x"), false);
});
