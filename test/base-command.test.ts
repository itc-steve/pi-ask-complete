import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  baseCommand,
  commandMatchesWhitelist,
  isPersistableBashKey,
  isSudoPrefixed,
  normalizeCommandForMatch,
  stripSudoPrefix,
} from "../src/base-command.ts";
import { describeToolCall } from "../src/describe-tool.ts";
import { PermissionStore } from "../src/permission-store.ts";

test("isPersistableBashKey rejects junk / keywords", () => {
  assert.equal(isPersistableBashKey("python3"), true);
  assert.equal(isPersistableBashKey("mkfs.ext4"), true);
  assert.equal(isPersistableBashKey("docker-compose"), true);
  assert.equal(isPersistableBashKey("for"), false);
  assert.equal(isPersistableBashKey("const"), false);
  assert.equal(isPersistableBashKey("then"), false);
  assert.equal(isPersistableBashKey("console.log"), false);
  assert.equal(isPersistableBashKey("{}).sort()"), false);
  assert.equal(isPersistableBashKey("git status*"), false); // patterns are seed-only, not from permanent UI
  assert.equal(isPersistableBashKey(""), false);
});

test("baseCommand extracts binary name", () => {
  assert.equal(baseCommand('grep -f "Hi"'), "grep");
  assert.equal(baseCommand("/usr/bin/grep foo"), "grep");
  assert.equal(baseCommand("sudo apt install x"), "apt");
  assert.equal(baseCommand("FOO=1 BAR=2 ls -la"), "ls");
  assert.equal(baseCommand("env FOO=1 npm test"), "npm");
  assert.equal(baseCommand("git status | head"), "git");
  assert.equal(baseCommand("sudo pacman -Sy"), "pacman");
});

test("sudo prefix helpers", () => {
  assert.equal(isSudoPrefixed("sudo pacman -Sy"), true);
  assert.equal(isSudoPrefixed("doas pacman -Sy"), true);
  assert.equal(isSudoPrefixed("pacman -Sy"), false);
  assert.equal(stripSudoPrefix("sudo pacman -Sy"), "pacman -Sy");
  assert.equal(stripSudoPrefix("sudo -n pacman -Sy"), "pacman -Sy");
});

test("commandMatchesWhitelist matches base or exact", () => {
  const allowed = new Set(["grep", "git status"]);
  assert.equal(commandMatchesWhitelist('grep -f "Hi"', allowed), true);
  assert.equal(commandMatchesWhitelist("git status", allowed), true);
  assert.equal(commandMatchesWhitelist("git push", allowed), false);
  assert.equal(commandMatchesWhitelist("rm -rf /", allowed), false);
});

test("normalizeCommandForMatch strips git globals", () => {
  assert.equal(normalizeCommandForMatch("git -C /tmp status -sb"), "git status -sb");
  assert.equal(
    normalizeCommandForMatch("git -C /home/u/proj -c foo=bar log --oneline"),
    "git log --oneline",
  );
  assert.equal(normalizeCommandForMatch("git --git-dir=.git status"), "git status");
  assert.equal(normalizeCommandForMatch("git --work-tree /repo diff"), "git diff");
  assert.equal(normalizeCommandForMatch("/usr/bin/git -C /x status"), "git status");
  assert.equal(normalizeCommandForMatch("git status"), "git status");
  assert.equal(normalizeCommandForMatch("ls -la"), "ls -la"); // non-git untouched
});

test("PermissionStore permanent allow is live in-session for bash + tools", () => {
  const dir = mkdtempSync(join(tmpdir(), "pi-ask-complete-"));
  const path = join(dir, "permission.json");
  writeFileSync(path, "{}\n");
  try {
    const store = new PermissionStore(path);
    assert.equal(store.isAllowed("bash", 'grep -f "Hi"'), false);
    assert.equal(store.isAllowed("write", "write"), false);

    assert.equal(store.allowPermanently("bash", 'grep -f "Hi"'), "grep");
    assert.equal(store.isAllowed("bash", "grep foo"), true);
    assert.equal(store.isAllowed("bash", "grep -n bar"), true);

    assert.equal(store.allowPermanently("write", "write"), "write");
    assert.equal(store.isAllowed("write", "write"), true);
    assert.equal(store.isAllowed("edit", "edit"), false);

    const onDisk = JSON.parse(readFileSync(path, "utf-8"));
    assert.equal(onDisk.bash.grep, "allow");
    assert.equal(onDisk.tools.write, "allow");

    const store2 = new PermissionStore(path);
    assert.equal(store2.isAllowed("bash", "grep z"), true);
    assert.equal(store2.isAllowed("write", "write"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("describeToolCall shapes write/edit/bash clearly", () => {
  const bash = describeToolCall("bash", { command: "rm /tmp/x" });
  assert.equal(bash.toolName, "bash");
  assert.equal(bash.prompt.base, "rm");
  assert.equal(bash.prompt.display, "rm /tmp/x");

  const write = describeToolCall("write", {
    path: "/tmp/pi_test_file.txt",
    content: "hello\nworld",
  });
  assert.equal(write.toolName, "write");
  assert.equal(write.subject, "write");
  assert.equal(write.prompt.display, "write /tmp/pi_test_file.txt");
  assert.match(write.prompt.detail ?? "", /2 line/);

  const edit = describeToolCall("edit", {
    path: "/tmp/pi_test_file.txt",
    edits: [{ oldText: "a", newText: "b" }],
  });
  assert.equal(edit.prompt.base, "/tmp/pi_test_file.txt");
  assert.equal(edit.prompt.display, "edit /tmp/pi_test_file.txt");
});
