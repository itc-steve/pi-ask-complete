/**
 * Permission store: bash + tools + path wildcards.
 * All rules come from permission.json — no hardcoded blocklists in code.
 *
 * File: ~/.pi/agent/permission.json
 * Seeded from permission.json.example on first run.
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import {
  baseCommand,
  isPersistableBashKey,
  isSudoPrefixed,
  normalizeCommandForMatch,
  stripSudoPrefix,
  stripWrappers,
  wrapperHasArgs,
} from "./base-command.ts";
import {
  hasUnresolvedExpansion,
  isUnresolvedPath,
  pathArgs,
  splitUnits,
} from "./bash-scan.ts";
import { matchGlob, normalizePath, resolveRules } from "./wildcard.ts";

export type PermissionKind = "bash" | "tools" | "paths";
export type RuleState = "allow" | "deny" | "ask";

export type PermissionFile = {
  bash?: Record<string, RuleState>;
  tools?: Record<string, RuleState>;
  paths?: Record<string, "allow" | "deny">;
};

type PathRule = { pattern: string; state: "allow" | "deny" };

/** Expand ~/ and resolve relative/`..` against cwd (absolute args keep their root). */
function resolvePathArg(arg: string, cwd: string): string {
  if (arg === "~") return homedir();
  if (arg.startsWith("~/")) return resolve(homedir(), arg.slice(2));
  return resolve(cwd, arg);
}

function agentDir(): string {
  const fromEnv = process.env.PI_CODING_AGENT_DIR?.trim();
  if (fromEnv) return fromEnv;
  return join(homedir(), ".pi", "agent");
}

export function permissionFilePath(): string {
  return join(agentDir(), "permission.json");
}

/** Bundled example shipped next to this package. */
export function examplePermissionPath(): string {
  // src/ → package root
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "permission.json.example");
}

function readJsonFile(path: string): PermissionFile | null {
  try {
    const v = JSON.parse(readFileSync(path, "utf-8")) as unknown;
    // Arrays / primitives parse but are not a rules object — treat as corrupt.
    if (!v || typeof v !== "object" || Array.isArray(v)) return null;
    return v as PermissionFile;
  } catch {
    return null;
  }
}

/** Read example body if it is a usable non-array object JSON; else null. */
function readExampleBody(): string | null {
  const examplePath = examplePermissionPath();
  try {
    if (!existsSync(examplePath)) return null;
    const body = readFileSync(examplePath, "utf-8");
    const v = JSON.parse(body) as unknown;
    if (!v || typeof v !== "object" || Array.isArray(v)) return null;
    return body;
  } catch {
    return null;
  }
}

export class PermissionStore {
  private bash = new Map<string, RuleState>();
  private tools = new Map<string, RuleState>();
  private pathRules: PathRule[] = [];
  private pathIndex = new Map<string, "allow" | "deny">();
  /** In-memory allows for this agent session only (not written to disk). */
  private sessionBash = new Set<string>();
  private sessionTools = new Set<string>();
  private sessionPaths = new Set<string>();
  /** Session-only: auto-approve asks. Never upgrades deny; never written to disk. */
  private yoloOn = false;
  /**
   * No loadable policy (missing user file AND missing/unreadable example).
   * Empty maps must not mean "everything readable" — checkPath denies all.
   */
  private noPolicy = false;
  private path: string;

  constructor(path = permissionFilePath()) {
    this.path = path;
    this.reload();
  }

  get filePath(): string {
    return this.path;
  }

  get yolo(): boolean {
    return this.yoloOn;
  }

  /** Toggle session YOLO — memory only; never touches permission.json. */
  setYolo(on: boolean): void {
    this.yoloOn = on;
  }

  /** Drop session-only allows + yolo (e.g. on new agent session). */
  clearSession(): void {
    this.sessionBash.clear();
    this.sessionTools.clear();
    this.sessionPaths.clear();
    this.yoloOn = false;
  }

  /** Load rules from the user JSON only. Session allows are kept. */
  reload(): void {
    if (!existsSync(this.path)) {
      // Missing live config (…/permission.json) → re-seed from example.
      // Ephemeral/test paths with other names stay empty (no auto-seed).
      // seedUserFile writes only; does not call reload (no recursion).
      const isLiveConfig = basename(this.path) === "permission.json";
      if (isLiveConfig && this.seedUserFile()) {
        // File now exists; fall through to normal load.
      } else if (isLiveConfig) {
        // Broken install: keep last-good maps. Empty + no example → noPolicy.
        if (this.bash.size === 0 && this.tools.size === 0 && this.pathIndex.size === 0) {
          this.noPolicy = true;
        }
        return;
      } else {
        // Missing non-live path: do not clear (fail closed on last-good).
        return;
      }
    }

    const parsed = readJsonFile(this.path);
    // Corrupt / unreadable file: keep last good in-memory rules (fail closed on denies).
    if (!parsed) return;

    this.noPolicy = false;
    this.bash.clear();
    this.tools.clear();
    this.pathRules = [];
    this.pathIndex.clear();

    for (const [k, v] of Object.entries(parsed.bash ?? {})) {
      if (k && (v === "allow" || v === "deny" || v === "ask")) this.bash.set(k, v);
    }
    for (const [k, v] of Object.entries(parsed.tools ?? {})) {
      if (k && (v === "allow" || v === "deny" || v === "ask")) this.tools.set(k, v);
    }
    for (const [k, v] of Object.entries(parsed.paths ?? {})) {
      if (k && (v === "allow" || v === "deny")) this.pathIndex.set(k, v);
    }

    const allows: PathRule[] = [];
    const denies: PathRule[] = [];
    for (const [pattern, state] of this.pathIndex) {
      (state === "allow" ? allows : denies).push({ pattern, state });
    }
    this.pathRules = [...allows, ...denies];
  }

  /**
   * Write permission.json.example bytes to this.path when missing.
   * Does not call reload (avoids recursion). False when example is unusable.
   */
  private seedUserFile(): boolean {
    if (existsSync(this.path)) return true;
    const body = readExampleBody();
    if (body === null) return false;
    const dir = dirname(this.path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(this.path, body);
    return true;
  }

  checkPath(filePath: string): "allow" | "deny" | undefined {
    if (!filePath) return undefined;
    // Broken install (no user file, no example): deny every path — empty ≠ readable.
    if (this.noPolicy) return "deny";
    return resolveRules(this.pathRules, normalizePath(filePath));
  }

  /**
   * Whole-command decision: every command unit (segments + substitutions) must
   * be allowed, and no path-like argument may hit a path deny rule.
   * deny wins → deny; any non-allowed unit → ask; allow only when all allow.
   */
  checkBash(command: string, opts?: { cwd?: string }): RuleState {
    const plan = this.planBash(command, opts);
    if (plan.action === "deny") return "deny";
    if (plan.action === "ask") return "ask";
    return "allow";
  }

  /**
   * Per-unit plan for a bash line. Deny still wins per unit/path; ask lists units
   * that need approval. The gate prompts ONCE for the whole line (not per unit).
   * `cwd` is used to resolve relative path args (optional; defaults to process.cwd()).
   */
  planBash(
    command: string,
    opts?: { cwd?: string },
  ):
    | { action: "allow" }
    | {
        action: "deny";
        label: string;
        kind: "path" | "bash" | "sudo_redirect";
      }
    | { action: "ask"; units: string[] } {
    const units = splitUnits(command);
    const cwd = opts?.cwd ?? process.cwd();

    // sudo/doas after wrappers (`env sudo …`) → same redirect as a leading sudo.
    for (const unit of units) {
      const effective = stripWrappers(unit) || unit;
      if (isSudoPrefixed(effective)) {
        const inner = stripSudoPrefix(effective) || effective;
        return {
          action: "deny",
          label: JSON.stringify(inner),
          kind: "sudo_redirect",
        };
      }
    }

    // Path deny on the full line AND every unit (covers substitution bodies).
    const pathCandidates = new Set<string>([
      ...pathArgs(command),
      ...units.flatMap((u) => pathArgs(u)),
    ]);
    for (const arg of pathCandidates) {
      // Literal token first (`$HOME/.env` matches **/.env as typed).
      if (this.checkPath(normalizePath(arg)) === "deny") {
        return { action: "deny", label: arg, kind: "path" };
      }
      // Resolve ~/ and relative/`..` against cwd so `/etc/shadow` denies still hit.
      const abs = resolvePathArg(arg, cwd);
      if (normalizePath(abs) !== normalizePath(arg) && this.checkPath(normalizePath(abs)) === "deny") {
        return { action: "deny", label: arg, kind: "path" };
      }
    }

    const ask: string[] = [];
    for (const unit of units) {
      const state = this.checkUnit(unit);
      if (state === "deny") {
        return {
          action: "deny",
          label: baseCommand(unit) || unit,
          kind: "bash",
        };
      }
      if (state === "ask") ask.push(unit);
    }

    // Unresolved globs/braces/$'' — fail-closed ask when yolo is off (path may be
    // a secret: `cat .*` → .env). Under yolo, treat like any other ask → allow;
    // resolved path/bash denies above still block.
    if (hasUnresolvedExpansion(command) || [...pathCandidates].some(isUnresolvedPath)) {
      if (this.yoloOn) return { action: "allow" };
      return {
        action: "ask",
        units: ask.length ? ask : units.length ? units : [command],
      };
    }

    if (ask.length) {
      if (this.yoloOn) return { action: "allow" };
      return { action: "ask", units: ask };
    }
    return { action: "allow" };
  }

  /** Unique persistable base names for units that still need approval. */
  askBases(units: string[]): string[] {
    const out: string[] = [];
    const seen = new Set<string>();
    for (const unit of units) {
      const b = baseCommand(unit);
      // Drop junk (`1` from a bad split, keywords, etc.) — only real binaries.
      if (!b || seen.has(b) || !isPersistableBashKey(b)) continue;
      seen.add(b);
      out.push(b);
    }
    return out;
  }

  /** Rule lookup for a SINGLE command unit (no operators/substitutions). */
  checkUnit(command: string): RuleState {
    const trimmed = command.trim();
    // Peel env/strace/timeout/… so an allow-listed wrapper cannot launder the inner binary.
    // Bare `env` peels to "" → keep original so the wrapper itself can still allow.
    const peeled = stripWrappers(trimmed);
    // Wrapper with args but no resolvable inner (`strace -f` alone) → ask, never allow.
    if (!peeled && wrapperHasArgs(trimmed)) {
      return this.yoloOn ? "allow" : "ask";
    }
    const effective = peeled || trimmed;

    // First token of the *resolved* command (sudo after wrappers, real binary).
    const rawFirst = (effective.split(/\s+/)[0] ?? "").replace(/^['"]|['"]$/g, "");
    const rawBase = rawFirst.split(/[/\\]/).pop() ?? rawFirst;

    // Never classify sudo/doas via the stripped inner binary (true; sudo id → id allow).
    if (/^(sudo|doas)$/i.test(rawBase)) return "deny";

    if (rawBase && this.bash.has(rawBase)) {
      const s = this.bash.get(rawBase)!;
      if (s !== "ask") return s;
    }

    // Full-command subjects: resolved + normalized (e.g. strip `git -C path`)
    const normalized = normalizeCommandForMatch(effective);
    const subjects =
      normalized !== effective ? [effective, normalized] : [effective];

    for (const sub of subjects) {
      if (this.bash.has(sub)) {
        const s = this.bash.get(sub)!;
        if (s !== "ask") return s;
      }
    }

    const base = baseCommand(effective);
    if (base && base !== rawBase && this.bash.has(base)) {
      const s = this.bash.get(base)!;
      if (s !== "ask") return s;
    }

    // Wildcard patterns against full/normalized command, raw first token, base
    for (const [pattern, state] of this.bash) {
      if (!pattern.includes("*") && !pattern.includes("?")) continue;
      const hit =
        subjects.some((sub) => matchGlob(pattern, sub)) ||
        (rawBase ? matchGlob(pattern, rawBase) : false) ||
        (base ? matchGlob(pattern, base) : false);
      if (hit) {
        if (state === "allow") return "allow";
        if (state === "deny") return "deny";
      }
    }

    // Session allow only upgrades ask → allow (never overrides deny).
    if ((base && this.sessionBash.has(base)) || (rawBase && this.sessionBash.has(rawBase))) {
      return "allow";
    }
    // yolo last: only after every deny/allow lookup above.
    return this.yoloOn ? "allow" : "ask";
  }

  checkTool(toolName: string): RuleState {
    const s = this.tools.get(toolName);
    if (s === "allow" || s === "deny") return s;
    if (this.sessionTools.has(toolName)) return "allow";
    // yolo upgrades ask / default-ask only — deny already returned.
    if (this.yoloOn) return "allow";
    return s ?? "ask";
  }

  decide(
    toolName: string,
    subject: string,
    filePath?: string,
  ): { state: RuleState; matched?: string } {
    if (filePath) {
      const pathState = this.checkPath(filePath);
      if (pathState === "allow") return { state: "allow", matched: filePath };
      if (pathState === "deny") return { state: "deny", matched: filePath };
      if (this.sessionPaths.has(normalizePath(filePath))) {
        return { state: "allow", matched: filePath };
      }
    }
    const state =
      toolName === "bash" ? this.checkBash(subject) : this.checkTool(toolName);
    // yolo already applied inside checkBash/checkTool (including glob asks).
    return { state };
  }

  isAllowed(toolName: string, subject: string, filePath?: string): boolean {
    return this.decide(toolName, subject, filePath).state === "allow";
  }

  isDenied(toolName: string, subject: string, filePath?: string): boolean {
    return this.decide(toolName, subject, filePath).state === "deny";
  }

  /** Persist allow to permission.json (and live maps). */
  allowPermanently(toolName: string, subject: string, filePath?: string): string {
    if (toolName === "bash") {
      const entry = baseCommand(subject) || subject.trim();
      // Refuse prose/keyword/junk keys — still allow once for this call via session.
      if (!entry || !isPersistableBashKey(entry)) {
        if (entry) this.sessionBash.add(entry); // session-only so this chain can finish
        return "";
      }
      this.bash.set(entry, "allow");
      this.sessionBash.add(entry); // live immediately even if disk write fails later
      this.persistUserKey("bash", entry, "allow");
      return entry;
    }

    if (filePath) {
      const entry = normalizePath(filePath);
      this.pathIndex.set(entry, "allow");
      this.pathRules = [
        { pattern: entry, state: "allow" },
        ...this.pathRules.filter((r) => r.pattern !== entry),
      ];
      this.sessionPaths.add(entry);
      this.persistUserKey("paths", entry, "allow");
      return entry;
    }

    const entry = toolName.trim();
    this.tools.set(entry, "allow");
    this.sessionTools.add(entry);
    this.persistUserKey("tools", entry, "allow");
    return entry;
  }

  /** Allow for this agent session only — not written to disk. */
  allowSession(toolName: string, subject: string, filePath?: string): string {
    if (toolName === "bash") {
      const entry = baseCommand(subject) || subject.trim();
      if (entry) this.sessionBash.add(entry);
      return entry;
    }
    if (filePath) {
      const entry = normalizePath(filePath);
      this.sessionPaths.add(entry);
      return entry;
    }
    const entry = toolName.trim();
    this.sessionTools.add(entry);
    return entry;
  }

  /** Allow several bash bases for this session (one chain prompt). */
  allowSessionBases(bases: string[]): string[] {
    const out: string[] = [];
    for (const b of bases) {
      const entry = b.trim();
      if (!entry) continue;
      // Session can be looser than disk, but still skip empty/absurd keys.
      if (entry.length > 64 || /[\s{}"'`]/.test(entry)) continue;
      this.sessionBash.add(entry);
      out.push(entry);
    }
    return out;
  }

  /** Persist several bash bases (one chain prompt → multi allow). */
  allowPermanentlyBases(bases: string[]): string[] {
    const out: string[] = [];
    for (const b of bases) {
      const entry = this.allowPermanently("bash", b);
      if (entry) out.push(entry);
    }
    return out;
  }

  listAllowed(): {
    bash: string[];
    tools: string[];
    paths: string[];
    sessionBash: string[];
    sessionTools: string[];
    sessionPaths: string[];
  } {
    return {
      bash: [...this.bash.entries()].filter(([, s]) => s === "allow").map(([k]) => k).sort(),
      tools: [...this.tools.entries()].filter(([, s]) => s === "allow").map(([k]) => k).sort(),
      paths: [...this.pathIndex.entries()].filter(([, s]) => s === "allow").map(([k]) => k).sort(),
      sessionBash: [...this.sessionBash].sort(),
      sessionTools: [...this.sessionTools].sort(),
      sessionPaths: [...this.sessionPaths].sort(),
    };
  }

  listDeniedPaths(): string[] {
    return [...this.pathIndex.entries()].filter(([, s]) => s === "deny").map(([k]) => k).sort();
  }

  private persistUserKey(
    section: "bash" | "tools" | "paths",
    key: string,
    state: "allow" | "deny" | "ask",
  ): void {
    const dir = dirname(this.path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

    let existing: PermissionFile = {};
    if (existsSync(this.path)) {
      existing = readJsonFile(this.path) ?? {};
    }

    const bucket = { ...(existing[section] ?? {}) } as Record<string, string>;
    bucket[key] = state;
    const next: PermissionFile = { ...existing, [section]: bucket };
    const body = `${JSON.stringify(next, null, 2)}\n`;
    // Atomic replace so a crash mid-write cannot leave corrupt JSON (fail-open).
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, body, "utf-8");
    renameSync(tmp, this.path);
  }

  /**
   * If the user config is missing, seed it from permission.json.example.
   * Does not overwrite an existing file. Does not write an empty stub when the
   * example is missing (that would fail open) — sets noPolicy instead.
   */
  ensureUserFile(): void {
    if (existsSync(this.path)) return;
    if (!this.seedUserFile()) {
      // Broken install: do not write {} (empty file = no rules = secrets readable).
      if (this.bash.size === 0 && this.tools.size === 0 && this.pathIndex.size === 0) {
        this.noPolicy = true;
      }
      return;
    }
    this.reload();
  }
}
