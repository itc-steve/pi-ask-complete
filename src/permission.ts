// ask_permission + automatic gate for bash / write / edit / sudo_run / sensitive reads.
// Path wildcards: most-specific wins; equal score → deny.
// Prompt: Allow this | Allow for this session | Allow permanently | Deny with reason
// Bash: every unit is checked; one prompt per tool call (not per unit).
// Session remembers all ask-bases; permanent writes the primary base only.

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import {
  baseCommand,
  isPersistableBashKey,
  isSudoPrefixed,
  stripSudoPrefix,
} from "./base-command.ts";
import { splitUnits } from "./bash-scan.ts";
import { describeToolCall } from "./describe-tool.ts";
import {
  type PermissionDecision,
  type PermissionPrompt,
  runPermissionPanel,
} from "./permission-panel.ts";
import { PermissionStore } from "./permission-store.ts";

export type { PermissionDecision };
export { describeToolCall };

/** Tools that prompt unless allow/deny rule hits. */
const ASK_TOOLS = new Set(["bash", "write", "edit"]);
/** Only auto-block on path deny — never prompt on normal reads. */
const PATH_DENY_TOOLS = new Set(["read", "write", "edit"]);

let queue: Promise<unknown> = Promise.resolve();
function enqueue<T>(fn: () => Promise<T>): Promise<T> {
  const run = queue.then(fn, fn);
  queue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

function blockReason(
  kind: "path" | "bash" | "tool" | "sudo_redirect",
  label: string,
  extra?: string,
): string {
  if (kind === "sudo_redirect") {
    return (
      `Privileged commands must use the sudo_run tool, not bash. ` +
      `Call sudo_run with command: ${label}` +
      (extra ? ` (${extra})` : "")
    );
  }
  if (kind === "path") {
    return (
      `Blocked by path rule for \`${label}\`. ` +
      `Add a paths allow entry in permission.json to override.`
    );
  }
  return (
    `Blocked by permission rule for \`${label}\`. ` +
    `Add an allow entry in permission.json to override.` +
    (extra ? ` ${extra}` : "")
  );
}

export async function promptPermission(
  ctx: Pick<ExtensionContext, "ui" | "hasUI">,
  store: PermissionStore,
  toolName: string,
  subject: string,
  prompt: PermissionPrompt,
  filePath?: string,
): Promise<PermissionDecision> {
  if (!ctx.hasUI) {
    return {
      action: "deny",
      reason: "Action requires approval, but no interactive UI is available.",
    };
  }

  return enqueue(async () => {
    if (store.isAllowed(toolName, subject, filePath)) return { action: "allow_once" };
    if (store.isDenied(toolName, subject, filePath)) {
      return {
        action: "deny",
        reason: blockReason(filePath ? "path" : "bash", prompt.base),
      };
    }

    const decision = await runPermissionPanel(ctx, prompt);

    if (decision.action === "allow_always") {
      const entry = store.allowPermanently(toolName, subject, filePath);
      return { action: "allow_always", entry };
    }
    if (decision.action === "allow_session") {
      store.allowSession(toolName, subject, filePath);
      return { action: "allow_session" };
    }

    return decision;
  });
}

export type BashGateResult =
  | { ok: true; decision: "already_allowed" | "approved"; entries: string[] }
  | { ok: false; reason: string; decision: "deny" | "cancelled" };

/**
 * Gate a bash line: every unit + path arg is checked, but the user is prompted
 * at most once for the whole tool call. Session allow covers every ask-base;
 * permanent allow writes only the primary base.
 */
export async function gateBashCommand(
  ctx: Pick<ExtensionContext, "ui" | "hasUI">,
  store: PermissionStore,
  command: string,
  opts?: { cwd?: string; detail?: string },
): Promise<BashGateResult> {
  const plan = store.planBash(command, { cwd: opts?.cwd });
  if (plan.action === "deny") {
    return {
      ok: false,
      decision: "deny",
      reason: blockReason(plan.kind, plan.label),
    };
  }
  if (plan.action === "allow") {
    return { ok: true, decision: "already_allowed", entries: [] };
  }

  // Session remembers every real base in the chain; permanent only the primary.
  const bases = store.askBases(plan.units);
  const cmdBase = baseCommand(command);
  const primary =
    bases[0] || (isPersistableBashKey(cmdBase) ? cmdBase : "") || "bash";

  const prompt: PermissionPrompt = {
    base: primary,
    display: command,
    detail: opts?.detail?.trim() || undefined,
    // Fixed short labels (A/B/C) — bases stay out of the option text.
    session: "Allow for this session",
    permanent: "Allow permanently",
  };

  if (!ctx.hasUI) {
    return {
      ok: false,
      decision: "deny",
      reason: "Action requires approval, but no interactive UI is available.",
    };
  }

  const result = await enqueue(async () => {
    // Re-check after queue wait — a prior session allow may already cover us.
    const again = store.planBash(command, { cwd: opts?.cwd });
    if (again.action === "allow") return { action: "allow_once" as const };
    if (again.action === "deny") {
      return {
        action: "deny" as const,
        reason: blockReason(again.kind, again.label),
      };
    }
    return runPermissionPanel(ctx, prompt);
  });

  switch (result.action) {
    case "allow_once":
      return { ok: true, decision: "approved", entries: [] };
    case "allow_session": {
      // Whole chain: every base that still needed approval this call.
      const entries = store.allowSessionBases(bases.length ? bases : [primary]);
      return { ok: true, decision: "approved", entries };
    }
    case "allow_always": {
      // C: permanent = primary base only (not every unit in the pipeline).
      const entries = store.allowPermanentlyBases([primary]);
      return { ok: true, decision: "approved", entries };
    }
    case "deny":
      return { ok: false, decision: "deny", reason: result.reason };
    case "cancelled":
      return {
        ok: false,
        decision: "cancelled",
        reason: "Permission prompt cancelled by user.",
      };
  }
}

const AskPermissionParams = Type.Object({
  command: Type.String({
    description: "The system command (or action description) that needs approval",
  }),
  detail: Type.Optional(
    Type.String({
      description: "Optional extra context shown under the command (why it's needed)",
    }),
  ),
});

export function registerPermission(pi: ExtensionAPI, store: PermissionStore): void {
  store.ensureUserFile();

  pi.registerTool({
    name: "ask_permission",
    label: "Ask Permission",
    description:
      "Request user approval before a sensitive system action. Prefer letting the automatic gate handle bash/write/edit/sudo_run — call this only for other sensitive actions. One prompt per call (chains checked as units, prompted once).",
    parameters: AskPermissionParams,
    executionMode: "sequential",

    async execute(_id, params, _signal, _onUpdate, ctx) {
      const command = params.command;
      const units = splitUnits(command);
      const bases = units.map((u) => baseCommand(u) || u);

      const result = await gateBashCommand(ctx, store, command, {
        cwd: ctx.cwd,
        detail: params.detail,
      });

      const payload = result.ok
        ? {
            approved: true as const,
            decision: result.decision,
            command,
            bases,
            entries: result.entries.length ? result.entries : undefined,
          }
        : {
            approved: false as const,
            decision: result.decision,
            command,
            bases,
            reason: result.reason,
          };

      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
        details: payload,
      };
    },
  });

  pi.on("tool_call", async (event, ctx) => {
    const toolName = event.toolName;
    const input = (event.input ?? {}) as Record<string, unknown>;

    // ── bash: one prompt per call; sudo/doas (any unit) → sudo_run redirect ──
    if (toolName === "bash") {
      const command = String(input.command ?? "");
      if (!command.trim()) return undefined;

      // Leading sudo still short-circuits here; mid-chain is caught in planBash.
      if (isSudoPrefixed(command)) {
        const inner = stripSudoPrefix(command) || command;
        return {
          block: true,
          reason: blockReason("sudo_redirect", JSON.stringify(inner)),
        };
      }

      const result = await gateBashCommand(ctx, store, command, { cwd: ctx.cwd });
      if (result.ok) return undefined;
      return { block: true, reason: result.reason };
    }

    // ── sudo_run: not gated here. pix-sudo's PAM password prompt IS the gate
    // (no password entered = denied). JSON gating would be redundant. ──

    const isAskTool = ASK_TOOLS.has(toolName);
    const isPathDenyTool = PATH_DENY_TOOLS.has(toolName);
    if (!isAskTool && !isPathDenyTool) return undefined;

    const desc = describeToolCall(toolName, input, ctx.cwd);
    const decision = store.decide(toolName, desc.subject, desc.filePath);

    if (decision.state === "allow") return undefined;

    if (decision.state === "deny") {
      return {
        block: true,
        reason: blockReason(
          desc.filePath ? "path" : "tool",
          desc.filePath ?? desc.prompt.base,
        ),
      };
    }

    // state === "ask" — read only auto-denies; never prompt for normal reads
    if (!isAskTool) return undefined;

    const result = await promptPermission(
      ctx,
      store,
      toolName,
      desc.subject,
      desc.prompt,
      desc.filePath,
    );

    switch (result.action) {
      case "allow_once":
      case "allow_session":
      case "allow_always":
        return undefined;
      case "deny":
        return { block: true, reason: result.reason };
      case "cancelled":
        return { block: true, reason: "Permission prompt cancelled by user." };
    }
  });

  pi.on("session_start", () => {
    store.clearSession();
    store.reload();
  });

  pi.registerCommand("permissions", {
    description: "Show permission allows/denies (bash, tools, path wildcards)",
    handler: async (_args, ctx) => {
      store.reload();
      const { bash, tools, paths, sessionBash, sessionTools, sessionPaths } = store.listAllowed();
      const denied = store.listDeniedPaths();
      const lines = [
        ...(store.yolo
          ? ["YOLO: on (auto-approving asks; denies + sudo_run redirect still enforced)"]
          : []),
        bash.length ? `bash allow: ${bash.join(", ")}` : "bash allow: (none extra)",
        tools.length ? `tools allow: ${tools.join(", ")}` : "tools allow: (none)",
        paths.length ? `paths allow:\n  ${paths.join("\n  ")}` : "paths allow: (none extra)",
        denied.length ? `paths deny: ${denied.length} patterns` : "paths deny: (none)",
        sessionBash.length || sessionTools.length || sessionPaths.length
          ? `session: bash[${sessionBash.join(", ") || "—"}] tools[${sessionTools.join(", ") || "—"}] paths[${sessionPaths.length}]`
          : "session: (none)",
        "",
        "bash+sudo → redirected to sudo_run. sudo_run → gated by pix-sudo password prompt.",
        `File: ${store.filePath}`,
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });

  pi.registerCommand("yolo", {
    description:
      "Toggle session YOLO (auto-approve asks; deny rules + sudo_run redirect still enforced)",
    handler: async (args, ctx) => {
      const a = (args ?? "").trim().toLowerCase();
      if (a === "on") store.setYolo(true);
      else if (a === "off") store.setYolo(false);
      else store.setYolo(!store.yolo);

      ctx.ui.notify(
        store.yolo
          ? "YOLO on — auto-approving asks this session. Deny rules and sudo_run redirect are still enforced."
          : "YOLO off — prompts restored.",
        "info",
      );
    },
  });
}
