/**
 * Build a human-readable permission prompt from a tool call.
 */

import { resolve } from "node:path";
import { baseCommand } from "./base-command.ts";
import { normalizePath } from "./wildcard.ts";

export type PermissionPrompt = {
  /** Short subject shown in header + used as permanent-allow key. */
  base: string;
  /** Full description of what will run (command line / tool action). */
  display: string;
  /** Optional extra context under the display. */
  detail?: string;
  /** Human blast-radius label for the session-allow option. */
  session?: string;
  /** Human blast-radius label for the permanent-allow option. */
  permanent?: string;
};

export type ToolCallDescription = {
  toolName: string;
  /** bash command string, or tool name for tools */
  subject: string;
  /** Absolute-ish path for write/edit/read when present */
  filePath?: string;
  prompt: PermissionPrompt;
};

function summarize(text: string, max = 200): string {
  const one = text.replace(/\s+/g, " ").trim();
  if (one.length <= max) return one;
  return `${one.slice(0, max - 1)}…`;
}

function resolvePath(p: string, cwd?: string): string {
  const raw = p.trim();
  if (!raw) return raw;
  try {
    return normalizePath(cwd ? resolve(cwd, raw) : resolve(raw));
  } catch {
    return normalizePath(raw);
  }
}

export function describeToolCall(
  toolName: string,
  input: Record<string, unknown>,
  cwd?: string,
): ToolCallDescription {
  if (toolName === "bash" || toolName === "sudo_run") {
    const command = String(input.command ?? "");
    const base = baseCommand(command) || "(unknown)";
    const reason =
      toolName === "sudo_run" && typeof input.reason === "string"
        ? input.reason.trim()
        : "";
    const details: string[] = [];
    if (toolName === "sudo_run") details.push("via sudo_run (root)");
    if (reason) details.push(reason);
    if (input.cwd) details.push(`cwd: ${String(input.cwd)}`);
    return {
      toolName,
      subject: command,
      prompt: {
        base,
        display: toolName === "sudo_run" ? `sudo ${command}` : command,
        detail: details.length ? details.join(" · ") : undefined,
        session: "Allow for this session",
        permanent: "Allow permanently",
      },
    };
  }

  if (toolName === "write") {
    const rawPath = String(input.path ?? "(no path)");
    const filePath = rawPath === "(no path)" ? undefined : resolvePath(rawPath, cwd);
    const content = typeof input.content === "string" ? input.content : "";
    const lines = content ? content.split("\n").length : 0;
    return {
      toolName: "write",
      subject: "write",
      filePath,
      prompt: {
        base: filePath ?? "write",
        display: `write ${filePath ?? rawPath}`,
        session: "Allow writes to this file this session",
        permanent: "Allow writes to this file permanently",
        detail: content
          ? `${lines} line(s), ${content.length} chars · preview: ${summarize(content, 160)}`
          : "empty content",
      },
    };
  }

  if (toolName === "edit") {
    const rawPath = String(input.path ?? "(no path)");
    const filePath = rawPath === "(no path)" ? undefined : resolvePath(rawPath, cwd);
    const edits = Array.isArray(input.edits) ? input.edits : [];
    const first = edits[0] as { oldText?: string; newText?: string } | undefined;
    const detailParts = [`${edits.length} edit(s)`];
    if (first?.oldText) detailParts.push(`old: ${summarize(first.oldText, 80)}`);
    if (first?.newText) detailParts.push(`new: ${summarize(first.newText, 80)}`);
    return {
      toolName: "edit",
      subject: "edit",
      filePath,
      prompt: {
        base: filePath ?? "edit",
        display: `edit ${filePath ?? rawPath}`,
        session: "Allow edits to this file this session",
        permanent: "Allow edits to this file permanently",
        detail: detailParts.join(" · "),
      },
    };
  }

  if (toolName === "read") {
    const rawPath = String(input.path ?? "(no path)");
    const filePath = rawPath === "(no path)" ? undefined : resolvePath(rawPath, cwd);
    return {
      toolName: "read",
      subject: "read",
      filePath,
      prompt: {
        base: filePath ?? "read",
        display: `read ${filePath ?? rawPath}`,
      },
    };
  }

  return {
    toolName,
    subject: toolName,
    prompt: {
      base: toolName,
      display: `${toolName} ${summarize(JSON.stringify(input), 240)}`,
    },
  };
}
