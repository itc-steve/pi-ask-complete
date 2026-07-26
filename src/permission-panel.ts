/**
 * Single-shot permission panel (bottom slot, overlay:false).
 * Four fixed options; Enter confirms immediately (no review tab).
 * Deny opens a free-text editor for a reason.
 */

import type { ExtensionContext, Theme } from "@earendil-works/pi-coding-agent";
import {
  type Component,
  Editor,
  type EditorTheme,
  type Focusable,
  Key,
  matchesKey,
  truncateToWidth,
  wrapTextWithAnsi,
} from "@earendil-works/pi-tui";
import type { PermissionPrompt } from "./describe-tool.ts";
import { withHerdrBlocked } from "./herdr-attention.ts";
import { padRight, sanitizeMultiline } from "./helpers.ts";
import {
  ICON_CURSOR,
  ICON_RADIO_EMPTY,
  ICON_RADIO_FILLED,
  TOGGLE_HINT,
  TOGGLE_KEY,
  type TuiLike,
} from "./types.ts";

export type { PermissionPrompt };

export type PermissionDecision =
  | { action: "allow_once" }
  | { action: "allow_session" }
  | { action: "allow_always"; entry: string }
  | { action: "deny"; reason: string }
  | { action: "cancelled" };

type Opt = {
  id: "once" | "session" | "always" | "deny";
  label: string;
  description: string;
};

function optionsFor(prompt: PermissionPrompt): Opt[] {
  return [
    {
      id: "once",
      label: "Allow this",
      description: "Permit this once. Ask again next time.",
    },
    {
      id: "session",
      label: prompt.session ?? "Allow for this session",
      description: "Remember bases from this call until the agent session ends.",
    },
    {
      id: "always",
      label: prompt.permanent ?? "Allow permanently",
      description: prompt.base
        ? `Whitelist \`${prompt.base}\` in permission.json. Survives restarts.`
        : "Whitelist in permission.json. Survives restarts.",
    },
    {
      id: "deny",
      label: "Deny this with reason",
      description: "Block. Opens a reason editor; empty reason still denies.",
    },
  ];
}

class PermissionPanel implements Component, Focusable {
  focused = false;
  private theme: Theme;
  private tui: TuiLike;
  private prompt: PermissionPrompt;
  private opts: Opt[];
  private cursor = 0;
  private selected = -1;
  private collapsed = false;
  private inputMode = false;
  private editor: Editor;
  private onDone: (d: PermissionDecision) => void;
  private cachedLines?: string[];

  constructor(
    prompt: PermissionPrompt,
    tui: TuiLike,
    theme: Theme,
    onDone: (d: PermissionDecision) => void,
  ) {
    this.prompt = prompt;
    this.opts = optionsFor(prompt);
    this.tui = tui;
    this.theme = theme;
    this.onDone = onDone;

    const editorTheme: EditorTheme = {
      borderColor: (s) => theme.fg("accent", s),
      selectList: {
        selectedPrefix: (t) => theme.fg("accent", t),
        selectedText: (t) => theme.fg("accent", t),
        description: (t) => theme.fg("muted", t),
        scrollInfo: (t) => theme.fg("dim", t),
        noMatch: (t) => theme.fg("warning", t),
      },
    };
    this.editor = new Editor(tui as never, editorTheme);
    this.editor.onSubmit = (value) => {
      const reason = value.trim() || "Denied by user";
      this.onDone({ action: "deny", reason });
    };
  }

  private refresh(): void {
    this.cachedLines = undefined;
    this.tui.requestRender();
  }

  private finish(opt: Opt): void {
    if (opt.id === "once") {
      this.onDone({ action: "allow_once" });
      return;
    }
    if (opt.id === "session") {
      this.onDone({ action: "allow_session" });
      return;
    }
    if (opt.id === "always") {
      this.onDone({ action: "allow_always", entry: this.prompt.base });
      return;
    }
    this.selected = this.cursor;
    this.inputMode = true;
    this.refresh();
  }

  handleInput(data: string): void {
    if (matchesKey(data, TOGGLE_KEY)) {
      this.collapsed = !this.collapsed;
      this.refresh();
      return;
    }

    if (this.collapsed) {
      if (matchesKey(data, Key.escape)) this.onDone({ action: "cancelled" });
      return;
    }

    if (this.inputMode) {
      if (matchesKey(data, Key.escape)) {
        this.inputMode = false;
        this.editor.setText("");
        this.refresh();
        return;
      }
      this.editor.handleInput(data);
      this.refresh();
      return;
    }

    if (matchesKey(data, Key.escape)) {
      this.onDone({ action: "cancelled" });
      return;
    }
    if (matchesKey(data, Key.up)) {
      this.cursor = Math.max(0, this.cursor - 1);
      this.refresh();
      return;
    }
    if (matchesKey(data, Key.down)) {
      this.cursor = Math.min(this.opts.length - 1, this.cursor + 1);
      this.refresh();
      return;
    }
    if (matchesKey(data, Key.space) || matchesKey(data, Key.enter)) {
      this.selected = this.cursor;
      this.finish(this.opts[this.cursor]!);
    }
  }

  render(width: number): string[] {
    if (this.cachedLines) return this.cachedLines;
    const th = this.theme;
    const innerW = Math.max(20, width - 2);
    // Hard-clamp every content cell — long python -c / base lists must never
    // exceed terminal width (pi TUI throws on overflow).
    const row = (s: string) => {
      const fitted = truncateToWidth(s, innerW);
      return th.fg("border", "│") + padRight(fitted, innerW) + th.fg("border", "│");
    };

    if (this.collapsed) {
      this.cachedLines = [
        th.fg("border", `╭${"─".repeat(innerW)}╮`),
        row(
          ` ${th.fg("warning", "⏸")} ${th.fg("accent", "Permission")} ${th.fg("dim", `· ${TOGGLE_HINT} expand · Esc cancel`)}`,
        ),
        th.fg("border", `╰${"─".repeat(innerW)}╯`),
      ];
      return this.cachedLines;
    }

    const lines: string[] = [];
    lines.push(th.fg("border", `╭${"─".repeat(innerW)}╮`));
    lines.push(
      row(
        ` ${th.fg("accent", th.bold("Permission required"))}${th.fg("dim", ` · ${this.prompt.base}`)}`,
      ),
    );
    lines.push(row(""));
    lines.push(row(` ${th.fg("muted", "The agent wants to:")}`));
    const display = sanitizeMultiline(this.prompt.display).replace(/\s+/g, " ").trim();
    for (const w of wrapTextWithAnsi(th.fg("text", `  ${display}`), Math.max(8, innerW - 2))) {
      lines.push(row(` ${w}`));
    }
    if (this.prompt.detail?.trim()) {
      lines.push(row(""));
      for (const w of wrapTextWithAnsi(
        th.fg("dim", this.prompt.detail.trim()),
        Math.max(8, innerW - 2),
      )) {
        lines.push(row(` ${w}`));
      }
    }
    lines.push(row(""));

    if (this.inputMode) {
      lines.push(row(` ${th.fg("warning", "Reason for denial:")}`));
      for (const el of this.editor.render(Math.max(8, innerW - 2))) lines.push(row(` ${el}`));
      lines.push(row(th.fg("dim", " Enter submit · Esc back")));
    } else {
      for (let i = 0; i < this.opts.length; i++) {
        const opt = this.opts[i]!;
        const isCursor = i === this.cursor;
        const isSel = i === this.selected;
        const glyph = isSel
          ? th.fg("success", ICON_RADIO_FILLED)
          : th.fg("dim", ICON_RADIO_EMPTY);
        const cur = isCursor ? th.fg("accent", ICON_CURSOR) : " ";
        // Truncate label text before coloring so bold/fg don't hide overflow.
        const labelMax = Math.max(4, innerW - 6);
        const labelPlain = truncateToWidth(opt.label, labelMax, "");
        const label = isCursor
          ? th.fg("accent", th.bold(labelPlain))
          : th.fg("text", labelPlain);
        lines.push(row(` ${cur} ${glyph} ${label}`));
        const desc = truncateToWidth(opt.description, Math.max(4, innerW - 6), "");
        lines.push(row(`     ${th.fg("muted", desc)}`));
      }
    }

    lines.push(th.fg("border", `├${"─".repeat(innerW)}┤`));
    lines.push(
      row(th.fg("dim", ` ${TOGGLE_HINT} collapse · ↑↓ move · Enter confirm · Esc cancel`)),
    );
    lines.push(th.fg("border", `╰${"─".repeat(innerW)}╯`));
    this.cachedLines = lines;
    return lines;
  }
}

export async function runPermissionPanel(
  ctx: Pick<ExtensionContext, "ui">,
  prompt: PermissionPrompt,
): Promise<PermissionDecision> {
  return withHerdrBlocked("Permission needed", async () => {
    const result = await ctx.ui.custom<PermissionDecision>(
      (tui, theme, _kb, done) => {
        return new PermissionPanel(prompt, tui as TuiLike, theme, done);
      },
      { overlay: false },
    );
    return result ?? { action: "cancelled" };
  });
}
