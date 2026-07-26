/**
 * pi-ask-complete
 *
 * Bottom-panel ask_user (transcript stays visible) + bash permission gate
 * that reuses the same panel for Allow / Allow permanently / Deny with reason.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerAskUser } from "./src/ask-user.ts";
import { bindHerdrAttention } from "./src/herdr-attention.ts";
import { registerPermission } from "./src/permission.ts";
import { PermissionStore } from "./src/permission-store.ts";

export default function piCompleteAsk(pi: ExtensionAPI) {
  const store = new PermissionStore();

  // Herdr dings only when this pane is backgrounded (see herdr-attention.ts).
  bindHerdrAttention(pi.events);
  registerAskUser(pi);
  registerPermission(pi, store);

  // Nudge the model to use ask_user / sudo_run correctly.
  pi.on("before_agent_start", async (event) => {
    const tip =
      "\n\n# User interaction tools\n" +
      "- Use `ask_user` whenever you need the user to choose between options, confirm a decision, or answer a clarifying question. Do not present multi-choice questions as plain text when `ask_user` is available.\n" +
      "- System shell commands are gated automatically; you do not need to call `ask_permission` for normal bash — the user will be prompted.\n" +
      "- Never run `sudo`/`doas` via bash. Use `sudo_run` with the command (no sudo prefix) and a short reason; the user will approve and enter their password.\n";

    return {
      systemPrompt: (event.systemPrompt ?? "") + tip,
    };
  });
}
