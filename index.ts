/**
 * pi-ask-complete
 *
 * Bottom-panel ask_user with model guidance and a visible transcript.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerAskUser } from "./src/ask-user.ts";
import { bindHerdrAttention } from "./src/herdr-attention.ts";

export default function piCompleteAsk(pi: ExtensionAPI) {
  // Herdr dings only when this pane is backgrounded (see herdr-attention.ts).
  bindHerdrAttention(pi.events);
  registerAskUser(pi);

  pi.on("before_agent_start", async (event) => ({
    systemPrompt:
      (event.systemPrompt ?? "") +
      "\n\n# User interaction tools\n" +
      "- Use `ask_user` whenever you need the user to choose between options, confirm a decision, or answer a clarifying question. Do not present multiple-choice questions as plain text when `ask_user` is available.\n",
  }));
}
