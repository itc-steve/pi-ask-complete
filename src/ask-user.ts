/**
 * ask_user tool — multi-question bottom panel the LLM can call.
 */

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import {
  AskUserParams,
  AskUserResultView,
  buildAskUserJsonPayload,
  runAskUserPanel,
  sanitizeQuestions,
  type AskUserResult,
} from "./ask-user-panel.ts";
import { errorResult } from "./helpers.ts";

const ASK_USER_DESCRIPTION =
  "Ask the user one or more questions with selectable options. " +
  "ALWAYS prefer this tool over plain-text multiple-choice questions when you need a decision, preference, or confirmation. " +
  "Supports single-select and multi-select. Every question includes a 'Type something.' row for free-form answers. " +
  "Use for clarifying requirements, picking between distinct paths, or confirming decisions. " +
  "Pass 2–4 options per question with short labels and descriptions. " +
  "Result JSON: { cancelled, answers: [{ tab, answer|custom|answers|skipped }], message? }.";

export function registerAskUser(pi: ExtensionAPI): void {
  pi.registerTool({
    name: "ask_user",
    label: "Ask User",
    description: ASK_USER_DESCRIPTION,
    parameters: AskUserParams,
    executionMode: "sequential",

    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (!ctx.hasUI) {
        return errorResult("Error: UI not available (running in non-interactive mode)");
      }
      if (params.questions.length === 0) {
        return errorResult("Error: No questions provided");
      }

      const questions = sanitizeQuestions(params.questions);
      const result = await runAskUserPanel(ctx, questions);
      const payload = buildAskUserJsonPayload(questions, result);

      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
        details: result,
      };
    },

    renderResult(result, options, theme, context) {
      const questions = (context.args?.questions ?? []).map(
        (question: { header: string; tab: string }, index: number) => ({
          ...question,
          id: `question-${index + 1}`,
        }),
      );
      const raw = (result.details ?? {}) as Partial<AskUserResult>;
      const details: AskUserResult = {
        questions: raw.questions ?? [],
        answers: raw.answers ?? [],
        cancelled: raw.cancelled ?? true,
        message: raw.message,
      };
      const comp =
        context.lastComponent instanceof AskUserResultView
          ? context.lastComponent
          : new AskUserResultView(questions, details, theme);
      comp.setExpanded(options.expanded);
      return comp;
    },
  });
}
