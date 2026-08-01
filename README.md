# pi-ask-complete

Model-guided **ask_user** questions in a bottom panel for the [Pi coding agent](https://pi.dev).

The extension tells the model to use `ask_user` for decisions, preferences, confirmations, and clarifying questions instead of writing multiple-choice prompts in chat. It does not intercept, approve, deny, or modify other tool calls.

## Features

- Single-select and multi-select questions
- Free-form answers on every question
- Optional descriptions and side-by-side previews
- Multiple questions with tabs and a final review screen
- Required or skippable questions
- Bottom-panel UI that keeps the transcript visible
- Structured JSON answers returned to the model
- Herdr attention notification when the panel waits in a background pane

## Install

```bash
pi install npm:@itc-steve/pi-ask-complete
```

From a local checkout:

```bash
pi install /path/to/pi-ask-complete
```

Run `/reload` after installation.

## Model-facing tool

```ts
ask_user({
  questions: [
    {
      header: "Which layout?",
      tab: "Layout",
      prompt: "Choose the default page layout.",
      options: [
        { label: "Grid", description: "Dense overview of many items." },
        { label: "List", description: "More detail for each item." }
      ],
      allowSkip: false
    }
  ]
})
```

Every question also includes a **Type something.** row. The tool returns structured JSON containing the user's selections, custom answers, skipped questions, cancellation state, and optional note.

## Upgrade from 0.x

Version 1.0 removes the permission system entirely:

- No automatic gate for `bash`, `read`, `write`, or `edit`
- No `ask_permission` tool
- No `/permissions` or `/yolo` commands
- No `permission.json` or path/command rules
- No `sudo`/`doas` redirection

Delete `~/.pi/agent/permission.json` if no other extension uses it. Pi and other installed extensions remain responsible for tool permissions.
