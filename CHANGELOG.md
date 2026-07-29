# Changelog

## 0.2.0

- Path allows now act like directory-scoped YOLO for bash, write, and edit asks
- Any matching bash or path deny now takes priority over every allow

## 0.1.0

First public release.

- Bottom-panel `ask_user` (multi-question, transcript stays visible)
- Permission gate for `bash` / `write` / `edit` with path wildcards
- `permission.json` rules (bash / tools / paths); seeds from example when missing
- Session / permanent allow; deny with reason
- Chain / substitution unit checks; path-deny on bash args; sudo → `sudo_run` redirect
- `/yolo` session mode: auto-approve every gate **ask** (including globs); **deny** and sudo redirect still enforced; `ask_user` untouched
- `/permissions` lists allows/denies and YOLO state
- Herdr attention: ding only when the pane is backgrounded
