# pi-ask-complete

Bottom-panel **ask_user** + **permission gate** (bash / write / edit + path wildcards) for the [Pi coding agent](https://pi.dev).

## Gate

| Tool | Behavior |
| --- | --- |
| `bash` | Every unit (segments, `$(...)`, backticks) is **checked**; path deny args block. **One prompt per tool call** (not per unit). Session/permanent allow applies to each unique base that needed approval |
| `write` / `edit` | Path rules first, then tool rule, else ask |
| `read` | Allowed by default; only auto-**deny** on matching path deny rules — never prompts for normal reads |

### Default bash allows

Seeded `permission.json` allows non-destructive **explore / troubleshoot** commands
out of the box (listing, read/print text, search, process/system info, network
diagnostics, checksums, git read-only subcommands). `find`/`awk`/`curl`/`fd` etc are
**ask** (not allow) — they are general exec engines.
Path **deny** rules still block secret files even when the binary or project
directory is allowed (`cat .env` → deny).

Still **ask** (not pre-allowed): writers and mutators — `rm`, `mv`, `cp`, `mkdir`,
`touch`, `sed`, `tee`, `chmod`, package managers, `git push` / `commit` / `reset`,
shells (`bash`/`python`/`node`), etc. Catastrophic commands stay **deny**:
`mkfs`, `dd`, `shutdown`, `reboot`, `poweroff`, `halt`.

Panel options: **Allow this** · **Allow for this session** · **Allow permanently** · **Deny with reason**

- **Session** — in-memory until the agent session ends (not written to disk).
  For a bash pipeline, remembers **every** real base that still needed approval.
- **Permanent** — live immediately + written to `permission.json`
  - bash → **primary base only** (`herdr … | python3 … | sed …` → only `herdr`)
  - write/edit → **exact file path** in `paths`

## Path wildcards

```
*     any chars except /
**    any chars including /
?     one char except /
```

**Deny always wins.** If any matching path rule is `deny`, no `allow` can
override it. Otherwise, a matching directory `allow` acts like path-scoped YOLO:
bash asks running in that directory, plus writes and edits there, are approved
automatically. A command that starts with `cd` into an allowed directory is also
approved when all detected path arguments are allowed. Bash deny rules and path
deny rules still block it.

Bash commands are decomposed for **policy**: chains (`;` `|` `&&`) and substitutions
each become a unit that must independently pass. Path-like args are checked against
path deny rules — so `ls; rm -rf x` and `cat .env` no longer slip through an allowed
prefix. The user still sees **one** prompt for the whole line; choosing session or
permanent allow covers every base that still needed approval.
(Heuristic, not a full shell parser — `$VAR` expansion isn't resolved.)

| Path | With example config |
| --- | --- |
| `.env` | deny |
| `prod.env` | deny |
| `.env.example` | **allow** |
| `.ssh/id_rsa` | deny |
| `src/main.ts` | ask (no rule) |

## permission.json

All policy is in JSON — **nothing is hard-blocked in code**.

`~/.pi/agent/permission.json` (or `$PI_CODING_AGENT_DIR/permission.json`).

If the file is **missing** (deleted or never created), load seeds it from
`permission.json.example` and re-creates the file on disk so you can edit it.
If the file is **present**, it is obeyed verbatim — even a single rule or an
empty `{}`. Existing files are never merged with, unioned against, or
overwritten by the example defaults.

`sudo_run` (from pix-sudo) is **not** gated here — its PAM password prompt is the
approve/deny step. Raw `sudo`/`doas` in bash is redirected to `sudo_run`.

```json
{
  "bash": {
    "ls": "allow",
    "cat": "allow",
    "rg": "allow",
    "git status*": "allow",
    "dd": "deny"
  },
  "tools": {
    "read": "allow",
    "write": "ask"
  },
  "paths": {
    "**/.env.example": "allow",
    "**/*.env": "deny",
    "/home/you/Projects/**": "allow"
  }
}
```

Full starter list: `permission.json.example`.

## Install

```bash
pi install npm:@itc-steve/pi-ask-complete
```

From a local checkout:

```bash
pi install /path/to/pi-ask-complete
```

Then `/reload`. `/permissions` shows current allows.

## `/yolo`

Session-scoped mode that auto-approves everything that would otherwise **ask**
(bash / write / edit / unresolved globs — the permission panel stays quiet).

- **Does:** skip the permission panel for every gate `ask` (including globs/`$VAR`).
- **Does not bypass:** path/bash/tool **deny** rules, or the `sudo`/`doas` → `sudo_run` redirect.
- **Does not touch:** `ask_user` (model questions still prompt you).
- **Dies with the session** — memory only; nothing written to `permission.json`. Cleared on `session_start`.

`/yolo` toggles · `/yolo on` · `/yolo off`. When on, `/permissions` shows the YOLO line.

## ask_user

LLM-callable multi-question bottom panel (`overlay: false` — transcript stays visible). Prefer this over plain-text multi-choice.

## Threat model / limits

This is a **heuristic agent gate**, not a sandbox or seccomp profile. The model is still the adversary; the gate reduces accidents and casual exfil, it does not stop a determined local process.

| Covered | Not a full guarantee |
| --- | --- |
| Chain / pipe / `&&` units each checked | Full shell AST / exotic quoting |
| `$(…)`, backticks, process subs as units | Nested quote mazes |
| Path deny on args, redirects, `if=`, `@file`, git `rev:path` | Paths only after real `$VAR` expansion |
| Glued operators (`cat .env;true`) cleaned | Every future shell metacharacter |
| Unresolved globs / braces / `$''` → **ask** | Interpreter `-c` payloads (permanent-allow `python3`/`bash` is high blast radius) |
| Any unit starting with `sudo`/`doas` → redirect | Root via other helpers |
| Corrupt / non-object `permission.json` keeps last good rules | First load of a corrupt file (everything asks) |
| Missing `permission.json` re-seeds from example (fail closed) | Broken install with no example (path deny-all via noPolicy) |

**Allow permanently** stores a **binary base** (e.g. all `cat`) or an **exact file path** for write/edit. Prefer session allow for interpreters.
