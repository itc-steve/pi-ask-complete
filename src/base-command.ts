/**
 * Extract the base command name used for permanent whitelist entries.
 *
 * Examples:
 *   grep -f "Hi"           → grep
 *   /usr/bin/grep foo      → grep
 *   sudo apt install x     → apt
 *   FOO=1 BAR=2 ls -la     → ls
 *   env FOO=1 npm test     → npm
 *   strace -f rm -rf x     → rm
 */

/** True when the command is invoked via sudo/doas (bash should use sudo_run instead). */
export function isSudoPrefixed(command: string): boolean {
  const s = command.trim();
  if (!s) return false;
  // sudo / doas, optional long flags before the real command
  return /^(sudo|doas)(\s|$)/i.test(s);
}

/** Strip a leading sudo/doas (+ common flags) so rules match the real binary. */
export function stripSudoPrefix(command: string): string {
  let s = command.trim();
  // sudo -n -u root pacman … → pacman …
  s = s.replace(/^(sudo|doas)(\s+(-[A-Za-z]+|--\S+))*(?=\s|$)/i, "").trim();
  return s;
}

/**
 * Exec wrappers whose own allow must never stand for the inner binary.
 * Keep in sync with stripWrappers.
 */
const WRAPPERS = new Set([
  "command",
  "builtin",
  "time",
  "nohup",
  "nice",
  "env",
  "strace",
  "ltrace",
  "timeout",
  "xargs",
  "stdbuf",
  "setsid",
  "chroot",
  "unshare",
]);

/** Long opts that take a separate argument for the wrappers above. */
const WRAPPER_LONG_VALUE = new Set([
  "user",
  "unset",
  "chdir",
  "split-string",
  "arg-file",
  "delimiter",
  "replace",
  "signal",
  "kill-after",
  "max-procs",
  "max-args",
  "max-chars",
]);

/** Short opts that take a separate argument (`-u NAME`, `-e EXPR`, …). */
const WRAPPER_SHORT_VALUE = new Set([
  "u",
  "e",
  "p",
  "s",
  "k",
  "n",
  "C",
  "I",
  "E",
  "L",
  "P",
  "S",
  "o", // stdbuf -o MODE
]);

/** Drop leading wrapper flags (`-f`, `-i`, `-u NAME`, `--flag`, timeout duration). */
function skipWrapperFlags(rest: string): string {
  for (let n = 0; n < 24 && rest; n++) {
    if (rest === "--") return "";
    if (rest.startsWith("-- ")) return rest.slice(3).trim();

    if (rest.startsWith("--")) {
      const m = rest.match(/^--([^=\s]+)(?:=(\S+))?(?:\s+|$)([\s\S]*)/);
      if (!m) break;
      rest = (m[3] ?? "").trim();
      // --user NAME (value not glued with =)
      if (m[2] === undefined && WRAPPER_LONG_VALUE.has(m[1]!) && rest && !rest.startsWith("-")) {
        rest = rest.replace(/^\S+\s*/, "").trim();
      }
      continue;
    }

    if (rest[0] === "-" && rest[1] && rest[1] !== "-") {
      // -f / -i / -u NAME / -e=expr
      const m = rest.match(/^-([A-Za-z0-9]+)(?:=(\S+))?(?:\s+|$)([\s\S]*)/);
      if (!m) break;
      const flags = m[1]!;
      rest = (m[3] ?? "").trim();
      if (m[2] !== undefined) continue; // -e=expr already consumed
      // single short opt that takes a value: -u NAME
      if (
        flags.length === 1 &&
        WRAPPER_SHORT_VALUE.has(flags) &&
        rest &&
        !rest.startsWith("-")
      ) {
        rest = rest.replace(/^\S+\s*/, "").trim();
      }
      continue;
    }

    // timeout duration: 5 / 5s / 1m
    if (/^\d/.test(rest)) {
      rest = rest.replace(/^\S+\s*/, "").trim();
      continue;
    }
    break;
  }
  return rest;
}

/**
 * True when command starts with a wrapper that has trailing tokens.
 * Combined with stripWrappers() === "", means the inner binary is unresolvable.
 */
export function wrapperHasArgs(command: string): boolean {
  let s = command.trim();
  s = s.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+)+/, "").trim();
  if (!s) return false;
  const m = s.match(/^(\S+)(?:\s+(\S+))?/);
  if (!m?.[2]) return false;
  const tok = m[1]!.replace(/^['"]|['"]$/g, "");
  const bin = (tok.split(/[/\\]/).pop() ?? tok).toLowerCase();
  return WRAPPERS.has(bin);
}

/**
 * Peel leading ENV=value assignments + exec wrappers (env/strace/timeout/…).
 * Returns the inner command, or "" when only a bare wrapper remains.
 * Callers must treat "" + a wrapper prefix as unresolvable (ask, never allow).
 */
export function stripWrappers(command: string): string {
  let s = command.trim();
  if (!s) return "";

  for (let i = 0; i < 8; i++) {
    // FOO=1 BAR=2 cmd → cmd
    s = s
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+)+/, "")
      .trim();
    if (!s) return "";

    const m = s.match(/^(\S+)(?:\s+([\s\S]*))?$/);
    if (!m) return s;
    const tok = m[1]!.replace(/^['"]|['"]$/g, "");
    const bin = (tok.split(/[/\\]/).pop() ?? tok).toLowerCase();
    if (!WRAPPERS.has(bin)) return s; // real binary — stop

    const rest = skipWrapperFlags((m[2] ?? "").trim());
    if (!rest) return ""; // bare wrapper / flags only
    s = rest;
  }
  return s.trim();
}

export function baseCommand(command: string): string {
  let s = stripSudoPrefix(command.trim());
  if (!s) return "";

  // Resolve through wrappers so `strace -f rm` → rm (not strace).
  // Bare `env` peels to "" — fall back so the wrapper name itself is the base.
  s = stripWrappers(s) || s;

  // If the user wrote a pipeline/list, whitelist against the first segment.
  const first = s.split(/[|;&\n]/)[0]?.trim() ?? s;
  const token = first.split(/\s+/)[0] ?? "";
  if (!token) return "";

  // Drop surrounding quotes and path prefix.
  const unquoted = token.replace(/^['"]|['"]$/g, "");
  const base = unquoted.split(/[/\\]/).pop() ?? unquoted;
  return base;
}

/** Keywords / non-binaries that must never become permanent allow keys. */
const BLOCKED_BASH_KEYS = new Set([
  // shell grammar
  "if",
  "then",
  "else",
  "elif",
  "fi",
  "for",
  "while",
  "until",
  "do",
  "done",
  "case",
  "esac",
  "function",
  "select",
  "coproc",
  "in",
  // common leaks from node/python heredoc bodies
  "const",
  "let",
  "var",
  "return",
  "class",
  "import",
  "from",
  "def",
]);

/**
 * True when a bash allow key is safe to write to permission.json.
 * Permanent allow only stores simple binary names (python3, mkfs.ext4) — never
 * prose fragments, JS lines, or shell keywords that leaked from bad splits.
 */
export function isPersistableBashKey(key: string): boolean {
  if (!key || key.length > 64) return false;
  if (BLOCKED_BASH_KEYS.has(key)) return false;
  // Simple binary: rg, python3, docker-compose
  if (/^[A-Za-z_][A-Za-z0-9_+-]*$/.test(key)) return true;
  // Dotted binaries only for known families (mkfs.ext4, python3.12) — not console.log
  if (/^(mkfs|fsck|python|pip|node)[0-9]*\.[A-Za-z0-9_+-]+$/.test(key)) return true;
  return false;
}

/** True when `command` is covered by a whitelist entry (base name or exact). */
export function commandMatchesWhitelist(
  command: string,
  allowed: ReadonlySet<string> | readonly string[],
): boolean {
  const set = allowed instanceof Set ? allowed : new Set(allowed);
  if (set.size === 0) return false;
  const full = command.trim();
  if (set.has(full)) return true;
  const base = baseCommand(command);
  return base !== "" && set.has(base);
}

/**
 * Strip noise so rule patterns match the logical command.
 * Today: git globals (`-C`, `-c`, `--git-dir`, …) so `git status*` matches
 * `git -C /path status`.
 *
 * ponytail: regex strip of known globals; quoted paths with spaces not handled.
 */
export function normalizeCommandForMatch(command: string): string {
  const trimmed = command.trim();
  if (!trimmed) return trimmed;

  // First token's basename is `git` (covers git, /usr/bin/git, ./git).
  // Always rewrite to bare `git` so patterns like `git status*` match.
  const tok = trimmed.match(/^\S+/);
  if (!tok) return trimmed;
  const bin = (tok[0]!.split(/[/\\]/).pop() ?? tok[0]!).replace(/^['"]|['"]$/g, "");
  if (!/^git$/i.test(bin)) return trimmed;

  let rest = trimmed.slice(tok[0]!.length).replace(/^\s+/, "");

  // Repeatedly peel one global option from the front until the subcommand.
  // Options that take a value: -C path, -c key=val, --git-dir[=]path, …
  const withVal =
    /^(?:-C|--git-dir|--work-tree|--namespace|--config-env|--exec-path)(?:=|\s+)\S+\s*/;
  const shortC = /^-c\s+\S+\s*/;
  const flagOnly =
    /^(?:-p|--paginate|-P|--no-pager|--bare|--no-replace-objects|--no-optional-locks|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs)\s+/;

  for (let i = 0; i < 16; i++) {
    let next = rest.replace(withVal, "").replace(shortC, "").replace(flagOnly, "");
    // --exec-path with no value (prints path; rare in agent cmds)
    next = next.replace(/^--exec-path\s+/, "");
    if (next === rest) break;
    rest = next;
  }

  return rest ? `git ${rest}`.trim() : "git";
}
