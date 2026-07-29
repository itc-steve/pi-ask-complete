/**
 * Heuristic bash decomposition for the permission gate.
 *
 * Two jobs:
 *  - splitUnits: break a command line into individual command "units" so a rule
 *    lookup can require EVERY unit to be allowed (closes `ls; rm -rf x` bypass).
 *    Units include segments split on ; | && || & \n AND the contents of
 *    command substitution `$(...)` / backticks (closes `echo $(rm x)`).
 *  - pathArgs: pull path-like arguments (incl. redirect targets) out of a
 *    command so they can be checked against path deny rules
 *    (closes `cat .env` / `echo x > .env`).
 *
 * ponytail: regex heuristic, not a real shell parser. Misses full $VAR resolution
 * and nested quote mazes. Unresolved globs/braces/$'' force ask at the store.
 * Upgrade to a shell AST (mvdan-style) only if those vectors matter.
 */

const MAX_DEPTH = 6;

/**
 * Blank out <<EOF … EOF heredoc bodies so their lines are not treated as units
 * (node <<'EOF' / const / for / console.log were landing in permission.json).
 */
export function stripHeredocs(command: string): string {
  // <<[-]?  optional quotes  WORD  then body until a line that is exactly WORD
  return command.replace(
    /<<(-)?\s*(['"]?)(\w+)\2\r?\n[\s\S]*?\r?\n\3(?=\r?\n|$)/g,
    " ",
  );
}

/**
 * Drop `# …` comments outside quotes so agent annotations don't become units
 * (`# setup; then rm x` → no `#`/`then` bases from prose).
 * ponytail: not a full lexer; # inside $'…' / unclosed quotes is best-effort.
 */
export function stripComments(command: string): string {
  let out = "";
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!;
    if (quote) {
      out += c;
      if (c === "\\" && quote === '"' && i + 1 < command.length) {
        out += command[++i];
      } else if (c === quote) {
        quote = null;
      }
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      out += c;
      continue;
    }
    // Bash: # starts a comment only at a word boundary (not $# / ${#x} / foo#bar).
    const prev = i === 0 ? "" : command[i - 1]!;
    if (c === "#" && (i === 0 || /[\s;|&()]/.test(prev))) {
      while (i + 1 < command.length && command[i + 1] !== "\n") i++;
      continue;
    }
    out += c;
  }
  return out;
}

/**
 * Split on shell control operators, but NOT inside quotes.
 * Fixes `python3 -c "…\n…"` being shredded into fake units (and crashing the
 * permission panel with a 20-base label).
 */
function splitSegments(command: string): string[] {
  const parts: string[] = [];
  let cur = "";
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!;
    if (quote) {
      cur += c;
      if (c === "\\" && quote === '"' && i + 1 < command.length) {
        cur += command[++i];
      } else if (c === quote) {
        quote = null;
      }
      continue;
    }
    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    // && or ||
    if ((c === "&" || c === "|") && command[i + 1] === c) {
      if (cur.trim()) parts.push(cur.trim());
      cur = "";
      i++;
      continue;
    }
    // Redirects that contain & must not become split points:
    //   2>&1  >&2  &>file  &>>file
    // (bare `cmd &` / `cmd1 & cmd2` still split — that's intentional).
    if (c === "&") {
      const prev = cur.length ? cur[cur.length - 1]! : "";
      const next = command[i + 1] ?? "";
      if (prev === ">" || next === ">") {
        cur += c;
        continue;
      }
    }
    if (c === ";" || c === "|" || c === "&" || c === "\n") {
      if (cur.trim()) parts.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

/** Extract `$(...)`, backtick, and process substitution <(...)/>(...) bodies.
 * (one level; recursion + segment split handles nesting). */
function extractSubstitutions(command: string): string[] {
  const out: string[] = [];
  // $( ... )
  const dollar = /\$\(([^()]*(?:\([^()]*\)[^()]*)*)\)/g;
  let m: RegExpExecArray | null;
  while ((m = dollar.exec(command))) {
    if (m[1]?.trim()) out.push(m[1].trim());
  }
  // backticks
  const back = /`([^`]*)`/g;
  while ((m = back.exec(command))) {
    if (m[1]?.trim()) out.push(m[1].trim());
  }
  // process substitution <(cmd) and >(cmd) — C1 fix
  const proc = /[<>]\(\s*([^()]*?(?:\([^()]*\)[^()]*?)*)\s*\)/g;
  while ((m = proc.exec(command))) {
    if (m[1]?.trim()) out.push(m[1].trim());
  }
  return out;
}

/**
 * All command units in a line: each segment, plus every substitution body
 * (recursively), each itself segment-split.
 */
export function splitUnits(command: string, depth = 0): string[] {
  // Top-level only: drop comments + heredoc bodies before segmenting.
  const cleaned =
    depth === 0 ? stripComments(stripHeredocs(command)) : command;
  const trimmed = cleaned.trim();
  if (!trimmed || depth > MAX_DEPTH) return trimmed ? [trimmed] : [];

  const units: string[] = [];
  for (const seg of splitSegments(trimmed)) {
    const subs = extractSubstitutions(seg);
    // The segment with substitutions blanked out is still a real command to check.
    const bare = seg
      .replace(/\$\([^)]*\)/g, " ")
      .replace(/`[^`]*`/g, " ")
      .replace(/[<>]\([^)]*\)/g, " ")
      .trim();
    if (bare) units.push(bare);
    for (const sub of subs) units.push(...splitUnits(sub, depth + 1));
  }
  return units.length ? units : [];
}

/**
 * Collapse shell quoting/escapes to the path value the shell would open.
 *  - unquoted \x → x; drop unescaped ' and " anywhere (not just edges)
 *  - single-quoted text is literal (including $ and \) — closes C3 while
 *    keeping `'$HOME'/.env` as the literal path $HOME/.env
 *  - double-quoted: \ only escapes $ ` " \ newline; $ residue stays so
 *    isUnresolvedPath still fires for "$HOME"/.env
 * Unclosed quote → return s unchanged (fail closed: ambiguous).
 */
function collapseShellToken(s: string): string {
  let out = "";
  let i = 0;
  while (i < s.length) {
    const c = s[i]!;
    if (c === "'") {
      i++;
      let closed = false;
      while (i < s.length) {
        if (s[i] === "'") {
          closed = true;
          i++;
          break;
        }
        out += s[i++];
      }
      if (!closed) return s;
      continue;
    }
    if (c === '"') {
      i++;
      let closed = false;
      while (i < s.length) {
        if (s[i] === '"') {
          closed = true;
          i++;
          break;
        }
        if (s[i] === "\\" && i + 1 < s.length) {
          const n = s[i + 1]!;
          // bash: inside double quotes only $ ` " \ and newline are special
          if (n === "$" || n === "`" || n === '"' || n === "\\" || n === "\n") {
            out += n;
            i += 2;
          } else {
            out += s[i++]; // keep the backslash
          }
        } else {
          out += s[i++];
        }
      }
      if (!closed) return s;
      continue;
    }
    if (c === "\\" && i + 1 < s.length) {
      out += s[i + 1];
      i += 2;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

function unquote(s: string): string {
  return collapseShellToken(s).trim();
}

/**
 * Normalize a raw argv token into a path candidate:
 *  - strip @file upload prefix, trailing ) from subs
 *  - strip trailing shell operators glued on (`cat .env;true` → `.env`)
 *  - peel git pathspecs (`HEAD:.env` → `.env`)
 *  - peel dd-style if=/of= assignments
 *  - collapse intra-word quotes/escapes (`.en''v` → `.env`) so path globs match
 */
export function cleanPathToken(token: string): string {
  let t = token.trim();
  if (!t) return "";
  t = t.replace(/^@/, "");
  // Operators glued to the path without whitespace (bypass vector).
  t = t.replace(/[;|&`].*$/, "");
  t = t.replace(/\)+$/, "").trim();
  if (!t) return "";

  // dd/install style: if=.env of=/tmp/x
  const assign = t.match(
    /^(?:if|of|in|out|file|path|filename|dest|source)=(.+)$/i,
  );
  if (assign?.[1]) t = assign[1];

  // git pathspec rev:path / :path — not Windows drive (C:\… / C:/…)
  if (
    t.includes(":") &&
    !/^[A-Za-z]:[\\/]/.test(t) &&
    !/^[A-Za-z]:$/.test(t)
  ) {
    const pathPart = t.slice(t.lastIndexOf(":") + 1);
    if (pathPart) t = pathPart;
  }

  // After operator/assign/pathspec peel: collapse quotes so **/.env matches.
  return collapseShellToken(t).trim();
}

/**
 * True when the token still needs shell expansion before path policy can allow.
 * Quote-aware: single-quoted text is literal (`'$HOME'` is not an expansion);
 * `$VAR` / `${…}` / `$(…)` / `$ '…'` / globs / braces outside single quotes
 * (and `$` inside double quotes) still force unresolved.
 */
export function isUnresolvedPath(token: string): boolean {
  if (!token) return false;
  // Bash expands ~user, but this gate only resolves the current user's ~/.
  if (/^~[^/\s]+(?:\/|$)/.test(token)) return true;
  let i = 0;
  while (i < token.length) {
    const c = token[i]!;
    if (c === "'") {
      const end = token.indexOf("'", i + 1);
      if (end < 0) return true; // unclosed — fail closed
      i = end + 1;
      continue;
    }
    if (c === '"') {
      i++;
      while (i < token.length && token[i] !== '"') {
        if (token[i] === "\\" && i + 1 < token.length) {
          i += 2;
          continue;
        }
        // $ expands inside double quotes; globs do not
        if (token[i] === "$" && i + 1 < token.length) {
          const n = token[i + 1]!;
          if (n === "'" || n === "{" || n === "(" || /[A-Za-z_]/.test(n)) return true;
        }
        i++;
      }
      if (i >= token.length) return true; // unclosed
      i++;
      continue;
    }
    if (c === "\\" && i + 1 < token.length) {
      i += 2;
      continue;
    }
    // unquoted glob / brace / $
    if (c === "*" || c === "?" || c === "[" || c === "{") return true;
    if (c === "$" && i + 1 < token.length) {
      const n = token[i + 1]!;
      if (n === "'" || n === "{" || n === "(" || /[A-Za-z_]/.test(n)) return true;
    }
    i++;
  }
  return false;
}

// Looks like a path argument (has a slash or a dotfile/ext), not a flag.
function looksLikePath(token: string): boolean {
  if (!token || token.startsWith("-")) return false;
  if (token.includes("=")) return false; // env assignment / --opt=val left after clean
  return (
    token.includes("/") ||
    /^\.?[\w.-]+\.\w+$/.test(token) ||
    token.startsWith(".") ||
    // git pathspec residue or plain secret basenames without a dot (id_rsa)
    /^(id_rsa|id_ed25519|id_ecdsa|id_dsa|shadow|gshadow|sudoers|kubeconfig)$/i.test(
      token,
    )
  );
}

/**
 * Path-like arguments across the whole command line, including redirect targets
 * (`> file`, `>> file`, `2> file`). Quotes stripped; returned cleaned.
 */
export function pathArgs(command: string): string[] {
  const src = stripComments(stripHeredocs(command));
  const out: string[] = [];

  const push = (raw: string) => {
    const t = cleanPathToken(raw);
    if (t && (looksLikePath(t) || isUnresolvedPath(t))) out.push(t);
  };

  // redirect targets: >, >>, <, 2>, &> followed by a filename (but NOT <( > ( process subs)
  const redir = /(?:\d*&?>{1,2}|<)\s*("[^"]+"|'[^']+'|(?!\()\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = redir.exec(src))) {
    const t = unquote(m[1]!);
    if (t && !t.startsWith("&")) push(t);
  }

  // bare tokens (and if=/.git pathspec forms via cleanPathToken)
  for (const rawTok of src.split(/\s+/)) {
    if (!rawTok) continue;
    // Attached option values commonly carry paths (`--file=.env`, `--chdir=/tmp`).
    const optionValue = rawTok.match(/^--?[A-Za-z][A-Za-z0-9-]*=(.+)$/)?.[1];
    if (optionValue) {
      push(optionValue);
      continue;
    }
    // Keep if=.env visible to cleanPathToken (looksLikePath alone would skip `=`).
    if (/^(?:if|of|in|out|file|path|filename|dest|source)=/i.test(rawTok)) {
      push(rawTok);
      continue;
    }
    push(rawTok.replace(/^[<>]+\(?/, ""));
  }

  return [...new Set(out)];
}

/**
 * True when the line has unquoted glob/brace/ANSI-C tokens so path policy
 * cannot prove the real path — caller should force ask (never silent allow).
 */
export function hasUnresolvedExpansion(command: string): boolean {
  const src = stripComments(stripHeredocs(command));
  for (const rawTok of src.split(/\s+/)) {
    if (!rawTok || rawTok.startsWith("-")) continue;
    // Quote-aware on the raw token first: '$HOME' is literal, "$HOME" is not.
    // Do not re-scan the collapsed form for $ — that would turn single-quoted
    // literal $ into a false expansion after cleanPathToken strips the quotes.
    if (isUnresolvedPath(rawTok)) return true;
    const t = cleanPathToken(rawTok);
    // Globs/braces that survive collapse (unquoted) still force ask.
    if (t && /[*?[{]/.test(t)) return true;
  }
  // Whole-line $'…' even when glued
  if (/\$'[^']*'/.test(src)) return true;
  return false;
}
