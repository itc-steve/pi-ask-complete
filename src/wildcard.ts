/**
 * Path / command glob matching.
 *
 *   *   → any chars except /
 *   **  → any chars including /
 *   ?   → one char except /
 *
 * Patterns with no `/` also match against the basename
 * (so `*.env` matches `/a/b/foo.env` and `.env`, but not `.env.example`).
 */

const MAX_PATTERN = 500;

export function normalizePath(p: string): string {
  return p.replaceAll("\\", "/").replace(/\/{2,}/g, "/");
}

/** Compile a glob to a RegExp. Invalid/oversized patterns never match. */
export function compileGlob(pattern: string): RegExp {
  if (!pattern || pattern.length > MAX_PATTERN) return /$^/;

  const p = normalizePath(pattern);
  let out = "^";
  for (let i = 0; i < p.length; ) {
    if (p[i] === "*" && p[i + 1] === "*") {
      if (p[i + 2] === "/") {
        // **/ → zero or more directories
        out += "(?:.*/)?";
        i += 3;
      } else {
        out += ".*";
        i += 2;
      }
    } else if (p[i] === "*") {
      out += "[^/]*";
      i += 1;
    } else if (p[i] === "?") {
      out += "[^/]";
      i += 1;
    } else {
      const c = p[i]!;
      out += /[.+^${}()|[\]\\]/.test(c) ? `\\${c}` : c;
      i += 1;
    }
  }
  out += "$";
  // nosemgrep: pattern is length-bounded + escaped; only * ? ** are wild
  return new RegExp(out);
}

export function matchGlob(pattern: string, value: string): boolean {
  const re = compileGlob(pattern);
  const norm = normalizePath(value);
  if (re.test(norm)) return true;

  // File-name-only patterns also match basename
  if (!pattern.includes("/")) {
    const base = norm.split("/").pop() ?? norm;
    if (re.test(base)) return true;
  }
  return false;
}

/**
 * Specificity score for a glob: more literal (non-wildcard) chars = more
 * specific; fewer `*` breaks ties. So a deep dotfile deny beats a broad
 * `Projects` tree allow for the same file even though both match.
 */
export function globSpecificity(pattern: string): number {
  const p = normalizePath(pattern);
  // Literal chars AFTER the last wildcard pin the filename/tail — the strongest
  // specificity signal. A pattern ending in `**` (broad tree) pins nothing → 0,
  // so two trees tie and resolveRules' deny-wins tiebreak decides.
  const lastWild = Math.max(p.lastIndexOf("*"), p.lastIndexOf("?"));
  const suffix = lastWild < 0 ? p : p.slice(lastWild + 1);
  return suffix.replace(/[*?]/g, "").length;
}

/**
 * Most-specific matching rule wins, regardless of allow/deny. On an exact
 * specificity tie, deny wins (fail closed). Returns undefined when nothing
 * matches.
 */
export function resolveRules(
  rules: ReadonlyArray<{ pattern: string; state: "allow" | "deny" }>,
  value: string,
): "allow" | "deny" | undefined {
  let best: { state: "allow" | "deny"; score: number } | undefined;
  for (const rule of rules) {
    if (!matchGlob(rule.pattern, value)) continue;
    const score = globSpecificity(rule.pattern);
    if (
      !best ||
      score > best.score ||
      // equal score → deny wins
      (score === best.score && rule.state === "deny")
    ) {
      best = { state: rule.state, score };
    }
  }
  return best?.state;
}
