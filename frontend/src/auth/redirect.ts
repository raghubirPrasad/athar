/** Where LoginPage sends the user after success. Router state only — never web storage. */
export interface RedirectState {
  from?: string;
}

/**
 * A path that is unambiguously same-origin, or `/`.
 *
 * The obvious check — starts with `/`, does not start with `//` — is not enough, and the gap is
 * the one `react-router`'s own open-redirect advisory describes: a browser normalises a backslash
 * to a forward slash while parsing a URL, so `/\evil.example` is read as `//evil.example` and
 * leaves the origin. Control characters are the second half of the same trick: browsers strip
 * tabs, newlines and other C0 characters before parsing, so a tab inside the path arrives as
 * `//evil.example` too.
 *
 * So: reject anything carrying a character the parser would remove, then require a leading `/`
 * that is not followed by another separator of either kind. Rejected input becomes `/`, never an
 * error — a failed redirect should land the user on the dashboard, not on a stack trace.
 *
 * Written here rather than left to the router, because this holds whatever version is installed.
 */
export function redirectTarget(state: unknown): string {
  if (typeof state !== "object" || state === null) return "/";
  const from = (state as RedirectState).from;
  if (typeof from !== "string") return "/";
  // eslint-disable-next-line no-control-regex -- the C0 range is exactly what is being rejected
  if (/[\u0000-\u0020\u007f]/.test(from)) return "/";
  if (!/^\/(?![/\\])/.test(from)) return "/";
  return from;
}
