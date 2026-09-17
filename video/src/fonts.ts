import { staticFile } from "remotion";

// CSS-only font declaration (no delayRender — local woff2 files load instantly and never hang
// the render). font-display: block so glyphs wait briefly for the real face rather than flashing.
const files: [string, string, number][] = [
  ["IBM Plex Sans", "fonts/ibm-plex-sans-300.woff2", 300],
  ["IBM Plex Sans", "fonts/ibm-plex-sans-400.woff2", 400],
  ["IBM Plex Sans", "fonts/ibm-plex-sans-500.woff2", 500],
  ["IBM Plex Sans", "fonts/ibm-plex-sans-600.woff2", 600],
  ["IBM Plex Sans", "fonts/ibm-plex-sans-700.woff2", 700],
  ["Cascadia Mono", "fonts/cascadia-mono-400.woff2", 400],
  ["Cascadia Mono", "fonts/cascadia-mono-600.woff2", 600],
];

if (typeof document !== "undefined" && !document.getElementById("athar-fonts")) {
  const style = document.createElement("style");
  style.id = "athar-fonts";
  style.textContent = files
    .map(
      ([fam, file, w]) =>
        `@font-face{font-family:"${fam}";font-weight:${w};font-display:block;src:url(${staticFile(
          file,
        )}) format("woff2");}`,
    )
    .join("");
  document.head.appendChild(style);
  // Kick off loads so the faces are ready as early as possible (best-effort, non-blocking).
  files.forEach(([fam, file, w]) => {
    try {
      const face = new FontFace(fam, `url(${staticFile(file)})`, { weight: String(w) });
      face.load().then((f) => document.fonts.add(f)).catch(() => undefined);
    } catch {
      /* ignore */
    }
  });
}
