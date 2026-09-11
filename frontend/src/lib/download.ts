/**
 * Hand a fetched blob to the browser as a download. The bytes come from the
 * API through the shared client (cookie auth, problem+json on failure), so this
 * only does the DOM part; nothing is written to web storage.
 */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoke on the next tick: Safari needs the URL alive for the click to land.
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Pretty-print a provider JSON fragment for an evidence panel. */
export function prettyJson(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}
