import type { SecurityKeys } from './api';

/**
 * Fetch a SecWeb resource with the per-request security-key headers and return
 * an object-URL. Browsers cannot attach custom headers to `<video src>` /
 * `<img src>`, so we fetch-with-headers and hand the media a blob URL.
 *
 * The caller MUST revoke() the returned URL when done (avoids leaking
 * decrypted bytes to session memory beyond their use).
 */
export async function fetchBlobUrl(
  path: string,
  keys: SecurityKeys,
): Promise<{ url: string; revoke: () => void }> {
  // Mirror api.headers: base64-encode the keys for header safety.
  const b64 = (s: string): string => {
    try {
      return btoa(s);
    } catch {
      // Non-Latin1 input: UTF-8 encode first, then base64.
      const bytes = new TextEncoder().encode(s);
      let bin = '';
      for (const b of bytes) bin += String.fromCharCode(b);
      return btoa(bin);
    }
  };
  const res = await fetch(path, {
    headers: {
      'X-Sec-Key-1': b64(keys.key1),
      'X-Sec-Key-2': b64(keys.key2),
    },
  });
  if (!res.ok) {
    throw new Error(`fetch failed: ${res.status}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  return { url, revoke: () => URL.revokeObjectURL(url) };
}
