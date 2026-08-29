/**
 * SecWeb API client.
 *
 * Zero-knowledge discipline (SPEC.md directives #1/#2): the two security keys
 * are kept ONLY in React state (memory) for the session and sent in the
 * `X-Sec-Key-1` / `X-Sec-Key-2` headers on every key-bearing request. They are
 * never persisted to localStorage/cookies and are wiped on logout/close.
 */

export interface RegisterPayload {
  username: string;
  password: string;
  key1: string;
  key2: string;
}

export interface AuthResult {
  jwt: string;
  user_id: number;
}

export interface Folder {
  id: number;
  name: string;
  encrypted_name: string;
  parent_id: number | null;
  file_count: number;
}

export interface FileItem {
  id: string;
  type: string;
  encrypted_name: string;
  name: string;
  extension: string;
  size: number;
  created_at: string;
  thumb_id: string | null;
}

export interface SecurityKeys {
  key1: string;
  key2: string;
}

export interface ApiOptions {
  keys: SecurityKeys;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
  }
}

function b64(s: string): string {
  // Header-safe base64 (matches the backend's tolerant decode; also safe for
  // any non-ASCII bytes the user pastes into the key fields).
  try {
    return btoa(s);
  } catch {
    // Non-Latin1 input: UTF-8 encode first, then base64.
    const bytes = new TextEncoder().encode(s);
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }
}

function headers(keys: SecurityKeys): Record<string, string> {
  return {
    'X-Sec-Key-1': b64(keys.key1),
    'X-Sec-Key-2': b64(keys.key2),
  };
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (body && typeof body.detail === 'string') detail = body.detail;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

export const api = {
  // --- auth ---
  // The backend base64-decodes key1/key2 (see `_b64` in auth_routes.py), so we
  // send them base64-encoded here. The frontend keeps the user's raw strings in
  // memory only (directive #2) and only base64-encodes them for the wire.
  register(payload: RegisterPayload): Promise<AuthResult> {
    const body: RegisterPayload = { ...payload, key1: b64(payload.key1), key2: b64(payload.key2) };
    return fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => handle<AuthResult>(r));
  },

  login(payload: RegisterPayload): Promise<AuthResult> {
    const body: RegisterPayload = { ...payload, key1: b64(payload.key1), key2: b64(payload.key2) };
    return fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => handle<AuthResult>(r));
  },

  logout(): Promise<{ ok: boolean }> {
    return fetch('/api/auth/logout', { method: 'POST' }).then((r) => handle<{ ok: boolean }>(r));
  },

  // --- folders ---
  listFolders(opts: ApiOptions): Promise<Folder[]> {
    return fetch('/api/folders', { headers: headers(opts.keys) }).then((r) => handle<Folder[]>(r));
  },

  createFolder(opts: ApiOptions, name: string, parent_id?: number): Promise<{ id: number }> {
    return fetch('/api/folders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers(opts.keys) },
      body: JSON.stringify({ name, parent_id: parent_id ?? null }),
    }).then((r) => handle<{ id: number }>(r));
  },

  // --- files ---
  listFiles(opts: ApiOptions, folder_id?: number): Promise<FileItem[]> {
    const qs = folder_id != null ? `?folder_id=${folder_id}` : '';
    return fetch(`/api/files${qs}`, { headers: headers(opts.keys) }).then((r) => handle<FileItem[]>(r));
  },

  upload(opts: ApiOptions, file: File, folder_id?: number): Promise<{ id: string; thumb_id: string | null }> {
    const fd = new FormData();
    fd.append('file', file);
    if (folder_id != null) fd.append('folder_id', String(folder_id));
    return fetch('/api/files/upload', {
      method: 'POST',
      headers: headers(opts.keys),
      body: fd,
    }).then((r) => handle<{ id: string; thumb_id: string | null }>(r));
  },

  contentUrl(id: string): string {
    return `/api/files/${id}/content`;
  },

  thumbUrl(id: string): string {
    return `/api/files/${id}/thumb`;
  },

  // --- favorites ---
  listFavorites(opts: ApiOptions): Promise<{ file_id: string }[]> {
    return fetch('/api/favorites', { headers: headers(opts.keys) }).then((r) => handle<{ file_id: string }[]>(r));
  },

  addFavorite(opts: ApiOptions, file_id: string): Promise<{ ok: boolean }> {
    return fetch(`/api/favorites/${file_id}`, { method: 'POST', headers: headers(opts.keys) }).then(
      (r) => handle<{ ok: boolean }>(r),
    );
  },

  removeFavorite(opts: ApiOptions, file_id: string): Promise<{ ok: boolean }> {
    return fetch(`/api/favorites/${file_id}`, { method: 'DELETE', headers: headers(opts.keys) }).then(
      (r) => handle<{ ok: boolean }>(r),
    );
  },
};
