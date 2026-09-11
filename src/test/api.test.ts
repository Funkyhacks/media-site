import { describe, it, expect, vi, afterEach } from 'vitest';
import { api, ApiError } from '../lib/api';

function mockFetch(impl: (url: string, init?: RequestInit) => Response | Promise<Response>) {
  // Real fetch() returns a Promise; mirror that so `.then()` works.
  const fn = vi.fn((...args: [string, RequestInit?]) => Promise.resolve(impl(args[0], args[1])));
  vi.stubGlobal('fetch', fn);
  return fn;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

const KEYS = { key1: 'alpha', key2: 'beta' };

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('api client', () => {
  it('base64-encodes security keys in request headers', async () => {
    const fn = mockFetch(() => jsonResponse([]));
    await api.listFolders({ keys: KEYS });
    const [url, init] = fn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/folders');
    const h = init.headers as Record<string, string>;
    expect(h['X-Sec-Key-1']).toBe(btoa('alpha'));
    expect(h['X-Sec-Key-2']).toBe(btoa('beta'));
  });

  it('sends folder filter as a query param when provided', async () => {
    const fn = mockFetch(() => jsonResponse([]));
    await api.listFiles({ keys: KEYS }, 42);
    const [url] = fn.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/files?folder_id=42');
  });

  it('throws ApiError with the backend detail on non-2xx', async () => {
    mockFetch(() => jsonResponse({ detail: 'security keys rejected' }, 403));
    await expect(api.listFolders({ keys: KEYS })).rejects.toMatchObject({
      status: 403,
      message: 'security keys rejected',
    });
  });

  it('ApiError is an Error instance', () => {
    const e = new ApiError(404, 'not found');
    expect(e).toBeInstanceOf(Error);
    expect(e.status).toBe(404);
  });
});
