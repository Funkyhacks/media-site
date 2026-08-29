/**
 * Player — custom media viewer (SPEC.md §2 Media Viewer).
 *
 * Supports Play, Pause, Next, Prev within the current folder context. Content is
 * decrypted + streamed from the backend with the per-request security-key
 * headers, rendered from a blob URL that is revoked on change/unmount.
 *
 * Browsers block custom headers on <video src>, so we fetch-with-headers and
 * hand the element a blob URL (decrypted bytes live in memory only, then freed).
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import type { FileItem, SecurityKeys } from '../lib/api';
import { api } from '../lib/api';
import { fetchBlobUrl } from '../lib/blobUrl';

export function Player({
  current,
  list,
  keys,
}: {
  current: FileItem | null;
  list: FileItem[];
  keys: SecurityKeys;
}) {
  const [url, setUrl] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const revokeRef = useRef<(() => void) | null>(null);

  const index = list.findIndex((f) => f.id === current?.id);

  const [playing, setPlaying] = useState(false);
  const videoRef = useRef<HTMLVideoElement | null>(null);

  const load = useCallback(
    async (item: FileItem) => {
      setBusy(true);
      setErr(null);
      try {
        const r = await fetchBlobUrl(api.contentUrl(item.id), keys);
        revokeRef.current?.();
        revokeRef.current = r.revoke;
        setUrl(r.url);
      } catch (e) {
        setErr(e instanceof Error ? e.message : 'failed to open');
        setUrl(null);
      } finally {
        setBusy(false);
      }
    },
    [keys],
  );

  useEffect(() => {
    if (current) void load(current);
    else setUrl(null);
    return () => {
      revokeRef.current?.();
      revokeRef.current = null;
    };
  }, [current, load]);

  const step = (delta: number) => {
    if (!list.length) return;
    const i = index < 0 ? 0 : (index + delta + list.length) % list.length;
    load(list[i]);
  };

  if (!current) {
    return <div className="banner" style={{ color: 'var(--muted)' }}>Select a file to play.</div>;
  }

  const isVideo = /^video\//.test(current.type);
  const isImage = /^image\//.test(current.type);

  return (
    <div className="player">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
        <h3 style={{ margin: 0 }}>{current.name}</h3>
        <span className="badge">{current.extension.toUpperCase()}</span>
      </div>

      {busy && <div className="banner" style={{ color: 'var(--muted)' }}>Decrypting…</div>}
      {err && <div className="banner error" role="alert">{err}</div>}

      {!busy && !err && url && (
        isVideo ? (
          <video
            ref={videoRef}
            src={url}
            controls
            autoPlay
            style={{ width: '100%' }}
            onPlay={() => setPlaying(true)}
            onPause={() => setPlaying(false)}
          />
        ) : isImage ? (
          <img src={url} alt={current.name} style={{ width: '100%', maxWidth: 720, borderRadius: 8 }} />
        ) : (
          <div className="banner" style={{ color: 'var(--muted)' }}>
            Preview not available for {current.type} — use the Download action.
          </div>
        )
      )}

      <div className="controls">
        {isVideo && (
          <>
            <button
              className="btn primary"
              onClick={() => {
                const v = videoRef.current;
                if (!v) return;
                if (v.paused) void v.play();
                else v.pause();
              }}
            >
              {playing ? '⏸ Pause' : '▶ Play'}
            </button>
          </>
        )}
        <button className="btn" disabled={!list.length} onClick={() => step(-1)}>
          ◀ Prev
        </button>
        <button className="btn primary" onClick={() => current && load(current)}>
          Reload
        </button>
        <button className="btn" disabled={!list.length} onClick={() => step(1)}>
          Next ▶
        </button>
        {url && (
          <a className="btn" href={url} download={current.name}>
            Download
          </a>
        )}
      </div>
    </div>
  );
}
