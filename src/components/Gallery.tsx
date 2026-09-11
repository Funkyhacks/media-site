/**
 * Gallery — grid of files in the current folder context.
 *
 * Thumbnails are fetched *with* the per-request security-key headers (browsers
 * can't attach headers to <img src>), rendered from a blob URL, and revoked on
 * unmount so decrypted bytes don't linger in memory longer than needed.
 * Clicking a tile opens the full content in the Player (decrypts + streams).
 */
import { useEffect, useState } from 'react';
import type { FileItem, SecurityKeys } from '../lib/api';
import { api } from '../lib/api';
import { fetchBlobUrl } from '../lib/blobUrl';

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function Tile({
  item,
  keys,
  onOpen,
  isFav,
  onToggleFav,
}: {
  item: FileItem;
  keys: SecurityKeys;
  onOpen: (item: FileItem) => void;
  isFav: boolean;
  onToggleFav: (id: string) => void;
}) {
  const [thumb, setThumb] = useState<string | null>(null);

  useEffect(() => {
    let revoke: (() => void) | null = null;
    let cancelled = false;
    if (item.thumb_id) {
      fetchBlobUrl(api.thumbUrl(item.id), keys)
        .then((r) => {
          if (cancelled) {
            r.revoke();
            return;
          }
          setThumb(r.url);
          revoke = r.revoke;
        })
        .catch(() => {
          /* no thumbnail / wrong keys — tile shows a placeholder */
        });
    }
    return () => {
      cancelled = true;
      if (revoke) revoke();
    };
  }, [item.id, item.thumb_id, keys]);

  const isImage = /^image\//.test(item.type) || /\.(png|jpe?g|gif|webp|svg|bmp|avif)$/i.test(item.name);

  return (
    <div className="tile">
      {thumb ? (
        <img src={thumb} alt="" style={{ width: '100%', height: 90, objectFit: 'cover', borderRadius: 6 }} />
      ) : (
        <div style={{ height: 90, display: 'grid', placeItems: 'center', color: 'var(--muted)', fontSize: '1.8rem' }}>
          {isImage ? '🖼' : '📄'}
        </div>
      )}
      <h3 title={item.name}>{item.name}</h3>
      <div className="meta">
        <span>{item.extension.toUpperCase()}</span>
        <span>{formatBytes(item.size)}</span>
      </div>
      <div className="actions">
        <button className="btn primary" onClick={() => onOpen(item)}>
          Open
        </button>
        <button className={isFav ? 'btn danger' : 'btn'} onClick={() => onToggleFav(item.id)} title="favorite">
          {isFav ? '★' : '☆'}
        </button>
      </div>
    </div>
  );
}

export function Gallery({
  files,
  keys,
  favIds,
  onOpen,
  onToggleFav,
}: {
  files: FileItem[];
  keys: SecurityKeys;
  favIds: Set<string>;
  onOpen: (item: FileItem) => void;
  onToggleFav: (id: string) => void;
}) {
  if (files.length === 0) {
    return <div className="banner" style={{ color: 'var(--muted)' }}>No files here yet — upload one above.</div>;
  }
  return (
    <div className="grid">
      {files.map((f) => (
        <Tile key={f.id} item={f} keys={keys} onOpen={onOpen} isFav={favIds.has(f.id)} onToggleFav={onToggleFav} />
      ))}
    </div>
  );
}
