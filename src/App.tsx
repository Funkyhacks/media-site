import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ChangeEvent } from 'react';
import { useAuth } from './context/AuthContext';
import { api } from './lib/api';
import type { FileItem, Folder } from './lib/api';
import { Login } from './components/Login';
import { Gallery } from './components/Gallery';
import { Player } from './components/Player';

type Tab = 'folders' | 'favorites';

export function App() {
  const auth = useAuth();
  const keys = useMemo(() => ({ key1: auth.key1, key2: auth.key2 }), [auth.key1, auth.key2]);

  const [tab, setTab] = useState<Tab>('folders');
  const [folders, setFolders] = useState<Folder[]>([]);
  const [activeFolder, setActiveFolder] = useState<number | null>(null);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [favIds, setFavIds] = useState<Set<string>>(new Set());
  const [current, setCurrent] = useState<FileItem | null>(null);
  const [newFolder, setNewFolder] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const opts = { keys };

  const refreshFolders = useCallback(async () => {
    const f = await api.listFolders(opts);
    setFolders(f);
  }, [keys.key1, keys.key2]); // eslint-disable-line react-hooks/exhaustive-deps

  const refreshFiles = useCallback(
    async (folderId: number | null) => {
      const f = await api.listFiles(opts, folderId ?? undefined);
      setFiles(f);
    },
    [keys.key1, keys.key2], // eslint-disable-line react-hooks/exhaustive-deps
  );

  const refreshFavs = useCallback(async () => {
    const f = await api.listFavorites(opts);
    setFavIds(new Set(f.map((x) => x.file_id)));
  }, [keys.key1, keys.key2]); // eslint-disable-line react-hooks/exhaustive-deps

  // Load the workspace when authed.
  useEffect(() => {
    if (!auth.isAuthed) return;
    void (async () => {
      try {
        await Promise.all([refreshFolders(), refreshFiles(activeFolder), refreshFavs()]);
      } catch (e) {
        setError(e instanceof Error ? e.message : 'failed to load');
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auth.isAuthed]);

  async function onLogout() {
    await auth.logout();
  }

  async function createFolder() {
    if (!newFolder.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.createFolder(opts, newFolder.trim(), activeFolder ?? undefined);
      setNewFolder('');
      await Promise.all([refreshFolders(), refreshFiles(activeFolder)]);
      setNotice(`Created folder ${r.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'failed to create folder');
    } finally {
      setBusy(false);
    }
  }

  async function onUpload() {
    if (!uploadFile) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.upload(opts, uploadFile, activeFolder ?? undefined);
      setUploadFile(null);
      await refreshFiles(activeFolder);
      setNotice(`Uploaded ${r.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'upload failed');
    } finally {
      setBusy(false);
    }
  }

  async function toggleFav(id: string) {
    setError(null);
    try {
      if (favIds.has(id)) {
        await api.removeFavorite(opts, id);
        setFavIds((s) => {
          const n = new Set(s);
          n.delete(id);
          return n;
        });
      } else {
        await api.addFavorite(opts, id);
        setFavIds((s) => new Set(s).add(id));
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'favorites update failed');
    }
  }

  function pickFile(e: ChangeEvent<HTMLInputElement>) {
    setUploadFile(e.target.files?.[0] ?? null);
  }

  if (!auth.isAuthed) {
    return (
      <div className="app">
        <div className="app-header">
          <h1>SecWeb</h1>
          <span className="sub">zero-knowledge media portal</span>
        </div>
        <Login />
      </div>
    );
  }

  // In favorites tab, show the favorited subset of the loaded files.
  const visibleFiles = tab === 'favorites' ? files.filter((f) => favIds.has(f.id)) : files;

  return (
    <div className="app">
      <div className="app-header">
        <div>
          <h1>SecWeb</h1>
          <span className="sub">
            {auth.username} · keys in-memory · session only
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <span className="badge ok">● keys active</span>
          <button className="btn danger" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </div>

      <div className="row">
        <button
          className={tab === 'folders' ? 'btn primary' : 'btn'}
          onClick={() => {
            setTab('folders');
            setCurrent(null);
            void refreshFiles(activeFolder);
          }}
        >
          Folders
        </button>
        <button
          className={tab === 'favorites' ? 'btn primary' : 'btn'}
          onClick={() => {
            setTab('favorites');
            setCurrent(null);
            // Favorites span all folders — load the full file set.
            void refreshFiles(null);
          }}
        >
          Favorites ({favIds.size})
        </button>
      </div>

      {tab === 'folders' && (
        <div className="card">
          <p className="section-title">Folders</p>
          <div className="grid" style={{ marginBottom: '0.75rem' }}>
            {folders.map((f) => (
              <button
                key={f.id}
                className="tile"
                style={{ cursor: 'pointer', textAlign: 'left' }}
                onClick={() => {
                  setActiveFolder(f.id);
                  setCurrent(null);
                  void refreshFiles(f.id);
                }}
              >
                <h3>📁 {f.name}</h3>
                <div className="meta">
                  <span>{f.file_count} file(s)</span>
                  {f.parent_id != null && <span>in #{f.parent_id}</span>}
                </div>
              </button>
            ))}
          </div>
          <div className="row">
            <div className="field">
              <label htmlFor="nf">New folder name</label>
              <input id="nf" value={newFolder} onChange={(e) => setNewFolder(e.target.value)} placeholder="e.g. 2026" />
            </div>
            <button className="btn primary" onClick={createFolder} disabled={busy || !newFolder.trim()}>
              {busy ? '…' : 'Add folder'}
            </button>
            {activeFolder != null && (
              <button className="btn" onClick={() => { setActiveFolder(null); void refreshFiles(null); }}>
                ↑ All files
              </button>
            )}
          </div>
        </div>
      )}

      <div className="card">
        <p className="section-title">Upload {activeFolder != null ? `→ folder #${activeFolder}` : '→ root'}</p>
        <div className="row">
          <div className="field">
            <input id="up" type="file" onChange={pickFile} />
          </div>
          <button className="btn primary" onClick={onUpload} disabled={busy || !uploadFile}>
            {busy ? 'Uploading…' : 'Upload & encrypt'}
          </button>
        </div>
      </div>

      {error && (
        <div className="banner error" role="alert">
          {error} <button className="btn" onClick={() => setError(null)}>dismiss</button>
        </div>
      )}
      {notice && (
        <div className="banner ok">
          {notice} <button className="btn" onClick={() => setNotice(null)}>dismiss</button>
        </div>
      )}

      <div className="card">
        <Player current={current} list={visibleFiles} keys={keys} />
      </div>

      <div className="card">
        <p className="section-title">{tab === 'favorites' ? 'Favorited files' : 'Files'}</p>
        <Gallery files={visibleFiles} keys={keys} favIds={favIds} onOpen={(item) => setCurrent(item)} onToggleFav={toggleFav} />
      </div>
    </div>
  );
}
