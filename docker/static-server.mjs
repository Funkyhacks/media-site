// Minimal zero-dependency static file server for the SecWeb frontend image.
// Serves ./dist with sane MIME types, directory index resolution, and a
// no-store header for HTML (directive #6 spirit: no caching of the app shell).
import http from 'node:http';
import { promises as fs } from 'node:fs';
import path from 'node:path';

const ROOT = path.resolve(process.cwd(), process.env.STATIC_ROOT || 'dist');
const PORT = Number(process.env.PORT || 4173);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    let p = decodeURIComponent(url.pathname);
    if (p.endsWith('/')) p += 'index.html';
    let file = path.normalize(path.join(ROOT, p));
    if (!file.startsWith(ROOT)) {
      res.writeHead(403).end('forbidden');
      return;
    }
    let stat;
    try {
      stat = await fs.stat(file);
    } catch {
      file = path.join(ROOT, 'index.html'); // SPA fallback
      stat = await fs.stat(file);
    }
    if (stat.isDirectory()) {
      file = path.join(file, 'index.html');
      stat = await fs.stat(file);
    }
    const ext = path.extname(file).toLowerCase();
    const headers = {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Content-Length': stat.size,
    };
    if (ext === '.html') headers['Cache-Control'] = 'no-store';
    res.writeHead(200, headers);
    const stream = fs.createReadStream(file);
    stream.pipe(res);
    stream.on('error', (e) => {
      if (!res.headersSent) res.writeHead(500).end('error');
      else res.destroy();
    });
  } catch (e) {
    if (!res.headersSent) res.writeHead(500).end('error');
    else res.destroy();
  }
});

server.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`SecWeb frontend listening on :${PORT} (root=${ROOT})`);
});
