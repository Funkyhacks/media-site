# SecWeb — Project Specification

> Source: operator-provided spec (2026-08-20). Saved verbatim as the project's
> canonical spec. The Security Directives below are **IMMUTABLE** — every
> implementation, review, and handoff must comply.

## Project Overview

SecWeb is a media viewer portal that stores images and videos with extreme
security measures.

- **Backend**: FastAPI (Python 3.10+)
- **Frontend**: React (Vite + TypeScript)
- **Database**: SQLite (encrypted fields for metadata)
- **Cache**: Redis (ephemeral, no disk persistence)
- **Deployment**: Docker Container

## 🔐 CRITICAL SECURITY DIRECTIVES (IMMUTABLE)

1. **Dual-Key Encryption**: Content is encrypted/decrypted ONLY using two keys supplied by the user at runtime.
2. **Zero-Knowledge Architecture**: The server NEVER stores encryption keys. Keys are passed in request headers/body for the specific operation and discarded immediately after use.
3. **Encrypted Metadata**: Original filenames, extensions, and folder structures are stored in the database ONLY in encrypted form.
4. **Obfuscated Storage**: Physical files on disk must have random UUID names with no extension. Original mapping exists only in the encrypted DB.
5. **Ephemeral Caching**: Redis must be configured with `appendonly no` and `save ""` to prevent disk writes. All keys must have a strict TTL.
6. **No Browser Persistence**: Login forms must have `autocomplete="off"` and `Cache-Control: no-store` headers.

## Technical Specifications

### 1. Backend (FastAPI)

- **Authentication**: JWT-based. Only authorized users can access endpoints.
- **Encryption Logic**:
  - Implement a function `derive_master_key(key1, key2)` using HKDF or PBKDF2 to combine the two user keys.
  - Use `cryptography.fernet` or `AES-GCM` for file content encryption.
  - Encrypt database fields (filename, extension, path) using the derived master key or a separate wrapped key.
- **File Handling**:
  - Uploads: Receive file -> Generate UUID -> Encrypt Stream -> Save to disk as `UUID.bin`.
  - Thumbnails: Generate server-side -> Encrypt -> Save as `UUID_thumb.bin`.
  - Download/View: Stream decryption directly to response (never save decrypted temp files to disk).
- **Database (SQLite)**:
  - Tables: `Users`, `Folders`, `Files`.
  - Columns `original_name`, `extension`, `folder_path` must be stored as encrypted blobs/hex strings.
- **Redis**:
  - Configure for cache only (e.g., session tokens, temporary decryption chunks).
  - Enforce TTL on every set operation.

### 2. Frontend (React)

- **Login Page**:
  - Inputs for Username, Password, **Key 1**, **Key 2**.
  - Attributes: `autocomplete="off"`, `readonly` on focus hack to prevent browser caching.
- **Media Viewer**:
  - Custom Video Player: Supports Play, Pause, Next, Prev within a folder context.
  - Gallery View: Grid of encrypted thumbnails. Clicking decrypts and streams the full content.
  - Favorites: User-specific list of file IDs (stored in DB), viewed similarly to folders.
- **State Management**: Keys should be held in memory (React Context/State) only for the session duration and cleared on logout/close.

### 3. Infrastructure & DevOps

- **Dockerfile**: Multi-stage build for Python and Node.
- **Docker Compose**:
  - Service `api`: FastAPI app.
  - Service `db`: SQLite (volume mounted).
  - Service `cache`: Redis configured with `command: redis-server --appendonly no --save ""`.
- **Directory Structure**:

  ```text
  /app
  ├── /backend
  │   ├── /core (security, encryption)
  │   ├── /api (routes)
  │   ├── /models (DB schemas)
  │   └── main.py
  ├── /frontend
  │   ├── /src
  │   │   ├── /components (Player, Gallery, Login)
  │   │   └── /context (AuthContext)
  │   └── package.json
  ├── /storage (encrypted files)
  ├── docker-compose.yml
  └── requirements.txt
  ```
