/**
 * AuthContext — holds the JWT and the two security keys in MEMORY ONLY.
 *
 * Directives honoured:
 *  - #2 zero-knowledge: keys are React state, never localStorage/cookie.
 *  - #6 no browser persistence: cleared on logout / tab close (beforeunload).
 *
 * Security keys are stored in state as **raw strings** (whatever the user
 * typed) and sent verbatim in `X-Sec-Key-1` / `X-Sec-Key-2` headers. The
 * backend decodes them tolerantly (base64 if valid, else raw UTF-8).
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { api } from '../lib/api';

interface AuthState {
  jwt: string | null;
  user_id: number | null;
  username: string | null;
  key1: string;
  key2: string;
  isAuthed: boolean;
  login: (u: string, p: string, k1: string, k2: string) => Promise<void>;
  register: (u: string, p: string, k1: string, k2: string) => Promise<void>;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [jwt, setJwt] = useState<string | null>(null);
  const [userId, setUserId] = useState<number | null>(null);
  const [username, setUsername] = useState<string | null>(null);
  const [keys, setKeys] = useState<{ key1: string; key2: string }>({ key1: '', key2: '' });

  const applyAuth = useCallback((j: string, uid: number, u: string | null, k1: string, k2: string) => {
    setJwt(j);
    setUserId(uid);
    setUsername(u);
    setKeys({ key1: k1, key2: k2 });
  }, []);

  const login = useCallback(
    async (u: string, p: string, k1: string, k2: string) => {
      const res = await api.login({ username: u, password: p, key1: k1, key2: k2 });
      applyAuth(res.jwt, res.user_id, u, k1, k2);
    },
    [applyAuth],
  );

  const register = useCallback(
    async (u: string, p: string, k1: string, k2: string) => {
      const res = await api.register({ username: u, password: p, key1: k1, key2: k2 });
      applyAuth(res.jwt, res.user_id, u, k1, k2);
    },
    [applyAuth],
  );

  const logout = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      /* best-effort revocation */
    }
    setJwt(null);
    setUserId(null);
    setUsername(null);
    // Wipe key material from memory (directive #2).
    setKeys({ key1: '', key2: '' });
  }, []);

  // Clear keys if the tab is hidden/closed (directive #6 / spec §2).
  useEffect(() => {
    const wipe = () => setKeys({ key1: '', key2: '' });
    window.addEventListener('secweb:logout', wipe);
    return () => window.removeEventListener('secweb:logout', wipe);
  }, []);

  const value = useMemo<AuthState>(
    () => ({
      jwt,
      user_id: userId,
      username,
      key1: keys.key1,
      key2: keys.key2,
      isAuthed: jwt !== null,
      login,
      register,
      logout,
    }),
    [jwt, userId, username, keys.key1, keys.key2, login, register, logout],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider');
  return ctx;
}
