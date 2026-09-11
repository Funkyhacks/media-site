/**
 * Login / Register form.
 *
 * Directive #6 (no browser persistence): every input uses `autocomplete="off"`,
 * and the key inputs also use the `readonly`-on-focus + blur trick so the
 * browser cannot autofill or cache them (SPEC.md §2 Login Page).
 */
import { useState } from 'react';
import type { FormEvent } from 'react';
import { useAuth } from '../context/AuthContext';
import { ApiError } from '../lib/api';

function NoFill({
  id,
  value,
  onChange,
  placeholder,
  type = 'text',
  autoComplete = 'off',
}: {
  id?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  autoComplete?: string;
}) {
  // readonly-on-focus: prevents autofill managers from touching the field;
  // we drop readonly as soon as the user actually types.
  const [editable, setEditable] = useState(false);
  return (
    <input
      id={id}
      type={type}
      value={value}
      placeholder={placeholder}
      autoComplete={autoComplete}
      readOnly={!editable}
      onFocus={() => setEditable(true)}
      onChange={(e) => {
        setEditable(true);
        onChange(e.target.value);
      }}
    />
  );
}

export function Login() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [key1, setKey1] = useState('');
  const [key2, setKey2] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (mode === 'login') {
        await login(username, password, key1, key2);
      } else {
        await register(username, password, key1, key2);
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'authentication failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card" style={{ maxWidth: 460, margin: '2rem auto' }}>
      <div className="row" style={{ justifyContent: 'center', marginBottom: '0.5rem' }}>
        <button className={mode === 'login' ? 'btn primary' : 'btn'} onClick={() => setMode('login')}>
          Sign in
        </button>
        <button className={mode === 'register' ? 'btn primary' : 'btn'} onClick={() => setMode('register')}>
          Create account
        </button>
      </div>
      <p className="sub" style={{ color: 'var(--muted)', fontSize: '0.8rem', textAlign: 'center' }}>
        Your two security keys are held in memory only and are never stored by the server.
      </p>
      {error && <div className="banner error" role="alert">{error}</div>}
      <form onSubmit={submit} autoComplete="off" style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
        <div className="field">
          <label htmlFor="u">Username</label>
          <input id="u" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" required />
        </div>
        <div className="field">
          <label htmlFor="p">Password</label>
          <NoFill id="p" type="password" value={password} onChange={setPassword} placeholder="identity password" />
        </div>
        <div className="field">
          <label htmlFor="k1">Security Key 1</label>
          <NoFill id="k1" value={key1} onChange={setKey1} placeholder="key 1 (zero-knowledge)" />
        </div>
        <div className="field">
          <label htmlFor="k2">Security Key 2</label>
          <NoFill id="k2" value={key2} onChange={setKey2} placeholder="key 2 (zero-knowledge)" />
        </div>
        <button className="btn primary" type="submit" disabled={busy}>
          {busy ? 'Working…' : mode === 'login' ? 'Sign in' : 'Create account'}
        </button>
      </form>
    </div>
  );
}
