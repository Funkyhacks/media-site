import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AuthProvider } from '../context/AuthContext';
import { Login } from '../components/Login';

afterEach(() => vi.unstubAllGlobals());

function stubAuth(result: { jwt: string; user_id: number }, status = 200) {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve(
        new Response(JSON.stringify(status >= 400 ? { detail: 'bad' } : result), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    ),
  );
}

describe('Login', () => {
  it('has sign-in and create-account mode toggles', () => {
    const { container } = render(
      <AuthProvider>
        <Login />
      </AuthProvider>,
    );
    // Both mode toggles are present and the form renders its four fields.
    expect(screen.getAllByRole('button', { name: /sign in/i }).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByRole('button', { name: /create account/i }).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('identity password')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('key 1 (zero-knowledge)')).toBeInTheDocument();
    expect(screen.getByPlaceholderText('key 2 (zero-knowledge)')).toBeInTheDocument();
    // directive #6: inputs must not be autofillable
    const keyInputs = Array.from(container.querySelectorAll('input'));
    for (const inp of keyInputs) {
      expect(inp.getAttribute('autocomplete')).toBe('off');
    }
  });

  function fillLogin() {
    fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'alice' } });
    // readonly-on-focus inputs: focus first to enable editing
    const pw = screen.getByPlaceholderText('identity password');
    fireEvent.focus(pw);
    fireEvent.change(pw, { target: { value: 'pw' } });
    const k1 = screen.getByPlaceholderText('key 1 (zero-knowledge)');
    fireEvent.focus(k1);
    fireEvent.change(k1, { target: { value: 'K1' } });
    const k2 = screen.getByPlaceholderText('key 2 (zero-knowledge)');
    fireEvent.focus(k2);
    fireEvent.change(k2, { target: { value: 'K2' } });
  }

  it('submits credentials and keys', async () => {
    stubAuth({ jwt: 'tok', user_id: 1 });
    render(
      <AuthProvider>
        <Login />
      </AuthProvider>,
    );
    fillLogin();
    // submit button is the <button type=submit>
    const form = document.querySelector('form')!;
    fireEvent.submit(form);
    await waitFor(() => {
      // on success no alert banner
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    });
  });

  it('shows an error banner on 401', async () => {
    stubAuth({} as never, 401);
    render(
      <AuthProvider>
        <Login />
      </AuthProvider>,
    );
    fillLogin();
    const form = document.querySelector('form')!;
    fireEvent.submit(form);
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
  });
});
