import './index.css';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { AuthProvider } from './context/AuthContext';

const el = document.getElementById('root');
if (!el) throw new Error('missing #root');

createRoot(el).render(
  <StrictMode>
    <AuthProvider>
      <App />
    </AuthProvider>
  </StrictMode>,
);

// Directive #2 / spec §2: clear in-memory keys when the tab is closed or hidden.
window.addEventListener('beforeunload', () => {
  window.dispatchEvent(new CustomEvent('secweb:logout'));
});
