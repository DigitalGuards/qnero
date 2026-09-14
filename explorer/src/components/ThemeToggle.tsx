import { useEffect, useState, type ReactNode } from 'react';

type Theme = 'system' | 'light' | 'dark';

const KEY = 'qnero-explorer-theme';
const ORDER: Theme[] = ['system', 'light', 'dark'];

function read(): Theme {
  try {
    const stored = window.localStorage.getItem(KEY);
    if (stored === 'light' || stored === 'dark' || stored === 'system') {
      return stored;
    }
  } catch {
    // A private window, or site data blocked. The system theme is the answer.
  }
  return 'system';
}

function apply(theme: Theme): void {
  if (theme === 'system') {
    delete document.documentElement.dataset['theme'];
  } else {
    document.documentElement.dataset['theme'] = theme;
  }
}

export function ThemeToggle(): ReactNode {
  const [theme, setTheme] = useState<Theme>(read);
  useEffect(() => {
    apply(theme);
    try {
      window.localStorage.setItem(KEY, theme);
    } catch {
      // Nothing to remember it with. The choice still holds for this page.
    }
  }, [theme]);
  const next = ORDER[(ORDER.indexOf(theme) + 1) % ORDER.length] ?? 'system';
  return (
    <button
      type="button"
      className="button"
      style={{ height: '20px', padding: '0 8px', fontSize: 'var(--fs-meta)' }}
      onClick={() => {
        setTheme(next);
      }}
      aria-label={`Theme: ${theme}. Switch to ${next}.`}
    >
      theme: {theme}
    </button>
  );
}
