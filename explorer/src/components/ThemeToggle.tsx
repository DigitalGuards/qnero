import { useEffect, useState, type ReactNode } from 'react';

/**
 * The theme control: one 32 px icon, once per surface.
 *
 * It was an 86 px bordered box reading "theme: system" at 20 px tall, sitting
 * in the status strip where it was the only interactive thing on the page and
 * failed every tap-target bar there is. It is now the same control the site
 * carries: a sun in dark, a moon in light, at the end of the nav row.
 *
 * Which icon shows is decided in CSS rather than here, so a reader who has
 * stored no choice and changes their system setting gets the right icon with
 * no re-render. `public/theme.js` applies the stored choice before the first
 * paint; this component is what changes it.
 */

type Theme = 'light' | 'dark';

const KEY = 'qnero-explorer-theme';

function systemTheme(): Theme {
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function stored(): Theme | null {
  try {
    const value = window.localStorage.getItem(KEY);
    return value === 'light' || value === 'dark' ? value : null;
  } catch {
    // A private window, or site data blocked. The system theme is the answer.
    return null;
  }
}

/** The attribute first: theme.js has already put the stored choice there. */
function current(): Theme {
  const attribute = document.documentElement.dataset['theme'];
  if (attribute === 'light' || attribute === 'dark') {
    return attribute;
  }
  return stored() ?? systemTheme();
}

function apply(theme: Theme): void {
  document.documentElement.dataset['theme'] = theme;
  try {
    window.localStorage.setItem(KEY, theme);
  } catch {
    // Nothing to remember it with. The choice still holds for this page.
  }
}

export function ThemeToggle(): ReactNode {
  const [theme, setTheme] = useState<Theme>(current);
  useEffect(() => {
    apply(theme);
  }, [theme]);
  const name =
    theme === 'dark' ? 'Theme: dark. Switch to light.' : 'Theme: light. Switch to dark.';
  return (
    <button
      type="button"
      className="theme-toggle"
      aria-label={name}
      title={name}
      onClick={() => {
        setTheme(theme === 'dark' ? 'light' : 'dark');
      }}
    >
      <svg
        className="t-sun"
        width="16"
        height="16"
        viewBox="0 0 16 16"
        aria-hidden="true"
        focusable="false"
      >
        <circle cx="8" cy="8" r="3.1" />
        <path d="M8 0.9v1.9M8 13.2v1.9M2.9 2.9l1.4 1.4M11.7 11.7l1.4 1.4M0.9 8h1.9M13.2 8h1.9M2.9 13.1l1.4-1.4M11.7 4.3l1.4-1.4" />
      </svg>
      <svg
        className="t-moon"
        width="16"
        height="16"
        viewBox="0 0 16 16"
        aria-hidden="true"
        focusable="false"
      >
        <path d="M13.4 10.3A5.9 5.9 0 0 1 5.7 2.6a5.7 5.7 0 1 0 7.7 7.7z" />
      </svg>
    </button>
  );
}
