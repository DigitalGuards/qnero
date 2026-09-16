import { Monitor, Moon, Sun } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';

import { Button } from './Button';

/**
 * Light, dark, or whatever the system says.
 *
 * Three states rather than two. The tokens are defined light first with both
 * the media query and `data-theme` redefining the same names, so a page whose
 * JavaScript has not run still reads and the toggle wins in both directions.
 */
type Theme = 'system' | 'light' | 'dark';

const KEY = 'qnero-wallet-theme';

function read(): Theme {
  try {
    const stored = localStorage.getItem(KEY);
    return stored === 'light' || stored === 'dark' ? stored : 'system';
  } catch {
    // A private window, or site data blocked. A remembered theme is a
    // convenience and its absence is not a failure.
    return 'system';
  }
}

export function ThemeToggle(): ReactNode {
  const [theme, setTheme] = useState<Theme>(read);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') {
      root.removeAttribute('data-theme');
    } else {
      root.setAttribute('data-theme', theme);
    }
    try {
      if (theme === 'system') {
        localStorage.removeItem(KEY);
      } else {
        localStorage.setItem(KEY, theme);
      }
    } catch {
      // See `read`.
    }
  }, [theme]);

  const next: Theme = theme === 'system' ? 'dark' : theme === 'dark' ? 'light' : 'system';
  const Icon = theme === 'system' ? Monitor : theme === 'dark' ? Moon : Sun;
  return (
    <Button
      // The control height rather than the small one: this lives on the
      // settings screen now, where every other control is a thumb's target.
      aria-label={`Theme: ${theme}. Switch to ${next}.`}
      onClick={() => {
        setTheme(next);
      }}
    >
      <Icon className="size-3.5" aria-hidden />
      {/* The label is always shown: this control lives on the settings screen
          now, where a row is a label and a control, and an icon on its own
          reads as a state rather than as a switch. */}
      <span>{theme}</span>
    </Button>
  );
}
