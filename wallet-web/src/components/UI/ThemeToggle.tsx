import { Monitor, Moon, Sun } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';

import { applyTheme, readTheme, storeTheme, type Theme } from '../../app/theme';
import { Button } from './Button';

/**
 * Light, dark, or whatever the system says.
 *
 * Three states rather than two. The tokens are defined light first with both
 * the media query and `data-theme` redefining the same names, so a page whose
 * JavaScript has not run still reads and the toggle wins in both directions.
 *
 * The key, the read and the write live in `app/theme.ts`, because `main.tsx`
 * applies the same choice before the first paint and this screen is where it
 * is changed. One rule, two call sites.
 */
export function ThemeToggle(): ReactNode {
  const [theme, setTheme] = useState<Theme>(readTheme);

  useEffect(() => {
    applyTheme(theme);
    storeTheme(theme);
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
