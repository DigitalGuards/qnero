/**
 * The theme this browser chose, and the one rule that applies it.
 *
 * It used to live inside `ThemeToggle`, which mounts on the settings screen
 * alone. So the choice was written to `localStorage` and then applied by the
 * component that wrote it, and nothing applied it again: a reader who chose
 * light on a phone whose system is dark got the dark wallet on every open,
 * the unlock screen included, until they opened Settings, at which point the
 * whole page flipped mid-session. The site has done this correctly since it
 * shipped, in `site/js/theme.js`.
 *
 * Both call sites share this module, so the key is spelled once and the rule
 * that reads it is the rule that writes it.
 */

/** Light, dark, or whatever the system says. */
export type Theme = 'system' | 'light' | 'dark';

export const THEME_KEY = 'qnero-wallet-theme';

/** The stored choice, or `system` when there is none this module wrote. */
export function readTheme(): Theme {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    return stored === 'light' || stored === 'dark' ? stored : 'system';
  } catch {
    // A private window, or site data blocked. A remembered theme is a
    // convenience and its absence is not a failure.
    return 'system';
  }
}

/**
 * Put the choice on the root element, or take it off for `system`.
 *
 * The tokens are defined light first with both the media query and
 * `data-theme` redefining the same names, so removing the attribute is what
 * hands the page back to `prefers-color-scheme`.
 */
export function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === 'system') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', theme);
  }
}

/** Remember the choice, or forget it for `system`. */
export function storeTheme(theme: Theme): void {
  try {
    if (theme === 'system') {
      localStorage.removeItem(THEME_KEY);
    } else {
      localStorage.setItem(THEME_KEY, theme);
    }
  } catch {
    // See `readTheme`.
  }
}
