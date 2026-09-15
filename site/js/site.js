/*
 * qnero.io: the theme toggle, and nothing else.
 *
 * The palette is decided in CSS. This file records one reader's choice and
 * lets the choice win over the system setting in both directions. A reader
 * with JavaScript off keeps the system setting and every page still reads.
 * js/theme.js applies the stored choice before the first paint; this file
 * falls back to reading storage itself, so a blocked bootstrap costs a late
 * repaint and never the setting.
 */
(function () {
  'use strict';

  var KEY = 'qnero-theme';
  var root = document.documentElement;

  function systemTheme() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
      ? 'light'
      : 'dark';
  }

  function stored() {
    try {
      var t = localStorage.getItem(KEY);
      return t === 'light' || t === 'dark' ? t : null;
    } catch (err) {
      return null;
    }
  }

  /* The attribute first, because theme.js has already put the stored choice
     there. Reading storage again is the fallback for the case where theme.js
     was blocked: the page repaints late and the setting survives. */
  function current() {
    return root.getAttribute('data-theme') || stored() || systemTheme();
  }

  function label(button, theme) {
    button.textContent = theme === 'light' ? 'Theme: light' : 'Theme: dark';
    button.setAttribute(
      'aria-label',
      theme === 'light' ? 'Theme: light. Switch to dark.' : 'Theme: dark. Switch to light.'
    );
  }

  function apply(theme, button) {
    root.setAttribute('data-theme', theme);
    try {
      localStorage.setItem(KEY, theme);
    } catch (err) {
      /* A browser with storage blocked keeps the choice for this page only. */
    }
    if (button) {
      label(button, theme);
    }
  }

  document.addEventListener('DOMContentLoaded', function () {
    var button = document.querySelector('[data-theme-toggle]');
    if (!button) {
      return;
    }
    var theme = current();
    if (root.getAttribute('data-theme') !== theme && stored()) {
      root.setAttribute('data-theme', theme);
    }
    button.hidden = false;
    label(button, theme);
    button.addEventListener('click', function () {
      apply(current() === 'light' ? 'dark' : 'light', button);
    });
  });
})();
