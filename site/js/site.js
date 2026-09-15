/*
 * qnero.io: the theme toggle, and nothing else.
 *
 * The palette is decided in CSS. This file records one reader's choice and
 * lets the choice win over the system setting in both directions. A reader
 * with JavaScript off keeps the system setting and every page still reads.
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

  function current() {
    return root.getAttribute('data-theme') || systemTheme();
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
    button.hidden = false;
    label(button, current());
    button.addEventListener('click', function () {
      apply(current() === 'light' ? 'dark' : 'light', button);
    });
  });
})();
