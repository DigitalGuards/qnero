/*
 * qnero.io: the theme toggle, and the footer links to the other apps.
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

  /* The button holds two inline SVGs and CSS decides which one shows, so this
     writes the accessible name and never the content: setting textContent
     would delete the icons. */
  function label(button, theme) {
    var name = theme === 'light' ? 'Theme: light. Switch to dark.' : 'Theme: dark. Switch to light.';
    button.setAttribute('aria-label', name);
    button.setAttribute('title', name);
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

/*
 * The footer's links to the other apps, pointed at the deployment serving this
 * page. The markup carries the project's own hosts, so a reader with no script
 * still has somewhere to go; a copy served from another apex links to its own
 * wallet, explorer and faucet.
 */
(function () {
  'use strict';
  var host = location.hostname;
  if (!host || host === 'localhost' || /^[0-9.]+$/.test(host) || host.indexOf('.') < 0) return;
  var links = document.querySelectorAll('a[data-host]');
  for (var i = 0; i < links.length; i++) {
    var sub = links[i].getAttribute('data-host');
    links[i].href = 'https://' + (sub ? sub + '.' : '') + host + '/';
  }
})();

