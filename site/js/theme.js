/*
 * qnero.io: the theme, before the first paint.
 *
 * This runs in <head> without `defer`, so a reader's stored choice is on the
 * root element before anything is painted and there is no flash of the other
 * palette. It lives in a file so a host can send
 * `script-src 'self'` and keep it: an inline block dies under that policy and
 * the stored choice is discarded on every load, silently.
 */
(function () {
  'use strict';
  try {
    var t = localStorage.getItem('qnero-theme');
    if (t === 'light' || t === 'dark') {
      document.documentElement.setAttribute('data-theme', t);
    }
  } catch (err) {
    /* Storage blocked. The system setting decides, and the page still reads. */
  }
})();
