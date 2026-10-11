// --- FIX #3: DOM-based XSS --------------------------------------------
// Same feature as the vulnerable version (read a "welcome note" from the
// URL hash) but the fix uses textContent instead of innerHTML, so the
// browser never parses the value as HTML/JS — it is always shown as
// literal, inert text, no matter what it contains.
(function () {
  const hash = window.location.hash;
  if (hash && hash.startsWith('#welcome=')) {
    const raw = decodeURIComponent(hash.substring('#welcome='.length));
    const banner = document.getElementById('welcome-banner');
    banner.textContent = 'Note: ' + raw; // <-- SAFE sink, no HTML parsing
  }
})();
