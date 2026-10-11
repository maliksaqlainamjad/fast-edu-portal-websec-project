// --- VULNERABILITY #3: DOM-based XSS --------------------------------
// This runs entirely in the browser and never touches the server.
// The hash fragment (#welcome=...) is decoded and written straight into
// the page with innerHTML, so any HTML/JS in it executes immediately.
//
// Payload (append to the dashboard URL):
//   #welcome=<img src=x onerror=alert('DOM XSS')>
(function () {
  const hash = window.location.hash; // e.g. "#welcome=<img src=x onerror=alert(1)>"
  if (hash && hash.startsWith('#welcome=')) {
    const raw = decodeURIComponent(hash.substring('#welcome='.length));
    const banner = document.getElementById('welcome-banner');
    banner.innerHTML = 'Note: ' + raw; // <-- VULNERABLE sink
  }
})();
