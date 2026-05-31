// Service Worker – stellt sicher dass HTML-Dateien nie gecacht werden
const HTML_FILES = ['/', '/dienstplan.html', '/nicode_login.html'];

self.addEventListener('install', (e) => {
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  const isHtml = HTML_FILES.some(f => url.pathname.endsWith(f) || url.pathname === f)
    || url.pathname.endsWith('.html');

  if(isHtml){
    // HTML immer frisch vom Server (network-first, kein Cache)
    e.respondWith(
      fetch(e.request, { cache: 'no-store' })
        .catch(() => caches.match(e.request))
    );
  }
  // Alle anderen Ressourcen (JS, CSS) normal cachen
});
