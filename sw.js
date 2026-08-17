/* BB Money service worker.

   Nothing is ever fetched from anywhere but this folder, and no request carries
   any expense data: the records live in IndexedDB and are never sent anywhere.

   TWO STRATEGIES, deliberately, because one size was wrong:

   - The PAGE ITSELF is network-first. A cache-first document means an installed
     app can never receive an update: the phone keeps serving the version it first
     saw until the cache name changes, so shipping a fix would reach nobody. The
     network is tried first, and the cache is the fallback when there is no signal,
     which is what keeps it working offline.
   - Icons and the manifest are cache-first, because they are immutable in practice
     and cache-first is what makes a cold offline launch instant.

   Also: never `ignoreSearch`. It made ?selftest resolve to the plain cached page,
   so the harness could not be reached on an installed copy. */
const CACHE = 'bbmoney-shell-v3';
const SHELL = ['./', './index.html', './manifest.json',
               './icon-192.png', './icon-512.png', './apple-touch-icon.png'];
/* The PDF reader is fetched on first use rather than precached, because it is 1.4MB
   and most opens never import a statement. Once cached, importing works offline.
   It is a local file in vendor/, the same as an icon: no statement byte and no
   request of any kind leaves this device. */

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => Promise.allSettled(SHELL.map(f => c.add(f))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

const isDocument = req =>
  req.mode === 'navigate' || (req.destination === '' && req.headers.get('accept') || '').includes('text/html');

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  if (new URL(req.url).origin !== location.origin) return;

  if (isDocument(req)) {
    // network first, so an update always wins when there is a connection
    e.respondWith(
      fetch(req)
        .then(r => {
          const copy = r.clone();
          caches.open(CACHE).then(c => c.put('./index.html', copy));
          return r;
        })
        .catch(() => caches.match(req).then(hit => hit || caches.match('./index.html')))
    );
    return;
  }

  // static assets: cache first, fill the cache on first miss
  e.respondWith(
    caches.match(req).then(hit =>
      hit || fetch(req).then(r => {
        if (r.ok) {
          const copy = r.clone();
          caches.open(CACHE).then(c => c.put(req, copy));
        }
        return r;
      })
    )
  );
});
