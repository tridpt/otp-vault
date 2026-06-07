/* Service worker cho OTP Vault (PWA).
 *
 * Chiến lược: network-first cho mọi thứ (đây là app cục bộ, luôn ưu tiên bản
 * mới nhất từ server), dùng cache làm dự phòng khi mất kết nối. KHÔNG bao giờ
 * cache các request /api/* (dữ liệu nhạy cảm + luôn cần dữ liệu tươi).
 */
const CACHE = "otp-vault-v1";
const SHELL = [
  "/",
  "/index.html",
  "/app.js",
  "/style.css",
  "/vendor/jsQR.js",
  "/manifest.json",
  "/icon.svg",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Không xử lý API: luôn đi thẳng ra mạng, không cache.
  if (url.pathname.startsWith("/api/")) return;
  if (request.method !== "GET") return;

  event.respondWith(
    fetch(request)
      .then((resp) => {
        // Lưu bản mới vào cache để dự phòng offline.
        const copy = resp.clone();
        caches.open(CACHE).then((c) => c.put(request, copy)).catch(() => {});
        return resp;
      })
      .catch(() => caches.match(request).then((r) => r || caches.match("/")))
  );
});
