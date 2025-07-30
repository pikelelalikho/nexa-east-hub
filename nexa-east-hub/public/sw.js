// public/sw.js
self.addEventListener('install', (event) => {
  console.log('Service Worker installed');
});

self.addEventListener('fetch', (event) => {
  // Optional: intercept and cache requests here
});
