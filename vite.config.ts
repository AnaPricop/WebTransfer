import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { VitePWA } from 'vite-plugin-pwa';
import basicSsl from '@vitejs/plugin-basic-ssl';

// `npm run dev`       -> http://localhost:5173 (proxy /ws catre serverul de signaling local, :8787)
// `npm run dev:https` -> https cu certificat local (necesar ca telefonul sa poata folosi WebCrypto)
export default defineConfig(({ mode }) => ({
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      registerType: 'autoUpdate',
      manifest: {
        name: 'WebBeam',
        short_name: 'WebBeam',
        description: 'Transfer de fisiere si text intre dispozitive, criptat cap la cap.',
        theme_color: '#0a0a0a',
        background_color: '#0a0a0a',
        display: 'standalone',
        start_url: '/',
        icons: [
          { src: '/icon-192.png', sizes: '192x192', type: 'image/png' },
          { src: '/icon-512.png', sizes: '512x512', type: 'image/png' },
          { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
        ],
      },
      workbox: { navigateFallbackDenylist: [/^\/ws/] },
    }),
    ...(mode === 'https' ? [basicSsl()] : []),
  ],
  server: {
    host: true,
    proxy: { '/ws': { target: 'ws://localhost:8787', ws: true } },
  },
  build: { target: 'es2022' },
}));
