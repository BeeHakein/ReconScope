import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

/**
 * Vite configuration for the ReconScope frontend.
 *
 * - Uses the React plugin for JSX fast-refresh and transforms.
 * - Dev server listens on port 3000.
 * - API requests under /api are proxied to the FastAPI backend at localhost:8000.
 * - WebSocket connections under /ws are proxied to the backend WebSocket server.
 *
 * @see https://vitejs.dev/config/
 */
export default defineConfig({
  plugins: [react()],

  server: {
    port: 3000,

    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },

      '/ws': {
        target: 'ws://localhost:8000',
        ws: true,
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
