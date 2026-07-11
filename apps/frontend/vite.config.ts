import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  return {
    root: '.',
    server: {
      port: 5173,
      host: true, // ✅ Exposes the frontend server to your Android mobile IP on the local subnet
      strictPort: true,
      proxy: {
        // 1️⃣ CORE API ROUTING (Catches the client's base URL and routes to Relay)
        '/api/v1': {
          target: 'http://localhost:3001',
          changeOrigin: false,
          secure: false,
          configure: (proxy, _options) => {
            proxy.on('proxyReq', (proxyReq, _req, _res) => {
              proxyReq.setHeader('x-brone-origin-signature', 'placeholder_secret_key_change_me_in_prod');
              proxyReq.setHeader('x-brone-edge-token', 'dev_sandbox_token_string');
            });
          }
        },

        // 2️⃣ OUT-OF-BAND EDGE ROUTING (Resolves Wall of Truth metrics via proxy-region-asia on 3001)
        '/api/proxy-edge': {
          target: 'http://localhost:3001',
          changeOrigin: false,
          secure: false,
          rewrite: (path) => path.replace(/^\/api\/proxy-edge/, ''),
          configure: (proxy, _options) => {
            proxy.on('proxyReq', (proxyReq, _req, _res) => {
              proxyReq.setHeader('x-brone-edge-token', 'dev_sandbox_token_string');
            });
          }
        }
      }
    },
    define: {
      global: 'window',
      'process.env.VITE_API_URL': JSON.stringify(env.VITE_API_URL || process.env.VITE_API_URL || ''),
      'process.env.NODE_ENV': JSON.stringify(mode || 'development'),
    },
    plugins: [
      react(),
      {
        name: 'dev-csp-relax',
        transformIndexHtml(html) {
          return html;
        }
      }
    ],
    resolve: {
      alias: {
        '@brone/crypto-core': path.resolve(__dirname, '../../packages/crypto-core/src'),
        '@brone/types': path.resolve(__dirname, '../../packages/types/src'),
        '@': path.resolve(__dirname, './src')
      }
    },
    build: {
      target: 'esnext',
      minify: 'esbuild',
    },
    esbuild: {
      drop: ['console', 'debugger'],
    }
  };
});