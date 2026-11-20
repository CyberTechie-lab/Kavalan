import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  plugins: [react()],
  publicDir: false,
  build: {
    outDir: path.resolve(__dirname, 'public'),
    emptyOutDir: false,
    lib: {
      entry: path.resolve(__dirname, 'src/client/firebaseBridge.ts'),
      formats: ['es'],
      fileName: () => 'firebase-client.js',
    },
  },
  server: {
    host: '0.0.0.0',
    port: 3000,
    hmr: false,
    allowedHosts: true,
  },
  preview: {
    host: '0.0.0.0',
    port: 3000,
    allowedHosts: true,
  },
});
