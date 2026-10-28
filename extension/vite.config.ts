import { resolve } from 'path';
import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json';

// manifest.json is the one manifest: what is in it is what ships.

export default defineConfig({
  plugins: [crx({ manifest })],
  build: {
    target: 'chrome114',
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        approval: resolve(__dirname, 'approval.html'),
      },
    },
  },
});
