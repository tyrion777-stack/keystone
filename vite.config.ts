import { resolve } from 'path';
import { defineConfig } from 'vite';
import { crx, defineManifest } from '@crxjs/vite-plugin';

const manifest = defineManifest({
  manifest_version: 3,
  name: 'Keystone',
  version: '0.1.0',
  description: 'Your cryptographic identity for the web. Sign in anywhere — no passwords, no accounts.',
  permissions: ['storage', 'windows'],
  background: {
    service_worker: 'src/background.ts',
    type: 'module' as const,
  },
  content_scripts: [
    {
      matches: ['<all_urls>'],
      js: ['src/inject.ts'],
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      world: 'MAIN' as any,
      run_at: 'document_start',
    },
    {
      matches: ['<all_urls>'],
      js: ['src/content.ts'],
      run_at: 'document_start',
    },
  ],
  action: {
    default_popup: 'popup.html',
    default_title: 'Keystone',
    default_icon: {
      16: 'icons/icon16.png',
      48: 'icons/icon48.png',
      128: 'icons/icon128.png',
    },
  },
  icons: {
    16: 'icons/icon16.png',
    48: 'icons/icon48.png',
    128: 'icons/icon128.png',
  },
});

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
