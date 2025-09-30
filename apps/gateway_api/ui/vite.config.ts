import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'https://autollm.local',
      '/risk': 'https://autollm.local'
    }
  },
  build: {
    outDir: '../static',
    emptyOutDir: true
  }
});
