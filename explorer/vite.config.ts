import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Relative asset URLs, so the built directory works at a domain root and in a
// subdirectory without a rebuild.
export default defineConfig({
  base: './',
  plugins: [react()],
  build: { target: 'es2022', sourcemap: false },
});
