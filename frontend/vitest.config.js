import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

/**
 * Vitest configuration for the ReconScope frontend test suite.
 *
 * - Uses jsdom to simulate a browser environment.
 * - Loads a global setup file that registers testing-library matchers
 *   and mocks browser APIs not provided by jsdom (matchMedia, ResizeObserver).
 * - Collects v8 coverage for all source files under src/.
 *
 * @see https://vitest.dev/config/
 */
export default defineConfig({
  plugins: [react()],

  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/__tests__/setup.js'],

    include: ['src/**/*.{test,spec}.{js,jsx}'],

    coverage: {
      provider: 'v8',
      include: ['src/**/*.{js,jsx}'],
      exclude: ['src/__tests__/setup.js'],
    },
  },
});
