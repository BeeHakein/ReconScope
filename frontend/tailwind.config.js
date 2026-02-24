/**
 * Tailwind CSS configuration for the ReconScope dark cybersecurity theme.
 *
 * Extends the default palette with:
 * - `primary`  – deep navy backgrounds used throughout the dashboard.
 * - `accent`   – cyan and blue highlights for interactive elements.
 * - `severity` – colour-coded severity badges (critical through info).
 *
 * @see https://tailwindcss.com/docs/configuration
 */

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,jsx}',
  ],

  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#0f172a',
          light: '#1e293b',
          dark: '#020617',
        },

        accent: {
          cyan: '#06b6d4',
          blue: '#3b82f6',
        },

        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#22c55e',
          info: '#06b6d4',
        },
      },
    },
  },

  plugins: [],
};
