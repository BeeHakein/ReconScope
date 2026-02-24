/**
 * @file Global test setup for Vitest.
 *
 * This file is loaded before every test suite (see vitest.config.js).
 * It registers the custom jest-dom matchers (e.g. `toBeInTheDocument`)
 * and stubs browser APIs that jsdom does not implement.
 */

import '@testing-library/jest-dom';

/* ── Mock: window.matchMedia ───────────────────────────────── */

/**
 * jsdom does not implement `window.matchMedia`.  Many UI libraries
 * (and Tailwind dark-mode detection) rely on it, so we provide a
 * minimal stub that always reports "no match".
 */
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

/* ── Mock: ResizeObserver ──────────────────────────────────── */

/**
 * jsdom does not implement `ResizeObserver`.  Components that measure
 * their own dimensions (e.g. the Cytoscape graph wrapper) would throw
 * without this stub.
 */
class ResizeObserverStub {
  /**
   * @param {ResizeObserverCallback} _callback
   */
  constructor(_callback) {
    this._callback = _callback;
  }

  /** @param {Element} _target */
  observe(_target) {
    // intentional no-op
  }

  /** @param {Element} _target */
  unobserve(_target) {
    // intentional no-op
  }

  disconnect() {
    // intentional no-op
  }
}

globalThis.ResizeObserver = ResizeObserverStub;
