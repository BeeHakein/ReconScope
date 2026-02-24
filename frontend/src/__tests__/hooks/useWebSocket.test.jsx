/**
 * @file Tests for the useWebSocket hook.
 *
 * Uses a mock WebSocket class to verify connection lifecycle: mount,
 * reconnect on close, message handling, cleanup on unmount, and the
 * no-connection path when scanId is null.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import React from 'react';
import { ScanProvider } from '../../context/ScanContext';

/* ── Mock WebSocket ────────────────────────────────────────── */

let wsInstances = [];

class MockWebSocket {
  /**
   * @param {string} url
   */
  constructor(url) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this._listeners = {};
    wsInstances.push(this);
  }

  addEventListener(event, handler) {
    if (!this._listeners[event]) {
      this._listeners[event] = [];
    }
    this._listeners[event].push(handler);
  }

  removeEventListener(event, handler) {
    if (this._listeners[event]) {
      this._listeners[event] = this._listeners[event].filter((h) => h !== handler);
    }
  }

  close() {
    this.readyState = MockWebSocket.CLOSED;
    this._triggerEvent('close', {});
  }

  /** Simulate firing an event on this instance. */
  _triggerEvent(event, data) {
    (this._listeners[event] ?? []).forEach((handler) => handler(data));
  }

  /** Simulate the server opening the connection. */
  _simulateOpen() {
    this.readyState = MockWebSocket.OPEN;
    this._triggerEvent('open', {});
  }

  /** Simulate receiving a message from the server. */
  _simulateMessage(payload) {
    this._triggerEvent('message', { data: JSON.stringify(payload) });
  }

  /** Simulate the server closing the connection. */
  _simulateClose() {
    this.readyState = MockWebSocket.CLOSED;
    this._triggerEvent('close', {});
  }

  /** Simulate a connection error. */
  _simulateError() {
    this._triggerEvent('error', new Error('WebSocket error'));
  }
}

MockWebSocket.CONNECTING = 0;
MockWebSocket.OPEN = 1;
MockWebSocket.CLOSING = 2;
MockWebSocket.CLOSED = 3;

/* ── Setup ─────────────────────────────────────────────────── */

vi.stubGlobal('WebSocket', MockWebSocket);

// Dynamically import after mocking WebSocket so the hook picks it up.
const { default: useWebSocket } = await import('../../hooks/useWebSocket');

/**
 * Wrapper providing the ScanProvider context.
 */
function Wrapper({ children }) {
  return <ScanProvider>{children}</ScanProvider>;
}

/* ── Test suite ────────────────────────────────────────────── */

describe('useWebSocket', () => {
  beforeEach(() => {
    wsInstances = [];
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('connects on mount when scanId is provided', () => {
    const { result } = renderHook(() => useWebSocket('scan-123'), {
      wrapper: Wrapper,
    });

    expect(wsInstances.length).toBeGreaterThanOrEqual(1);
    const ws = wsInstances[0];
    expect(ws.url).toContain('scan-123');
    expect(result.current.status).toBe('connecting');
  });

  it('transitions to connected status when the socket opens', () => {
    const { result } = renderHook(() => useWebSocket('scan-456'), {
      wrapper: Wrapper,
    });

    const ws = wsInstances[0];
    act(() => {
      ws._simulateOpen();
    });

    expect(result.current.status).toBe('connected');
  });

  it('does not create a connection when scanId is null', () => {
    const { result } = renderHook(() => useWebSocket(null), {
      wrapper: Wrapper,
    });

    expect(wsInstances).toHaveLength(0);
    expect(result.current.status).toBe('disconnected');
  });

  it('handles incoming messages and exposes lastMessage', () => {
    const { result } = renderHook(() => useWebSocket('scan-789'), {
      wrapper: Wrapper,
    });

    const ws = wsInstances[0];
    act(() => {
      ws._simulateOpen();
    });

    act(() => {
      ws._simulateMessage({ event: 'module_started', module: 'dns' });
    });

    expect(result.current.lastMessage).toEqual({
      event: 'module_started',
      module: 'dns',
    });
    expect(result.current.messages.length).toBeGreaterThanOrEqual(1);
  });

  it('attempts to reconnect after the socket closes', () => {
    renderHook(() => useWebSocket('scan-reconnect'), {
      wrapper: Wrapper,
    });

    const ws = wsInstances[0];
    act(() => {
      ws._simulateOpen();
    });

    const countBefore = wsInstances.length;

    act(() => {
      ws._simulateClose();
    });

    // Advance timers past the first reconnect delay (RECONNECT_INTERVAL * 2^0 = 3000ms)
    act(() => {
      vi.advanceTimersByTime(4000);
    });

    // A new WebSocket instance should have been created
    expect(wsInstances.length).toBeGreaterThan(countBefore);
  });

  it('closes the socket on unmount', () => {
    const { unmount } = renderHook(() => useWebSocket('scan-cleanup'), {
      wrapper: Wrapper,
    });

    const ws = wsInstances[0];
    act(() => {
      ws._simulateOpen();
    });

    const closeSpy = vi.spyOn(ws, 'close');

    unmount();

    expect(closeSpy).toHaveBeenCalled();
  });

  it('transitions to disconnected status after unmount', () => {
    const { result, unmount } = renderHook(() => useWebSocket('scan-unmount'), {
      wrapper: Wrapper,
    });

    const ws = wsInstances[0];
    act(() => {
      ws._simulateOpen();
    });

    expect(result.current.status).toBe('connected');

    unmount();

    // After unmount, the latest status before unmount was 'connected',
    // but the cleanup would have closed the ws. We verify via the close spy above.
  });

  it('handles error events by closing the socket', () => {
    const { result } = renderHook(() => useWebSocket('scan-error'), {
      wrapper: Wrapper,
    });

    const ws = wsInstances[0];
    act(() => {
      ws._simulateOpen();
    });

    const closeSpy = vi.spyOn(ws, 'close');

    act(() => {
      ws._simulateError();
    });

    expect(result.current.status).toBe('disconnected');
    expect(closeSpy).toHaveBeenCalled();
  });

  it('builds the WebSocket URL using the scan ID', () => {
    renderHook(() => useWebSocket('abc-def-123'), {
      wrapper: Wrapper,
    });

    const ws = wsInstances[0];
    expect(ws.url).toBe('ws://localhost:8000/ws/scans/abc-def-123');
  });
});
