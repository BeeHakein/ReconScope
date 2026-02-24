/**
 * @file WebSocket hook with automatic reconnection for live scan updates.
 *
 * Connects to the backend WebSocket endpoint for a specific scan and
 * dispatches incoming events into the global ScanContext so that every
 * component stays synchronised with the server.
 */

import { useEffect, useRef, useState, useCallback } from 'react';
import {
  WS_SCAN_URL,
  RECONNECT_INTERVAL,
  MAX_RECONNECT_ATTEMPTS,
} from '../constants/config';
import {
  useScanContext,
  ADD_WS_MESSAGE,
  UPDATE_SCAN_PROGRESS,
  SET_CURRENT_SCAN,
} from '../context/ScanContext';

/**
 * Opens a WebSocket to the scan-update feed and re-connects automatically
 * when the connection drops.
 *
 * @param {string|null} scanId - UUID of the scan to subscribe to.
 *   Pass `null` to keep the socket closed.
 * @returns {{ status: string, messages: Array<object>, lastMessage: object|null }}
 */
export default function useWebSocket(scanId) {
  const { state, dispatch } = useScanContext();
  const [status, setStatus] = useState('disconnected');
  const [lastMessage, setLastMessage] = useState(null);

  const wsRef = useRef(null);
  const attemptsRef = useRef(0);
  const timerRef = useRef(null);

  /* Use a ref to avoid stale closures and infinite reconnect loops. */
  const currentScanRef = useRef(state.currentScan);
  useEffect(() => {
    currentScanRef.current = state.currentScan;
  }, [state.currentScan]);

  /** Dispatch context updates based on the event type from the server. */
  const handleMessage = useCallback(
    (event) => {
      const data = JSON.parse(event.data);

      dispatch({ type: ADD_WS_MESSAGE, payload: data });
      setLastMessage(data);

      const scan = currentScanRef.current;

      switch (data.event) {
        case 'module_started': {
          const currentModules = data.data?.module ?? data.module;
          dispatch({
            type: UPDATE_SCAN_PROGRESS,
            payload: {
              status: 'running',
              progress: {
                ...(scan?.progress ?? {}),
                current_module: currentModules,
              },
            },
          });
          break;
        }

        case 'module_completed': {
          const prevCompleted = scan?.progress?.modules_completed ?? [];
          const prevPending = scan?.progress?.modules_pending ?? [];
          const moduleName = data.module ?? data.data?.module;
          const newCompleted = [...prevCompleted, moduleName];
          const newPending = prevPending.filter((m) => m !== moduleName);
          const total = newCompleted.length + newPending.length;
          const pct = total > 0 ? Math.round((newCompleted.length / total) * 100) : 0;

          dispatch({
            type: UPDATE_SCAN_PROGRESS,
            payload: {
              progress: {
                current_module: null,
                modules_completed: newCompleted,
                modules_pending: newPending,
                percentage: pct,
              },
            },
          });
          break;
        }

        case 'post_processing_started':
          dispatch({
            type: UPDATE_SCAN_PROGRESS,
            payload: {
              status: 'running',
              progress: {
                ...(scan?.progress ?? {}),
                current_module: 'post_processing',
                modules_pending: [],
                percentage: 90,
              },
            },
          });
          break;

        case 'scan_completed':
          dispatch({
            type: SET_CURRENT_SCAN,
            payload: {
              ...(scan ?? {}),
              status: 'completed',
              ...data.data,
              progress: {
                current_module: null,
                modules_completed: scan?.progress?.modules_completed ?? [],
                modules_pending: [],
                percentage: 100,
              },
            },
          });
          break;

        case 'scan_failed':
        case 'error':
          dispatch({
            type: UPDATE_SCAN_PROGRESS,
            payload: { status: 'failed' },
          });
          break;

        default:
          break;
      }
    },
    [dispatch],
  );

  /** Attempt to (re-)open the WebSocket connection. */
  const connect = useCallback(() => {
    if (!scanId) return;

    setStatus('connecting');

    const ws = new WebSocket(WS_SCAN_URL(scanId));
    wsRef.current = ws;

    ws.addEventListener('open', function handleOpen() {
      setStatus('connected');
      attemptsRef.current = 0;
    });

    ws.addEventListener('message', handleMessage);

    ws.addEventListener('close', function handleClose() {
      setStatus('disconnected');

      if (attemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
        const delay =
          RECONNECT_INTERVAL * Math.pow(2, attemptsRef.current);
        attemptsRef.current += 1;
        timerRef.current = setTimeout(connect, delay);
      }
    });

    ws.addEventListener('error', function handleError() {
      setStatus('error');
      ws.close();
    });
  }, [scanId, handleMessage]);

  /* Open / close the socket when the scanId changes. */
  useEffect(() => {
    if (!scanId) {
      setStatus('disconnected');
      return undefined;
    }

    connect();

    return () => {
      clearTimeout(timerRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [scanId, connect]);

  return { status, messages: state.wsMessages, lastMessage };
}
