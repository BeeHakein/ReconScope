/**
 * @file Application entry point.
 *
 * Mounts the root React component into the DOM and wraps it in
 * React.StrictMode so that potential problems are surfaced early
 * during development.
 */

import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
