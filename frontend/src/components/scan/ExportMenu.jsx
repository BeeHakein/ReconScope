/**
 * @file Dropdown export menu for downloading scan results.
 *
 * Provides JSON, CSV, and PDF export options. Each triggers a blob
 * download from the backend export endpoints.
 */

import React, { useState, useCallback, useRef, useEffect } from 'react';
import PropTypes from 'prop-types';
import { exportScanJSON, exportScanCSV, exportScanPDF } from '../../api/client';

const FORMATS = [
  { id: 'json', label: 'JSON', fn: exportScanJSON, icon: '{ }' },
  { id: 'csv', label: 'CSV', fn: exportScanCSV, icon: '\u2630' },
  { id: 'pdf', label: 'PDF', fn: exportScanPDF, icon: '\u25A3' },
];

/**
 * Export dropdown button.
 *
 * @param {{ scanId: string }} props
 * @returns {React.ReactElement}
 */
export default function ExportMenu({ scanId }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(null);
  const menuRef = useRef(null);

  /* Close menu on outside click. */
  useEffect(() => {
    function handleClickOutside(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleExport = useCallback(
    async (format) => {
      setLoading(format.id);
      try {
        const response = await format.fn(scanId);
        const blob = new Blob([response.data], {
          type: response.headers['content-type'] || 'application/octet-stream',
        });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;

        // Extract filename from content-disposition or generate one
        const disposition = response.headers['content-disposition'] || '';
        const filenameMatch = disposition.match(/filename="?([^"]+)"?/);
        link.download = filenameMatch
          ? filenameMatch[1]
          : `reconscope_export.${format.id}`;

        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      } catch (err) {
        console.error(`Export failed (${format.id}):`, err);
      } finally {
        setLoading(null);
        setOpen(false);
      }
    },
    [scanId],
  );

  return (
    <div className="relative" ref={menuRef}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-300 hover:bg-slate-700 transition-colors"
        aria-haspopup="true"
        aria-expanded={open}
      >
        Export
        <span className="text-[10px]">{open ? '\u25B2' : '\u25BC'}</span>
      </button>

      {open && (
        <div className="absolute right-0 top-full z-20 mt-1 w-36 rounded-lg border border-slate-700 bg-slate-800 py-1 shadow-lg">
          {FORMATS.map((fmt) => (
            <button
              key={fmt.id}
              type="button"
              disabled={loading !== null}
              onClick={() => handleExport(fmt)}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs text-slate-300 hover:bg-slate-700 disabled:opacity-50 transition-colors"
            >
              <span className="w-5 text-center text-slate-500">{fmt.icon}</span>
              {loading === fmt.id ? 'Downloading...' : fmt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

ExportMenu.propTypes = {
  /** UUID of the scan to export. */
  scanId: PropTypes.string.isRequired,
};
