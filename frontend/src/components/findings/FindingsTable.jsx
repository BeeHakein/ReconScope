/**
 * @file Sortable table listing scan findings with expandable detail rows.
 *
 * Columns: Severity, Title, Asset, Risk Score, CVSS.  Clicking a column
 * header toggles the sort direction.  Clicking a row toggles its
 * expandable detail section showing description and evidence.
 */

import React, { useState, useCallback, useMemo } from 'react';
import PropTypes from 'prop-types';
import SeverityBadge from '../common/SeverityBadge';

/** Map severity labels to numeric weight for sorting. */
const SEV_WEIGHT = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Generic comparator factory.
 *
 * @param {string} key
 * @param {'asc'|'desc'} dir
 * @returns {(a: object, b: object) => number}
 */
function comparator(key, dir) {
  return function compare(a, b) {
    let va = a[key] ?? '';
    let vb = b[key] ?? '';

    if (key === 'severity') {
      va = SEV_WEIGHT[va] ?? 5;
      vb = SEV_WEIGHT[vb] ?? 5;
    }

    if (typeof va === 'number' && typeof vb === 'number') {
      return dir === 'asc' ? va - vb : vb - va;
    }

    return dir === 'asc'
      ? String(va).localeCompare(String(vb))
      : String(vb).localeCompare(String(va));
  };
}

/** Column definitions. */
const COLUMNS = [
  { key: 'severity', label: 'Severity' },
  { key: 'title', label: 'Title' },
  { key: 'asset', label: 'Asset' },
  { key: 'risk_score', label: 'Risk Score' },
  { key: 'cvss_score', label: 'CVSS' },
];

/**
 * Sortable findings table with expandable rows.
 *
 * @param {{ findings: object[] }} props
 * @returns {React.ReactElement}
 */
const PAGE_SIZES = [25, 50, 100];

export default function FindingsTable({ findings, pageSize: externalPageSize }) {
  const [sortKey, setSortKey] = useState('risk_score');
  const [sortDir, setSortDir] = useState('desc');
  const [expandedId, setExpandedId] = useState(null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(externalPageSize || 25);

  /** Toggle sort direction or change the sort column. */
  const handleSort = useCallback(
    function onSort(key) {
      if (key === sortKey) {
        setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
      } else {
        setSortKey(key);
        setSortDir('desc');
      }
    },
    [sortKey],
  );

  /** Toggle a row's expanded state. */
  const handleRowToggle = useCallback(function onToggle(id) {
    setExpandedId((prev) => (prev === id ? null : id));
  }, []);

  const sorted = useMemo(
    () => [...findings].sort(comparator(sortKey, sortDir)),
    [findings, sortKey, sortDir],
  );

  /* Reset to first page when findings or page size change. */
  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const safePage = Math.min(page, totalPages - 1);
  if (safePage !== page) setPage(safePage);

  const start = safePage * pageSize;
  const end = Math.min(start + pageSize, sorted.length);
  const pageItems = sorted.slice(start, end);

  if (!findings.length) {
    return (
      <p className="py-10 text-center text-sm text-slate-500">
        No findings to display.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-left text-sm" aria-label="Findings table">
          <thead className="border-b border-slate-800 bg-slate-900/80 text-xs uppercase text-slate-400">
            <tr>
              {COLUMNS.map((col) => (
                <th key={col.key} className="px-4 py-3">
                  <button
                    type="button"
                    className="flex items-center gap-1 hover:text-slate-200 transition-colors"
                    onClick={function onHeaderClick() { handleSort(col.key); }}
                    aria-label={`Sort by ${col.label}`}
                  >
                    {col.label}
                    {sortKey === col.key && (
                      <span className="text-cyan-400">
                        {sortDir === 'asc' ? '\u2191' : '\u2193'}
                      </span>
                    )}
                  </button>
                </th>
              ))}
            </tr>
          </thead>

          <tbody className="divide-y divide-slate-800">
            {pageItems.map((f) => (
              <React.Fragment key={f.id}>
                <tr
                  className="cursor-pointer hover:bg-slate-800/50 transition-colors"
                  onClick={function onRowClick() { handleRowToggle(f.id); }}
                  aria-expanded={expandedId === f.id}
                  aria-label={`Finding: ${f.title}`}
                >
                  <td className="px-4 py-3">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-4 py-3 font-medium text-slate-200">
                    {f.title}
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-400">
                    {f.asset ?? '\u2014'}
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-300">
                    {f.risk_score ?? '\u2014'}
                  </td>
                  <td className="px-4 py-3 font-mono text-slate-300">
                    {f.cvss_score ?? '\u2014'}
                  </td>
                </tr>

                {expandedId === f.id && (
                  <tr>
                    <td
                      colSpan={COLUMNS.length}
                      className="bg-slate-800/30 px-6 py-4 text-sm text-slate-300"
                    >
                      {f.description && (
                        <p className="mb-3">{f.description}</p>
                      )}
                      {f.evidence && Object.keys(f.evidence).length > 0 && (
                        <pre className="overflow-x-auto rounded bg-slate-900 p-3 font-mono text-xs text-slate-400">
                          {JSON.stringify(f.evidence, null, 2)}
                        </pre>
                      )}
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination controls */}
      {sorted.length > PAGE_SIZES[0] && (
        <div className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-2 text-xs text-slate-400">
          <span>
            {start + 1}&ndash;{end} von {sorted.length} Findings
          </span>

          <div className="flex items-center gap-3">
            <label className="flex items-center gap-1.5">
              Pro Seite
              <select
                value={pageSize}
                onChange={(e) => { setPageSize(Number(e.target.value)); setPage(0); }}
                className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 focus:border-cyan-400 focus:outline-none"
              >
                {PAGE_SIZES.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </label>

            <div className="flex gap-1">
              <button
                type="button"
                disabled={safePage === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                aria-label="Previous page"
              >
                &laquo;
              </button>
              {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                let pageNum;
                if (totalPages <= 7) {
                  pageNum = i;
                } else if (safePage < 4) {
                  pageNum = i;
                } else if (safePage > totalPages - 5) {
                  pageNum = totalPages - 7 + i;
                } else {
                  pageNum = safePage - 3 + i;
                }
                return (
                  <button
                    key={pageNum}
                    type="button"
                    onClick={() => setPage(pageNum)}
                    className={`rounded border px-2 py-1 transition-colors ${
                      pageNum === safePage
                        ? 'border-cyan-500 bg-cyan-500/20 text-cyan-400'
                        : 'border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700'
                    }`}
                  >
                    {pageNum + 1}
                  </button>
                );
              })}
              <button
                type="button"
                disabled={safePage >= totalPages - 1}
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                className="rounded border border-slate-700 bg-slate-800 px-2 py-1 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                aria-label="Next page"
              >
                &raquo;
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

FindingsTable.propTypes = {
  /** Array of finding objects from the API. */
  findings: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.string.isRequired,
      severity: PropTypes.string.isRequired,
      title: PropTypes.string.isRequired,
      asset: PropTypes.string,
      risk_score: PropTypes.number,
      cvss_score: PropTypes.number,
      description: PropTypes.string,
      evidence: PropTypes.object,
    }),
  ).isRequired,
  /** Optional initial page size. */
  pageSize: PropTypes.number,
};

FindingsTable.defaultProps = {
  pageSize: 25,
};
