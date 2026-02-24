/**
 * @file Domain input form with module selection, scan mode toggle, scope
 *       confirmation, and start button for initiating a new reconnaissance scan.
 *
 * Fully styled with TailwindCSS classes and the dark cybersecurity theme.
 */

import React, { useState, useCallback } from 'react';
import { DEFAULT_MODULES, ACTIVE_MODULES } from '../../constants/config';
import useScan from '../../hooks/useScan';

/** Regex mirroring the backend's domain validation rule. */
const DOMAIN_RE =
  /^(?!-)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

/** Human-readable labels for each module identifier. */
const MODULE_LABELS = {
  // Passive modules — generic category names
  crtsh: 'Certificate Transparency',
  alienvault: 'Threat Intelligence',
  hackertarget: 'Passive Subdomain Search',
  anubis: 'Subdomain Database',
  webarchive: 'Web Archive Analysis',
  dns: 'DNS Enumeration',
  whois: 'WHOIS Lookup',
  techdetect: 'Technology Detection',
  cvematch: 'Vulnerability Matching',
  // Active modules
  subbuster: 'Subdomain Bruteforce',
  portscan: 'Port Scanner (nmap)',
  dirbuster: 'Directory Discovery',
  sslaudit: 'SSL/TLS Audit',
  headeraudit: 'Security Headers',
};

/**
 * Renders the primary scan-launch form.
 *
 * @returns {React.ReactElement}
 */
export default function ScanInput() {
  const { startScan, loading } = useScan();

  const [domain, setDomain] = useState('');
  const [modules, setModules] = useState([...DEFAULT_MODULES]);
  const [error, setError] = useState('');
  const [scanMode, setScanMode] = useState('passive');

  const isActive = scanMode === 'active';
  const trimmed = domain.trim().toLowerCase();
  const isDomainValid = DOMAIN_RE.test(trimmed);
  const canSubmit = isDomainValid && modules.length > 0;

  /** Toggle a module identifier in or out of the selection array. */
  const handleModuleToggle = useCallback(function toggleModule(mod) {
    setModules((prev) =>
      prev.includes(mod) ? prev.filter((m) => m !== mod) : [...prev, mod],
    );
  }, []);

  /** Switch between passive and active scan modes. */
  function handleModeChange(mode) {
    setScanMode(mode);
    if (mode === 'passive') {
      // Remove any active modules from selection when switching to passive
      setModules((prev) => prev.filter((m) => !ACTIVE_MODULES.includes(m)));
    }
  }

  /** Handle changes on the domain text input. */
  function handleDomainChange(e) {
    setDomain(e.target.value);
    setError('');
  }

  /** Validate and submit the form. */
  async function handleSubmit(e) {
    e.preventDefault();
    setError('');

    if (!DOMAIN_RE.test(trimmed)) {
      setError('Please enter a valid domain (e.g. example.com).');
      return;
    }

    try {
      await startScan(trimmed, modules, true, scanMode);
    } catch (err) {
      setError(err.apiError?.message ?? 'Failed to start scan.');
    }
  }

  return (
    <section className="mx-auto max-w-xl animate-fade-in">
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-8">
        <h2 className="mb-1 text-2xl font-bold text-slate-100">
          New <span className="text-cyan-400">Scan</span>
        </h2>
        <p className="mb-6 text-sm text-slate-400">
          Enter a target domain and select the modules to execute.
        </p>

        <form onSubmit={handleSubmit} data-testid="scan-input-form">
          {/* Domain input */}
          <div className="mb-5">
            <label
              htmlFor="domain-input"
              className="mb-1.5 block text-sm font-medium text-slate-300"
            >
              Target Domain
            </label>
            <input
              id="domain-input"
              type="text"
              value={domain}
              onChange={handleDomainChange}
              placeholder="acme-corp.de"
              autoComplete="off"
              spellCheck="false"
              aria-label="Target Domain"
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-4 py-2.5 font-mono text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 focus:outline-none"
            />
          </div>

          {/* Scan Mode Toggle */}
          <div className="mb-5">
            <span className="mb-2 block text-sm font-medium text-slate-300">
              Scan Mode
            </span>
            <div className="flex rounded-lg border border-slate-700 bg-slate-800/50 p-1">
              <button
                type="button"
                onClick={function onPassive() { handleModeChange('passive'); }}
                data-testid="mode-passive"
                className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors ${
                  !isActive
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-300'
                }`}
              >
                Passive
              </button>
              <button
                type="button"
                onClick={function onActive() { handleModeChange('active'); }}
                data-testid="mode-active"
                className={`flex-1 rounded-md px-4 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    : 'text-slate-400 hover:text-slate-300'
                }`}
              >
                Active
              </button>
            </div>
          </div>

          {/* Active mode warning */}
          {isActive && (
            <div
              data-testid="active-warning"
              className="mb-5 rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-300"
            >
              <strong className="font-semibold">Warning:</strong>{' '}
              Active scan mode sends requests directly to the target
              infrastructure (port scans, path discovery). Make sure you
              have explicit authorization.
            </div>
          )}

          {/* Passive Module checkboxes */}
          <fieldset className="mb-5">
            <legend className="mb-2 text-sm font-medium text-slate-300">
              Passive Modules
            </legend>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {DEFAULT_MODULES.map((mod) => (
                <label
                  key={mod}
                  className="flex cursor-pointer items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/50 px-3 py-2 text-sm text-slate-300 hover:border-slate-600"
                >
                  <input
                    type="checkbox"
                    checked={modules.includes(mod)}
                    onChange={function onToggle() { handleModuleToggle(mod); }}
                    className="h-4 w-4 rounded border-slate-600 bg-slate-700 text-cyan-400 focus:ring-cyan-400"
                  />
                  {MODULE_LABELS[mod] ?? mod}
                </label>
              ))}
            </div>
          </fieldset>

          {/* Active Module checkboxes (only shown in active mode) */}
          {isActive && (
            <fieldset className="mb-5">
              <legend className="mb-2 text-sm font-medium text-amber-300">
                Active Modules
              </legend>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {ACTIVE_MODULES.map((mod) => (
                  <label
                    key={mod}
                    className="flex cursor-pointer items-center gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-sm text-amber-200 hover:border-amber-500/40"
                  >
                    <input
                      type="checkbox"
                      checked={modules.includes(mod)}
                      onChange={function onToggle() { handleModuleToggle(mod); }}
                      className="h-4 w-4 rounded border-amber-600 bg-slate-700 text-amber-400 focus:ring-amber-400"
                    />
                    {MODULE_LABELS[mod] ?? mod}
                  </label>
                ))}
              </div>
            </fieldset>
          )}

          {/* Error display */}
          {error && (
            <p
              role="alert"
              className="mb-4 rounded-lg bg-red-500/10 px-4 py-2 text-sm text-red-400"
            >
              {error}
            </p>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={!canSubmit || loading}
            data-testid="start-scan-btn"
            aria-label="Start Scan"
            className={`w-full rounded-lg px-4 py-2.5 text-sm font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
              isActive
                ? 'bg-amber-500 text-slate-950 hover:bg-amber-400'
                : 'bg-cyan-500 text-slate-950 hover:bg-cyan-400'
            }`}
          >
            {loading ? 'Starting...' : isActive ? 'Start Active Scan' : 'Start Scan'}
          </button>
        </form>
      </div>
    </section>
  );
}
