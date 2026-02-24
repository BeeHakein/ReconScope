/**
 * @file Top-level layout shell for the ReconScope application.
 *
 * Wraps descendant components with the ScanProvider context and renders
 * the persistent Header above a scrollable main content area.
 */

import React from 'react';
import PropTypes from 'prop-types';
import { ScanProvider } from '../../context/ScanContext';
import Header from './Header';

/**
 * Full-viewport layout containing the fixed header and a content slot.
 *
 * @param {{ children: React.ReactNode }} props
 * @returns {React.ReactElement}
 */
export default function Layout({ children }) {
  return (
    <ScanProvider>
      <div className="min-h-screen bg-slate-950 text-slate-100">
        <Header />
        <main className="pt-16 px-4 pb-8 max-w-screen-2xl mx-auto">
          {children}
        </main>
      </div>
    </ScanProvider>
  );
}

Layout.propTypes = {
  children: PropTypes.node.isRequired,
};
