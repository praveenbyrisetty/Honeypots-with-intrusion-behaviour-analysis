import React, { useState, useEffect } from 'react';
import './App.css';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import ThreatsView from './components/ThreatsView';
import IntelligenceView from './components/IntelligenceView';
import ReportsView from './components/ReportsView';
import SettingsView from './components/SettingsView';

const THEME_STORAGE_KEY = 'honey_theme_preference';

const PAGE_TITLES = {
  dashboard: { title: 'Security Operations', breadcrumb: 'Command Center' },
  threats: { title: 'Threat Analysis', breadcrumb: 'Active Threats' },
  intelligence: { title: 'Threat Intelligence', breadcrumb: 'Actor Profiling' },
  reports: { title: 'Reports & Export', breadcrumb: 'Automated Reports' },
  settings: { title: 'Configuration', breadcrumb: 'System Settings' },
};

const getSystemTheme = () => {
  if (typeof window === 'undefined' || !window.matchMedia) return 'dark';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
};

const getInitialThemePreference = () => {
  if (typeof window === 'undefined') return 'system';
  const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
  return ['light', 'dark', 'system'].includes(saved) ? saved : 'system';
};

function TopBar({ activePage }) {
  const [time, setTime] = useState(new Date());
  const page = PAGE_TITLES[activePage] || PAGE_TITLES.dashboard;

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="top-bar">
      <div className="top-bar-left">
        <div className="top-bar-title">{page.title}</div>
        <div className="top-bar-breadcrumb">/ {page.breadcrumb}</div>
      </div>
      <div className="top-bar-right">
        <div className="top-bar-search">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          Search...
          <kbd>⌘K</kbd>
        </div>
        <div className="top-bar-clock">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: '6px', opacity: 0.5 }}><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          {time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
        </div>
      </div>
    </div>
  );
}

function App() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activePage, setActivePage] = useState('dashboard');
  const [themePreference, setThemePreference] = useState(getInitialThemePreference);
  const [resolvedTheme, setResolvedTheme] = useState(getSystemTheme);

  useEffect(() => {
    const testAPI = async () => {
      try {
        const response = await fetch('/api/health');
        if (!response.ok) throw new Error('API returned an error');
        setLoading(false);
        setError(null);
      } catch (err) {
        setError(err.message);
        setLoading(false);
      }
    };
    testAPI();
  }, []);

  useEffect(() => {
    const systemThemeQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const applyTheme = () => {
      const nextTheme = themePreference === 'system'
        ? (systemThemeQuery.matches ? 'dark' : 'light')
        : themePreference;
      setResolvedTheme(nextTheme);
      document.documentElement.setAttribute('data-theme', nextTheme);
    };
    window.localStorage.setItem(THEME_STORAGE_KEY, themePreference);
    applyTheme();

    if (themePreference !== 'system') return undefined;
    const handler = () => applyTheme();
    systemThemeQuery.addEventListener?.('change', handler);
    return () => systemThemeQuery.removeEventListener?.('change', handler);
  }, [themePreference]);

  const renderPage = () => {
    switch (activePage) {
      case 'threats': return <ThreatsView />;
      case 'intelligence': return <IntelligenceView />;
      case 'reports': return <ReportsView />;
      case 'settings':
        return (
          <SettingsView
            themePreference={themePreference}
            resolvedTheme={resolvedTheme}
            onThemeChange={setThemePreference}
          />
        );
      default: return <Dashboard />;
    }
  };

  return (
    <div className="app">
      <Sidebar activePage={activePage} setActivePage={setActivePage} />
      <div className="main-content">
        <TopBar activePage={activePage} />
        <div className="main-scroll-area">
          {error && !loading && (
            <div className="api-offline-banner">
              <div className="api-offline-left">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                <span>Backend Offline — API unreachable. Showing cached/demo data.</span>
              </div>
              <button
                className="btn-refresh"
                onClick={() => window.location.reload()}
                style={{ fontSize: '11px', padding: '4px 12px' }}
              >
                Reconnect
              </button>
            </div>
          )}
          {loading ? (
            <div className="dashboard-loading">
              <div className="loading-spinner"></div>
              <p>Connecting to Honeypot SOC Backend...</p>
            </div>
          ) : (
            renderPage()
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
