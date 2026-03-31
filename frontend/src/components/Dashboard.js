import React, { useState, useEffect, useCallback } from 'react';
import StatsSection from './StatsSection';
import ChartsSection from './ChartsSection';
import ConnectionsTable from './ConnectionsTable';
import CredentialsTable from './CredentialsTable';
import GlobeMap from './GlobeMap';

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [attackSummary, setAttackSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(new Date());

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, summaryRes] = await Promise.all([
        fetch('/api/stats'),
        fetch('/api/attack-summary'),
      ]);
      if (!statsRes.ok) throw new Error('Failed to fetch stats');
      const statsData = await statsRes.json();
      setStats(statsData);

      if (summaryRes.ok) {
        const summaryData = await summaryRes.json();
        setAttackSummary(summaryData);
      }

      setError(null);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, [fetchData]);

  const getTrendIcon = (trend) => {
    if (trend === 'increasing') return '↑';
    if (trend === 'decreasing') return '↓';
    return '→';
  };

  const getTrendColor = (trend) => {
    if (trend === 'increasing') return 'var(--accent-red)';
    if (trend === 'decreasing') return 'var(--accent-green)';
    return 'var(--text-muted)';
  };

  return (
    <div className="dashboard">
      {/* ── Header ──────────────────────────────────────── */}
      <div className="dashboard-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h1>Security Operations Center</h1>
            <p>
              Last updated: {lastUpdated.toLocaleTimeString()}
              {stats?.last_event && (
                <> • Last event: {new Date(stats.last_event).toLocaleString()}</>
              )}
            </p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className="live-indicator">
              <span className="live-dot" style={{ background: 'var(--accent-green)', boxShadow: '0 0 6px rgba(0,255,170,0.5)' }}></span>
              Monitoring
            </span>
          </div>
        </div>
      </div>

      {loading && !stats ? (
        <div className="dashboard-loading">
          <div className="loading-spinner"></div>
          <p>Initializing security telemetry...</p>
        </div>
      ) : error && !stats ? (
        <div className="dashboard-error">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent-red)" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <p>Unable to reach the API: {error}</p>
          <button className="btn-refresh" onClick={() => { setLoading(true); fetchData(); }}>
            Retry Connection
          </button>
        </div>
      ) : (
        <>
          {/* ── Threat Pulse Banner ───────────────────────── */}
          {attackSummary && (
            <div className="threat-pulse-banner">
              <div className="pulse-item">
                <span className="pulse-label">Last Hour</span>
                <span className="pulse-value">{attackSummary.current_hour_attacks}</span>
                <span className="pulse-meta">attacks</span>
              </div>
              <div className="pulse-divider"></div>
              <div className="pulse-item">
                <span className="pulse-label">Trend</span>
                <span className="pulse-value" style={{ color: getTrendColor(attackSummary.trend) }}>
                  {getTrendIcon(attackSummary.trend)} {Math.abs(attackSummary.trend_percent)}%
                </span>
                <span className="pulse-meta">{attackSummary.trend}</span>
              </div>
              <div className="pulse-divider"></div>
              <div className="pulse-item">
                <span className="pulse-label">Active Protocols</span>
                <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                  {attackSummary.protocols?.slice(0, 4).map((p, i) => (
                    <span key={i} className={`protocol ${p.protocol}`} style={{ fontSize: '9px' }}>{p.protocol}</span>
                  ))}
                </div>
              </div>
              {attackSummary.recent_attackers?.length > 0 && (
                <>
                  <div className="pulse-divider"></div>
                  <div className="pulse-item">
                    <span className="pulse-label">Latest Attacker</span>
                    <span className="pulse-value ip-address" style={{ fontSize: '13px' }}>
                      {attackSummary.recent_attackers[0]?.ip}
                    </span>
                  </div>
                </>
              )}
            </div>
          )}

          {/* ── Stats Cards ──────────────────────────────── */}
          <StatsSection stats={stats} onRefresh={fetchData} />

          {/* ── Main Content Grid ────────────────────────── */}
          <div className="dashboard-grid-2col">
            {/* Left: Globe Map */}
            <div className="dashboard-primary">
              <div className="section-divider">Threat Origin Map</div>
              <div className="chart-card">
                <h3>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                  Live Threat Origin Map
                </h3>
                <GlobeMap />
              </div>
            </div>

            {/* Right: Quick Intel */}
            <div className="dashboard-secondary">
              <div className="section-divider">Quick Intel</div>
              {attackSummary?.recent_attackers?.length > 0 ? (
                <div className="chart-card">
                  <h3>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
                    Recent Attackers
                  </h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {attackSummary.recent_attackers.map((a, i) => (
                      <div key={i} className="quick-intel-item">
                        <span className="ip-address" style={{ fontSize: '12px' }}>{a.ip}</span>
                        <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>
                          {a.last_seen ? new Date(a.last_seen).toLocaleTimeString() : '—'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="chart-card">
                  <h3>Recent Attackers</h3>
                  <div className="mini-empty-state">
                    <span>🛡️</span>
                    <p>No recent activity detected</p>
                  </div>
                </div>
              )}

              {attackSummary?.protocols?.length > 0 && (
                <div className="chart-card" style={{ marginTop: '16px' }}>
                  <h3>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
                    Protocol Distribution
                  </h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {attackSummary.protocols.slice(0, 5).map((p, i) => {
                      const max = attackSummary.protocols[0]?.count || 1;
                      return (
                        <div key={i}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                            <span className={`protocol ${p.protocol}`} style={{ fontSize: '10px' }}>{p.protocol}</span>
                            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace" }}>{p.count}</span>
                          </div>
                          <div style={{ width: '100%', height: '4px', background: 'var(--glass-bg)', borderRadius: '4px', overflow: 'hidden' }}>
                            <div style={{
                              height: '100%',
                              width: `${(p.count / max) * 100}%`,
                              background: 'linear-gradient(90deg, var(--accent-cyan), rgba(0,229,255,0.3))',
                              borderRadius: '4px',
                              animation: 'growWidth 0.6s var(--ease-out) both',
                              animationDelay: `${i * 0.08}s`,
                            }}></div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* ── Analytics ──────────────────────────────────── */}
          <div className="section-divider">Analytics</div>
          <ChartsSection />

          {/* ── Data Tables ────────────────────────────────── */}
          <div className="section-divider">Event Logs</div>
          <ConnectionsTable />
          <CredentialsTable />
        </>
      )}
    </div>
  );
}

export default Dashboard;
