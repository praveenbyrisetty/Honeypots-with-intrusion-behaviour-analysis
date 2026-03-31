import React, { useState, useEffect, useCallback } from 'react';

function IntelligenceView() {
  const [threats, setThreats] = useState([]);
  const [summary, setSummary] = useState({ total_actors: 0, countries: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [expandedRow, setExpandedRow] = useState(null);

  const fetchIntelligence = useCallback(async () => {
    try {
      const response = await fetch('/api/threat-intelligence');
      if (!response.ok) throw new Error('Failed to fetch threat intelligence');
      const data = await response.json();
      setThreats(data.threats || []);
      setSummary(data.summary || { total_actors: 0, countries: [] });
      setError(null);
      setLastRefresh(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIntelligence();
    const interval = setInterval(fetchIntelligence, 30000);
    return () => clearInterval(interval);
  }, [fetchIntelligence]);

  const getConfidenceColor = (val) => {
    if (val >= 85) return 'var(--accent-red)';
    if (val >= 60) return 'var(--accent-yellow)';
    return 'var(--accent-green)';
  };

  const getThreatLevel = (val) => {
    if (val >= 85) return 'CRITICAL';
    if (val >= 60) return 'HIGH';
    if (val >= 30) return 'MEDIUM';
    return 'LOW';
  };

  const getThreatLevelClass = (val) => {
    if (val >= 85) return 'critical';
    if (val >= 60) return 'elevated';
    return 'normal';
  };

  const getCountryFlag = (countryCode) => {
    if (!countryCode || countryCode === 'XX' || countryCode === 'LO') return '🌐';
    try {
      return countryCode
        .toUpperCase()
        .split('')
        .map(c => String.fromCodePoint(0x1F1E6 + c.charCodeAt(0) - 65))
        .join('');
    } catch {
      return '🌐';
    }
  };

  return (
    <div className="dashboard intelligence-view">
      <div className="dashboard-header" style={{ borderLeftColor: 'var(--accent-purple)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1>Threat Intelligence</h1>
            <p>Real-time threat actor profiling from live honeypot telemetry + GeoIP enrichment.</p>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            {lastRefresh && (
              <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>
                Updated {lastRefresh.toLocaleTimeString()}
              </span>
            )}
            <button
              className="btn-refresh"
              onClick={() => { setLoading(true); fetchIntelligence(); }}
              disabled={loading}
              title="Refresh intelligence data"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10" /><polyline points="1 20 1 14 7 14" />
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
              </svg>
            </button>
          </div>
        </div>
      </div>

      {loading && threats.length === 0 ? (
        <div className="intel-loading">
          <div className="loading-spinner"></div>
          <p>Analyzing threat actors and enriching with GeoIP data...</p>
        </div>
      ) : error && threats.length === 0 ? (
        <div className="intel-error">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          <p>Unable to fetch threat intelligence: {error}</p>
          <button className="btn-refresh" onClick={() => { setLoading(true); fetchIntelligence(); }}>
            Retry
          </button>
        </div>
      ) : threats.length === 0 ? (
        <div className="intel-empty">
          <div className="intel-empty-icon">🛡️</div>
          <h3>No Threat Actors Detected</h3>
          <p>Your honeypots have not recorded any attack traffic yet. Once attackers connect, their IPs will be profiled here with full GeoIP intelligence.</p>
        </div>
      ) : (
        <>
          {/* ── Summary Cards ──────────────────────────────── */}
          <div className="intel-summary-grid">
            <div className="intel-summary-card">
              <div className="intel-summary-icon" style={{ background: 'rgba(255,59,110,0.08)', color: 'var(--accent-red)' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
              </div>
              <div>
                <div className="intel-summary-value">{summary.total_actors}</div>
                <div className="intel-summary-label">Threat Actors</div>
              </div>
            </div>
            <div className="intel-summary-card">
              <div className="intel-summary-icon" style={{ background: 'rgba(168,85,247,0.08)', color: 'var(--accent-purple)' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
              </div>
              <div>
                <div className="intel-summary-value">{summary.countries?.length || 0}</div>
                <div className="intel-summary-label">Countries</div>
              </div>
            </div>
            <div className="intel-summary-card">
              <div className="intel-summary-icon" style={{ background: 'rgba(251,191,36,0.08)', color: 'var(--accent-yellow)' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
              </div>
              <div>
                <div className="intel-summary-value">{threats.filter(t => t.confidence >= 85).length}</div>
                <div className="intel-summary-label">Critical Threats</div>
              </div>
            </div>
            <div className="intel-summary-card">
              <div className="intel-summary-icon" style={{ background: 'rgba(0,229,255,0.08)', color: 'var(--accent-cyan)' }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
              </div>
              <div>
                <div className="intel-summary-value">{threats.reduce((s, t) => s + t.total_attacks, 0).toLocaleString()}</div>
                <div className="intel-summary-label">Total Attacks</div>
              </div>
            </div>
          </div>

          {/* ── Geographic Distribution ────────────────────── */}
          {summary.countries && summary.countries.length > 0 && (
            <div className="intel-geo-section">
              <h3>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
                Attack Origin Countries
              </h3>
              <div className="intel-country-bars">
                {summary.countries.slice(0, 6).map((c, i) => {
                  const maxAttacks = summary.countries[0]?.attacks || 1;
                  return (
                    <div key={i} className="intel-country-row">
                      <div className="intel-country-info">
                        <span className="intel-country-rank">#{i + 1}</span>
                        <span className="intel-country-name">{c.country}</span>
                      </div>
                      <div className="intel-country-bar-wrap">
                        <div
                          className="intel-country-bar-fill"
                          style={{
                            width: `${(c.attacks / maxAttacks) * 100}%`,
                            animationDelay: `${i * 0.08}s`,
                          }}
                        ></div>
                      </div>
                      <span className="intel-country-count">{c.attacks.toLocaleString()}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ── Threat Actors Table ────────────────────────── */}
          <div className="table-container" style={{ marginTop: '24px' }}>
            <h3>
              Threat Actor Profiles
              <span className="live-indicator" style={{ marginLeft: '12px' }}>
                <span className="live-dot"></span>
                Live
              </span>
            </h3>
            <table className="data-table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Location</th>
                  <th>Classification</th>
                  <th>Attacks</th>
                  <th>Confidence</th>
                  <th>MITRE ATT&CK</th>
                  <th>Threat Level</th>
                </tr>
              </thead>
              <tbody>
                {threats.map((t, i) => (
                  <React.Fragment key={i}>
                    <tr
                      className={`threat-row-${getThreatLevelClass(t.confidence)}`}
                      onClick={() => setExpandedRow(expandedRow === i ? null : i)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td className="ip-address">{t.ip}</td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        <span style={{ marginRight: '6px' }}>{getCountryFlag(t.countryCode)}</span>
                        {t.country}
                        {t.city && t.city !== '—' && (
                          <span style={{ color: 'var(--text-dim)', fontSize: '11px' }}> • {t.city}</span>
                        )}
                      </td>
                      <td>
                        <span className={`protocol ${t.primary_protocol}`}>{t.classification}</span>
                      </td>
                      <td style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700 }}>
                        {t.total_attacks.toLocaleString()}
                      </td>
                      <td>
                        <div className="confidence-bar-wrap">
                          <div className="confidence-bar">
                            <div
                              className="confidence-bar-fill"
                              style={{
                                width: `${t.confidence}%`,
                                background: getConfidenceColor(t.confidence),
                                animationDelay: `${i * 0.08}s`,
                              }}
                            ></div>
                          </div>
                          <span className="confidence-text" style={{ color: getConfidenceColor(t.confidence) }}>
                            {t.confidence}%
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="mitre-chip">{t.mitre_technique}</span>
                      </td>
                      <td>
                        <span className={`severity-chip ${getThreatLevelClass(t.confidence)}`}>
                          {getThreatLevel(t.confidence)}
                        </span>
                      </td>
                    </tr>
                    {expandedRow === i && (
                      <tr className="intel-expanded-row">
                        <td colSpan="7">
                          <div className="intel-detail-grid">
                            <div className="intel-detail-item">
                              <span className="intel-detail-label">ISP / Provider</span>
                              <span className="intel-detail-value">{t.isp || '—'}</span>
                            </div>
                            <div className="intel-detail-item">
                              <span className="intel-detail-label">Organization</span>
                              <span className="intel-detail-value">{t.org || '—'}</span>
                            </div>
                            <div className="intel-detail-item">
                              <span className="intel-detail-label">Credential Attempts</span>
                              <span className="intel-detail-value">{t.credential_attempts || 0}</span>
                            </div>
                            <div className="intel-detail-item">
                              <span className="intel-detail-label">MITRE Technique</span>
                              <span className="intel-detail-value">{t.mitre_name}</span>
                            </div>
                            <div className="intel-detail-item">
                              <span className="intel-detail-label">Protocols Used</span>
                              <span className="intel-detail-value">
                                {t.protocols && Object.entries(t.protocols).map(([proto, count]) => (
                                  <span key={proto} className={`protocol ${proto}`} style={{ marginRight: '6px' }}>
                                    {proto} ({count})
                                  </span>
                                ))}
                              </span>
                            </div>
                            <div className="intel-detail-item">
                              <span className="intel-detail-label">Last Seen</span>
                              <span className="intel-detail-value">
                                {t.last_seen ? new Date(t.last_seen).toLocaleString() : '—'}
                              </span>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

export default IntelligenceView;
