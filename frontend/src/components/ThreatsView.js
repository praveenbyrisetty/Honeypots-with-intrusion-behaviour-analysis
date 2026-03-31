import React, { useState, useEffect } from 'react';

function ThreatsView() {
  const [commands, setCommands] = useState([]);
  const [topIps, setTopIps] = useState([]);
  const [sessions, setSessions] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [cmdsRes, ipsRes, sessRes] = await Promise.all([
          fetch('/api/commands'),
          fetch('/api/top-ips'),
          fetch('/api/sessions'),
        ]);
        const cmdsData = await cmdsRes.json();
        const ipsData = await ipsRes.json();
        const sessData = await sessRes.json();
        setCommands(cmdsData.data ? cmdsData.data.slice(0, 15) : []);
        setTopIps(ipsData ? ipsData.slice(0, 5) : []);
        setSessions(Array.isArray(sessData) ? sessData.slice(0, 5) : []);
      } catch (e) {
        console.error("Error fetching threat data", e);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 15000);
    return () => clearInterval(interval);
  }, []);

  const maxAttacks = Math.max(...topIps.map(ip => ip.count || 0), 1);

  return (
    <div className="dashboard threats-view">
      <div className="dashboard-header" style={{ borderLeftColor: 'var(--accent-red)' }}>
        <h1>Threat Analysis Center</h1>
        <p>Deep-dive into attacker behavior — commands executed, session recordings, and threat actor ranking.</p>
      </div>

      {loading ? (
        <div className="dashboard-loading">
          <div className="loading-spinner"></div>
          <p>Loading threat intelligence...</p>
        </div>
      ) : (
        <>
          {/* ── Top row: Threat actors + Sessions ──────── */}
          <div className="threats-top-grid">
            {/* Threat Actors */}
            <div className="table-container" style={{ margin: 0 }}>
              <h3>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
                Top Threat Actors
              </h3>
              {topIps.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {topIps.map((ip, i) => (
                    <div key={i} className="threat-actor-card">
                      <div className="threat-actor-left">
                        <span className="threat-actor-rank" style={{
                          background: i < 3 ? `${['rgba(255,59,110,0.12)', 'rgba(251,191,36,0.12)', 'rgba(168,85,247,0.12)'][i]}` : 'var(--glass-bg)',
                          color: i < 3 ? `${['var(--accent-red)', 'var(--accent-yellow)', 'var(--accent-purple)'][i]}` : 'var(--text-dim)',
                          borderColor: i < 3 ? `${['rgba(255,59,110,0.25)', 'rgba(251,191,36,0.25)', 'rgba(168,85,247,0.25)'][i]}` : 'var(--border-color)',
                        }}>
                          #{i + 1}
                        </span>
                        <div>
                          <div className="ip-address" style={{ fontSize: '13px', fontWeight: 600 }}>{ip.ip}</div>
                          <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginTop: '2px' }}>
                            {ip.count > 100 ? 'Active attacker' : ip.count > 20 ? 'Recurring probe' : 'Low-frequency scan'}
                          </div>
                        </div>
                      </div>
                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, fontSize: '14px', color: 'var(--text-main)' }}>
                          {ip.count.toLocaleString()}
                        </div>
                        <div className="threat-score-bar" style={{ width: '80px', marginTop: '4px' }}>
                          <div className="threat-score-fill" style={{
                            width: `${(ip.count / maxAttacks) * 100}%`,
                            background: i < 3
                              ? 'linear-gradient(90deg, var(--accent-red), rgba(255,59,110,0.3))'
                              : 'linear-gradient(90deg, var(--accent-yellow), rgba(251,191,36,0.3))',
                            animationDelay: `${i * 0.1}s`
                          }}></div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mini-empty-state">
                  <span>🛡️</span>
                  <p>No threat actors detected yet</p>
                </div>
              )}
            </div>

            {/* Active Sessions */}
            <div className="table-container" style={{ margin: 0 }}>
              <h3>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                Recent Sessions
              </h3>
              {sessions.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {sessions.map((s, i) => (
                    <div key={i} className="session-card">
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span className="ip-address" style={{ fontSize: '12px' }}>{s.src_ip}</span>
                        <span className={`protocol ${(s.honeypot || '').split('_').pop()}`} style={{ fontSize: '9px' }}>
                          {(s.honeypot || '').split('_').pop()}
                        </span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '6px', fontSize: '10px', color: 'var(--text-dim)' }}>
                        <span>{typeof s.duration === 'number' ? `${s.duration}s` : s.duration}</span>
                        <span>{s.commands_count} cmds</span>
                        <span>{s.end_time === 'Active' ? '🟢 Active' : '⏹ Ended'}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="mini-empty-state">
                  <span>📊</span>
                  <p>No interactive sessions recorded</p>
                </div>
              )}
            </div>
          </div>

          {/* ── Commands Table ─────────────────────────── */}
          <div className="table-container" style={{ marginTop: '20px' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
              Live Commands Captured
              <span className="live-indicator">
                <span className="live-dot"></span>
                Live
              </span>
            </h3>
            {commands.length > 0 ? (
              <div style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th style={{ width: '140px' }}>Timestamp</th>
                      <th style={{ width: '120px' }}>Source IP</th>
                      <th>Command Payload</th>
                    </tr>
                  </thead>
                  <tbody>
                    {commands.map((cmd, i) => (
                      <tr key={i}>
                        <td style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                          {cmd.timestamp ? new Date(cmd.timestamp).toLocaleTimeString() : '—'}
                        </td>
                        <td className="ip-address" style={{ verticalAlign: 'top' }}>{cmd.src_ip}</td>
                        <td>
                          <code style={{
                            color: 'var(--command-pill-text)',
                            background: 'var(--command-pill-bg)',
                            border: '1px solid var(--command-pill-border)',
                            padding: '5px 10px',
                            borderRadius: '6px',
                            display: 'block',
                            wordBreak: 'break-all',
                            whiteSpace: 'pre-wrap',
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize: '11px',
                            lineHeight: 1.5
                          }}>
                            {cmd.command}
                          </code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="mini-empty-state" style={{ padding: '40px 20px' }}>
                <span>⚡</span>
                <h4>No Commands Captured</h4>
                <p>Waiting for attackers to execute commands in interactive honeypot shells.</p>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

export default ThreatsView;
