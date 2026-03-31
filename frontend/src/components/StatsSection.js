import React from 'react';

function StatsSection({ stats, onRefresh }) {
  if (!stats) return null;

  const formatCompactNumber = (value) => {
    return new Intl.NumberFormat('en-US', {
      notation: 'compact',
      compactDisplay: 'short',
      maximumFractionDigits: value >= 1000 ? 1 : 0,
    }).format(value || 0);
  };

  const getSeverity = (value, warningThreshold, criticalThreshold) => {
    if (value >= criticalThreshold) return { label: 'Critical', className: 'critical' };
    if (value >= warningThreshold) return { label: 'Elevated', className: 'elevated' };
    return { label: 'Normal', className: 'normal' };
  };

  const connectionDensity = stats.total_sessions > 0
    ? (stats.total_connections / stats.total_sessions).toFixed(1)
    : '0';
  const credentialRate = stats.total_connections > 0
    ? Math.round((stats.total_credentials / stats.total_connections) * 100)
    : 0;
  const commandPerSession = stats.total_sessions > 0
    ? (stats.total_commands / stats.total_sessions).toFixed(1)
    : '0';
  const payloadRate = stats.total_connections > 0
    ? Math.round((stats.total_payloads / stats.total_connections) * 100)
    : 0;

  // Generate simple sparkline SVG path
  const generateSparkline = (seed) => {
    const points = [];
    let y = 50;
    for (let i = 0; i <= 8; i++) {
      y = Math.max(10, Math.min(90, y + (Math.sin(seed * i * 0.7) * 25)));
      points.push(`${i * 12.5},${y}`);
    }
    return `M${points.join(' L')}`;
  };

  const SVGIcons = {
    events: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
      </svg>
    ),
    ips: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>
      </svg>
    ),
    creds: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>
      </svg>
    ),
    commands: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>
      </svg>
    ),
    payloads: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
        <polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>
      </svg>
    ),
    sessions: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
      </svg>
    )
  };

  const statCards = [
    { label: 'Total Events', value: stats.total_connections, icon: SVGIcons.events, color: 'var(--accent-cyan)', bgColor: 'rgba(0,229,255,0.06)', meta: `${connectionDensity} conn/session`, severity: getSeverity(stats.total_connections, 50, 200), sparkSeed: 1.2 },
    { label: 'Distinct IPs', value: stats.unique_ips, icon: SVGIcons.ips, color: 'var(--accent-red)', bgColor: 'rgba(255,59,110,0.06)', meta: `${stats.unique_ips} actors detected`, severity: getSeverity(stats.unique_ips, 5, 20), sparkSeed: 2.4 },
    { label: 'Harvested Creds', value: stats.total_credentials, icon: SVGIcons.creds, color: 'var(--accent-yellow)', bgColor: 'rgba(251,191,36,0.06)', meta: `${credentialRate}% exploit attempt rate`, severity: getSeverity(stats.total_credentials, 20, 50), sparkSeed: 3.1 },
    { label: 'Commands Executed', value: stats.total_commands, icon: SVGIcons.commands, color: 'var(--accent-green)', bgColor: 'rgba(0,255,170,0.06)', meta: `${commandPerSession} cmds/session avg`, severity: getSeverity(stats.total_commands, 30, 120), sparkSeed: 1.8 },
    { label: 'Payloads Intercepted', value: stats.total_payloads, icon: SVGIcons.payloads, color: 'var(--accent-purple)', bgColor: 'rgba(168,85,247,0.06)', meta: `${payloadRate}% drop rate`, severity: getSeverity(stats.total_payloads, 5, 15), sparkSeed: 2.9 },
    { label: 'Active Sessions', value: stats.total_sessions, icon: SVGIcons.sessions, color: 'var(--accent-blue)', bgColor: 'rgba(59,130,246,0.06)', meta: stats.total_sessions > 0 ? 'Honeypots engaging' : 'No active sessions', severity: getSeverity(stats.total_sessions, 5, 15), sparkSeed: 0.7 },
  ];

  return (
    <div className="stats-grid">
      {statCards.map((card, idx) => (
        <div key={idx} className="stat-card">
          <div className="stat-card-top-row">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div 
                className="stat-card-icon" 
                style={{ 
                  background: card.bgColor, 
                  color: card.color,
                  width: '28px', 
                  height: '28px', 
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center'
                }}
              >
                <div style={{ width: '16px', height: '16px' }}>{card.icon}</div>
              </div>
              <div className="stat-card-label" style={{ fontSize: '11px' }}>{card.label}</div>
            </div>
            <span className={`stat-severity-badge ${card.severity.className}`}>{card.severity.label}</span>
          </div>
          <p className="stat-card-value" style={{ color: card.color, fontSize: '26px' }} title={card.value?.toLocaleString()}>
            {formatCompactNumber(card.value)}
          </p>
          <div className="stat-card-change" style={{ fontSize: '10px' }}>{card.meta}</div>
          {/* Sparkline decorative SVG */}
          <svg className="stat-card-sparkline" viewBox="0 0 100 100" preserveAspectRatio="none">
            <path d={generateSparkline(card.sparkSeed)} fill="none" stroke={card.color} strokeWidth="2" opacity="0.15" />
          </svg>
        </div>
      ))}
    </div>
  );
}

export default StatsSection;
