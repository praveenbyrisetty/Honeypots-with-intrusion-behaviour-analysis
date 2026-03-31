import React, { useState, useEffect } from 'react';

const RANK_COLORS = ['#ff3b6e', '#fbbf24', '#00e5ff'];

function ChartsSection() {
  const [protocolStats, setProtocolStats] = useState([]);
  const [topIPs, setTopIPs] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hoveredPoint, setHoveredPoint] = useState(null);

  useEffect(() => {
    Promise.all([
      fetch('/api/protocol-stats').then(r => r.json()).then(data => setProtocolStats(data)),
      fetch('/api/top-ips').then(r => r.json()).then(data => setTopIPs(data)),
      fetch('/api/timeline').then(r => r.json()).then(data => setTimeline(data)),
    ]).finally(() => setLoading(false));
  }, []);

  const maxProtocolCount = Math.max(...protocolStats.map(p => p.count || 0), 1);
  const maxTimelineCount = Math.max(...timeline.map(p => p.count || 0), 1);

  // Helper to generate SVG paths for the area chart
  const generateTelemetryPaths = () => {
    if (timeline.length === 0) return { area: '', line: '', points: [] };
    
    const svgWidth = 1000;
    const svgHeight = 160;
    const padding = 10;
    const effectiveHeight = svgHeight - (padding * 2);
    
    const stepX = svgWidth / Math.max(timeline.length - 1, 1);
    
    let pathNodes = [];
    let pointData = [];
    
    timeline.forEach((point, i) => {
      const x = i * stepX;
      // Invert Y because SVG origin is top-left
      const normalizedY = maxTimelineCount > 0 ? (point.count / maxTimelineCount) : 0;
      const y = svgHeight - padding - (normalizedY * effectiveHeight);
      
      pathNodes.push(`${x},${y}`);
      pointData.push({ x, y, ...point });
    });
    
    const lineStr = `M ${pathNodes.join(' L ')}`;
    const areaStr = `M 0,${svgHeight} L ${pathNodes.join(' L ')} L ${svgWidth},${svgHeight} Z`;
    
    return { area: areaStr, line: lineStr, points: pointData };
  };

  const { area, line, points } = generateTelemetryPaths();

  return (
    <div className="charts-container">
      {/* Protocol Distribution */}
      <div className="chart-card">
        <h3>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>
          Layer Distribution
        </h3>
        {loading ? (
          <div className="loading-spinner"></div>
        ) : protocolStats.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {protocolStats.map((protocol, idx) => (
              <div key={idx}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '11px' }}>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: "'JetBrains Mono', monospace", fontWeight: 600 }}>
                    {protocol.honeypot || 'Unknown'}
                  </span>
                  <strong style={{ color: 'var(--accent-cyan)', fontFamily: "'JetBrains Mono', monospace" }}>{protocol.count.toLocaleString()}</strong>
                </div>
                <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--glass-bg)', borderRadius: '4px', overflow: 'hidden' }}>
                  <div style={{
                    height: '100%',
                    width: `${(protocol.count / maxProtocolCount) * 100}%`,
                    background: `linear-gradient(90deg, var(--accent-cyan), rgba(0, 229, 255, 0.4))`,
                    borderRadius: '4px',
                    animation: 'growWidth 0.8s var(--ease-out) both',
                    animationDelay: `${idx * 0.1}s`
                  }}></div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="mini-empty-state">
             <span>🛡️</span>
             <p>No activity recorded yet.</p>
          </div>
        )}
      </div>

      {/* Top Attackers */}
      <div className="chart-card">
        <h3>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
          Active Threat Sources
        </h3>
        {loading ? (
          <div className="loading-spinner"></div>
        ) : topIPs.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {topIPs.slice(0, 5).map((ip, idx) => (
              <div key={idx} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                fontSize: '11px',
                padding: '10px 12px',
                background: idx < 3 ? 'rgba(255,59,110,0.04)' : 'var(--glass-bg)',
                borderRadius: '8px',
                border: `1px solid ${idx < 3 ? 'rgba(255,59,110,0.12)' : 'var(--border-color)'}`,
                animation: 'fadeIn 0.3s var(--ease-out) both',
                animationDelay: `${idx * 0.05}s`
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  {idx < 3 ? (
                    <span style={{
                      width: '20px', height: '20px',
                      borderRadius: '4px',
                      background: `${RANK_COLORS[idx]}15`,
                      border: `1px solid ${RANK_COLORS[idx]}30`,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: '9px', fontWeight: 700, color: RANK_COLORS[idx],
                      fontFamily: "'JetBrains Mono', monospace"
                    }}>#{idx + 1}</span>
                  ) : (
                    <span style={{
                      width: '20px', textAlign: 'center',
                      fontSize: '9px', color: 'var(--text-dim)',
                      fontFamily: "'JetBrains Mono', monospace"
                    }}>#{idx + 1}</span>
                  )}
                  <span className="ip-address" style={{ fontWeight: 600, fontSize: '12px' }}>{ip.ip}</span>
                </div>
                <span style={{ color: 'var(--text-muted)', fontFamily: "'JetBrains Mono', monospace", fontSize: '11px' }}>
                  {ip.count.toLocaleString()} <span style={{fontSize: '9px'}}>hits</span>
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="mini-empty-state">
             <span>🛡️</span>
             <p>No threat sources identified.</p>
          </div>
        )}
      </div>

      {/* Timeline (Area Chart) */}
      <div className="chart-card" style={{ gridColumn: '1 / -1' }}>
        <h3>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          24H Event Telemetry
        </h3>
        {loading ? (
          <div className="loading-spinner"></div>
        ) : timeline.length > 0 ? (
          <div style={{ position: 'relative', marginTop: '20px', paddingTop: '10px' }}>
            
            {/* SVG Chart Area */}
            <div style={{ width: '100%', height: '180px', position: 'relative' }}>
              
              {/* Grid Lines */}
              <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', zIndex: 0 }}>
                {[0, 1, 2, 3].map(i => (
                  <div key={i} style={{ borderBottom: '1px dashed var(--border-color)', opacity: Math.max(0.2, 0.6 - (i*0.1)), height: '0px' }}></div>
                ))}
              </div>

              <svg 
                viewBox="0 0 1000 160" 
                preserveAspectRatio="none" 
                style={{ width: '100%', height: '100%', display: 'block', position: 'absolute', zIndex: 1, overflow: 'visible' }}
                onMouseLeave={() => setHoveredPoint(null)}
              >
                <defs>
                  <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--accent-green)" stopOpacity="0.35" />
                    <stop offset="80%" stopColor="var(--accent-green)" stopOpacity="0.0" />
                  </linearGradient>
                  
                  {/* Glowing line filter */}
                  <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="3" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                  </filter>
                </defs>

                {/* Fill Area */}
                <path 
                  d={area} 
                  fill="url(#areaGradient)" 
                  style={{ animation: 'fadeIn 1s var(--ease-out) both' }} 
                />
                
                {/* Stroke Line */}
                <path 
                  d={line} 
                  fill="none" 
                  stroke="var(--accent-green)" 
                  strokeWidth="3" 
                  strokeLinejoin="round" 
                  strokeLinecap="round" 
                  filter="url(#glow)"
                  style={{
                    strokeDasharray: '3000',
                    strokeDashoffset: '3000',
                    animation: 'drawLine 1.5s var(--ease-out) forwards'
                  }} 
                />

                {/* Interactive Points */}
                {points.map((p, i) => (
                  <g 
                    key={i} 
                    onMouseEnter={() => setHoveredPoint(p)}
                    style={{ cursor: 'crosshair' }}
                  >
                    {/* Invisible larger circle for easier hover */}
                    <circle cx={p.x} cy={p.y} r="20" fill="transparent" />
                    {/* Actual visible dot */}
                    <circle 
                      cx={p.x} 
                      cy={p.y} 
                      r={hoveredPoint === p ? "5" : "0"} 
                      fill="var(--bg-primary)" 
                      stroke="var(--accent-green)" 
                      strokeWidth="2"
                      style={{ transition: 'all 0.2s', filter: 'url(#glow)' }}
                    />
                  </g>
                ))}
              </svg>

              {/* Tooltip for Hover */}
              {hoveredPoint && (
                <div style={{
                  position: 'absolute',
                  left: `calc(${(hoveredPoint.x / 1000) * 100}% - 40px)`,
                  top: `calc(${(hoveredPoint.y / 160) * 100}% - 45px)`,
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--accent-green)',
                  borderRadius: '6px',
                  padding: '6px 10px',
                  boxShadow: 'var(--glow-green)',
                  pointerEvents: 'none',
                  zIndex: 10,
                  transform: 'translateX(0%)',
                }}>
                  <div style={{ fontSize: '12px', fontWeight: 'bold', color: 'var(--text-main)' }}>{hoveredPoint.count.toLocaleString()}</div>
                  <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{hoveredPoint.hour}</div>
                </div>
              )}
            </div>

            {/* Clean X-Axis Labels (Only showing evenly spaced intervals) */}
            <div style={{ display: 'flex', justifyContent: 'space-between', padding: '12px 0 0 0', position: 'relative' }}>
              {timeline.filter((_, i) => i === 0 || i === 5 || i === 11 || i === 17 || i === 23).map((point, idx) => (
                <div key={idx} style={{ 
                  fontSize: '11px', 
                  color: 'var(--text-secondary)',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontWeight: 500
                }}>
                  {point.hour}
                </div>
              ))}
            </div>

          </div>
        ) : (
          <div className="mini-empty-state" style={{ padding: '60px 20px' }}>
             <span>📡</span>
             <p>No telemetry data collected in the last 24 hours.</p>
          </div>
        )}
      </div>

      <style dangerouslySetInnerHTML={{__html: `
        @keyframes drawLine {
          to { stroke-dashoffset: 0; }
        }
      `}} />

    </div>
  );
}

export default ChartsSection;
