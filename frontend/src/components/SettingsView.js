import React, { useState } from 'react';

function SettingsView({ themePreference = 'system', resolvedTheme = 'dark', onThemeChange = () => {} }) {
  const [saved, setSaved] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [nodes, setNodes] = useState({ ssh: true, ftp: true, http: false, smb: false });

  const themeStatus = themePreference === 'system'
    ? `Following ${resolvedTheme} system preference`
    : `Using ${themePreference} mode`;

  const handleSave = () => {
    setDeploying(true);
    setTimeout(() => {
      setDeploying(false);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    }, 1200);
  };

  const toggleNode = (node) => setNodes({ ...nodes, [node]: !nodes[node] });

  return (
    <div className="dashboard settings-view">
      <div className="dashboard-header" style={{ borderLeftColor: 'var(--accent-cyan)' }}>
        <h1>System Settings</h1>
        <p>Advanced configuration, integrations, and active node management.</p>
      </div>

      <div className="settings-grid">
        {/* Card 1: Integrations */}
        <div className="settings-card">
          <h3 style={{ color: 'var(--accent-cyan)' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
            Integration & Webhooks
          </h3>
          <div className="settings-group">
            <label className="settings-label">
              Interface Theme
              <span>{themeStatus}</span>
            </label>
            <div className="theme-toggle" role="radiogroup" aria-label="Interface theme mode">
              <button type="button" className={`theme-toggle-btn ${themePreference === 'light' ? 'active' : ''}`} onClick={() => onThemeChange('light')}>☀️ Light</button>
              <button type="button" className={`theme-toggle-btn ${themePreference === 'dark' ? 'active' : ''}`} onClick={() => onThemeChange('dark')}>🌙 Dark</button>
              <button type="button" className={`theme-toggle-btn ${themePreference === 'system' ? 'active' : ''}`} onClick={() => onThemeChange('system')}>💻 System</button>
            </div>
          </div>
          <div className="settings-group">
            <label className="settings-label">Slack Webhook URL</label>
            <input type="text" className="settings-input" placeholder="https://hooks.slack.com/services/..." defaultValue="https://hooks.slack.com/services/T0000/B0000/XXXXX" />
          </div>
          <div className="settings-group">
            <label className="settings-label">SOC Email Distribution</label>
            <input type="email" className="settings-input" placeholder="soc-team@company.com" defaultValue="soc-alerts@honey-corp.dev" />
          </div>
          <div className="settings-group">
            <label className="settings-label">Splunk / SIEM Forwarder IP</label>
            <input type="text" className="settings-input" placeholder="192.168.1.100:8088" />
          </div>
        </div>

        {/* Card 2: Security Thresholds */}
        <div className="settings-card">
          <h3 style={{ color: 'var(--accent-yellow)' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Alerting Thresholds
          </h3>
          <div className="settings-group">
            <label className="settings-label">Severity Level</label>
            <select className="settings-select" defaultValue="medium">
              <option value="low">Low (Log all pings & recon)</option>
              <option value="medium">Medium (Log brute force & drops)</option>
              <option value="high">High (Log ONLY successful exploit)</option>
              <option value="critical">Critical (Page on call directly)</option>
            </select>
          </div>
          <div className="settings-group" style={{ marginTop: '24px' }}>
            <label className="settings-label" style={{ marginBottom: '12px' }}>Automatic Actions</label>
            <div className="toggle-row">
              <div className="toggle-info">
                <span className="toggle-title">Auto-ban IP Address</span>
                <span className="toggle-desc">Ban IP after 5 failed attempts</span>
              </div>
              <label className="switch"><input type="checkbox" defaultChecked /><span className="slider"></span></label>
            </div>
            <div className="toggle-row">
              <div className="toggle-info">
                <span className="toggle-title">Packet Capture (PCAP)</span>
                <span className="toggle-desc">Auto-record PCAP on payload drop</span>
              </div>
              <label className="switch"><input type="checkbox" defaultChecked /><span className="slider"></span></label>
            </div>
          </div>
        </div>

        {/* Card 3: Node Management */}
        <div className="settings-card">
          <h3 style={{ color: 'var(--accent-purple)' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12" y2="20"/></svg>
            Honeypot Nodes
          </h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '16px', lineHeight: 1.5 }}>
            Enable or disable specific honeypot services. Disabling a node tears down the socket listener.
          </p>
          <div className="settings-group">
            {[
              { key: 'ssh', label: 'SSH Node (Port 22)', desc: 'High Interaction Shell', color: 'var(--accent-red)' },
              { key: 'ftp', label: 'FTP Node (Port 21)', desc: 'File Transfer Emulator', color: 'var(--accent-cyan)' },
              { key: 'http', label: 'HTTP Node (Port 80)', desc: 'Web App Vulnerability Sink', color: 'var(--accent-green)' },
              { key: 'smb', label: 'SMB Node (Port 445)', desc: 'EternalBlue & Ransomware', color: 'var(--accent-purple)' },
            ].map(node => (
              <div className="toggle-row" key={node.key}>
                <div className="toggle-info">
                  <span className="toggle-title" style={{ color: node.color }}>{node.label}</span>
                  <span className="toggle-desc">{node.desc}</span>
                </div>
                <label className="switch"><input type="checkbox" checked={nodes[node.key]} onChange={() => toggleNode(node.key)} /><span className="slider"></span></label>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '16px', alignItems: 'center', marginTop: '8px' }}>
        <button className="btn-primary" onClick={handleSave} disabled={deploying}>
          {deploying ? (
            <>
              <div className="loading-spinner" style={{ width: 16, height: 16, borderWidth: 2, margin: 0 }}></div>
              Deploying...
            </>
          ) : (
            <>💾 Deploy Configuration</>
          )}
        </button>
        {saved && (
          <div className="deploy-status">
            <div className="deploy-success">
              <span className="deploy-checkmark">✓</span>
              Configuration pushed to all nodes
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default SettingsView;
