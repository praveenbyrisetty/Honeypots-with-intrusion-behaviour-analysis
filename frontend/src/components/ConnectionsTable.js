import React, { useState, useEffect } from 'react';

function ConnectionsTable() {
  const [connections, setConnections] = useState([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const perPage = 20;

  useEffect(() => {
    fetchConnections(page);
  }, [page]);

  const fetchConnections = async (pageNum) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/connections?page=${pageNum}&per_page=${perPage}`);
      const data = await response.json();
      setConnections(data.data || []);
      setTotal(data.total || 0);
    } catch (error) {
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const getProtocol = (conn) => {
    const fromHoneypot = (conn.honeypot || '').split('_').pop();
    return (fromHoneypot || conn.protocol || 'unknown').toLowerCase();
  };

  const getConnectionProfile = (conn) => {
    const protocol = getProtocol(conn);
    const isMediumInteraction = (conn.honeypot || '').startsWith('med_');
    const isInternal = /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(conn.src_ip || '');

    const attackTypeMap = {
      ssh: 'SSH brute-force probe',
      ftp: 'Credential harvesting',
      http: 'Web recon / exploit probe',
      telnet: 'IoT credential spray',
      smb: 'Lateral movement probe',
    };

    const severityByProtocol = {
      ssh: isMediumInteraction ? 'critical' : 'elevated',
      ftp: 'elevated',
      http: isMediumInteraction ? 'critical' : 'elevated',
      telnet: 'elevated',
      smb: 'critical',
      unknown: 'normal',
    };

    return {
      protocol,
      attackType: attackTypeMap[protocol] || 'Generic reconnaissance',
      severity: severityByProtocol[protocol] || 'normal',
      segment: isInternal ? 'Internal' : 'External',
      interaction: isMediumInteraction ? 'Medium' : 'Low',
    };
  };

  const profileSummary = connections.reduce(
    (acc, conn) => {
      const profile = getConnectionProfile(conn);
      acc[profile.severity] += 1;
      return acc;
    },
    { critical: 0, elevated: 0, normal: 0 }
  );

  const totalPages = Math.ceil(total / perPage);

  return (
    <div className="table-container">
      <div className="table-header-row">
        <h3>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
          Connection Log
          <span style={{ fontSize: '11px', fontWeight: 400, color: 'var(--text-dim)', marginLeft: '8px' }}>
            ({total.toLocaleString()} total)
          </span>
        </h3>
        <div className="table-insights">
          <span className="mini-chip critical">Critical: {profileSummary.critical}</span>
          <span className="mini-chip elevated">Elevated: {profileSummary.elevated}</span>
          <span className="mini-chip normal">Normal: {profileSummary.normal}</span>
        </div>
      </div>

      {loading && connections.length === 0 ? (
        <div style={{ padding: '40px', textAlign: 'center' }}>
          <div className="loading-spinner"></div>
        </div>
      ) : connections.length === 0 ? (
        <div className="mini-empty-state" style={{ padding: '50px 20px' }}>
          <span>🔌</span>
          <h4>No Connections Recorded</h4>
          <p>Honeypots are active and listening. Connections will appear here as they are detected.</p>
        </div>
      ) : (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Attack Type</th>
                <th>Protocol</th>
                <th>Source IP</th>
                <th>Flow</th>
                <th>Segment</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((conn, idx) => {
                const profile = getConnectionProfile(conn);
                return (
                  <tr key={idx} className={`threat-row-${profile.severity}`}>
                    <td style={{ fontSize: '11px', whiteSpace: 'nowrap' }}>{new Date(conn.timestamp).toLocaleString()}</td>
                    <td>
                      <span className="threat-chip">{profile.attackType}</span>
                    </td>
                    <td>
                      <span className={`protocol ${profile.protocol}`}>{profile.protocol}</span>
                    </td>
                    <td className="ip-address">{conn.src_ip}</td>
                    <td style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px' }}>
                      {conn.src_port} → {conn.dst_port}
                    </td>
                    <td>
                      <span className="segment-chip">{profile.segment}</span>
                    </td>
                    <td>
                      <span className={`severity-chip ${profile.severity}`}>{profile.severity}</span>
                      <div className="subtext-chip">{profile.interaction} int.</div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {totalPages > 1 && (
            <div className="pagination">
              <button onClick={() => setPage(1)} disabled={page === 1}>First</button>
              <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>Prev</button>
              <span className="pagination-info">
                Page {page} of {totalPages}
              </span>
              <button onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages}>Next</button>
              <button onClick={() => setPage(totalPages)} disabled={page === totalPages}>Last</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default ConnectionsTable;
