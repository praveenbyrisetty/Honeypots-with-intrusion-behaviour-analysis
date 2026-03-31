import React, { useState, useEffect } from 'react';

function CredentialsTable() {
  const [credentials, setCredentials] = useState([]);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const perPage = 20;

  useEffect(() => {
    fetchCredentials(page);
  }, [page]);

  const fetchCredentials = async (pageNum) => {
    setLoading(true);
    try {
      const response = await fetch(`/api/credentials?page=${pageNum}&per_page=${perPage}`);
      const data = await response.json();
      setCredentials(data.data || []);
      setTotal(data.total || 0);
    } catch (error) {
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  const getCredentialProfile = (cred) => {
    const username = (cred.username || '').toLowerCase();
    const password = cred.password || '';
    const weakPasswords = ['1234', '12345', '123456', 'password', 'admin', 'root', 'test', 'qwerty'];
    const isPrivileged = ['root', 'admin', 'administrator'].includes(username);
    const hasPassword = password.length > 0;
    const isWeak = weakPasswords.includes(password.toLowerCase()) || password.length <= 6;
    const isMediumInteraction = (cred.honeypot || '').startsWith('med_');

    let pattern = 'User enumeration';
    let severity = 'normal';

    if (hasPassword && isPrivileged) {
      pattern = 'Privileged credential attack';
      severity = 'critical';
    } else if (hasPassword && isWeak) {
      pattern = 'Weak password spray';
      severity = 'elevated';
    } else if (hasPassword) {
      pattern = 'Credential stuffing';
      severity = 'elevated';
    }

    return {
      pattern,
      severity,
      captureZone: isMediumInteraction ? 'Interactive shell' : 'Credential sink',
      passwordState: hasPassword ? (isWeak ? 'Weak' : 'Non-trivial') : 'Blank',
    };
  };

  const profileSummary = credentials.reduce(
    (acc, cred) => {
      const profile = getCredentialProfile(cred);
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
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
          Captured Credentials
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

      {loading && credentials.length === 0 ? (
        <div style={{ padding: '40px', textAlign: 'center' }}>
          <div className="loading-spinner"></div>
        </div>
      ) : credentials.length === 0 ? (
        <div className="mini-empty-state" style={{ padding: '50px 20px' }}>
          <span>🔑</span>
          <h4>No Credentials Captured</h4>
          <p>Credential harvesting is active. Login attempts will be logged here when attackers attempt authentication.</p>
        </div>
      ) : (
        <>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Breach Pattern</th>
                <th>Username</th>
                <th>Password</th>
                <th>Source IP</th>
                <th>Trap</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {credentials.map((cred, idx) => {
                const profile = getCredentialProfile(cred);
                return (
                <tr key={idx} className={`threat-row-${profile.severity}`}>
                  <td style={{ fontSize: '11px', whiteSpace: 'nowrap' }}>{new Date(cred.timestamp).toLocaleString()}</td>
                  <td><span className="threat-chip">{profile.pattern}</span></td>
                  <td style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, fontSize: '12px' }}>{cred.username}</td>
                  <td style={{ fontFamily: "'JetBrains Mono', monospace", color: 'var(--accent-red)', fontSize: '12px' }}>
                    {'•'.repeat(Math.min(cred.password?.length || 0, 12))}
                  </td>
                  <td className="ip-address">{cred.src_ip}</td>
                  <td>
                    <span className="segment-chip">{profile.captureZone}</span>
                    <div className="subtext-chip">{profile.passwordState}</div>
                  </td>
                  <td>
                    <span className={`severity-chip ${profile.severity}`}>{profile.severity}</span>
                  </td>
                </tr>
              )})}
            </tbody>
          </table>

          {totalPages > 1 && (
            <div className="pagination">
              <button onClick={() => setPage(1)} disabled={page === 1}>First</button>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>Prev</button>
              <span className="pagination-info">
                Page {page} of {totalPages}
              </span>
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>Next</button>
              <button onClick={() => setPage(totalPages)} disabled={page === totalPages}>Last</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default CredentialsTable;
