import React, { useState } from 'react';

const REPORTS = [
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
      </svg>
    ),
    title: 'Executive Summary',
    desc: 'High-level attack metrics, risk posture overview, and key findings for stakeholder reporting.',
    format: 'PDF',
    color: 'var(--accent-cyan)',
    url: '/api/export/pdf'
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
    title: 'Forensic Evidence Dump',
    desc: 'Full connection logs, payload captures, and session data for incident response analysis.',
    format: 'CSV',
    color: 'var(--accent-green)',
    url: '/api/export/csv'
  },
  {
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
        <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
      </svg>
    ),
    title: 'Geo-Threat Report',
    desc: 'IP-to-threat-level mapping with attack volume metrics for geographic trend analysis.',
    format: 'CSV',
    color: 'var(--accent-purple)',
    url: '/api/export/geo'
  },
];

function ReportsView() {
  const [generating, setGenerating] = useState(null);

  const handleDownload = (url, index) => {
    setGenerating(index);
    // Small delay for visual feedback
    setTimeout(() => {
      window.location.href = url;
      setTimeout(() => setGenerating(null), 2000);
    }, 600);
  };

  return (
    <div className="dashboard reports-view">
      <div className="dashboard-header" style={{ borderLeftColor: 'var(--accent-yellow)' }}>
        <h1>Reports & Export</h1>
        <p>Generate compliance-ready reports, forensic evidence dumps, and threat intelligence exports.</p>
      </div>

      <div className="reports-grid">
        {REPORTS.map((report, i) => (
          <div key={i} className="report-card">
            <div className="report-card-header">
              <div className="report-card-icon" style={{ color: report.color, background: `${report.color}10` }}>
                {report.icon}
              </div>
              <div className="report-card-badge" style={{ color: report.color, borderColor: `${report.color}30` }}>
                {report.format}
              </div>
            </div>
            <h3>{report.title}</h3>
            <p>{report.desc}</p>
            <button
              className="report-download-btn"
              style={{ color: report.color, borderColor: `${report.color}40` }}
              onClick={() => handleDownload(report.url, i)}
              disabled={generating === i}
            >
              {generating === i ? (
                <>
                  <div className="loading-spinner" style={{ width: 14, height: 14, borderWidth: 2, margin: 0 }}></div>
                  Generating...
                </>
              ) : (
                <>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                  </svg>
                  Download {report.format}
                </>
              )}
            </button>
          </div>
        ))}
      </div>

      <div className="report-info-banner">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
        <span>Reports are generated on-demand from live database data. Large datasets may take a few seconds to process.</span>
      </div>
    </div>
  );
}

export default ReportsView;
