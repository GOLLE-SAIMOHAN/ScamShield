import { useEffect, useMemo, useState } from "react";
import PageContainer from "../layouts/PageContainer.jsx";
import { getDashboardSummary, getRiskDistribution, getRecentScans } from "../services/dashboardService.js";

export default function Analytics() {
  const [summary, setSummary] = useState({});
  const [distribution, setDistribution] = useState({});
  const [recentScans, setRecentScans] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let ignore = false;

    async function loadAnalytics() {
      setIsLoading(true);
      setError("");

      try {
        const [summaryResponse, distributionResponse, recentResponse] = await Promise.all([
          getDashboardSummary().catch(() => ({ data: {} })),
          getRiskDistribution().catch(() => ({ data: {} })),
          getRecentScans().catch(() => ({ data: [] })),
        ]);

        if (ignore) return;

        setSummary(summaryResponse?.data || {});
        setDistribution(distributionResponse?.data || {});
        setRecentScans(recentResponse?.data || []);
      } catch (requestError) {
        if (!ignore) {
          setError(requestError?.message || "Failed to load analytics data.");
        }
      } finally {
        if (!ignore) setIsLoading(false);
      }
    }

    loadAnalytics();
    return () => {
      ignore = true;
    };
  }, []);

  const stats = useMemo(
    () => [
      { label: "Total scans", value: summary.total_scans ?? 0 },
      { label: "Threats flagged", value: summary.threats_detected ?? 0 },
      { label: "Verified safe", value: summary.safe_urls ?? 0 },
      { label: "Known threats", value: summary.known_threats ?? 0 },
    ],
    [summary],
  );

  const chartValues = [
    { label: "Safe", value: distribution.safe ?? 0, color: "#22c55e" },
    { label: "Low", value: distribution.low ?? 0, color: "#38bdf8" },
    { label: "Medium", value: distribution.medium ?? 0, color: "#fbbf24" },
    { label: "High", value: distribution.high ?? 0, color: "#fb7185" },
    { label: "Critical", value: distribution.critical ?? 0, color: "#ef4444" },
  ];

  const maxValue = Math.max(1, ...chartValues.map((item) => item.value));

  return (
    <PageContainer title="Analytics" subtitle="Monitor risk trends, scan distributions, and operational signals across the ScamShield platform.">
      {error ? <div className="analytics-error">{error}</div> : null}

      {isLoading ? (
        <div className="glass-panel analytics-loading-panel">
          <div className="spinner-border text-info" role="status" aria-label="Loading analytics" />
          <div className="analytics-loading-text">Loading analytics data…</div>
        </div>
      ) : (
        <>
          <div className="row g-4 mb-4 analytics-summary-grid">
            {stats.map((stat) => (
              <div key={stat.label} className="col-12 col-sm-6 col-xl-3">
                <div className="analytics-stat-card glass-panel h-100">
                  <small>{stat.label}</small>
                  <div className="analytics-stat-value">{stat.value}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="row g-4">
            <div className="col-12 col-xl-8">
              <div className="analytics-panel glass-panel p-4 h-100">
                <div className="analytics-panel-header">
                  <h3>Risk distribution</h3>
                  <span className="analytics-live-badge">Live</span>
                </div>

                <div className="analytics-bars">
                  {chartValues.map((item) => (
                    <div key={item.label} className="analytics-bar-row">
                      <div className="analytics-bar-meta">
                        <span>{item.label}</span>
                        <span>{item.value}</span>
                      </div>
                      <div className="analytics-progress">
                        <div
                          className="analytics-progress-bar"
                          role="progressbar"
                          aria-valuenow={item.value}
                          aria-valuemin="0"
                          aria-valuemax={maxValue}
                          style={{ width: `${(item.value / maxValue) * 100}%`, background: item.color }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="col-12 col-xl-4">
              <div className="analytics-panel glass-panel p-4 h-100">
                <h3 className="analytics-panel-title">Recent activity</h3>
                <div className="analytics-activity-list">
                  {recentScans.length > 0 ? recentScans.slice(0, 5).map((scan) => (
                    <div key={scan.scan_id || Math.random()} className="analytics-activity-item">
                      <div className="analytics-activity-kind">{scan.kind || "Scan"}</div>
                      <div className="analytics-activity-target">{scan.input || "Unknown target"}</div>
                      <div className="analytics-activity-risk">{scan.risk || "Unknown risk"}</div>
                    </div>
                  )) : (
                    <div className="analytics-empty">No recent activity found.</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </PageContainer>
  );
}
