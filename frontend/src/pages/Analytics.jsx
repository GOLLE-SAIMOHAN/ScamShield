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
      {error ? <div className="alert alert-danger mb-4">{error}</div> : null}

      {isLoading ? (
        <div className="glass-panel p-5 text-center">
          <div className="spinner-border text-info" role="status" aria-label="Loading analytics" />
          <div className="text-secondary mt-3">Loading analytics data…</div>
        </div>
      ) : (
        <>
          <div className="row g-4 mb-4">
            {stats.map((stat) => (
              <div key={stat.label} className="col-12 col-sm-6 col-xl-3">
                <div className="glass-panel p-4 h-100">
                  <small className="text-secondary text-uppercase tracking-wider">{stat.label}</small>
                  <div className="display-6 text-light mt-2 fw-bold">{stat.value}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="row g-4">
            <div className="col-12 col-xl-8">
              <div className="glass-panel p-4 h-100">
                <div className="d-flex align-items-center justify-content-between mb-3">
                  <h3 className="h5 text-light mb-0">Risk distribution</h3>
                  <span className="badge rounded-pill bg-info bg-opacity-10 text-info">Live</span>
                </div>

                <div className="d-grid gap-3">
                  {chartValues.map((item) => (
                    <div key={item.label}>
                      <div className="d-flex justify-content-between small text-secondary mb-1">
                        <span>{item.label}</span>
                        <span>{item.value}</span>
                      </div>
                      <div className="progress" style={{ height: 12, background: "rgba(255,255,255,0.08)" }}>
                        <div
                          className="progress-bar rounded-pill"
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
              <div className="glass-panel p-4 h-100">
                <h3 className="h5 text-light mb-3">Recent activity</h3>
                <div className="d-grid gap-3">
                  {recentScans.length > 0 ? recentScans.slice(0, 5).map((scan) => (
                    <div key={scan.scan_id || Math.random()} className="border rounded-4 p-3 border-secondary border-opacity-25">
                      <div className="small text-secondary">{scan.kind || "Scan"}</div>
                      <div className="fw-semibold text-light text-truncate">{scan.input || "Unknown target"}</div>
                      <div className="small text-info">{scan.risk || "Unknown risk"}</div>
                    </div>
                  )) : (
                    <div className="text-secondary small">No recent activity found.</div>
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
