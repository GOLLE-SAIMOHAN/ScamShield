import { useLocation, useNavigate, useParams } from "react-router-dom";
import PageContainer from "../layouts/PageContainer.jsx";

export default function ScanResults() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { state } = useLocation();
  const result = state?.result || {};

  const riskScore = Number(result.risk_score ?? result.scam_probability ?? result.ai_likelihood ?? 0);
  const riskLevel = result.risk_level || result.classification || result.risk || "Unknown";
  const findings = Array.isArray(result.reasons) ? result.reasons : Array.isArray(result.findings) ? result.findings : [];
  const recommendations = Array.isArray(result.recommendations) ? result.recommendations : [];
  const evidence = result.evidence || result.threat_intelligence || result.threat_summary || {};

  return (
    <PageContainer title="Scan Results" subtitle="Review the actual backend risk evaluation and supporting evidence for this investigation.">
      <div className="results-shell row g-4">
        <div className="col-12 col-xl-4">
          <div className="result-overview glass-panel h-100">
            <div className="results-meta-row">
              <span>Scan ID</span>
              <span className="results-badge">{id || "latest"}</span>
            </div>

            <div className="results-score">{Math.round(riskScore)}</div>
            <div className="results-score-label">Risk score</div>

            <div className="results-progress-wrap">
              <div
                className="results-progress"
                style={{ width: `${Math.min(riskScore, 100)}%`, background: riskScore >= 70 ? "#ef4444" : riskScore >= 40 ? "#fbbf24" : "#22c55e" }}
              />
            </div>

            <div className="results-risk-block">
              <div className="results-block-label">Risk level</div>
              <div className="results-block-value">{riskLevel}</div>
            </div>

            <div className="results-actions">
              <button className="btn-premium-secondary" type="button" onClick={() => navigate(-1)}>Back</button>
            </div>
          </div>
        </div>

        <div className="col-12 col-xl-8">
          <div className="results-panel glass-panel">
            <div className="results-panel-header">
              <h3>Threat classification</h3>
              <span className="results-pill">{result.classification || result.risk_level || "Unknown"}</span>
            </div>

            <div className="row g-3">
              <div className="col-12 col-md-6">
                <div className="results-subpanel">
                  <div className="results-subtitle">Analysis information</div>
                  <ul>
                    <li>Confidence: {result.confidence ?? "Unknown"}</li>
                    <li>Type: {result.content_type || result.kind || "N/A"}</li>
                    <li>URL: {result.url || result.target || "N/A"}</li>
                  </ul>
                </div>
              </div>

              <div className="col-12 col-md-6">
                <div className="results-subpanel">
                  <div className="results-subtitle">Evidence</div>
                  <pre>
                    {JSON.stringify(evidence, null, 2) || "No evidence metadata provided by the backend."}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="row g-4 mt-1">
        <div className="col-12 col-lg-6">
          <div className="results-panel glass-panel h-100">
            <h3 className="results-panel-title">Findings</h3>
            {findings.length > 0 ? (
              <ul className="results-list">
                {findings.map((finding, index) => (
                  <li key={`${finding}-${index}`}>{String(finding)}</li>
                ))}
              </ul>
            ) : (
              <div className="results-empty">No findings were returned by the backend.</div>
            )}
          </div>
        </div>

        <div className="col-12 col-lg-6">
          <div className="results-panel glass-panel h-100">
            <h3 className="results-panel-title">Recommendations</h3>
            {recommendations.length > 0 ? (
              <ul className="results-list">
                {recommendations.map((item, index) => (
                  <li key={`${item}-${index}`}>{String(item)}</li>
                ))}
              </ul>
            ) : (
              <div className="results-empty">No recommendations were returned by the backend.</div>
            )}
          </div>
        </div>
      </div>
    </PageContainer>
  );
}
