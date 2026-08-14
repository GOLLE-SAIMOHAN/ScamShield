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
      <div className="row g-4">
        <div className="col-12 col-xl-4">
          <div className="glass-panel p-4 h-100">
            <div className="d-flex align-items-center justify-content-between mb-3">
              <span className="text-secondary text-uppercase small tracking-wider">Scan ID</span>
              <span className="badge rounded-pill bg-info bg-opacity-10 text-info">{id || "latest"}</span>
            </div>

            <div className="display-4 fw-bold text-light">{Math.round(riskScore)}</div>
            <div className="text-secondary mb-3">Risk score</div>

            <div className="progress" style={{ height: 12, background: "rgba(255,255,255,0.08)" }}>
              <div
                className="progress-bar rounded-pill"
                style={{ width: `${Math.min(riskScore, 100)}%`, background: riskScore >= 70 ? "#ef4444" : riskScore >= 40 ? "#fbbf24" : "#22c55e" }}
              />
            </div>

            <div className="mt-4">
              <div className="small text-secondary">Risk level</div>
              <div className="h5 text-light mt-1">{riskLevel}</div>
            </div>

            <div className="d-grid gap-2 mt-4">
              <button className="btn btn-outline-light" type="button" onClick={() => navigate(-1)}>Back</button>
            </div>
          </div>
        </div>

        <div className="col-12 col-xl-8">
          <div className="glass-panel p-4">
            <div className="d-flex align-items-center justify-content-between mb-4">
              <h3 className="h5 text-light mb-0">Threat classification</h3>
              <span className="badge rounded-pill bg-dark border border-secondary text-light">{result.classification || result.risk_level || "Unknown"}</span>
            </div>

            <div className="row g-3">
              <div className="col-12 col-md-6">
                <div className="border rounded-4 p-3 border-secondary border-opacity-25">
                  <div className="small text-secondary mb-2">Analysis information</div>
                  <ul className="mb-0 ps-3 text-light small">
                    <li>Confidence: {result.confidence ?? "Unknown"}</li>
                    <li>Type: {result.content_type || result.kind || "N/A"}</li>
                    <li>URL: {result.url || result.target || "N/A"}</li>
                  </ul>
                </div>
              </div>

              <div className="col-12 col-md-6">
                <div className="border rounded-4 p-3 border-secondary border-opacity-25">
                  <div className="small text-secondary mb-2">Evidence</div>
                  <pre className="mb-0 text-light small" style={{ whiteSpace: "pre-wrap" }}>
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
          <div className="glass-panel p-4 h-100">
            <h3 className="h5 text-light mb-3">Findings</h3>
            {findings.length > 0 ? (
              <ul className="mb-0 ps-3 text-light">
                {findings.map((finding, index) => (
                  <li key={`${finding}-${index}`} className="mb-2">{String(finding)}</li>
                ))}
              </ul>
            ) : (
              <div className="text-secondary">No findings were returned by the backend.</div>
            )}
          </div>
        </div>

        <div className="col-12 col-lg-6">
          <div className="glass-panel p-4 h-100">
            <h3 className="h5 text-light mb-3">Recommendations</h3>
            {recommendations.length > 0 ? (
              <ul className="mb-0 ps-3 text-light">
                {recommendations.map((item, index) => (
                  <li key={`${item}-${index}`} className="mb-2">{String(item)}</li>
                ))}
              </ul>
            ) : (
              <div className="text-secondary">No recommendations were returned by the backend.</div>
            )}
          </div>
        </div>
      </div>
    </PageContainer>
  );
}
