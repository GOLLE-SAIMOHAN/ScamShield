import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth.js";

export default function Login() {
  const { isAuthenticated, login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "", password: "" });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);

    try {
      await login({
        email: form.email.trim(),
        password: form.password,
      });
      navigate("/dashboard", { replace: true });
    } catch (requestError) {
      setError(requestError?.message || "Login failed. Please check your credentials.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="container py-5">
      <div className="row justify-content-center align-items-center g-4 min-vh-75">
        <div className="col-12 col-lg-6">
          <div className="glass-panel p-4 p-md-5">
            <div className="mb-4">
              <span className="badge rounded-pill px-3 py-2 bg-info bg-opacity-10 text-info border border-info border-opacity-25 fw-semibold text-uppercase tracking-wider">Secure access</span>
              <h1 className="h2 mt-3 mb-2 text-light">Welcome back to ScamShield</h1>
              <p className="text-secondary mb-0">Monitor threats, review scans, and investigate suspicious activity from your security workspace.</p>
            </div>

            <form onSubmit={handleSubmit} className="row g-3">
              <div className="col-12">
                <label htmlFor="email" className="form-label text-light">Email address</label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  className="form-control form-control-lg bg-transparent border-secondary text-light"
                  required
                  value={form.email}
                  onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
                  placeholder="analyst@scamshield.ai"
                />
              </div>

              <div className="col-12">
                <label htmlFor="password" className="form-label text-light">Password</label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  className="form-control form-control-lg bg-transparent border-secondary text-light"
                  required
                  value={form.password}
                  onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                  placeholder="Enter your password"
                />
              </div>

              {error ? (
                <div className="col-12">
                  <div className="alert alert-danger mb-0" role="alert">{error}</div>
                </div>
              ) : null}

              <div className="col-12 d-grid mt-2">
                <button type="submit" className="btn btn-info btn-lg fw-semibold" disabled={isSubmitting}>
                  {isSubmitting ? "Signing in..." : "Sign in"}
                </button>
              </div>
            </form>

            <div className="d-flex flex-column flex-sm-row justify-content-between align-items-center gap-3 mt-4 pt-4 border-top border-secondary border-opacity-25 text-sm text-secondary">
              <span>Need an account?</span>
              <Link to="/register" className="text-info text-decoration-none fw-semibold">Create one</Link>
            </div>
          </div>
        </div>

        <div className="col-12 col-lg-6">
          <div className="glass-panel p-4 p-md-5 h-100">
            <div className="d-flex align-items-center gap-3 mb-4">
              <div className="brand-mark rounded-4 d-flex align-items-center justify-content-center text-dark fw-bold" style={{ width: 52, height: 52 }}>S</div>
              <div>
                <div className="text-uppercase small text-info tracking-wider">ScamShield</div>
                <h2 className="h4 text-light mb-0">Cybersecurity command center</h2>
              </div>
            </div>

            <div className="d-grid gap-3">
              {[
                ["Threat intelligence", "bi-bug", "Monitor suspicious domains and high-risk infrastructure."],
                ["Multi-modal scanning", "bi-shield-check", "Analyze URLs, text, files, and media for scam signals."],
                ["Explainable findings", "bi-file-earmark-text", "Review risk scoring with evidence and practical guidance."],
              ].map(([title, icon, text]) => (
                <div key={title} className="d-flex align-items-start gap-3 p-3 rounded-4 border border-secondary border-opacity-25 bg-dark bg-opacity-25">
                  <div className="rounded-3 bg-info bg-opacity-10 text-info d-flex align-items-center justify-content-center" style={{ width: 42, height: 42 }}>
                    <i className={`bi ${icon}`} />
                  </div>
                  <div>
                    <div className="fw-semibold text-light">{title}</div>
                    <small className="text-secondary">{text}</small>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
