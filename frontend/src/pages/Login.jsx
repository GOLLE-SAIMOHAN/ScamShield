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
    <div className="container py-5 auth-shell">
      <div className="row justify-content-center align-items-center g-4 min-vh-75">
        <div className="col-12 col-lg-6">
          <div className="glass-panel auth-panel">
            <div className="auth-header">
              <span className="auth-badge">Secure access</span>
              <h1>Welcome back to ScamShield</h1>
              <p>Monitor threats, review scans, and investigate suspicious activity from your security workspace.</p>
            </div>

            <form onSubmit={handleSubmit} className="auth-form row g-3">
              <div className="col-12">
                <label htmlFor="email">Email address</label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  className="form-control form-control-lg"
                  required
                  value={form.email}
                  onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
                  placeholder="analyst@scamshield.ai"
                />
              </div>

              <div className="col-12">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  name="password"
                  type="password"
                  className="form-control form-control-lg"
                  required
                  value={form.password}
                  onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                  placeholder="Enter your password"
                />
              </div>

              {error ? (
                <div className="col-12">
                  <div className="auth-alert" role="alert">{error}</div>
                </div>
              ) : null}

              <div className="col-12 d-grid mt-2">
                <button type="submit" className="btn auth-submit" disabled={isSubmitting}>
                  {isSubmitting ? "Signing in..." : "Sign in"}
                </button>
              </div>
            </form>

            <div className="auth-footer">
              <span>Need an account?</span>
              <Link to="/register">Create one</Link>
            </div>
          </div>
        </div>

        <div className="col-12 col-lg-6">
          <div className="glass-panel auth-panel auth-panel-alt">
            <div className="auth-brand-row">
              <div className="brand-mark auth-brand-mark">S</div>
              <div>
                <div className="auth-brand-label">ScamShield</div>
                <h2>Cybersecurity command center</h2>
              </div>
            </div>

            <div className="auth-feature-list">
              {[
                ["Threat intelligence", "bi-bug", "Monitor suspicious domains and high-risk infrastructure."],
                ["Multi-modal scanning", "bi-shield-check", "Analyze URLs, text, files, and media for scam signals."],
                ["Explainable findings", "bi-file-earmark-text", "Review risk scoring with evidence and practical guidance."],
              ].map(([title, icon, text]) => (
                <div key={title} className="auth-feature-item">
                  <div className="auth-feature-icon">
                    <i className={`bi ${icon}`} />
                  </div>
                  <div>
                    <div className="auth-feature-title">{title}</div>
                    <small>{text}</small>
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
