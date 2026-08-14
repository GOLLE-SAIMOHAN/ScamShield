import { useState } from "react";
import { Link, Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth.js";

const initialState = {
  username: "",
  email: "",
  password: "",
  confirmPassword: "",
};

export default function Register() {
  const { isAuthenticated, register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState(initialState);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState("");

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");

    if (form.password !== form.confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (form.password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    setIsSubmitting(true);

    try {
      await register({
        username: form.username.trim(),
        email: form.email.trim(),
        password: form.password,
      });
      navigate("/dashboard", { replace: true });
    } catch (requestError) {
      setError(requestError?.message || "Registration failed. Please try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="container py-5 auth-shell">
      <div className="row justify-content-center align-items-center g-4 min-vh-75">
        <div className="col-12 col-lg-7">
          <div className="glass-panel auth-panel">
            <div className="auth-header">
              <span className="auth-badge">Create account</span>
              <h1>Join the ScamShield analyst workspace</h1>
              <p>Register to start running scans, tracking history, and analyzing threat data.</p>
            </div>

            <form onSubmit={handleSubmit} className="auth-form row g-3">
              <div className="col-12">
                <label htmlFor="username">Display name</label>
                <input
                  id="username"
                  type="text"
                  className="form-control form-control-lg"
                  required
                  value={form.username}
                  onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))}
                  placeholder="Security Analyst"
                />
              </div>

              <div className="col-12">
                <label htmlFor="email">Email address</label>
                <input
                  id="email"
                  type="email"
                  className="form-control form-control-lg"
                  required
                  value={form.email}
                  onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
                  placeholder="analyst@company.com"
                />
              </div>

              <div className="col-12 col-md-6">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  className="form-control form-control-lg"
                  required
                  value={form.password}
                  onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                  placeholder="Min. 8 characters"
                />
              </div>

              <div className="col-12 col-md-6">
                <label htmlFor="confirmPassword">Confirm password</label>
                <input
                  id="confirmPassword"
                  type="password"
                  className="form-control form-control-lg"
                  required
                  value={form.confirmPassword}
                  onChange={(event) => setForm((current) => ({ ...current, confirmPassword: event.target.value }))}
                  placeholder="Repeat password"
                />
              </div>

              {error ? (
                <div className="col-12">
                  <div className="auth-alert" role="alert">{error}</div>
                </div>
              ) : null}

              <div className="col-12 d-grid mt-2">
                <button type="submit" className="btn auth-submit" disabled={isSubmitting}>
                  {isSubmitting ? "Creating account..." : "Create account"}
                </button>
              </div>
            </form>

            <div className="auth-footer">
              <span>Already registered?</span>
              <Link to="/login">Sign in</Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
