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
    <div className="container py-5">
      <div className="row justify-content-center align-items-center g-4 min-vh-75">
        <div className="col-12 col-lg-6">
          <div className="glass-panel p-4 p-md-5">
            <div className="mb-4">
              <span className="badge rounded-pill px-3 py-2 bg-info bg-opacity-10 text-info border border-info border-opacity-25 fw-semibold text-uppercase tracking-wider">Create account</span>
              <h1 className="h2 mt-3 mb-2 text-light">Join the ScamShield analyst workspace</h1>
              <p className="text-secondary mb-0">Register to start running scans, tracking history, and analyzing threat data.</p>
            </div>

            <form onSubmit={handleSubmit} className="row g-3">
              <div className="col-12">
                <label htmlFor="username" className="form-label text-light">Display name</label>
                <input
                  id="username"
                  type="text"
                  className="form-control form-control-lg bg-transparent border-secondary text-light"
                  required
                  value={form.username}
                  onChange={(event) => setForm((current) => ({ ...current, username: event.target.value }))}
                  placeholder="Security Analyst"
                />
              </div>

              <div className="col-12">
                <label htmlFor="email" className="form-label text-light">Email address</label>
                <input
                  id="email"
                  type="email"
                  className="form-control form-control-lg bg-transparent border-secondary text-light"
                  required
                  value={form.email}
                  onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
                  placeholder="analyst@company.com"
                />
              </div>

              <div className="col-12 col-md-6">
                <label htmlFor="password" className="form-label text-light">Password</label>
                <input
                  id="password"
                  type="password"
                  className="form-control form-control-lg bg-transparent border-secondary text-light"
                  required
                  value={form.password}
                  onChange={(event) => setForm((current) => ({ ...current, password: event.target.value }))}
                  placeholder="Min. 8 characters"
                />
              </div>

              <div className="col-12 col-md-6">
                <label htmlFor="confirmPassword" className="form-label text-light">Confirm password</label>
                <input
                  id="confirmPassword"
                  type="password"
                  className="form-control form-control-lg bg-transparent border-secondary text-light"
                  required
                  value={form.confirmPassword}
                  onChange={(event) => setForm((current) => ({ ...current, confirmPassword: event.target.value }))}
                  placeholder="Repeat password"
                />
              </div>

              {error ? (
                <div className="col-12">
                  <div className="alert alert-danger mb-0" role="alert">{error}</div>
                </div>
              ) : null}

              <div className="col-12 d-grid mt-2">
                <button type="submit" className="btn btn-info btn-lg fw-semibold" disabled={isSubmitting}>
                  {isSubmitting ? "Creating account..." : "Create account"}
                </button>
              </div>
            </form>

            <div className="d-flex justify-content-between align-items-center gap-3 mt-4 pt-4 border-top border-secondary border-opacity-25 text-sm text-secondary">
              <span>Already registered?</span>
              <Link to="/login" className="text-info text-decoration-none fw-semibold">Sign in</Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
