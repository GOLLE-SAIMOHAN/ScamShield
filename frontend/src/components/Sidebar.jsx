import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../hooks/useAuth.js";

const navItems = [
  { to: "/dashboard", icon: "bi-speedometer2", label: "Dashboard" },
  { to: "/scan", icon: "bi-shield-check", label: "New Scan" },
  { to: "/threat-intelligence", icon: "bi-bug", label: "Threat Intel" },
  { to: "/history", icon: "bi-clock-history", label: "Scan History" },
  { to: "/analytics", icon: "bi-graph-up-arrow", label: "Analytics" },
  { to: "/profile", icon: "bi-person", label: "Profile" },
  { to: "/settings", icon: "bi-gear", label: "Settings" },
];

export default function Sidebar({ isOpen, onClose }) {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    if (onClose) onClose();
    await logout();
    navigate("/login", { replace: true });
  };

  const handleLinkClick = () => {
    if (onClose) onClose();
  };

  return (
    <>
      {/* Backdrop overlay for mobile */}
      {isOpen ? (
        <div
          className="position-fixed d-md-none bg-black bg-opacity-50 z-2"
          onClick={onClose}
          style={{ backdropFilter: "blur(4px)", inset: 0 }}
        />
      ) : null}

      <aside className={`sidebar d-flex flex-column bg-dark bg-opacity-95 border-end border-secondary border-opacity-25 backdrop-blur z-3 ${isOpen ? 'is-open' : ''}`}>
        <div className="brand-block d-flex align-items-center justify-content-between p-4 border-bottom border-secondary border-opacity-15">
          <div className="d-flex align-items-center gap-2">
            <span className="brand-mark bg-info text-dark fw-extrabold d-flex align-items-center justify-content-center rounded-3 fs-5" style={{ width: "38px", height: "38px" }}>S</span>
            <div>
              <strong className="text-light d-block h6 mb-0">ScamShield</strong>
              <small className="text-muted small">Threat Defense</small>
            </div>
          </div>
          <button
            className="btn btn-link text-muted p-0 d-md-none border-0"
            type="button"
            onClick={onClose}
            aria-label="Close Sidebar"
          >
            <i className="bi bi-x fs-2" />
          </button>
        </div>

        <nav className="nav flex-column gap-2 p-3 flex-grow-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `nav-link d-flex align-items-center gap-3 px-3 py-2.5 rounded-3 text-decoration-none transition-all ${
                  isActive
                    ? "bg-info bg-opacity-15 text-info border border-info border-opacity-25 fw-semibold"
                    : "text-muted hover-bg-dark hover-text-light"
                }`
              }
              onClick={handleLinkClick}
            >
              <i className={`bi ${item.icon} fs-5`} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="p-3 border-top border-secondary border-opacity-15">
          <div className="d-flex align-items-center justify-content-between p-2.5 rounded-3 bg-dark bg-opacity-60 border border-info border-opacity-20">
            <div className="d-flex align-items-center gap-2">
              <span className="spinner-grow spinner-grow-sm text-info" role="status" aria-hidden="true" />
              <small className="text-light fw-bold fs-8 text-uppercase tracking-wider">Engine Active</small>
            </div>
            <span className="badge bg-info bg-opacity-20 text-info border border-info border-opacity-30 rounded-pill px-2 py-0.5 fs-9">
              v2.5 AI
            </span>
          </div>
        </div>
      </aside>
    </>
  );
}
