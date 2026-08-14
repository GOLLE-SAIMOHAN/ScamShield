import { useState } from "react";
import { Link, NavLink } from "react-router-dom";
import { useTheme } from "../hooks/useTheme.js";

const navItems = [
  { to: "/", label: "Home" },
  { to: "/login", label: "Login" },
  { to: "/register", label: "Register" },
  { to: "/about", label: "About" },
];

export default function PublicNavbar() {
  const [menuOpen, setMenuOpen] = useState(false);
  const { theme, toggleTheme } = useTheme();

  const closeMenu = () => setMenuOpen(false);

  return (
    <header className="public-navbar">
      <nav className="container d-flex align-items-center justify-content-between gap-3">
        <Link to="/" className="public-brand" onClick={closeMenu}>
          <span className="public-brand-mark">
            <i className="bi bi-shield-lock-fill" />
          </span>
          <span>ScamShield</span>
        </Link>

        <button
          className="nav-menu-button d-lg-none"
          type="button"
          onClick={() => setMenuOpen((current) => !current)}
          aria-label={menuOpen ? "Close navigation menu" : "Open navigation menu"}
          aria-expanded={menuOpen}
          aria-controls="public-nav-links"
        >
          <i className={`bi ${menuOpen ? "bi-x-lg" : "bi-list"}`} />
        </button>

        <div id="public-nav-links" className={`public-nav-links ${menuOpen ? "is-open" : ""}`}>
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => `public-nav-link ${isActive ? "active" : ""}`}
              onClick={closeMenu}
            >
              {item.label}
            </NavLink>
          ))}
          <a
            className="public-nav-link"
            href="https://github.com/"
            target="_blank"
            rel="noreferrer"
            onClick={closeMenu}
          >
            <i className="bi bi-github me-1" />
            GitHub
          </a>
          <button className="theme-toggle" type="button" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}>
            <i className={`bi ${theme === "dark" ? "bi-sun" : "bi-moon-stars"}`} />
            <span>{theme === "dark" ? "Light" : "Dark"}</span>
          </button>
        </div>
      </nav>
    </header>
  );
}
