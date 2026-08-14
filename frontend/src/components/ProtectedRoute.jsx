import { Navigate, Outlet } from "react-router-dom";
import LoadingSpinner from "./LoadingSpinner.jsx";
import { useAuth } from "../hooks/useAuth.js";

export default function ProtectedRoute() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="d-flex align-items-center justify-content-center min-vh-100 bg-dark text-light">
        <LoadingSpinner message="Verifying session..." />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
