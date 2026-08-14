import { createContext, useCallback, useEffect, useMemo, useState } from "react";
import {
  clearStoredToken,
  getCurrentUser,
  getStoredToken,
  login as loginRequest,
  logout as logoutRequest,
  register as registerRequest,
} from "../services/authService.js";

export const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshUser = useCallback(async () => {
    const token = getStoredToken();
    if (!token) {
      setUser(null);
      setIsLoading(false);
      return null;
    }

    try {
      const userData = await getCurrentUser();
      setUser(userData || null);
      return userData;
    } catch (error) {
      clearStoredToken();
      setUser(null);
      return null;
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshUser();
  }, [refreshUser]);

  const login = useCallback(async (credentials) => {
    const payload = await loginRequest(credentials);
    setUser(payload?.user || null);
    return payload;
  }, []);

  const register = useCallback(async (formPayload) => {
    const payload = await registerRequest(formPayload);
    setUser(payload?.user || null);
    return payload;
  }, []);

  const logout = useCallback(async () => {
    try {
      await logoutRequest();
    } finally {
      clearStoredToken();
      setUser(null);
    }
  }, []);

  const value = useMemo(
    () => ({
      user,
      isAuthenticated: Boolean(user),
      isLoading,
      login,
      logout,
      refreshUser,
      register,
    }),
    [isLoading, login, logout, refreshUser, register, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
