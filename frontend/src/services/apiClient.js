export const TOKEN_STORAGE_KEY = "scamshield_access_token";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

export function getStoredToken() {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setStoredToken(token) {
  if (token) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
  }
}

export function clearStoredToken() {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

async function requestOnce(path, method, body, headers, isFormData, auth) {
  const token = getStoredToken();
  const requestHeaders = {
    ...(!isFormData ? { "Content-Type": "application/json" } : {}),
    ...(auth && token ? { Authorization: `Bearer ${token}` } : {}),
    ...headers,
  };

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers: requestHeaders,
    body: isFormData ? body : body ? JSON.stringify(body) : undefined,
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await response.json()
    : { success: response.ok, message: await response.text() };

  return { response, data };
}

async function tryRefreshAccessToken() {
  const res = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) return false;

  const data = await res.json().catch(() => null);
  const newAccessToken = data?.data?.access_token;
  if (!newAccessToken) return false;

  setStoredToken(newAccessToken);
  return true;
}

export async function apiRequest(path, options = {}) {
  const {
    method = "GET",
    body,
    headers = {},
    auth = true,
    isFormData = false,
  } = options;

  let { response, data } = await requestOnce(
    path,
    method,
    body,
    headers,
    isFormData,
    auth
  );

  // A 401 on an authenticated request might just mean the access token
  // expired. Try once to refresh it transparently before giving up.
  if (!response.ok && response.status === 401 && auth) {
    const refreshed = await tryRefreshAccessToken();
    if (refreshed) {
      ({ response, data } = await requestOnce(
        path,
        method,
        body,
        headers,
        isFormData,
        auth
      ));
    }
  }

  if (!response.ok) {
    const error = new Error(data.error || data.message || "Request failed");
    error.status = response.status;
    error.data = data;
    throw error;
  }

  return data;
}
