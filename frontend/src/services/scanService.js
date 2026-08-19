import { apiRequest } from "./apiClient.js";

export function scanUrl(url) {
  return apiRequest("/api/check-url", {
    method: "POST",
    body: { url },
    auth: false,
  });
}

export function scanUrlAuthenticated(url) {
  return apiRequest("/api/scan/url", {
    method: "POST",
    body: { url },
  });
}

export function getScanHistory({ page = 1, perPage = 10, search = "", classification = "" } = {}) {
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
  });

  if (search.trim()) {
    params.set("search", search.trim());
  }

  if (classification) {
    params.set("classification", classification);
  }

  return apiRequest(`/api/scans/history?${params.toString()}`, { auth: false });
}

// Local anonymous history fallback for unauthenticated users.
const LOCAL_HISTORY_KEY = "scamshield_local_history";

export function addLocalHistory(entry) {
  try {
    const items = JSON.parse(localStorage.getItem(LOCAL_HISTORY_KEY) || "[]");
    items.unshift(entry);
    // Keep recent 200 entries to avoid unbounded growth
    localStorage.setItem(LOCAL_HISTORY_KEY, JSON.stringify(items.slice(0, 200)));
  } catch (e) {
    // Ignore storage errors
  }
}

export function getLocalHistory({ page = 1, perPage = 10 } = {}) {
  try {
    const items = JSON.parse(localStorage.getItem(LOCAL_HISTORY_KEY) || "[]");
    const start = (page - 1) * perPage;
    return {
      items: items.slice(start, start + perPage),
      pagination: {
        page,
        per_page: perPage,
        total: items.length,
        total_pages: Math.max(1, Math.ceil(items.length / perPage)),
        has_next: start + perPage < items.length,
        has_prev: page > 1,
      },
    };
  } catch (e) {
    return { items: [], pagination: { page: 1, per_page: perPage, total: 0, total_pages: 0, has_next: false, has_prev: false } };
  }
}

export function deleteLocalHistory(scanId) {
  try {
    const items = JSON.parse(localStorage.getItem(LOCAL_HISTORY_KEY) || "[]");
    localStorage.setItem(
      LOCAL_HISTORY_KEY,
      JSON.stringify(items.filter((item) => item.scan_id !== scanId)),
    );
  } catch (e) {
    // Ignore storage errors
  }
}

export function deleteScan(scanId) {
  return apiRequest(`/api/scans/${encodeURIComponent(scanId)}`, {
    method: "DELETE",
  });
}

export function analyzeContent(content, contentType = "text") {
  return apiRequest("/api/analyze", {
    method: "POST",
    body: { content, content_type: contentType },
    auth: false,
  });
}

export function analyzeFile(file, contentType = "file", transcript = "") {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("content_type", contentType);
  formData.append("transcript", transcript);

  return apiRequest("/api/analyze-file", {
    method: "POST",
    body: formData,
    auth: false,
    isFormData: true,
  });
}

export function analyzeMedia(file, metadata = {}) {
  const formData = new FormData();
  formData.append("file", file);
  Object.entries(metadata).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      formData.append(key, value);
    }
  });

  return apiRequest("/api/analyze-media", {
    method: "POST",
    body: formData,
    auth: false,
    isFormData: true,
  });
}
