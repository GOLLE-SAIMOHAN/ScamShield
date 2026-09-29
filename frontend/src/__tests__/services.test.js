import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  getStoredToken,
  setStoredToken,
  clearStoredToken,
  apiRequest,
} from "../services/apiClient.js";
import {
  addLocalHistory,
  getLocalHistory,
  deleteLocalHistory,
} from "../services/scanService.js";

// Lightweight in-memory localStorage mock for node/vitest environment
const storageStore = new Map();
global.localStorage = {
  getItem: (key) => storageStore.get(key) || null,
  setItem: (key, value) => storageStore.set(key, String(value)),
  removeItem: (key) => storageStore.delete(key),
  clear: () => storageStore.clear(),
};

describe("Frontend Authentication State Handling", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("stores and retrieves access token correctly", () => {
    setStoredToken("test-access-token-123");

    expect(getStoredToken()).toBe("test-access-token-123");
  });

  it("clears stored token on logout", () => {
    setStoredToken("test-access-token-123");

    clearStoredToken();

    expect(getStoredToken()).toBeNull();
  });
});

describe("Frontend API Error Handling & Request Propagation", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("propagates API error responses with status codes", async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      headers: { get: () => "application/json" },
      json: async () => ({ error: "Validation failed", message: "Invalid input" }),
    });

    await expect(apiRequest("/api/check-url", { method: "POST", auth: false })).rejects.toThrow(
      "Validation failed"
    );
  });

  it("attaches Bearer token to authenticated requests", async () => {
    setStoredToken("mock-bearer-token");
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: () => "application/json" },
      json: async () => ({ success: true, data: { user: { id: "1" } } }),
    });

    await apiRequest("/api/auth/me", { auth: true });

    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/auth/me"),
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer mock-bearer-token",
        }),
      })
    );
  });
});

describe("Scan History & Local Storage Handling", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("persists and paginates local scan history entries", () => {
    addLocalHistory({ scan_id: "scan-1", url: "https://example.com" });
    addLocalHistory({ scan_id: "scan-2", url: "https://test.com" });

    const history = getLocalHistory({ page: 1, perPage: 10 });
    expect(history.items.length).toBe(2);
    expect(history.items[0].scan_id).toBe("scan-2");
  });

  it("deletes specified local history entries", () => {
    addLocalHistory({ scan_id: "scan-1", url: "https://example.com" });
    addLocalHistory({ scan_id: "scan-2", url: "https://test.com" });

    deleteLocalHistory("scan-1");

    const history = getLocalHistory({ page: 1, perPage: 10 });
    expect(history.items.length).toBe(1);
    expect(history.items[0].scan_id).toBe("scan-2");
  });
});
