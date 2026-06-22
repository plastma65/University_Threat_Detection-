(function () {
  const ACCESS_TOKEN_KEY = "utd_rc1_access_token";
  const REFRESH_TOKEN_KEY = "utd_rc1_refresh_token";
  const LOGIN_PATH = "/dashboard/login.html";
  const DASHBOARD_PATH = "/dashboard/index.html";
  const ADMIN_PATH = "/dashboard/admin.html";

  function getToken() {
    return window.localStorage.getItem(ACCESS_TOKEN_KEY);
  }

  function setToken(token, refreshToken) {
    // This dashboard stores JWT in localStorage for simplicity.
    // Production should use a safer session strategy such as HttpOnly Secure cookies.
    window.localStorage.setItem(ACCESS_TOKEN_KEY, token);
    if (refreshToken) {
      window.localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    } else {
      window.localStorage.removeItem(REFRESH_TOKEN_KEY);
    }
  }

  function clearToken() {
    window.localStorage.removeItem(ACCESS_TOKEN_KEY);
    window.localStorage.removeItem(REFRESH_TOKEN_KEY);
  }

  function redirectToLogin() {
    if (window.location.pathname !== LOGIN_PATH) {
      window.location.replace(LOGIN_PATH);
    }
  }

  function buildHeaders(optionsHeaders) {
    const headers = new Headers(optionsHeaders || {});
    if (!headers.has("Accept")) {
      headers.set("Accept", "application/json");
    }
    return headers;
  }

  function buildQuery(params) {
    const query = new URLSearchParams();
    Object.keys(params || {}).forEach(function (key) {
      const value = params[key];
      if (value === undefined || value === null || value === "") {
        return;
      }
      query.set(key, String(value));
    });
    const queryString = query.toString();
    return queryString ? "?" + queryString : "";
  }

  function createHttpError(status, message) {
    const error = new Error(message);
    error.status = status;
    return error;
  }

  async function parseError(response) {
    const contentType = response.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
      const payload = await response.json();
      if (typeof payload.detail === "string") {
        return payload.detail;
      }
      return "Request failed.";
    }

    const text = await response.text();
    return text || "Request failed.";
  }

  async function authFetch(path, options, config) {
    const requestOptions = options || {};
    const fetchConfig = config || {};
    const headers = buildHeaders(requestOptions.headers);

    if (fetchConfig.auth !== false) {
      const token = getToken();
      if (!token) {
        redirectToLogin();
        throw new Error("Authentication required.");
      }
      headers.set("Authorization", "Bearer " + token);
    }

    if (requestOptions.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    const response = await window.fetch(path, {
      ...requestOptions,
      headers,
    });

    if (response.status === 401 && fetchConfig.auth !== false) {
      clearToken();
      redirectToLogin();
      throw new Error("Session expired. Please sign in again.");
    }

    if (!response.ok) {
      throw createHttpError(response.status, await parseError(response));
    }

    if (response.status === 204) {
      return null;
    }

    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return response.json();
    }

    return response.text();
  }

  function login(username, password) {
    return authFetch(
      "/api/auth/login",
      {
        method: "POST",
        body: JSON.stringify({ username, password }),
      },
      { auth: false }
    );
  }

  function fetchHealth() {
    return authFetch("/health", {}, { auth: false });
  }

  function fetchMe() {
    return authFetch("/api/auth/me");
  }

  function fetchOverview(hours) {
    return authFetch("/api/stats/overview" + buildQuery({ hours }));
  }

  function fetchTimeline(hours, bucket) {
    return authFetch("/api/stats/timeline" + buildQuery({
      bucket: bucket || "hour",
      hours,
    }));
  }

  function fetchEventTypes(hours) {
    return authFetch("/api/stats/event-types" + buildQuery({ hours }));
  }

  function fetchAlerts(options) {
    if (typeof options === "number") {
      return authFetch("/api/alerts" + buildQuery({ limit: options }));
    }

    const payload = options || {};
    return authFetch("/api/alerts" + buildQuery({
      limit: payload.limit || 100,
      hours: payload.hours,
      severity: payload.severity,
    }));
  }

  function fetchTopIps(limit, hours) {
    return authFetch("/api/stats/top-ips" + buildQuery({
      limit: limit || 10,
      hours,
    }));
  }

  function fetchSeverityDistribution(hours) {
    return authFetch("/api/stats/severity-distribution" + buildQuery({ hours }));
  }

  function patchAlertTriage(alertId, payload) {
    return authFetch("/api/alerts/" + encodeURIComponent(alertId) + "/triage", {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  }

  function fetchUsers() {
    return authFetch("/api/admin/users");
  }

  function fetchDashboardSettings() {
    return authFetch("/api/settings/dashboard");
  }

  function fetchAdminDashboardSettings() {
    return authFetch("/api/admin/dashboard-settings");
  }

  function updateAdminDashboardSettings(payload) {
    return authFetch("/api/admin/dashboard-settings", {
      method: "PUT",
      body: JSON.stringify(payload),
    });
  }

  function createUser(payload) {
    return authFetch("/api/admin/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  function updateUserRole(userId, role) {
    return authFetch("/api/admin/users/" + encodeURIComponent(userId) + "/role", {
      method: "PATCH",
      body: JSON.stringify({ role }),
    });
  }

  function updateUserPassword(userId, password) {
    return authFetch("/api/admin/users/" + encodeURIComponent(userId) + "/password", {
      method: "PATCH",
      body: JSON.stringify({ password }),
    });
  }

  function deleteUser(userId) {
    return authFetch("/api/admin/users/" + encodeURIComponent(userId), {
      method: "DELETE",
    });
  }

  function fetchAuditLogs(limit) {
    return authFetch("/api/admin/audit-logs" + buildQuery({ limit: limit || 100 }));
  }

  window.ApiClient = {
    ADMIN_PATH,
    DASHBOARD_PATH,
    LOGIN_PATH,
    authFetch,
    clearToken,
    createUser,
    deleteUser,
    fetchAlerts,
    fetchAdminDashboardSettings,
    fetchAuditLogs,
    fetchDashboardSettings,
    fetchEventTypes,
    fetchHealth,
    fetchMe,
    fetchOverview,
    fetchSeverityDistribution,
    fetchTimeline,
    fetchTopIps,
    fetchUsers,
    getToken,
    login,
    patchAlertTriage,
    setToken,
    updateAdminDashboardSettings,
    updateUserPassword,
    updateUserRole,
  };
}());
