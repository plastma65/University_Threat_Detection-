document.addEventListener("DOMContentLoaded", function () {
  if (!window.ApiClient.getToken()) {
    window.location.replace(window.ApiClient.LOGIN_PATH);
    return;
  }

  const MAX_ALERT_ROWS = 12;
  const TRIAGE_ENABLED_ROLES = ["admin", "analyst"];
  const ROLE_MODE_LABELS = {
    admin: "Admin",
    analyst: "Triage Enabled",
    viewer: "Viewer",
  };

  const state = {
    alerts: [],
    currentAlert: null,
    currentUser: null,
    isRefreshing: false,
    isSavingTriage: false,
    lastSuccessfulUpdate: null,
    lastHealthSuccess: null,
    pollIntervalMs: 15000,
    pollTimerId: null,
    triageStatusSelection: "open",
    filters: {
      aiOnly: false,
      severity: "all",
      eventType: "all",
      search: "",
      sortField: "timestamp",
      sortDirection: "desc",
      timeRange: "24",
      drilldownLabel: "",
    },
  };

  const logoutButton = document.getElementById("logout-button");
  const manualRefreshButton = document.getElementById("manual-refresh-button");
  const timeRangeFilter = document.getElementById("time-range-filter");
  const adminLink = document.getElementById("admin-link");
  const apiStatusBadge = document.getElementById("api-status-badge");
  const lastUpdatedNode = document.getElementById("last-updated");
  const totalAlertsValue = document.getElementById("total-alerts-value");
  const highCriticalValue = document.getElementById("high-critical-value");
  const systemHealthValue = document.getElementById("system-health-value");
  const systemHealthDetail = document.getElementById("system-health-detail");
  const pollingIntervalValue = document.getElementById("polling-interval-value");
  const pollingIntervalDetail = document.getElementById("polling-interval-detail");
  const topIpsBody = document.getElementById("top-ips-body");
  const recentAlertsBody = document.getElementById("recent-alerts-body");
  const severitySummary = document.getElementById("severity-summary");
  const alertsSummary = document.getElementById("alerts-summary");
  const severityFilter = document.getElementById("severity-filter");
  const eventTypeFilter = document.getElementById("event-type-filter");
  const aiFilter = document.getElementById("ai-filter");
  const ipSearch = document.getElementById("ip-search");
  const alertSort = document.getElementById("alert-sort");
  const sortTimestampButton = document.getElementById("sort-timestamp-button");
  const sortRiskButton = document.getElementById("sort-risk-button");
  const currentUsername = document.getElementById("current-username");
  const currentRole = document.getElementById("current-role");
  const currentMode = document.getElementById("current-mode");
  const dashboardFeedback = document.getElementById("dashboard-feedback");
  const activeFilterNotice = document.getElementById("active-filter-notice");
  const exportCsvButton = document.getElementById("export-csv-button");
  const triageControls = document.getElementById("triage-controls");
  const triageNoteInput = document.getElementById("triage-note-input");
  const triageFeedback = document.getElementById("triage-feedback");
  const triageSaveButton = document.getElementById("triage-save-button");
  const triageActionButtons = Array.from(document.querySelectorAll(".triage-action-button"));
  const recentAlertsPanel = document.getElementById("recent-alerts-body").closest("article");
  const alertDetailModalElement = document.getElementById("alert-detail-modal");
  const alertDetailModal = new bootstrap.Modal(alertDetailModalElement);

  const detailFields = {
    assignedTo: document.getElementById("detail-assigned-to"),
    eventType: document.getElementById("detail-event-type"),
    evidence: document.getElementById("detail-evidence"),
    ip: document.getElementById("detail-ip"),
    modelTriggered: document.getElementById("detail-model-triggered"),
    riskScore: document.getElementById("detail-risk-score"),
    severity: document.getElementById("detail-severity"),
    source: document.getElementById("detail-source"),
    status: document.getElementById("detail-status"),
    timestamp: document.getElementById("detail-timestamp"),
    title: document.getElementById("alert-detail-title"),
    triageNote: document.getElementById("detail-triage-note"),
    updatedAt: document.getElementById("detail-updated-at"),
  };

  const panelErrors = {
    eventTypes: document.getElementById("event-types-panel-error"),
    overview: document.getElementById("overview-panel-error"),
    recentAlerts: document.getElementById("recent-alerts-panel-error"),
    severity: document.getElementById("severity-panel-error"),
    timeline: document.getElementById("timeline-panel-error"),
    topIps: document.getElementById("top-ips-panel-error"),
  };

  function userCanTriage() {
    return Boolean(state.currentUser && TRIAGE_ENABLED_ROLES.indexOf(state.currentUser.role) !== -1);
  }

  function userIsAdmin() {
    return Boolean(state.currentUser && state.currentUser.role === "admin");
  }

  function showDashboardFeedback(message, type) {
    dashboardFeedback.textContent = message;
    dashboardFeedback.className = "status-banner mb-4";
    dashboardFeedback.classList.add(type === "error" ? "status-banner-error" : "status-banner-info");
    dashboardFeedback.classList.remove("d-none");
  }

  function clearDashboardFeedback() {
    dashboardFeedback.textContent = "";
    dashboardFeedback.className = "status-banner d-none mb-4";
  }

  function setApiStatus(isLive) {
    apiStatusBadge.textContent = isLive ? "Live" : "Service Offline";
    apiStatusBadge.classList.toggle("soc-badge-live", isLive);
    apiStatusBadge.classList.toggle("soc-badge-offline", !isLive);
  }

  function setLastUpdated(date) {
    lastUpdatedNode.textContent = date ? date.toLocaleString() : "Not refreshed yet";
  }

  function setRefreshState(isRefreshing) {
    state.isRefreshing = isRefreshing;
    manualRefreshButton.disabled = isRefreshing;
    timeRangeFilter.disabled = isRefreshing;
    manualRefreshButton.textContent = isRefreshing ? "Refreshing..." : "Refresh Now";
  }

  function setTriageSaveState(isSaving) {
    state.isSavingTriage = isSaving;
    triageSaveButton.disabled = isSaving;
    triageSaveButton.textContent = isSaving ? "Saving..." : "Save Triage Update";
  }

  function severityClass(severity) {
    const normalized = String(severity || "unknown").toLowerCase();
    if (["critical", "high", "medium", "low"].indexOf(normalized) !== -1) {
      return normalized;
    }
    return "unknown";
  }

  function clearPanelError(panelName) {
    const node = panelErrors[panelName];
    if (!node) {
      return;
    }
    node.textContent = "";
    node.classList.add("d-none");
  }

  function setPanelError(panelName, message) {
    const node = panelErrors[panelName];
    if (!node) {
      return;
    }
    node.textContent = message;
    node.classList.remove("d-none");
  }

  function replaceChildrenWithMessage(container, colspan, message) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = colspan;
    cell.className = "text-secondary";
    cell.textContent = message;
    row.appendChild(cell);
    container.replaceChildren(row);
  }

  function setRoleContext(user) {
    state.currentUser = user;
    currentUsername.textContent = user.username;
    currentRole.textContent = user.role;
    currentMode.textContent = ROLE_MODE_LABELS[user.role] || "Viewer";
    adminLink.classList.toggle("d-none", !userIsAdmin());
  }

  function renderPollingStatus() {
    const pollSeconds = Math.max(1, Math.floor(state.pollIntervalMs / 1000));
    pollingIntervalValue.textContent = String(pollSeconds) + "s";
    pollingIntervalDetail.textContent = "Auto-refresh every " + String(pollSeconds) + " seconds.";
  }

  function applyDashboardSettings(settings) {
    if (!settings) {
      return;
    }
    if (settings.default_time_range) {
      state.filters.timeRange = String(settings.default_time_range);
      timeRangeFilter.value = state.filters.timeRange;
    }
    if (settings.poll_interval_seconds) {
      state.pollIntervalMs = Number(settings.poll_interval_seconds) * 1000;
    }
    renderPollingStatus();
  }

  function startPolling() {
    if (state.pollTimerId) {
      window.clearInterval(state.pollTimerId);
    }
    renderPollingStatus();
    state.pollTimerId = window.setInterval(function () {
      loadDashboardData("poll");
    }, state.pollIntervalMs);
  }

  function renderOverview(data) {
    totalAlertsValue.textContent = String(data.total_alerts || 0);
    highCriticalValue.textContent = String(data.high_severity_alerts || 0);
  }

  function renderHealth(data) {
    const isLive = Boolean(data && data.status === "ok");
    if (isLive) {
      state.lastHealthSuccess = new Date();
    }

    setApiStatus(isLive);
    systemHealthValue.textContent = isLive ? "Healthy" : "Unavailable";
    systemHealthDetail.textContent = isLive
      ? "Last successful check: " + state.lastHealthSuccess.toLocaleString()
      : "Service check failed. Last known dashboard data is still shown.";
  }

  function applyIpDrilldown(ipAddress) {
    state.filters.search = ipAddress;
    state.filters.drilldownLabel = "Filtered by IP " + ipAddress;
    ipSearch.value = ipAddress;
    renderRecentAlerts();
    if (recentAlertsPanel) {
      recentAlertsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function renderTopIps(rows) {
    const points = Array.isArray(rows) ? rows : [];
    if (points.length === 0) {
      replaceChildrenWithMessage(topIpsBody, 3, "No high-risk IPs found.");
      return;
    }

    const fragment = document.createDocumentFragment();
    points.forEach(function (point) {
      const row = document.createElement("tr");
      row.className = "clickable-row";
      row.tabIndex = 0;
      row.addEventListener("click", function () {
        applyIpDrilldown(point.ip_address);
      });
      row.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          applyIpDrilldown(point.ip_address);
        }
      });

      const ipCell = document.createElement("td");
      ipCell.textContent = point.ip_address;
      const riskCell = document.createElement("td");
      riskCell.textContent = String(point.max_risk);
      const countCell = document.createElement("td");
      countCell.textContent = String(point.alert_count);
      row.append(ipCell, riskCell, countCell);
      fragment.appendChild(row);
    });

    topIpsBody.replaceChildren(fragment);
  }

  function applySeverityDrilldown(severity) {
    state.filters.severity = String(severity || "all").toLowerCase();
    state.filters.drilldownLabel = "Filtered by severity " + severity;
    severityFilter.value = state.filters.severity;
    renderRecentAlerts();
    if (recentAlertsPanel) {
      recentAlertsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function renderSeveritySummary(rows) {
    const points = Array.isArray(rows) ? rows : [];
    if (points.length === 0) {
      const message = document.createElement("p");
      message.className = "text-secondary mb-0";
      message.textContent = "No severity data yet.";
      severitySummary.replaceChildren(message);
      return;
    }

    const fragment = document.createDocumentFragment();
    points.forEach(function (point) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "severity-chip";
      chip.addEventListener("click", function () {
        applySeverityDrilldown(point.severity);
      });

      const label = document.createElement("span");
      label.className = "severity-chip-label";
      label.textContent = point.severity;

      const value = document.createElement("span");
      value.className = "severity-chip-value";
      value.textContent = String(point.count);

      chip.append(label, value);
      fragment.appendChild(chip);
    });

    severitySummary.replaceChildren(fragment);
  }

  function createSeverityBadge(severity) {
    const badge = document.createElement("span");
    const normalized = severityClass(severity);
    badge.className = "badge severity-badge severity-" + normalized;
    badge.textContent = String(severity || "unknown");
    return badge;
  }

  function getAlertStatus(alert) {
    return alert.status || "open";
  }

  function getModelTriggered(alert) {
    if (!alert || !alert.evidence || typeof alert.evidence !== "object") {
      return "";
    }
    return alert.evidence.model_triggered ? String(alert.evidence.model_triggered) : "";
  }

  function createAiBadge(alert) {
    const badge = document.createElement("span");
    const modelTriggered = getModelTriggered(alert);
    badge.className = "badge ai-badge " + (modelTriggered ? "ai-badge-active" : "ai-badge-inactive");
    badge.textContent = modelTriggered ? "AI" : "Manual";
    if (modelTriggered) {
      badge.title = "Model triggered: " + modelTriggered;
    }
    return badge;
  }

  function syncEventTypeFilterOptions() {
    const seen = {};
    const eventTypes = [];
    state.alerts.forEach(function (alert) {
      const value = String(alert.event_type || "").trim();
      if (value && !seen[value]) {
        seen[value] = true;
        eventTypes.push(value);
      }
    });
    eventTypes.sort();

    const previousValue = state.filters.eventType;
    const fragment = document.createDocumentFragment();
    const allOption = document.createElement("option");
    allOption.value = "all";
    allOption.textContent = "All event types";
    fragment.appendChild(allOption);

    eventTypes.forEach(function (eventType) {
      const option = document.createElement("option");
      option.value = eventType;
      option.textContent = eventType;
      fragment.appendChild(option);
    });

    eventTypeFilter.replaceChildren(fragment);
    if (previousValue !== "all" && eventTypes.indexOf(previousValue) === -1) {
      state.filters.eventType = "all";
    }
    eventTypeFilter.value = state.filters.eventType;
  }

  function applyAlertFilters() {
    const aiOnly = state.filters.aiOnly;
    const severity = state.filters.severity;
    const eventType = state.filters.eventType;
    const search = state.filters.search.toLowerCase();
    const sortField = state.filters.sortField;
    const sortDirection = state.filters.sortDirection === "asc" ? 1 : -1;

    return state.alerts
      .filter(function (alert) {
        if (severity !== "all" && String(alert.severity || "").toLowerCase() !== severity) {
          return false;
        }

        if (eventType !== "all" && String(alert.event_type || "") !== eventType) {
          return false;
        }

        if (aiOnly && !getModelTriggered(alert)) {
          return false;
        }

        if (search && !String(alert.ip_address || "").toLowerCase().includes(search)) {
          return false;
        }

        return true;
      })
      .slice()
      .sort(function (left, right) {
        if (sortField === "risk_score") {
          return ((left.risk_score ?? 0) - (right.risk_score ?? 0)) * sortDirection;
        }
        return (new Date(left.timestamp).getTime() - new Date(right.timestamp).getTime()) * sortDirection;
      });
  }

  function updateSortControls() {
    alertSort.value = state.filters.sortField + ":" + state.filters.sortDirection;
    sortTimestampButton.textContent = "Timestamp" + (
      state.filters.sortField === "timestamp"
        ? (state.filters.sortDirection === "desc" ? " ↓" : " ↑")
        : ""
    );
    sortRiskButton.textContent = "Risk Score" + (
      state.filters.sortField === "risk_score"
        ? (state.filters.sortDirection === "desc" ? " ↓" : " ↑")
        : ""
    );
  }

  function setActiveFilterNotice() {
    const parts = [];
    if (state.filters.drilldownLabel) {
      parts.push(state.filters.drilldownLabel);
    }
    if (state.filters.eventType !== "all") {
      parts.push("Event type: " + state.filters.eventType);
    }
    if (state.filters.aiOnly) {
      parts.push("AI alerts only");
    }
    if (state.filters.search) {
      parts.push("IP search: " + state.filters.search);
    }
    if (state.filters.severity !== "all") {
      parts.push("Severity: " + state.filters.severity);
    }
    activeFilterNotice.textContent = parts.length ? parts.join(" | ") : "No active filters.";
  }

  function setSelectedTriageStatus(status) {
    state.triageStatusSelection = status;
    triageActionButtons.forEach(function (button) {
      button.classList.toggle("active", button.getAttribute("data-status") === status);
    });
  }

  function renderTriagePanel(alert) {
    triageControls.classList.toggle("d-none", !userCanTriage());
    if (!userCanTriage()) {
      triageFeedback.textContent = "";
      return;
    }
    triageNoteInput.value = alert.triage_note || "";
    setSelectedTriageStatus(getAlertStatus(alert));
    triageFeedback.textContent = "Selected status: " + state.triageStatusSelection;
  }

  function openAlertDetail(alert) {
    state.currentAlert = alert;
    detailFields.title.textContent = "Alert #" + String(alert.id);
    detailFields.timestamp.textContent = new Date(alert.timestamp).toLocaleString();
    detailFields.ip.textContent = alert.ip_address || "-";
    detailFields.source.textContent = alert.source || "-";
    detailFields.eventType.textContent = alert.event_type || "-";
    detailFields.modelTriggered.textContent = getModelTriggered(alert) || "Manual";
    detailFields.riskScore.textContent = String(alert.risk_score ?? 0);
    detailFields.status.textContent = getAlertStatus(alert);
    detailFields.assignedTo.textContent = alert.assigned_to || "-";
    detailFields.updatedAt.textContent = alert.updated_at ? new Date(alert.updated_at).toLocaleString() : "-";
    detailFields.triageNote.textContent = alert.triage_note || "No triage note.";
    detailFields.severity.replaceChildren(createSeverityBadge(alert.severity));

    const evidence = alert.evidence && typeof alert.evidence === "object" ? alert.evidence : {};
    detailFields.evidence.textContent = JSON.stringify(evidence, null, 2);
    renderTriagePanel(alert);
    alertDetailModal.show();
  }

  function renderRecentAlerts() {
    const filteredAlerts = applyAlertFilters();
    alertsSummary.textContent = String(filteredAlerts.length) + " alerts shown";
    updateSortControls();
    setActiveFilterNotice();

    if (filteredAlerts.length === 0) {
      replaceChildrenWithMessage(
        recentAlertsBody,
        8,
        state.alerts.length === 0 ? "No alerts yet." : "No alerts match the current filters."
      );
      return;
    }

    const fragment = document.createDocumentFragment();
    filteredAlerts.slice(0, MAX_ALERT_ROWS).forEach(function (alert) {
      const row = document.createElement("tr");
      row.className = "clickable-row";
      row.tabIndex = 0;
      row.setAttribute("role", "button");
      row.setAttribute("aria-label", "Open alert " + String(alert.id) + " details");
      row.addEventListener("click", function () {
        openAlertDetail(alert);
      });
      row.addEventListener("keydown", function (event) {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openAlertDetail(alert);
        }
      });

      const timestampCell = document.createElement("td");
      timestampCell.textContent = new Date(alert.timestamp).toLocaleString();
      const ipCell = document.createElement("td");
      ipCell.textContent = alert.ip_address || "-";
      const sourceCell = document.createElement("td");
      sourceCell.textContent = alert.source || "-";
      const eventTypeCell = document.createElement("td");
      eventTypeCell.textContent = alert.event_type || "-";
      const aiCell = document.createElement("td");
      aiCell.appendChild(createAiBadge(alert));
      const severityCell = document.createElement("td");
      severityCell.appendChild(createSeverityBadge(alert.severity));
      const riskCell = document.createElement("td");
      riskCell.textContent = String(alert.risk_score ?? 0);
      const statusCell = document.createElement("td");
      statusCell.textContent = getAlertStatus(alert);

      row.append(timestampCell, ipCell, sourceCell, eventTypeCell, aiCell, severityCell, riskCell, statusCell);
      fragment.appendChild(row);
    });

    recentAlertsBody.replaceChildren(fragment);
  }

  function setSort(field) {
    if (state.filters.sortField === field) {
      state.filters.sortDirection = state.filters.sortDirection === "desc" ? "asc" : "desc";
    } else {
      state.filters.sortField = field;
      state.filters.sortDirection = "desc";
    }
    renderRecentAlerts();
  }

  function handleHealthFailure() {
    setApiStatus(false);
    systemHealthValue.textContent = "Offline";
    systemHealthDetail.textContent = state.lastHealthSuccess
      ? "Service offline. Last successful check: " + state.lastHealthSuccess.toLocaleString()
      : "Service offline. Waiting for first successful check.";
  }

  function replaceAlertInState(updatedAlert) {
    state.alerts = state.alerts.map(function (alert) {
      return alert.id === updatedAlert.id ? updatedAlert : alert;
    });
    state.currentAlert = updatedAlert;
  }

  async function saveTriageUpdate() {
    if (!state.currentAlert || !userCanTriage()) {
      return;
    }

    setTriageSaveState(true);
    triageFeedback.textContent = "Saving triage update...";

    try {
      const updatedAlert = await window.ApiClient.patchAlertTriage(state.currentAlert.id, {
        status: state.triageStatusSelection,
        triage_note: triageNoteInput.value.trim(),
      });
      replaceAlertInState(updatedAlert);
      openAlertDetail(updatedAlert);
      renderRecentAlerts();
      triageFeedback.textContent = "Triage update saved.";
      clearDashboardFeedback();
      await loadDashboardData("triage");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unable to save triage update.";
      triageFeedback.textContent = message;
      showDashboardFeedback(message, "error");
    } finally {
      setTriageSaveState(false);
    }
  }

  function getHoursParam() {
    return state.filters.timeRange;
  }

  async function loadDashboardData(reason) {
    const isManual = reason === "manual";
    if (state.isRefreshing) {
      return;
    }

    setRefreshState(true);

    try {
      const hours = getHoursParam();
      const tasks = {
        health: window.ApiClient.fetchHealth(),
        overview: window.ApiClient.fetchOverview(hours),
        timeline: window.ApiClient.fetchTimeline(hours, "hour"),
        eventTypes: window.ApiClient.fetchEventTypes(hours),
        alerts: window.ApiClient.fetchAlerts({ limit: 100, hours }),
        topIps: window.ApiClient.fetchTopIps(10, hours),
        severity: window.ApiClient.fetchSeverityDistribution(hours),
      };

      const entries = Object.entries(tasks);
      const results = await Promise.allSettled(entries.map(function (entry) {
        return entry[1];
      }));

      let hasSuccessfulProtectedPanel = false;
      let healthRendered = false;

      results.forEach(function (result, index) {
        const name = entries[index][0];
        if (result.status === "fulfilled") {
          if (name !== "health") {
            hasSuccessfulProtectedPanel = true;
          }

          switch (name) {
            case "health":
              renderHealth(result.value);
              healthRendered = true;
              break;
            case "overview":
              clearPanelError("overview");
              renderOverview(result.value);
              break;
            case "timeline":
              clearPanelError("timeline");
              window.DashboardCharts.renderTimelineChart(result.value);
              break;
            case "eventTypes":
              clearPanelError("eventTypes");
              window.DashboardCharts.renderEventTypeChart(result.value);
              break;
            case "alerts":
              clearPanelError("recentAlerts");
              state.alerts = Array.isArray(result.value) ? result.value : [];
              syncEventTypeFilterOptions();
              renderRecentAlerts();
              break;
            case "topIps":
              clearPanelError("topIps");
              renderTopIps(result.value);
              break;
            case "severity":
              clearPanelError("severity");
              window.DashboardCharts.renderSeverityChart(result.value);
              renderSeveritySummary(result.value);
              break;
            default:
              break;
          }
        } else {
          const message = result.reason instanceof Error ? result.reason.message : "Request failed.";
          if (name === "health") {
            handleHealthFailure();
            return;
          }

          if (name === "overview") {
            setPanelError("overview", message);
          } else if (name === "timeline") {
            setPanelError("timeline", message);
          } else if (name === "eventTypes") {
            setPanelError("eventTypes", message);
          } else if (name === "alerts") {
            setPanelError("recentAlerts", message);
          } else if (name === "topIps") {
            setPanelError("topIps", message);
          } else if (name === "severity") {
            setPanelError("severity", message);
          }
        }
      });

      if (!healthRendered && hasSuccessfulProtectedPanel) {
        setApiStatus(true);
        systemHealthValue.textContent = "Partial";
        systemHealthDetail.textContent = state.lastHealthSuccess
          ? "Protected API calls succeeded. Last successful health poll: " + state.lastHealthSuccess.toLocaleString()
          : "Protected API calls succeeded, but /health did not return.";
      }

      if (healthRendered || hasSuccessfulProtectedPanel) {
        state.lastSuccessfulUpdate = new Date();
        setLastUpdated(state.lastSuccessfulUpdate);
      }
    } finally {
      setRefreshState(false);
      if (isManual && !state.lastSuccessfulUpdate) {
        setLastUpdated(null);
      }
    }
  }

  function csvEscape(value) {
    const normalized = value === null || value === undefined ? "" : String(value);
    return "\"" + normalized.replace(/"/g, "\"\"") + "\"";
  }

  function exportCurrentAlertsCsv() {
    const filteredAlerts = applyAlertFilters();
    if (filteredAlerts.length === 0) {
      showDashboardFeedback("No alerts available for export.", "error");
      return;
    }

    const lines = [
      [
        "timestamp",
        "ip_address",
        "source",
        "event_type",
        "model_triggered",
        "severity",
        "risk_score",
        "status",
        "assigned_to",
      ].join(","),
    ];

    filteredAlerts.forEach(function (alert) {
      lines.push([
        csvEscape(alert.timestamp),
        csvEscape(alert.ip_address || ""),
        csvEscape(alert.source || ""),
        csvEscape(alert.event_type || ""),
        csvEscape(getModelTriggered(alert)),
        csvEscape(alert.severity || ""),
        csvEscape(alert.risk_score ?? 0),
        csvEscape(getAlertStatus(alert)),
        csvEscape(alert.assigned_to || ""),
      ].join(","));
    });

    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
    const link = document.createElement("a");
    const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "").replace("T", "_");
    link.href = URL.createObjectURL(blob);
    link.download = "soc_alerts_filtered_" + timestamp + ".csv";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
    showDashboardFeedback("Filtered alerts exported to CSV.", "info");
  }

  async function initializeDashboard() {
    try {
      const user = await window.ApiClient.fetchMe();
      setRoleContext(user);
      applyDashboardSettings(await window.ApiClient.fetchDashboardSettings());
      clearDashboardFeedback();
      await loadDashboardData("initial");
      startPolling();
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unable to load dashboard context.";
      showDashboardFeedback(message, "error");
    }
  }

  logoutButton.addEventListener("click", function () {
    window.ApiClient.clearToken();
    window.location.replace(window.ApiClient.LOGIN_PATH);
  });

  manualRefreshButton.addEventListener("click", function () {
    clearDashboardFeedback();
    loadDashboardData("manual");
  });

  timeRangeFilter.addEventListener("change", function () {
    state.filters.timeRange = timeRangeFilter.value;
    clearDashboardFeedback();
    loadDashboardData("time-range");
  });

  severityFilter.addEventListener("change", function () {
    state.filters.severity = severityFilter.value;
    if (severityFilter.value === "all" && state.filters.drilldownLabel.indexOf("severity") !== -1) {
      state.filters.drilldownLabel = "";
    }
    renderRecentAlerts();
  });

  eventTypeFilter.addEventListener("change", function () {
    state.filters.eventType = eventTypeFilter.value;
    renderRecentAlerts();
  });

  aiFilter.addEventListener("change", function () {
    state.filters.aiOnly = aiFilter.value === "ai_only";
    renderRecentAlerts();
  });

  ipSearch.addEventListener("input", function () {
    state.filters.search = ipSearch.value.trim();
    if (!state.filters.search && state.filters.drilldownLabel.indexOf("Filtered by IP") !== -1) {
      state.filters.drilldownLabel = "";
    }
    renderRecentAlerts();
  });

  alertSort.addEventListener("change", function () {
    const parts = alertSort.value.split(":");
    state.filters.sortField = parts[0];
    state.filters.sortDirection = parts[1];
    renderRecentAlerts();
  });

  sortTimestampButton.addEventListener("click", function () {
    setSort("timestamp");
  });

  sortRiskButton.addEventListener("click", function () {
    setSort("risk_score");
  });

  exportCsvButton.addEventListener("click", function () {
    exportCurrentAlertsCsv();
  });

  triageActionButtons.forEach(function (button) {
    button.addEventListener("click", function () {
      setSelectedTriageStatus(button.getAttribute("data-status"));
      triageFeedback.textContent = "Selected status: " + state.triageStatusSelection;
    });
  });

  triageSaveButton.addEventListener("click", function () {
    saveTriageUpdate();
  });

  updateSortControls();
  renderRecentAlerts();
  renderPollingStatus();
  initializeDashboard();
});
