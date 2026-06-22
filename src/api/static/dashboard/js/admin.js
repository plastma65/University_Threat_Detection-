document.addEventListener("DOMContentLoaded", function () {
  if (!window.ApiClient.getToken()) {
    window.location.replace(window.ApiClient.LOGIN_PATH);
    return;
  }

  const logoutButton = document.getElementById("admin-logout-button");
  const currentUserNode = document.getElementById("admin-current-user");
  const feedbackNode = document.getElementById("admin-feedback");
  const createUserForm = document.getElementById("create-user-form");
  const createUserButton = document.getElementById("create-user-button");
  const newUsername = document.getElementById("new-username");
  const newPassword = document.getElementById("new-password");
  const newRole = document.getElementById("new-role");
  const dashboardSettingsForm = document.getElementById("dashboard-settings-form");
  const dashboardSettingsButton = document.getElementById("dashboard-settings-button");
  const dashboardPollInterval = document.getElementById("dashboard-poll-interval");
  const dashboardDefaultTimeRange = document.getElementById("dashboard-default-time-range");
  const usersTableBody = document.getElementById("users-table-body");
  const auditTableBody = document.getElementById("audit-table-body");
  const state = {
    currentUser: null,
  };

  function showFeedback(message, type) {
    feedbackNode.textContent = message;
    feedbackNode.className = "status-banner mb-4";
    feedbackNode.classList.add(type === "error" ? "status-banner-error" : "status-banner-info");
    feedbackNode.classList.remove("d-none");
  }

  function replaceTableMessage(container, colspan, message) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = colspan;
    cell.className = "text-secondary";
    cell.textContent = message;
    row.appendChild(cell);
    container.replaceChildren(row);
  }

  function logout() {
    window.ApiClient.clearToken();
    window.location.replace(window.ApiClient.LOGIN_PATH);
  }

  function renderUsers(users) {
    if (!Array.isArray(users) || users.length === 0) {
      replaceTableMessage(usersTableBody, 5, "No users found.");
      return;
    }

    const fragment = document.createDocumentFragment();
    users.forEach(function (user) {
      const row = document.createElement("tr");

      const usernameCell = document.createElement("td");
      usernameCell.textContent = user.username;

      const roleCell = document.createElement("td");
      roleCell.textContent = user.role;

      const roleActionCell = document.createElement("td");
      const roleWrapper = document.createElement("div");
      roleWrapper.className = "d-flex gap-2";
      const roleSelect = document.createElement("select");
      roleSelect.className = "form-select form-select-sm";
      ["viewer", "analyst", "admin"].forEach(function (role) {
        const option = document.createElement("option");
        option.value = role;
        option.textContent = role;
        option.selected = user.role === role;
        roleSelect.appendChild(option);
      });
      const roleButton = document.createElement("button");
      roleButton.type = "button";
      roleButton.className = "btn btn-sm btn-outline-info";
      roleButton.textContent = "Save";
      roleButton.addEventListener("click", async function () {
        roleButton.disabled = true;
        try {
          await window.ApiClient.updateUserRole(user.id, roleSelect.value);
          showFeedback("Role updated for " + user.username + ".", "info");
          await loadAdminData();
        } catch (error) {
          showFeedback(error instanceof Error ? error.message : "Role update failed.", "error");
        } finally {
          roleButton.disabled = false;
        }
      });
      roleWrapper.append(roleSelect, roleButton);
      roleActionCell.appendChild(roleWrapper);

      const passwordCell = document.createElement("td");
      const passwordWrapper = document.createElement("div");
      passwordWrapper.className = "d-flex gap-2";
      const passwordInput = document.createElement("input");
      passwordInput.type = "password";
      passwordInput.className = "form-control form-control-sm";
      passwordInput.placeholder = "New password";
      passwordInput.minLength = 8;
      const passwordButton = document.createElement("button");
      passwordButton.type = "button";
      passwordButton.className = "btn btn-sm btn-outline-warning";
      passwordButton.textContent = "Reset";
      passwordButton.addEventListener("click", async function () {
        const password = passwordInput.value;
        if (!password || password.length < 8) {
          showFeedback("Password must be at least 8 characters.", "error");
          return;
        }

        passwordButton.disabled = true;
        try {
          await window.ApiClient.updateUserPassword(user.id, password);
          passwordInput.value = "";
          showFeedback("Password reset for " + user.username + ".", "info");
          await loadAdminData();
        } catch (error) {
          showFeedback(error instanceof Error ? error.message : "Password reset failed.", "error");
        } finally {
          passwordButton.disabled = false;
        }
      });
      passwordWrapper.append(passwordInput, passwordButton);
      passwordCell.appendChild(passwordWrapper);

      const deleteCell = document.createElement("td");
      if (state.currentUser && state.currentUser.username === user.username) {
        deleteCell.textContent = "Current user";
      } else {
        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.className = "btn btn-sm btn-outline-danger";
        deleteButton.textContent = "Delete";
        deleteButton.addEventListener("click", async function () {
          const confirmed = window.confirm("Delete user " + user.username + "?");
          if (!confirmed) {
            return;
          }

          deleteButton.disabled = true;
          try {
            await window.ApiClient.deleteUser(user.id);
            showFeedback("User deleted: " + user.username + ".", "info");
            await loadAdminData();
          } catch (error) {
            showFeedback(error instanceof Error ? error.message : "User deletion failed.", "error");
          } finally {
            deleteButton.disabled = false;
          }
        });
        deleteCell.appendChild(deleteButton);
      }

      row.append(usernameCell, roleCell, roleActionCell, passwordCell, deleteCell);
      fragment.appendChild(row);
    });

    usersTableBody.replaceChildren(fragment);
  }

  function formatDetailValue(value) {
    if (Array.isArray(value)) {
      return value.join(", ");
    }
    if (value && typeof value === "object") {
      return Object.entries(value)
        .map(function (entry) {
          return entry[0] + ": " + String(entry[1]);
        })
        .join(", ");
    }
    return String(value);
  }

  function renderAuditDetails(details) {
    const wrapper = document.createElement("div");
    wrapper.className = "d-flex flex-column gap-1";

    const entries = Object.entries(details || {});
    if (entries.length === 0) {
      wrapper.textContent = "-";
      return wrapper;
    }

    entries.forEach(function (entry) {
      const line = document.createElement("div");
      const key = document.createElement("strong");
      key.textContent = entry[0] + ": ";
      const value = document.createElement("span");
      value.textContent = formatDetailValue(entry[1]);
      line.append(key, value);
      wrapper.append(line);
    });

    return wrapper;
  }

  function renderAuditLogs(logs) {
    if (!Array.isArray(logs) || logs.length === 0) {
      replaceTableMessage(auditTableBody, 5, "No audit logs recorded yet.");
      return;
    }

    const fragment = document.createDocumentFragment();
    logs.forEach(function (entry) {
      const row = document.createElement("tr");
      const timestampCell = document.createElement("td");
      timestampCell.textContent = new Date(entry.timestamp).toLocaleString();
      const actorCell = document.createElement("td");
      actorCell.textContent = entry.actor_username + " (" + entry.actor_role + ")";
      const actionCell = document.createElement("td");
      actionCell.textContent = entry.action;
      const targetCell = document.createElement("td");
      targetCell.textContent = entry.target_type + " #" + entry.target_id;
      const detailsCell = document.createElement("td");
      detailsCell.className = "audit-details-cell";
      detailsCell.appendChild(renderAuditDetails(entry.details || {}));
      row.append(timestampCell, actorCell, actionCell, targetCell, detailsCell);
      fragment.appendChild(row);
    });
    auditTableBody.replaceChildren(fragment);
  }

  function renderDashboardSettings(settings) {
    if (!settings) {
      return;
    }
    dashboardPollInterval.value = String(settings.poll_interval_seconds || 15);
    dashboardDefaultTimeRange.value = String(settings.default_time_range || "24");
  }

  async function loadAdminData() {
    const results = await Promise.all([
      window.ApiClient.fetchUsers(),
      window.ApiClient.fetchAuditLogs(100),
      window.ApiClient.fetchAdminDashboardSettings(),
    ]);
    renderUsers(results[0]);
    renderAuditLogs(results[1]);
    renderDashboardSettings(results[2]);
  }

  async function initializeAdminPage() {
    try {
      const user = await window.ApiClient.fetchMe();
      state.currentUser = user;
      currentUserNode.textContent = user.username + " (" + user.role + ")";
      if (user.role !== "admin") {
        showFeedback("Permission denied. Redirecting to the dashboard.", "error");
        window.setTimeout(function () {
          window.location.replace(window.ApiClient.DASHBOARD_PATH);
        }, 1500);
        return;
      }

      await loadAdminData();
    } catch (error) {
      showFeedback(error instanceof Error ? error.message : "Admin page initialization failed.", "error");
    }
  }

  logoutButton.addEventListener("click", logout);

  createUserForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    createUserButton.disabled = true;
    createUserButton.textContent = "Creating...";
    try {
      await window.ApiClient.createUser({
        username: newUsername.value.trim(),
        password: newPassword.value,
        role: newRole.value,
      });
      newUsername.value = "";
      newPassword.value = "";
      newRole.value = "viewer";
      showFeedback("User created successfully.", "info");
      await loadAdminData();
    } catch (error) {
      showFeedback(error instanceof Error ? error.message : "User creation failed.", "error");
    } finally {
      createUserButton.disabled = false;
      createUserButton.textContent = "Create User";
    }
  });

  dashboardSettingsForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    dashboardSettingsButton.disabled = true;
    dashboardSettingsButton.textContent = "Saving...";
    try {
      const settings = await window.ApiClient.updateAdminDashboardSettings({
        poll_interval_seconds: Number(dashboardPollInterval.value),
        default_time_range: dashboardDefaultTimeRange.value,
      });
      renderDashboardSettings(settings);
      showFeedback("Dashboard settings updated.", "info");
      await loadAdminData();
    } catch (error) {
      showFeedback(error instanceof Error ? error.message : "Dashboard settings update failed.", "error");
    } finally {
      dashboardSettingsButton.disabled = false;
      dashboardSettingsButton.textContent = "Save Dashboard Settings";
    }
  });

  initializeAdminPage();
});
