document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("login-form");
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");
  const submitButton = document.getElementById("login-submit");
  const errorBox = document.getElementById("login-error");

  if (window.ApiClient.getToken()) {
    window.location.replace(window.ApiClient.DASHBOARD_PATH);
    return;
  }

  usernameInput.focus();

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    errorBox.classList.add("d-none");
    errorBox.textContent = "";
    submitButton.disabled = true;
    submitButton.textContent = "Signing in...";

    try {
      const response = await window.ApiClient.login(
        usernameInput.value.trim(),
        passwordInput.value
      );
      window.ApiClient.setToken(response.access_token, response.refresh_token);
      passwordInput.value = "";
      window.location.replace(window.ApiClient.DASHBOARD_PATH);
    } catch (error) {
      errorBox.textContent = error instanceof Error ? error.message : "Login failed.";
      errorBox.classList.remove("d-none");
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = "Access Dashboard";
    }
  });
});
