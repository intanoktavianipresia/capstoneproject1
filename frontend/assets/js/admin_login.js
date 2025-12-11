const ADMIN_LOGIN_ENDPOINT = `${CONFIG.API_BASE_URL}/auth-admin/login`;

const adminLoginForm = document.getElementById("adminLoginForm");
const usernameInput = document.getElementById("usernameInput");
const passwordInput = document.getElementById("passwordInput");
const togglePassword = document.getElementById("togglePassword");
const loginButton = document.getElementById("loginButton");
const loginText = document.getElementById("loginText");
const loginSpinner = document.getElementById("loginSpinner");
const errorMessage = document.getElementById("errorMessage");
const alertContainer = document.getElementById("alertContainer");

togglePassword.addEventListener("click", function () {
  const type = passwordInput.type === "password" ? "text" : "password";
  passwordInput.type = type;
  this.classList.toggle("bi-eye");
  this.classList.toggle("bi-eye-slash");
});

function showError(message) {
  errorMessage.textContent = message;
  errorMessage.style.display = "block";
  setTimeout(() => {
    errorMessage.style.display = "none";
  }, 5000);
}

function hideError() {
  errorMessage.style.display = "none";
}

function showAlert(message, type = "danger") {
  alertContainer.innerHTML = `
    <div class="alert alert-${type} alert-dismissible fade show" role="alert">
      <i class="bi bi-${
        type === "danger"
          ? "x-circle"
          : type === "success"
          ? "check-circle"
          : "info-circle"
      }-fill me-2"></i>
      ${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
  `;
  alertContainer.style.display = "block";
}

function setLoading(isLoading) {
  loginButton.disabled = isLoading;
  loginText.style.display = isLoading ? "none" : "inline";
  loginSpinner.style.display = isLoading ? "inline-block" : "none";

  usernameInput.disabled = isLoading;
  passwordInput.disabled = isLoading;
}

async function adminLogin(username, password) {
  try {
    const response = await fetch(ADMIN_LOGIN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json();
    console.log("Login Response:", data);

    if (response.ok && data.status === "success") {
      const { token, data: adminData } = data;

      saveToken(token);
      saveUserData(adminData);
      saveUserRole("admin");

      Swal.fire({
        icon: "success",
        title: "Login Berhasil!",
        text: "Mengalihkan ke dashboard...",
        timer: 1500,
        showConfirmButton: false,
      });

      setTimeout(() => {
        window.location.href = "dashboard_admin.html";
      }, 1500);
    } else {
      // Login gagal
      showError(data.message || "Username atau password salah");

      usernameInput.classList.add("border-danger");
      passwordInput.classList.add("border-danger");

      setTimeout(() => {
        usernameInput.classList.remove("border-danger");
        passwordInput.classList.remove("border-danger");
      }, 3000);
    }
  } catch (error) {
    console.error("Error:", error);
    showError("Gagal terhubung ke server. Pastikan backend sudah running.");
  }
}

adminLoginForm.addEventListener("submit", async function (e) {
  e.preventDefault();

  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    showError("Username dan password harus diisi");
    return;
  }

  if (username.length < 3) {
    showError("Username minimal 3 karakter");
    return;
  }

  if (password.length < 6) {
    showError("Password minimal 6 karakter");
    return;
  }

  hideError();
  setLoading(true);
  await adminLogin(username, password);
  setLoading(false);
});

passwordInput.addEventListener("keypress", function (e) {
  if (e.key === "Enter") {
    adminLoginForm.dispatchEvent(new Event("submit"));
  }
});

window.addEventListener("DOMContentLoaded", function () {
  const token = getToken();
  const role = getUserRole();

  if (token && role === "admin") {
    window.location.href = "dashboard_admin.html";
  }
});
