function saveToken(token) {
  localStorage.setItem(CONFIG.TOKEN_KEY, token);
}

function getToken() {
  return localStorage.getItem(CONFIG.TOKEN_KEY);
}

function removeToken() {
  localStorage.removeItem(CONFIG.TOKEN_KEY);
}

function saveUserData(userData) {
  localStorage.setItem(CONFIG.USER_KEY, JSON.stringify(userData));
}

function getUserData() {
  const data = localStorage.getItem(CONFIG.USER_KEY);
  return data ? JSON.parse(data) : null;
}

function saveUserRole(role) {
  localStorage.setItem(CONFIG.ROLE_KEY, role);
}

function getUserRole() {
  return localStorage.getItem(CONFIG.ROLE_KEY);
}

function clearAuthData() {
  removeToken();
  localStorage.removeItem(CONFIG.USER_KEY);
  localStorage.removeItem(CONFIG.ROLE_KEY);
}

// ========================================
// API HELPERS
// ========================================

async function apiRequest(endpoint, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...options.headers,
  };

  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  try {
    const response = await fetch(`${CONFIG.API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    const data = await response.json();

    if (!response.ok) {
      // Handle 401 Unauthorized
      if (response.status === 401) {
        clearAuthData();
        window.location.href = "admin_login.html";
        return;
      }
      throw new Error(data.message || "Request failed");
    }

    return data;
  } catch (error) {
    console.error("API Request Error:", error);
    throw error;
  }
}

// ========================================
// AUTH HELPERS
// ========================================

function checkAuth(requiredRole = null) {
  const token = getToken();
  const role = getUserRole();

  if (!token) {
    if (requiredRole === "admin") {
      window.location.href = "admin_login.html";
    } else {
      window.location.href = "login.html";
    }
    return false;
  }

  if (requiredRole && role !== requiredRole) {
    alert("Akses ditolak!");
    logout();
    return false;
  }

  return true;
}

function logout() {
  const role = getUserRole();
  clearAuthData();

  if (role === "admin") {
    window.location.href = "admin_login.html";
  } else {
    window.location.href = "login.html";
  }
}

// ========================================
// UI HELPERS
// ========================================

function showAlert(message, type = "info") {
  Swal.fire({
    icon: type,
    title:
      type === "error" ? "Error!" : type === "success" ? "Berhasil!" : "Info",
    text: message,
    confirmButtonColor: "#007bff",
  });
}

function showLoading(message = "Loading...") {
  Swal.fire({
    title: message,
    allowOutsideClick: false,
    allowEscapeKey: false,
    didOpen: () => {
      Swal.showLoading();
    },
  });
}

function hideLoading() {
  Swal.close();
}

function formatDate(dateString) {
  if (!dateString) return "-";
  const date = new Date(dateString);
  return date.toLocaleString("id-ID", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatDateShort(dateString) {
  if (!dateString) return "-";
  const date = new Date(dateString);
  return date.toLocaleString("id-ID", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getRiskBadgeClass(risiko) {
  const classes = {
    rendah: "bg-success",
    sedang: "bg-warning text-dark",
    tinggi: "bg-orange text-white",
    kritis: "bg-danger",
  };
  return classes[risiko] || "bg-secondary";
}

function getStatusBadgeClass(status) {
  const classes = {};
  return classes[status] || "bg-secondary";
}

// ========================================
// VALIDATION HELPERS
// ========================================

function validateNIM(nim) {
  if (!nim || nim.trim() === "") {
    return { valid: false, message: "NIM tidak boleh kosong" };
  }
  if (nim.length < 8 || nim.length > 15) {
    return { valid: false, message: "NIM harus 8-15 karakter" };
  }
  return { valid: true };
}

function validatePassword(password) {
  if (!password || password.trim() === "") {
    return { valid: false, message: "Password tidak boleh kosong" };
  }
  if (password.length < 8) {
    return { valid: false, message: "Password minimal 8 karakter" };
  }
  return { valid: true };
}

function validateEmail(email) {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || email.trim() === "") {
    return { valid: false, message: "Email tidak boleh kosong" };
  }
  if (!regex.test(email)) {
    return { valid: false, message: "Format email tidak valid" };
  }
  return { valid: true };
}
