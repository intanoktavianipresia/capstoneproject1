const API_BASE_URL = "http://127.0.0.1:5000/api";
const LOGIN_ENDPOINT = `${API_BASE_URL}/auth/login`;

const loginForm = document.getElementById("loginForm");
const nimInput = document.getElementById("nimInput");
const passwordInput = document.getElementById("passwordInput");
const togglePassword = document.getElementById("togglePassword");
const loginButton = document.getElementById("loginButton");
const loginText = document.getElementById("loginText");
const loginSpinner = document.getElementById("loginSpinner");
const errorMessage = document.getElementById("errorMessage");

// Modal references
const warningActivityModal = new bootstrap.Modal(
  document.getElementById("warningActivityModal")
);
const blockedModal = new bootstrap.Modal(
  document.getElementById("blockedModal")
);
const delayedModal = new bootstrap.Modal(
  document.getElementById("delayedModal")
);

const proceedWarningButton = document.getElementById("proceedWarningButton");
const delayedCountdown = document.getElementById("delayedCountdown");
const delayedMessage = document.getElementById("delayedMessage");

// Toggle password visibility (tetap sama)
togglePassword.addEventListener("click", function () {
  const type = passwordInput.type === "password" ? "text" : "password";
  passwordInput.type = type;
  this.classList.toggle("bi-eye");
  this.classList.toggle("bi-eye-slash");
});

/* -------------------------------
   UI HELPERS
--------------------------------*/
function showError(message) {
  errorMessage.textContent = message;
  errorMessage.style.display = "block";
  setTimeout(() => (errorMessage.style.display = "none"), 5000);
}

function setLoading(state) {
  loginButton.disabled = state;
  loginText.style.display = state ? "none" : "inline";
  loginSpinner.style.display = state ? "inline-block" : "none";
}

function saveToken(token, userData) {
  localStorage.setItem("token", token);
  localStorage.setItem("user", JSON.stringify(userData));
  localStorage.setItem("role", "mahasiswa");
}

/* -------------------------------
   LOGIN FUNCTION
--------------------------------*/
async function login(nim, password) {
  try {
    const headers = {
      "Content-Type": "application/json",
    };

    const res = await fetch(LOGIN_ENDPOINT, {
      method: "POST",
      headers: headers,
      body: JSON.stringify({ nim, password }),
    });

    const data = await res.json();
    console.log("Login Response:", data);

    if (!res.ok) {
      handleLoginError(data, res.status);
      return;
    }

    handleLoginSuccess(data);
  } catch (err) {
    console.error(err);
    showError("Tidak dapat menghubungi server!");
  }
}

/* -------------------------------
   HANDLE SUCCESS LOGIN (200 OK)
--------------------------------*/
function handleLoginSuccess(data) {
  const status = data.status;
  const userData = data.data;
  const token = data.token;
  const message = data.message;

  // RISIKO RENDAH → Langsung masuk dashboard
  if (status === "success") {
    saveToken(token, userData);
    Swal.fire({
      icon: "success",
      title: "Login Berhasil!",
      text: "Selamat datang di Portal Akademik",
      timer: 1500,
      showConfirmButton: false,
    }).then(() => {
      window.location.href = "dashboard_mahasiswa.html";
    });
  }

  // RISIKO SEDANG → Peringatan (tapi boleh login)
  else if (status === "success_with_warning") {
    warningActivityModal.show();

    const modalMessageElement = document
      .getElementById("warningActivityModal")
      .querySelector(".text-muted");
    if (modalMessageElement) {
      modalMessageElement.innerHTML = message;
    }

    proceedWarningButton.onclick = () => {
      saveToken(token, userData);
      warningActivityModal.hide();
      window.location.href = "dashboard_mahasiswa.html";
    };
  }
}

/* -------------------------------
   HANDLE ERROR LOGIN (401, 403, 429)
--------------------------------*/
function handleLoginError(data, statusCode) {
  const message = data.message || "Terjadi kesalahan";
  const status = data.status;

  // Status 401: Password/NIM salah
  if (statusCode === 401) {
    showError(message);
  }

  // Status 429: DELAYED LOGIN (ML TINGGI atau BRUTE FORCE TUNDA)
  else if (statusCode === 429) {
    // Logika Brute Force TUNDA atau ML TUNDA
    const userData = data.data;
    const idDelayed = userData?.id_delayed;
    const delaySeconds = userData?.delay_seconds || 60;

    // Set message
    if (delayedMessage) {
      delayedMessage.textContent = message;
    }

    delayedModal.show();
    startDelayedLoginCountdown(idDelayed, delaySeconds);
  }

  // Status 403: BLOCKED (ML KRITIS atau BRUTE FORCE BLOKIR)
  else if (statusCode === 403) {
    if (status === "blocked") {
      blockedModal.show();
    } else {
      showError(message);
    }
  }

  // Error lainnya (misal 500)
  else {
    showError(message);
  }
}

/* -------------------------------
   DELAYED LOGIN COUNTDOWN
--------------------------------*/
let countdownInterval = null;

function startDelayedLoginCountdown(idDelayed, totalSeconds) {
  let remaining = totalSeconds;

  if (countdownInterval) {
    clearInterval(countdownInterval);
  }

  // Pastikan totalSeconds valid
  if (remaining <= 0) {
    // Jika sisa waktu 0 atau kurang, langsung coba verifikasi
    checkDelayedLoginStatus(idDelayed);
    return;
  }

  // Update countdown setiap detik
  countdownInterval = setInterval(async () => {
    remaining--;

    // Update UI
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    delayedCountdown.textContent = `${minutes}:${seconds
      .toString()
      .padStart(2, "0")}`;

    // Jika countdown selesai
    if (remaining <= 0) {
      clearInterval(countdownInterval);
      delayedCountdown.textContent = "Memverifikasi...";

      // Check status dari backend jika kita punya ID delayed
      if (idDelayed) {
        await checkDelayedLoginStatus(idDelayed);
      } else {
        // Jika Brute Force (tanpa ID), kita tidak bisa check-delay.
        // Kita sembunyikan modal dan minta user coba login lagi.
        delayedModal.hide();
        Swal.fire({
          icon: "info",
          title: "Waktu Tunda Selesai",
          text: "Silakan coba login kembali untuk melanjutkan.",
          confirmButtonText: "OK",
        }).then(() => {
          // Force refresh page atau kembali ke form
          window.location.reload();
        });
      }
    }
  }, 1000);
}

async function checkDelayedLoginStatus(idDelayed) {
  // Dipanggil oleh timer jika delayed login punya ID dari ML
  try {
    const res = await fetch(
      `${API_BASE_URL}/auth/login/check-delay/${idDelayed}`,
      {
        method: "GET",
        headers: { "Content-Type": "application/json" },
      }
    );

    const data = await res.json();

    if (data.status === "completed" && data.token) {
      saveToken(data.token, data.data);
      delayedModal.hide();
      Swal.fire({
        icon: "success",
        title: "Waktu Tunda Selesai!",
        text: "Anda sekarang dapat masuk ke sistem",
        timer: 1500,
        showConfirmButton: false,
      }).then(() => {
        window.location.href = "dashboard_mahasiswa.html";
      });
    } else if (data.status === "waiting") {
      // Masih dalam periode tunda - restart timer
      const remaining = data.data.remaining_seconds;
      startDelayedLoginCountdown(idDelayed, remaining);
    } else {
      // Error atau cancelled
      delayedModal.hide();
      showError(data.message || "Login gagal. Silakan coba lagi.");
    }
  } catch (err) {
    console.error("Error checking delay status:", err);
    delayedModal.hide();
    showError("Tidak dapat memverifikasi status login. Silakan coba lagi.");
  }
}

/* -------------------------------
   FORM SUBMIT
--------------------------------*/
loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();

  const nim = nimInput.value.trim();
  const password = passwordInput.value;

  if (!nim || !password) {
    showError("NIM dan password wajib diisi");
    return;
  }

  setLoading(true);
  await login(nim, password);
  setLoading(false);
});

/* -------------------------------
   AUTO-REDIRECT JIKA SUDAH LOGIN
--------------------------------*/
window.addEventListener("DOMContentLoaded", () => {
  const token = localStorage.getItem("token");
  const role = localStorage.getItem("role");

  if (token && role === "mahasiswa") {
    window.location.href = "dashboard_mahasiswa.html";
  }
});
