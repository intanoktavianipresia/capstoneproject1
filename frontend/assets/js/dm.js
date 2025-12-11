const API = "http://127.0.0.1:5000/api";

window.addEventListener("DOMContentLoaded", () => {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "login.html";
    return;
  }
  loadProfile();
  loadMyLoginHistory();
});

// --- LOAD PROFIL ---
async function loadProfile() {
  try {
    const token = localStorage.getItem("token");
    if (!token) {
      window.location.href = "login.html";
      return;
    }

    const res = await fetch(`${API}/auth/profile`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status === 401) {
      localStorage.clear();
      window.location.href = "login.html";
      return;
    }

    const data = await res.json();

    if (data.status === "success") {
      const profile = data.data;

      // Update UI profil
      document.getElementById("userName").innerText = profile.nama;
      document.getElementById("userNim").innerText = profile.nim;

      document.getElementById("p_nim").innerText = profile.nim;
      document.getElementById("p_nama").innerText = profile.nama;
      document.getElementById("p_email").innerText = profile.email;
      document.getElementById("p_status").innerText = profile.status_akun;

      const tanggal = profile.tanggal_daftar
        ? new Date(profile.tanggal_daftar).toLocaleDateString("id-ID")
        : "-";
      document.getElementById("p_tanggal").innerText = tanggal;

      // Tampilkan badge status akun
      const statusBadge = getStatusBadge(profile.status_akun);
      document.getElementById("p_status").innerHTML = statusBadge;

      // Tampilkan warning jika dalam pantauan
      if (profile.dalam_pantauan) {
        showMonitoringWarning(profile.pantauan_mulai);
      }
    }
  } catch (e) {
    console.error("Error load profile:", e);
    alert("Gagal memuat profil. Silakan refresh halaman.");
  }
}

// Load recent login history
async function loadMyLoginHistory() {
  try {
    const token = localStorage.getItem("token");
    if (!token) return;

    const res = await fetch(`${API}/log/my-history?limit=5`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    if (data.status === "success") {
      displayLoginHistory(data.data);
    }
  } catch (e) {
    console.error("Error load history:", e);
  }
}

// Display login history di dashboard
function displayLoginHistory(logs) {
  const container = document.getElementById("recentLoginContainer");
  if (!container) return;

  if (logs.length === 0) {
    container.innerHTML = '<p class="text-muted">Belum ada riwayat login</p>';
    return;
  }

  const html = logs
    .map(
      (log) => `
    <div class="list-group-item">
      <div class="d-flex justify-content-between align-items-center">
        <div>
          <small class="text-muted">${formatDate(log.waktu_login)}</small><br>
          <strong>${log.lokasi || "-"}</strong> • ${log.device || "-"}<br>
          <code>${log.ip_address}</code>
        </div>
        <div class="text-end">
          <span class="badge ${getHasilBadge(log.hasil_deteksi)}">
            ${log.hasil_deteksi || "NORMAL"}
          </span><br>
          <small class="text-muted">Skor: ${log.skor_anomali.toFixed(3)}</small>
        </div>
      </div>
    </div>
  `
    )
    .join("");

  container.innerHTML = `<div class="list-group">${html}</div>`;
}

// Helper - Get status badge
function getStatusBadge(status) {
  const badges = {
    aktif: '<span class="badge bg-success">AKTIF</span>',
    diblokir: '<span class="badge bg-danger">DIBLOKIR</span>',
    ditunda: '<span class="badge bg-warning text-dark">DITUNDA</span>',
  };
  return badges[status] || status;
}

// Helper - Get hasil deteksi badge
function getHasilBadge(hasil) {
  const badges = {
    normal: "bg-success",
    izinkan: "bg-success",
    peringatan: "bg-warning text-dark",
    tunda: "bg-orange text-white",
    blokir: "bg-danger",
  };
  return badges[hasil] || "bg-secondary";
}

// Show monitoring warning
function showMonitoringWarning(pantauanMulai) {
  const container = document.getElementById("warningContainer");
  if (!container) return;

  const sejak = pantauanMulai
    ? new Date(pantauanMulai).toLocaleDateString("id-ID")
    : "sekarang";

  container.innerHTML = `
    <div class="alert alert-warning alert-dismissible fade show" role="alert">
      <i class="bi bi-exclamation-triangle-fill me-2"></i>
      <strong>Akun Anda Sedang Dipantau</strong><br>
      <small>Aktivitas Anda sedang dalam pantauan admin sejak ${sejak} karena terdeteksi aktivitas mencurigakan. Harap gunakan akun dengan normal.</small>
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
  `;
}

// Format date helper
function formatDate(dateString) {
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

// --- BUKA MODAL PROFIL ---
function openProfile() {
  const modal = new bootstrap.Modal(document.getElementById("profileModal"));
  modal.show();
}

// --- BUKA MODAL RESET PASSWORD ---
function openResetPassword() {
  document.getElementById("old_pass").value = "";
  document.getElementById("new_pass").value = "";
  document.getElementById("conf_pass").value = "";

  // Reset semua icon ke eye-slash (hidden)
  document.getElementById("icon_old_pass").className = "bi bi-eye-slash";
  document.getElementById("icon_new_pass").className = "bi bi-eye-slash";
  document.getElementById("icon_conf_pass").className = "bi bi-eye-slash";

  const modal = new bootstrap.Modal(document.getElementById("resetModal"));
  modal.show();
}

// --- TOGGLE PASSWORD VISIBILITY ---
function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  const icon = document.getElementById("icon_" + inputId);

  if (input.type === "password") {
    input.type = "text";
    icon.className = "bi bi-eye";
  } else {
    input.type = "password";
    icon.className = "bi bi-eye-slash";
  }
}

// --- RESET PASSWORD ---
async function submitPassword(e) {
  e.preventDefault();

  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "login.html";
    return;
  }

  const oldP = document.getElementById("old_pass").value.trim();
  const newP = document.getElementById("new_pass").value.trim();
  const confP = document.getElementById("conf_pass").value.trim();

  // Validasi frontend
  if (!oldP || !newP || !confP) {
    alert("Semua field wajib diisi!");
    return;
  }

  if (newP !== confP) {
    alert("Password baru dan konfirmasi tidak sama!");
    return;
  }

  if (newP.length < 8) {
    alert("Password baru minimal 8 karakter!");
    return;
  }

  if (oldP === newP) {
    alert("Password baru tidak boleh sama dengan password lama!");
    return;
  }

  try {
    const res = await fetch(`${API}/auth/reset-password`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        old_password: oldP,
        new_password: newP,
      }),
    });

    const data = await res.json();

    if (res.ok && data.status === "success") {
      alert(data.message);

      const modal = bootstrap.Modal.getInstance(
        document.getElementById("resetModal")
      );
      modal.hide();

      // Reset form
      document.getElementById("old_pass").value = "";
      document.getElementById("new_pass").value = "";
      document.getElementById("conf_pass").value = "";
    } else {
      alert(data.message || "Gagal mengubah password");
    }
  } catch (err) {
    console.error("Error reset password:", err);
    alert("Tidak dapat menghubungi server!");
  }
}

// --- LOGOUT ---
async function logout() {
  const token = localStorage.getItem("token");

  if (!token) {
    window.location.href = "login.html";
    return;
  }

  try {
    await fetch(`${API}/auth/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch (err) {
    console.error("Error logout:", err);
  }

  localStorage.clear();
  window.location.href = "login.html";
}
