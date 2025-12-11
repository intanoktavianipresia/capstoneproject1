if (!checkAuth("admin")) {
  window.location.href = "admin_login.html";
}

document.addEventListener("DOMContentLoaded", function () {
  loadDashboardData();

  const userData = getUserData();
  if (userData && userData.nama_admin) {
    document.getElementById("adminName").textContent = userData.nama_admin;
  }
});

async function loadDashboardData() {
  try {
    const response = await apiRequest("/admin/dashboard");
    const data = response.data;

    console.log("Dashboard Data:", data);

    if (data.mahasiswa) {
      document.getElementById("totalMahasiswa").textContent =
        data.mahasiswa.total || 0;
      document.getElementById("akunDiblokir").textContent =
        data.mahasiswa.diblokir || 0;

      // Update Tabel Status Akun
      document.getElementById("statusAktif").textContent =
        data.mahasiswa.aktif || 0;
      document.getElementById("statusDitunda").textContent =
        data.mahasiswa.ditunda || 0;
      document.getElementById("statusDiblokir").textContent =
        data.mahasiswa.diblokir || 0;
      document.getElementById("statusDipantau").textContent =
        data.mahasiswa.dalam_pantauan || 0;
    }

    document.getElementById("totalLoginToday").textContent =
      data.login_hari_ini || 0;

    if (data.deteksi) {
      document.getElementById("anomaliBelumDitinjau").textContent =
        data.deteksi.belum_ditinjau || 0;
    }

    // 2. Load Recent Activity
    await loadRecentActivity();
  } catch (error) {
    console.error("Error loading dashboard:", error);

    // Reset ke 0 jika error
    const ids = [
      "totalMahasiswa",
      "totalLoginToday",
      "akunDiblokir",
      "anomaliBelumDitinjau",
      "statusAktif",
      "statusDitunda",
      "statusDiblokir",
      "statusDipantau",
    ];

    ids.forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.textContent = "0";
    });

    showAlert("Gagal memuat data dashboard: " + error.message, "error");
  }
}

async function loadRecentActivity() {
  try {
    const response = await apiRequest("/log/history?limit=10");
    const logs = response.data || [];

    displayRecentActivity(logs);
  } catch (error) {
    console.error("Error loading recent activity:", error);
    document.getElementById("recentActivity").innerHTML =
      '<p class="text-danger text-center py-3">Gagal memuat aktivitas terbaru</p>';
  }
}

function displayRecentActivity(logs) {
  const tbody = document.getElementById("recentActivityTableBody");

  const latestLogs = logs ? logs.slice(0, 7) : [];

  if (latestLogs.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="6" class="text-muted text-center py-3">Belum ada aktivitas terbaru</td></tr>';
    return;
  }

  const html = latestLogs
    .map((log) => {
      const statusBadge = getHasilBadgeClass(log.hasil_deteksi);
      const skorBadge = getSkorBadgeClass(log.skor_anomali || 0);

      return `
        <tr>
          <td><strong>${log.nim}</strong></td> 
          <td>${log.nama_mahasiswa || "-"}</td> 
          <td><small class="text-muted">${formatDateShort(
            log.waktu_login
          )}</small></td>
          <td><small class="text-muted"><code>${
            log.ip_address || "-"
          }</code></small></td>
          <td class="text-center">
            <span class="badge ${skorBadge}">
              ${log.skor_anomali ? log.skor_anomali.toFixed(3) : "0.000"}
            </span>
          </td>
          <td class="text-center">
            <span class="badge ${statusBadge}">
              ${log.hasil_deteksi ? log.hasil_deteksi.toUpperCase() : "NORMAL"}
            </span>
          </td>
        </tr>
      `;
    })
    .join("");

  tbody.innerHTML = html;
}

function getSkorBadgeClass(skor) {
  // 4-Level Risk Logic
  if (skor < -0.1) return "bg-danger";
  if (skor < -0.05) return "bg-orange text-white";
  if (skor < 0.0) return "bg-warning text-dark";
  return "bg-success";
}

function getHasilBadgeClass(hasil) {
  const classes = {
    normal: "bg-success",
    izinkan: "bg-success",
    peringatan: "bg-warning text-dark",
    tunda: "bg-orange text-white",
    blokir: "bg-danger",
  };
  return classes[hasil] || "bg-secondary";
}

function goToDataUser() {
  window.location.href = "data_user.html";
}

function goToRiwayatLogin() {
  window.location.href = "riwayat_login.html";
}

function goToDeteksiAnomali() {
  window.location.href = "deteksi_anomali.html";
}

function handleLogout() {
  Swal.fire({
    title: "Logout?",
    text: "Anda yakin ingin keluar?",
    icon: "question",
    showCancelButton: true,
    confirmButtonColor: "#dc3545",
    cancelButtonColor: "#6c757d",
    confirmButtonText: "Ya, Logout",
    cancelButtonText: "Batal",
  }).then((result) => {
    if (result.isConfirmed) {
      logout();
    }
  });
}
