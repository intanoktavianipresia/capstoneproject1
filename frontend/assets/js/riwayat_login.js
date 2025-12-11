// ===============================
// AUTH CHECK
// ===============================
if (!checkAuth("admin")) {
  window.location.href = "admin_login.html";
}

let currentPage = 0;
const limit = 20; // Tampilkan 20 data per halaman
let totalPages = 0;

// ===============================
// DOM LOADED
// ===============================
document.addEventListener("DOMContentLoaded", function () {
  showLoadingTable();
  loadRiwayatData();

  const userData = getUserData();
  if (userData && userData.nama_admin) {
    document.getElementById("adminName").textContent = userData.nama_admin;
  }

  // Enter untuk apply filter
  document
    .getElementById("searchNIM")
    .addEventListener("keypress", function (e) {
      if (e.key === "Enter") applyFilter();
    });
});

// ===============================
// LOAD DATA
// ===============================
async function loadRiwayatData() {
  try {
    showLoadingTable();

    const nim = document.getElementById("searchNIM").value.trim();
    const status = document.getElementById("filterStatus").value;
    const hasil = document.getElementById("filterHasil").value;
    const riskLevel =
      document.getElementById("filterRiskLevel")?.value || "all";

    const params = new URLSearchParams({
      limit,
      offset: currentPage * limit,
    });

    if (nim) params.append("nim", nim);
    if (status !== "all") params.append("status", status);
    if (hasil !== "all") params.append("hasil", hasil);
    if (riskLevel !== "all") params.append("risk_level", riskLevel);

    const response = await apiRequest(`/log/history?${params}`);
    const logs = response.data;
    const pagination = response.pagination;

    displayRiwayat(logs);
    displayPagination(pagination);
  } catch (error) {
    console.error("Error loading riwayat:", error);
    document.getElementById("riwayatTable").innerHTML = `
      <tr>
        <td colspan="12" class="text-danger py-3">
          Gagal memuat data: ${error.message || "Server Error"}
        </td>
      </tr>`;
  }
}

// ===============================
// LOADING STATE
// ===============================
function showLoadingTable() {
  document.getElementById("riwayatTable").innerHTML = `
    <tr>
      <td colspan="12" class="text-center py-4">
        <div class="spinner-border text-primary" role="status">
          <span class="visually-hidden">Loading...</span>
        </div>
      </td>
    </tr>`;
}

// ===============================
// DISPLAY RIWAYAT
// ===============================
function displayRiwayat(logs) {
  const tbody = document.getElementById("riwayatTable");
  const COLSPAN = 12;

  if (logs.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="${COLSPAN}" class="text-muted py-3">
          Tidak ada data riwayat login
        </td>
      </tr>`;
    return;
  }

  tbody.innerHTML = logs
    .map(
      (log, index) => `
      <tr>
        <td>${currentPage * limit + index + 1}</td>
        <td><strong>${log.nim}</strong></td>
        <td>${log.nama_mahasiswa || "-"}</td>
        <td><small>${formatDate(log.waktu_login)}</small></td>
        <td><code>${log.ip_address || "-"}</code></td>
        <td><small>${log.lokasi || "-"}</small></td>
        <td><small>${log.device || "-"}</small></td>

        <td>
          <span class="badge ${
            log.status_login === "berhasil" ? "bg-success" : "bg-danger"
          }">
            ${log.status_login ? log.status_login.toUpperCase() : "-"}
          </span>
        </td>

        <td>
          <span class="badge ${getSkorBadgeClass(log.skor_anomali)}">
            ${log.skor_anomali ? log.skor_anomali.toFixed(3) : "0.000"}
          </span>
        </td>

        <td>
          ${
            log.risk_level
              ? `<span class="badge ${getRiskBadgeClass(log.risk_level)}">
                   ${log.risk_level.toUpperCase()}
                 </span>`
              : "-"
          }
        </td>

        <td>
          <span class="badge ${getHasilBadgeClass(log.hasil_deteksi)}">
            ${log.hasil_deteksi || "NORMAL"}
          </span>
        </td>

        <td class="ket-col"><small>${log.keterangan || "-"}</small></td>
      </tr>`
    )
    .join("");
}

// ===============================
// PAGINATION
// ===============================
function displayPagination(pagination) {
  totalPages = Math.ceil(pagination.total / limit);

  const start = currentPage * limit + 1;
  const end = Math.min(currentPage * limit + limit, pagination.total);
  document.getElementById(
    "paginationInfo"
  ).innerHTML = `Menampilkan ${start} - ${end} dari ${pagination.total} data`;

  const container = document.getElementById("paginationButtons");
  let btns = "";

  // Previous
  if (currentPage > 0) {
    btns += `
      <button class="btn btn-sm btn-primary btn-page"
              onclick="changePage(${currentPage - 1})">
        <i class="bi bi-chevron-left"></i> Prev
      </button>`;
  }

  // Page numbers
  const startPage = Math.max(0, currentPage - 2);
  const endPage = Math.min(totalPages - 1, currentPage + 2);

  for (let i = startPage; i <= endPage; i++) {
    btns += `
      <button class="btn btn-sm ${
        i === currentPage ? "btn-primary" : "btn-outline-primary"
      } btn-page"
      onclick="changePage(${i})">${i + 1}</button>`;
  }

  // Next
  if (currentPage < totalPages - 1) {
    btns += `
      <button class="btn btn-sm btn-primary btn-page"
              onclick="changePage(${currentPage + 1})">
        Next <i class="bi bi-chevron-right"></i>
      </button>`;
  }

  container.innerHTML = btns;
}

function changePage(page) {
  currentPage = page;
  loadRiwayatData();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function applyFilter() {
  currentPage = 0;
  loadRiwayatData();
}

// ===============================
// BADGE HELPERS
// ===============================
function getSkorBadgeClass(skor) {
  if (skor >= 0.1) return "bg-danger"; // Kritis
  if (skor >= 0) return "bg-orange text-white"; // Tinggi
  if (skor >= -0.1) return "bg-warning text-dark"; // Sedang
  return "bg-success"; // Rendah
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

// ===============================
// LOGOUT
// ===============================
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
    if (result.isConfirmed) logout();
  });
}
