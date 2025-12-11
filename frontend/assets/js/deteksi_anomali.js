if (!checkAuth("admin")) {
  window.location.href = "admin_login.html";
}

let currentPage = 0;
const limit = 10; // Menggunakan limit 10 untuk konsistensi halaman
let totalPages = 0;

// ============================================
// INIT
// ============================================
document.addEventListener("DOMContentLoaded", function () {
  // Pastikan status default adalah "belum_ditinjau"
  document.getElementById("filterStatus").value = "belum_ditinjau";
  loadDeteksiData();

  const userData = getUserData();
  if (userData && userData.nama_admin) {
    document.getElementById("adminName").textContent = userData.nama_admin;
  }
});

// ============================================
// LOAD DETEKSI DATA
// ============================================
async function loadDeteksiData() {
  try {
    showLoadingTable();

    const status = document.getElementById("filterStatus").value;
    const risiko = document.getElementById("filterRisiko").value;

    const params = new URLSearchParams({
      limit: limit,
      offset: currentPage * limit,
    });

    if (status !== "all") params.append("status", status);
    if (risiko !== "all") params.append("risiko", risiko);

    const response = await apiRequest(`/detection/anomalies?${params}`);

    const deteksi = response.data || [];
    const pagination = response.pagination || { total: 0 };

    displayDeteksi(deteksi);
    displayPagination(pagination);
  } catch (error) {
    console.error("Error loading deteksi:", error);
    document.getElementById("deteksiTable").innerHTML =
      '<tr><td colspan="10" class="text-danger py-3">Gagal memuat data: ' +
      (error.message || "Server Error") +
      "</td></tr>";
  }
}

function showLoadingTable() {
  document.getElementById("deteksiTable").innerHTML = `
    <tr>
      <td colspan="10" class="text-center py-4">
        <div class="spinner-border text-primary" role="status">
          <span class="visually-hidden">Loading...</span>
        </div>
      </td>
    </tr>
  `;
}

// ============================================
// DISPLAY DETEKSI (12 COLUMNS + BUTTONS)
// ============================================
function displayDeteksi(deteksi) {
  const tbody = document.getElementById("deteksiTable");

  if (!deteksi || deteksi.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="12" class="text-muted py-3">Tidak ada data deteksi anomali</td></tr>';
    return;
  }

  tbody.innerHTML = deteksi
    .map((d, index) => {
      const riskBadge = getRiskBadgeClass(d.tingkat_risiko);
      const actionBadge = getActionBadgeClass(d.tindakan_otomatis);

      // Logika Tombol Aksi Admin (Kolom 12)
      let actionButtons = "";
      if (d.status_tinjauan === "belum_ditinjau") {
        actionButtons = `
          <div class="btn-group btn-group-sm">
                
                        <button class="btn btn-success btn-action" onclick="handleAction(${
                          d.id_deteksi
                        }, 'abaikan', '${
          d.nim
        }')" title="Abaikan / Tandai Selesai">
              <i class="bi bi-check-circle"></i>
            </button>
            
                        <button class="btn btn-warning btn-action text-dark" onclick="handleAction(${
                          d.id_deteksi
                        }, 'reset_password', '${
          d.nim
        }')" title="Reset Password">
              <i class="bi bi-key"></i>
            </button>

                        ${
                          d.tingkat_risiko === "kritis" ||
                          d.tingkat_risiko === "tinggi"
                            ? `
              <button class="btn btn-danger btn-action" onclick="handleAction(${d.id_deteksi}, 'blokir_permanen', '${d.nim}')" title="Blokir Permanen">
                <i class="bi bi-x-circle"></i>
              </button>
            `
                            : ""
                        }
            
                        ${
                          d.require_admin
                            ? `
              <button class="btn btn-info btn-action" onclick="handleAction(${d.id_deteksi}, 'hapus_pantauan', '${d.nim}')" title="Hapus Pantauan">
                <i class="bi bi-eye-slash"></i>
              </button>
            `
                            : ""
                        }
          </div>
        `;
      } else {
        actionButtons =
          '<span class="badge bg-secondary">Sudah Ditinjau</span>';
      }
      // Akhir Logika Tombol

      return `
        <tr>
          <td>${currentPage * limit + index + 1}</td>
          <td><strong>${d.nim || "-"}</strong></td>
          <td>${d.nama_mahasiswa || "-"}</td>
          <td><small>${formatDate(d.waktu_deteksi)}</small></td>
          <td>
            <span class="badge ${getSkorBadgeClass(d.skor_anomali)}">
              ${d.skor_anomali.toFixed(3)}
            </span>
          </td>
          <td>
            <span class="badge ${riskBadge}">
              ${d.tingkat_risiko.toUpperCase()}
            </span>
          </td>
          <td>
            <span class="badge ${actionBadge}">
              ${d.tindakan_otomatis.toUpperCase()}
            </span>
          </td>
          <td>
            ${
              d.require_admin
                ? `<span class="badge bg-danger"><i class="bi bi-exclamation-triangle-fill"></i> Ya</span>`
                : `<span class="text-muted">Tidak</span>`
            }
          </td>
          <td>
            ${
              d.status_tinjauan === "belum_ditinjau"
                ? `<span class="badge bg-warning text-dark">Belum</span>`
                : `<span class="badge bg-success">Sudah</span>`
            }
          </td>
                    <td class="text-center">${actionButtons}</td>
        </tr>
      `;
    })
    .join("");
}

// ============================================
// PAGINATION & UTILS
// ============================================
function changePage(page) {
  currentPage = page;
  loadDeteksiData();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ============================================
// DISPLAY PAGINATION
// ============================================
function displayPagination(pagination) {
  const total = pagination.total || 0;

  if (total === 0) {
    document.getElementById("paginationInfo").innerHTML = "";
    return;
  }

  const showing = Math.min(currentPage * limit + limit, total);
  document.getElementById("paginationInfo").innerHTML = `
    <div class="d-flex justify-content-between align-items-center mt-3">
      <div>
        <small class="text-muted">
          Menampilkan ${currentPage * limit + 1} - ${showing} dari ${total} data
        </small>
      </div>
      <div id="paginationButtons"></div>
    </div>
  `;

  totalPages = Math.ceil(total / limit);
  const buttonsContainer = document.getElementById("paginationButtons");

  if (!buttonsContainer) return;

  let buttons = "";

  if (currentPage > 0) {
    buttons += `<button class="btn btn-sm btn-primary me-1" onclick="changePage(${
      currentPage - 1
    })">
            <i class="bi bi-chevron-left"></i> Prev
          </button>`;
  }

  const startPage = Math.max(0, currentPage - 2);
  const endPage = Math.min(totalPages - 1, currentPage + 2);

  for (let i = startPage; i <= endPage; i++) {
    buttons += `<button class="btn btn-sm ${
      i === currentPage ? "btn-primary" : "btn-outline-primary"
    } me-1" onclick="changePage(${i})">${i + 1}</button>`;
  }

  if (currentPage < totalPages - 1) {
    buttons += `<button class="btn btn-sm btn-primary" onclick="changePage(${
      currentPage + 1
    })">
            Next <i class="bi bi-chevron-right"></i>
          </button>`;
  }

  buttonsContainer.innerHTML = buttons;
}

function changePage(page) {
  currentPage = page;
  loadDeteksiData();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ==============
// HANDLE ACTIONS
// ===============
async function handleAction(idDeteksi, jenisTindakan, nim) {
  const actionText = {
    abaikan: `Abaikan deteksi anomali untuk NIM ${nim}?`,
    reset_password: `Reset password untuk mahasiswa NIM ${nim}?`,
    blokir_permanen: `Blokir akun mahasiswa NIM ${nim} secara permanen?`,
    buka_blokir: `Buka blokir akun mahasiswa NIM ${nim}?`,
    hapus_pantauan: `Hapus pantauan untuk mahasiswa NIM ${nim}?`,
  };

  const result = await Swal.fire({
    title: "Konfirmasi Tindakan",
    text: actionText[jenisTindakan],
    icon: "question",
    showCancelButton: true,
    confirmButtonColor:
      jenisTindakan === "blokir_permanen" ? "#dc3545" : "#007bff",
    cancelButtonColor: "#6c757d",
    confirmButtonText: "Ya, Lanjutkan",
    cancelButtonText: "Batal",
    input: "textarea",
    inputPlaceholder: "Catatan admin (opsional)...",
    inputAttributes: {
      rows: 3,
    },
  });

  if (result.isConfirmed) {
    showLoading("Memproses tindakan...");

    try {
      const response = await apiRequest("/detection/action", {
        method: "POST",
        body: JSON.stringify({
          id_deteksi: idDeteksi,
          jenis_tindakan: jenisTindakan,
          catatan_admin: result.value || "",
        }),
      });

      hideLoading();

      await Swal.fire({
        icon: "success",
        title: "Berhasil!",
        html: `
                <p>${response.message}</p>
                ${
                  response.data.new_password
                    ? `
                  <div class="alert alert-info mt-3">
                    <strong>Password Baru untuk NIM ${nim}:</strong><br>
                    <code style="font-size: 18px; background: #fff; padding: 8px; border-radius: 4px; display: inline-block; margin-top: 8px;">${response.data.new_password}</code>
                    <br><small class="text-muted mt-2 d-block">Salin dan beritahukan kepada mahasiswa</small>
                  </div>
                `
                    : ""
                }
              `,
        confirmButtonText: "OK",
      });

      loadDeteksiData();
    } catch (error) {
      hideLoading();
      showAlert(error.message || "Gagal memproses tindakan", "error");
    }
  }
}

// ============================================
// ✅ HELPER FUNCTIONS (4-Level Risk)
// ============================================
function getRiskBadgeClass(risiko) {
  const classes = {
    rendah: "bg-success",
    sedang: "bg-warning text-dark",
    tinggi: "bg-orange text-white",
    kritis: "bg-danger",
  };
  return classes[risiko] || "bg-secondary";
}

function getActionBadgeClass(action) {
  const classes = {
    izinkan: "bg-success",
    peringatan: "bg-warning text-dark",
    tunda: "bg-orange text-white",
    blokir: "bg-danger",
  };
  return classes[action] || "bg-secondary";
}

function getSkorBadgeClass(skor) {
  // Sesuaikan dengan threshold baru
  if (skor >= 0.1) return "bg-danger"; // Kritis
  if (skor >= 0) return "bg-orange text-white"; // Tinggi
  if (skor >= -0.1) return "bg-warning text-dark"; // Sedang
  return "bg-success"; // Rendah
}

// ============================================
// REFRESH
// ============================================
function refreshData() {
  currentPage = 0;
  document.getElementById("filterStatus").value = "belum_ditinjau";
  document.getElementById("filterRisiko").value = "all";
  loadDeteksiData();
}

// ============================================
// LOGOUT
// ============================================
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
