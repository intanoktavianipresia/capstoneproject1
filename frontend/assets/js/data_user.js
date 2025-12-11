let currentPage = 0;
let searchQuery = "";
let statusFilter = "all";
let pantauanFilter = "all";
const limit = 10;
let mahasiswaModal;
let detailProfileModal;

// =======================================
// INIT & SIDEBAR TOGGLE LOGIC
// =======================================

function initSidebarToggle() {
  const sidebar = document.getElementById("sidebar");
  const mainContainer = document.getElementById("mainContainer");
  const toggleButton = document.getElementById("sidebarToggle");

  // Dapatkan status dari Local Storage
  const isCollapsed = localStorage.getItem("sidebarCollapsed") === "true";

  // Terapkan status awal
  if (isCollapsed) {
    sidebar.classList.add("collapsed");
    sidebar.classList.remove("expanded");
    mainContainer.classList.add("shifted");
  } else {
    sidebar.classList.add("expanded");
    sidebar.classList.remove("collapsed");
    mainContainer.classList.remove("shifted");
  }

  // Listener untuk toggle
  if (toggleButton) {
    toggleButton.addEventListener("click", () => {
      const currentlyCollapsed = sidebar.classList.toggle("collapsed");
      sidebar.classList.toggle("expanded");
      mainContainer.classList.toggle("shifted");
      localStorage.setItem("sidebarCollapsed", currentlyCollapsed);
    });
  }
}

if (!checkAuth("admin")) {
  window.location.href = "admin_login.html";
}

document.addEventListener("DOMContentLoaded", function () {
  initSidebarToggle();

  mahasiswaModal = new bootstrap.Modal(
    document.getElementById("mahasiswaModal")
  );

  detailProfileModal = new bootstrap.Modal(
    document.getElementById("profileDetailModal")
  );

  const savedFilter = localStorage.getItem("filterStatus");
  const urlParams = new URLSearchParams(window.location.search);
  const statusParam = urlParams.get("status");

  if (savedFilter) {
    statusFilter = savedFilter;
    document.getElementById("filterStatus").value = savedFilter;
    localStorage.removeItem("filterStatus");

    Swal.fire({
      icon: "info",
      title: "Filter Otomatis",
      text: `Menampilkan mahasiswa dengan status: ${savedFilter}`,
      timer: 2000,
      showConfirmButton: false,
    });
  } else if (statusParam) {
    statusFilter = statusParam;
    document.getElementById("filterStatus").value = statusParam;
  }

  loadMahasiswa();

  const userData = getUserData();
  if (userData && userData.nama_admin) {
    document.getElementById("adminName").textContent = userData.nama_admin;
  }
});

async function loadMahasiswa() {
  try {
    showLoading("Memuat data...");
    const offset = currentPage * limit;
    const searchParam = searchQuery ? `&search=${searchQuery}` : "";
    const statusParam = statusFilter !== "all" ? `&status=${statusFilter}` : "";
    const pantauanParam =
      pantauanFilter !== "all" ? `&dalam_pantauan=${pantauanFilter}` : "";

    const response = await apiRequest(
      `/admin/mahasiswa?limit=${limit}&offset=${offset}${searchParam}${statusParam}${pantauanParam}`
    );
    hideLoading();

    const mahasiswa = response.data;
    const total = response.pagination.total;

    document.getElementById("totalData").textContent = total;
    renderTable(mahasiswa);
    renderPagination(total);
  } catch (error) {
    console.error("Error:", error);
    hideLoading();
    document.getElementById("mahasiswaTable").innerHTML =
      '<tr><td colspan="8" class="text-danger py-4">Gagal memuat data: ' +
      (error.message || "Server Error") +
      "</td></tr>";
  }
}

function renderTable(data) {
  const tbody = document.getElementById("mahasiswaTable");

  if (data.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="8" class="text-muted py-4">Tidak ada data</td></tr>';
    return;
  }

  tbody.innerHTML = data
    .map(
      (mhs, index) => `
        <tr>
          <td>${currentPage * limit + index + 1}</td>
          <td><strong>${mhs.nim}</strong></td>
          <td>${mhs.nama}</td>
          <td><small>${mhs.email}</small></td>
          <td>
            <span class="badge ${getStatusBadgeClass(mhs.status_akun)}">
              ${mhs.status_akun.toUpperCase()}
            </span>
          ${
            mhs.dalam_pantauan
              ? '<br><small class="badge bg-orange text-white mt-1"><i class="bi bi-eye-fill"></i> Dipantau</small>'
              : ""
          }
          </td>
          <td>${mhs.total_login || 0}</td>
          <td><small>${
            mhs.login_terakhir ? formatDateShort(mhs.login_terakhir) : "-"
          }</small></td>
          <td>
          <button class="btn btn-sm btn-warning btn-action" onclick="showEditModal('${
            mhs.nim
          }')" title="Edit Data">
              <i class="bi bi-pencil"></i>
            </button>
            <button class="btn btn-sm btn-info btn-action" onclick="showDetailModal('${
              mhs.nim
            }')" title="Lihat Detail Log">
              <i class="bi bi-eye"></i>
            </button>
            <button class="btn btn-sm btn-danger btn-action" onclick="resetPassword('${
              mhs.nim
            }')" title="Reset Password">
              <i class="bi bi-key"></i>
            </button>
            ${
              mhs.status_akun === "diblokir"
                ? `
              <button class="btn btn-sm btn-success btn-action" onclick="unblockMahasiswa('${mhs.nim}')" title="Buka Blokir">
                <i class="bi bi-unlock"></i>
              </button>`
                : ""
            }
            ${
              mhs.dalam_pantauan
                ? `
              <button class="btn btn-sm btn-secondary btn-action" onclick="stopMonitoring('${mhs.nim}')" title="Hentikan Pantauan">
                <i class="bi bi-eye-slash"></i>
              </button> `
                : ""
            }
          </td>
        </tr>
      `
    )
    .join("");
}

function renderPagination(total) {
  const totalPages = Math.ceil(total / limit);
  const pagination = document.getElementById("pagination");

  if (totalPages <= 1) {
    pagination.innerHTML = "";
    return;
  }

  let html = "";

  html += `
        <li class="page-item ${currentPage === 0 ? "disabled" : ""}">
          <a class="page-link" href="#" onclick="changePage(${
            currentPage - 1
          }); return false;">«</a>
        </li>`;
  for (let i = 0; i < totalPages; i++) {
    if (
      i === 0 ||
      i === totalPages - 1 ||
      (i >= currentPage - 1 && i <= currentPage + 1)
    ) {
      html += `
              <li class="page-item ${i === currentPage ? "active" : ""}">
                <a class="page-link" href="#" onclick="changePage(${i}); return false;">${
        i + 1
      }</a>
              </li>`;
    } else if (i === currentPage - 2 || i === currentPage + 2) {
      html +=
        '<li class="page-item disabled"><span class="page-link">...</span></li>';
    }
  }

  html += `
        <li class="page-item ${
          currentPage >= totalPages - 1 ? "disabled" : ""
        }">
          <a class="page-link" href="#" onclick="changePage(${
            currentPage + 1
          }); return false;">»</a>
        </li>
      `;

  pagination.innerHTML = html;
}

function changePage(page) {
  currentPage = page;
  loadMahasiswa();
}

function handleSearch() {
  const input = document.getElementById("searchInput").value;
  const status = document.getElementById("filterStatus").value;
  const pantauan = document.getElementById("filterPantauan")?.value || "all";

  searchQuery = input;
  statusFilter = status;
  pantauanFilter = pantauan;
  currentPage = 0;

  loadMahasiswa();
}

function showAddModal() {
  document.getElementById("modalTitle").textContent = "Tambah Mahasiswa";
  document.getElementById("mahasiswaForm").reset();
  document.getElementById("editMode").value = "false";
  document.getElementById("nim").disabled = false;

  // Tampilkan input password dan input CSV
  document.getElementById("passwordField").style.display = "block";
  document.getElementById("password").required = true;

  // Sembunyikan/Reset CSV input (jika menggunakan modal yang sama)
  const csvFileContainer = document.getElementById("csvFileContainer");
  if (csvFileContainer) csvFileContainer.style.display = "block";
  const csvFileInput = document.getElementById("csvFile");
  if (csvFileInput) csvFileInput.value = "";

  mahasiswaModal.show();
}

async function showEditModal(nim) {
  try {
    showLoading("Memuat data...");
    const response = await apiRequest(`/admin/mahasiswa/${nim}`);
    hideLoading();

    const mhs = response.data.mahasiswa;

    document.getElementById("modalTitle").textContent = "Edit Mahasiswa";
    document.getElementById("editMode").value = "true";
    document.getElementById("nim").value = mhs.nim;
    document.getElementById("nim").disabled = true;
    document.getElementById("nama").value = mhs.nama;
    document.getElementById("email").value = mhs.email;

    // Sembunyikan input password dan input CSV saat EDIT
    document.getElementById("passwordField").style.display = "none";
    document.getElementById("password").required = false;
    const csvFileContainer = document.getElementById("csvFileContainer");
    if (csvFileContainer) csvFileContainer.style.display = "none";

    mahasiswaModal.show();
  } catch (error) {
    hideLoading();
    showAlert(error.message, "error");
  }
}

async function saveMahasiswa() {
  const csvFileInput = document.getElementById("csvFile");
  const csvFile = csvFileInput ? csvFileInput.files[0] : null;

  if (csvFile) {
    // --- PROSES UPLOAD CSV (BULK IMPORT) ---
    if (!csvFile.name.endsWith(".csv")) {
      showAlert("File harus berformat CSV!", "error");
      return;
    }

    showLoading("Mengimpor data massal...");

    try {
      const formData = new FormData();
      formData.append("file", csvFile);

      const token = getToken(); // Pastikan getToken() tersedia di utils.js
      const response = await fetch(
        `${CONFIG.API_BASE_URL}/admin/mahasiswa/import-csv`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: formData,
        }
      );

      const data = await response.json();
      hideLoading();

      if (response.ok && data.status === "success") {
        showAlert(data.message, "success");
      } else {
        showAlert(data.message || "Gagal mengimpor data.", "error");
      }

      mahasiswaModal.hide();
      loadMahasiswa();
    } catch (error) {
      hideLoading();
      showAlert("Gagal terhubung ke server saat upload CSV.", "error");
    }
    return;
  }

  const editMode = document.getElementById("editMode").value === "true";
  const nim = document.getElementById("nim").value.trim();
  const nama = document.getElementById("nama").value.trim();
  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;

  if (!nim || !nama || !email) {
    showAlert("Semua field wajib diisi!", "error");
    return;
  }

  if (!editMode && !password) {
    showAlert("Password wajib diisi!", "error");
    return;
  }

  const emailValid = validateEmail(email);
  if (!emailValid.valid) {
    showAlert(emailValid.message, "error");
    return;
  }

  showLoading("Menyimpan...");

  try {
    const body = { nama, email };
    if (!editMode) body.password = password;

    if (editMode) {
      await apiRequest(`/admin/mahasiswa/${nim}`, {
        method: "PUT",
        body: JSON.stringify(body),
      });
      showAlert("Data berhasil diupdate!", "success");
    } else {
      body.nim = nim;
      await apiRequest("/admin/mahasiswa", {
        method: "POST",
        body: JSON.stringify(body),
      });
      showAlert("Mahasiswa berhasil ditambahkan!", "success");
    }

    mahasiswaModal.hide();
    loadMahasiswa();
  } catch (error) {
    hideLoading();
    showAlert(error.message, "error");
  }
}

async function unblockMahasiswa(nim) {
  const result = await Swal.fire({
    title: "Buka Blokir Akun?",
    text: `Akun ${nim} akan diaktifkan kembali. Reset password?`,
    icon: "question",
    showCancelButton: true,
    showDenyButton: true,
    confirmButtonColor: "#28a745",
    denyButtonColor: "#ffc107",
    cancelButtonColor: "#6c757d",
    confirmButtonText: "Ya, Reset Password",
    denyButtonText: "Tanpa Reset Password",
    cancelButtonText: "Batal",
    input: "textarea",
    inputPlaceholder: "Catatan (opsional)...",
  });

  if (result.isConfirmed || result.isDenied) {
    const resetPassword = result.isConfirmed;

    try {
      showLoading("Membuka blokir...");
      const response = await apiRequest(`/admin/mahasiswa/${nim}/unblock`, {
        method: "POST",
        body: JSON.stringify({
          reset_password: resetPassword,
          catatan: result.value || "Unblock oleh admin",
        }),
      });
      hideLoading();

      if (response.data.new_password) {
        await Swal.fire({
          icon: "success",
          title: "Blokir Berhasil Dibuka!",
          html: `
                  <p>Akun ${nim} sudah aktif kembali.</p>
                  <hr>
                  <p><strong>Password Baru:</strong></p>
                  <h4><code>${response.data.new_password}</code></h4>
                  <small class="text-muted">Berikan password ini ke mahasiswa</small>
                `,
          confirmButtonText: "OK",
        });
      } else {
        showAlert(response.message, "success");
      }

      loadMahasiswa();
    } catch (error) {
      hideLoading();
      showAlert(error.message, "error");
    }
  }
}

async function stopMonitoring(nim) {
  const result = await Swal.fire({
    title: "Hentikan Pantauan?",
    text: `Mahasiswa ${nim} akan dihapus dari daftar pantauan`,
    icon: "question",
    showCancelButton: true,
    confirmButtonColor: "#007bff",
    cancelButtonColor: "#6c757d",
    confirmButtonText: "Ya, Hentikan",
    cancelButtonText: "Batal",
    input: "textarea",
    inputPlaceholder: "Catatan (opsional)...",
  });

  if (result.isConfirmed) {
    try {
      showLoading("Menghentikan pantauan...");
      const response = await apiRequest(
        `/admin/mahasiswa/${nim}/stop-monitoring`,
        {
          method: "POST",
          body: JSON.stringify({
            catatan: result.value || "Monitoring dihentikan",
          }),
        }
      );
      hideLoading();

      showAlert(response.message, "success");
      loadMahasiswa();
    } catch (error) {
      hideLoading();
      showAlert(error.message, "error");
    }
  }
}

async function resetPassword(nim) {
  const result = await Swal.fire({
    title: "Reset Password?",
    text: "Password akan direset menjadi default",
    icon: "warning",
    showCancelButton: true,
    confirmButtonColor: "#ffc107",
    cancelButtonColor: "#6c757d",
    confirmButtonText: "Ya, Reset",
    cancelButtonText: "Batal",
  });

  if (!result.isConfirmed) return;

  try {
    showLoading("Mereset password...");
    const response = await apiRequest(
      `/admin/mahasiswa/${nim}/reset-password`,
      {
        method: "POST",
        body: JSON.stringify({}),
      }
    );
    hideLoading();

    Swal.fire({
      icon: "success",
      title: "Password Berhasil Direset!",
      html: `
            <p>Password baru untuk <strong>${nim}</strong>:</p>
            <h4><code>${response.data.new_password}</code></h4>
            <small class="text-muted">Simpan password ini dan berikan ke mahasiswa</small>
          `,
      confirmButtonText: "OK",
    });

    loadMahasiswa();
  } catch (error) {
    hideLoading();
    showAlert(error.message, "error");
  }
}

async function showDetailModal(nim) {
  try {
    showLoading(`Memuat Detail Profil ${nim}...`);

    const response = await apiRequest(`/admin/mahasiswa/${nim}`);
    hideLoading();

    if (response.status !== "success") {
      showAlert(response.message || "Gagal memuat detail data.", "error");
      return;
    }

    const data = response.data;

    renderProfileDetail(data);
    renderDetailLogs(data.recent_logins);
    renderSecurityHistory(data.security_history);

    detailProfileModal.show();
    document.getElementById("data-tab").click();
  } catch (error) {
    hideLoading();
    console.error("Gagal memuat detail mahasiswa:", error);
    showAlert(
      "Gagal memuat detail: " + (error.message || "Server Error"),
      "error"
    );
  }
}

function renderProfileDetail(data) {
  const mhs = data.mahasiswa;
  const stats = data.statistics;

  document.getElementById("detailNimProfile").textContent = mhs.nim;
  document.getElementById("detailNamaProfile").textContent = mhs.nama;

  document.getElementById("p_nim").textContent = mhs.nim;
  document.getElementById("p_nama").textContent = mhs.nama;
  document.getElementById("p_email").textContent = mhs.email;
  document.getElementById("p_daftar").textContent = formatDateShort(
    mhs.tanggal_daftar
  );

  document.getElementById(
    "p_status_akun"
  ).innerHTML = `<span class="badge ${getStatusBadgeClass(
    mhs.status_akun
  )}">${mhs.status_akun.toUpperCase()}</span>`;

  document.getElementById("p_dalam_pantauan").textContent = mhs.dalam_pantauan
    ? "Ya"
    : "Tidak";
  document.getElementById("p_pantauan_mulai").textContent = mhs.pantauan_mulai
    ? formatDateShort(mhs.pantauan_mulai)
    : "-";

  document.getElementById("p_berhasil").textContent = stats.login_berhasil;
  document.getElementById("p_gagal").textContent = stats.login_gagal;
  document.getElementById("p_kritis").textContent =
    stats.deteksi_anomali.kritis;

  document.getElementById("statsTotalDeteksi").textContent =
    stats.deteksi_anomali.rendah +
    stats.deteksi_anomali.sedang +
    stats.deteksi_anomali.tinggi +
    stats.deteksi_anomali.kritis;
  document.getElementById("statsRiskRendah").textContent =
    stats.deteksi_anomali.rendah;
  document.getElementById("statsRiskSedang").textContent =
    stats.deteksi_anomali.sedang;
  document.getElementById("statsRiskTinggi").textContent =
    stats.deteksi_anomali.tinggi;
  document.getElementById("statsRiskKritis").textContent =
    stats.deteksi_anomali.kritis;
}

function renderDetailLogs(logs) {
  const tbody = document.getElementById("detailLogTable");
  if (logs.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="7" class="text-center">Tidak ada riwayat login baru.</td></tr>';
    return;
  }

  tbody.innerHTML = logs
    .map((log) => {
      const statusClass =
        log.status_login === "berhasil" ? "text-success" : "text-danger";
      const riskBadge =
        log.risk_level_deteksi && log.risk_level_deteksi !== "n/a"
          ? `<span class="badge ${getRiskBadgeClass(
              log.risk_level_deteksi
            )}">${log.risk_level_deteksi.toUpperCase()}</span>`
          : "-";

      return `
            <tr>
                <td>${formatDateShort(log.waktu_login)}</td>
                <td>${log.ip_address}</td>
                <td>${log.lokasi}</td>
                <td>${log.device}</td>
                <td class="${statusClass} fw-bold">${log.status_login.toUpperCase()}</td>
                <td>${log.skor_anomali}</td>
                <td>${riskBadge}</td>
            </tr>
        `;
    })
    .join("");
}

function renderSecurityHistory(history) {
  const tbody = document.getElementById("securityHistoryTable");
  if (history.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="4" class="text-center">Tidak ada riwayat keamanan.</td></tr>';
    return;
  }

  tbody.innerHTML = history
    .map((event) => {
      const eventClass =
        event.event_type === "blocked" ? "text-danger" : "text-info";

      return `
            <tr>
                <td>${formatDateShort(event.event_time)}</td>
                <td class="${eventClass} fw-bold">${event.event_type
        .toUpperCase()
        .replace("_", " ")}</td>
                <td>${event.triggered_by}</td>
                <td>${event.reason}</td>
            </tr>
        `;
    })
    .join("");
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
