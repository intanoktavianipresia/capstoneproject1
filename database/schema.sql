CREATE DATABASE IF NOT EXISTS tes_cp;
USE tes_cp;

CREATE TABLE mahasiswa (
    nim VARCHAR(15) PRIMARY KEY,
    nama VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    status_akun ENUM('aktif', 'diblokir', 'ditunda') DEFAULT 'aktif',
    tanggal_daftar DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Kolom Tunda LAMA (dihapus/digantikan oleh delayed_logins)
    jumlah_gagal INT NOT NULL DEFAULT 0,
    
    -- Kolom Security Metadata (dari MIGRATION)
    diblokir_pada DATETIME NULL,
    alasan_blokir TEXT NULL,
    diblokir_oleh ENUM('system', 'admin') NULL,
    
    dalam_pantauan TINYINT(1) DEFAULT 0,
    pantauan_mulai DATETIME NULL,
    pantauan_selesai DATETIME NULL,
    
    terakhir_login DATETIME NULL,
    terakhir_ip VARCHAR(100) NULL,
    
    INDEX idx_status (status_akun),
    INDEX idx_email (email),
    INDEX idx_pantauan (dalam_pantauan),
    INDEX idx_terakhir_login (terakhir_login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE admin (
    id_admin INT AUTO_INCREMENT PRIMARY KEY,
    nama_admin VARCHAR(100) NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    role ENUM('superadmin', 'staff', 'admin') DEFAULT 'staff',
    
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================
-- 1. MODEL LOG LOGIN (ML Features Dikonversi ke FLOAT)
-- ============================================

CREATE TABLE log_login (
    id_log INT AUTO_INCREMENT PRIMARY KEY,
    nim VARCHAR(15) NOT NULL,
    waktu_login DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(100),
    lokasi VARCHAR(200),
    device VARCHAR(200),
    os VARCHAR(200),
    browser VARCHAR(200),
    
    -- Status dan Skor Log
    status_login ENUM('berhasil', 'gagal') NOT NULL,
    percobaan_ke INT DEFAULT 1,
    hasil_deteksi ENUM('normal', 'peringatan', 'tunda', 'blokir', 'izinkan') DEFAULT 'normal',
    skor_anomali FLOAT DEFAULT 0.0,
    keterangan TEXT,
    
    -- 10 Fitur ML (WAJIB FLOAT untuk log np.log1p)
    ip_score FLOAT DEFAULT 0.0,
    lokasi_score FLOAT DEFAULT 0.0,
    device_score FLOAT DEFAULT 0.0,
    os_score FLOAT DEFAULT 0.0,
    browser_score FLOAT DEFAULT 0.0,
    jam_login INT DEFAULT 0,
    ip_frequency FLOAT DEFAULT 0.693147, -- log(1+1)
    combo_frequency FLOAT DEFAULT 0.693147,
    is_high_risk_country TINYINT(1) DEFAULT 0,
    is_night_login TINYINT(1) DEFAULT 0,
    
    FOREIGN KEY (nim) REFERENCES mahasiswa(nim) ON DELETE CASCADE,
    INDEX idx_nim (nim),
    INDEX idx_waktu (waktu_login),
    INDEX idx_ip (ip_address),
    INDEX idx_hasil (hasil_deteksi),
    INDEX idx_status (status_login),
    INDEX idx_risk_score (skor_anomali),
    INDEX idx_jam_login (jam_login)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================
-- 2. MODEL DETEKSI ANOMALI (4-Level & Detail Action)
-- ============================================

CREATE TABLE deteksi_anomali (
    id_deteksi INT AUTO_INCREMENT PRIMARY KEY,
    id_log INT NOT NULL,
    waktu_deteksi DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    skor_anomali FLOAT NOT NULL,
    
    -- 4-level risk
    tingkat_risiko ENUM('rendah', 'sedang', 'tinggi', 'kritis') NOT NULL,
    tindakan_otomatis ENUM('izinkan', 'peringatan', 'tunda', 'blokir') NOT NULL,
    
    -- Detail action
    delay_seconds INT DEFAULT 0,
    require_admin TINYINT(1) DEFAULT 0,
    auto_block TINYINT(1) DEFAULT 0,
    message_to_user TEXT,
    detail_anomali TEXT,
    
    status_tinjauan ENUM('belum_ditinjau', 'ditinjau') DEFAULT 'belum_ditinjau',
    
    FOREIGN KEY (id_log) REFERENCES log_login(id_log) ON DELETE CASCADE,
    INDEX idx_log (id_log),
    INDEX idx_risiko (tingkat_risiko),
    INDEX idx_status (status_tinjauan)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================
-- 3. MODEL DELAYED LOGINS (Untuk Status Tunda)
-- ============================================

CREATE TABLE delayed_logins (
    id_delayed INT AUTO_INCREMENT PRIMARY KEY,
    nim VARCHAR(15) NOT NULL,
    id_log INT NULL,
    
    delay_seconds INT NOT NULL DEFAULT 60,
    delay_start DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    delay_end DATETIME NOT NULL,
    
    status_delay ENUM('waiting', 'completed', 'cancelled', 'expired') DEFAULT 'waiting',
    
    ip_address VARCHAR(100),
    user_agent TEXT,
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (nim) REFERENCES mahasiswa(nim) ON DELETE CASCADE,
    FOREIGN KEY (id_log) REFERENCES log_login(id_log) ON DELETE SET NULL,
    
    INDEX idx_nim (nim),
    INDEX idx_status (status_delay),
    INDEX idx_delay_end (delay_end)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================
-- 4. MODEL KEPUTUSAN ADMIN (Tindakan Baru)
-- ============================================

CREATE TABLE keputusan_admin (
    id_keputusan INT AUTO_INCREMENT PRIMARY KEY,
    id_deteksi INT NOT NULL,
    id_admin INT NOT NULL,
    waktu_keputusan DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    jenis_tindakan ENUM(
        'reset_password', 
        'blokir_permanen', 
        'buka_blokir',
        'hapus_pantauan',
        'abaikan'
    ) NOT NULL,
    catatan_admin TEXT,
    
    FOREIGN KEY (id_deteksi) REFERENCES deteksi_anomali(id_deteksi) ON DELETE CASCADE,
    FOREIGN KEY (id_admin) REFERENCES admin(id_admin) ON DELETE CASCADE,
    INDEX idx_deteksi (id_deteksi),
    INDEX idx_admin (id_admin)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- ============================================
-- 5. MODEL USER SECURITY HISTORY
-- ============================================

CREATE TABLE user_security_history (
    id_history INT AUTO_INCREMENT PRIMARY KEY,
    nim VARCHAR(15) NOT NULL,
    
    event_type ENUM('blocked', 'unblocked', 'monitoring_start', 'monitoring_end', 'password_reset') NOT NULL,
    event_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    triggered_by ENUM('system', 'admin') NOT NULL,
    admin_id INT NULL,
    
    reason TEXT NULL,
    metadata JSON NULL,
    
    FOREIGN KEY (nim) REFERENCES mahasiswa(nim) ON DELETE CASCADE,
    FOREIGN KEY (admin_id) REFERENCES admin(id_admin) ON DELETE SET NULL,
    
    INDEX idx_nim (nim),
    INDEX idx_event_type (event_type),
    INDEX idx_event_time (event_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;