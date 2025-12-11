from datetime import datetime, timezone
from extensions import db


# ================
# MODEL MAHASISWA (Kolom tunda_sampai/alasan dihapus)
# ================

class Mahasiswa(db.Model):
    __tablename__ = 'mahasiswa'

    nim = db.Column(db.String(15), primary_key=True)
    nama = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    status_akun = db.Column(
        db.Enum('aktif', 'diblokir', 'ditunda'),
        default='aktif',
        nullable=False
    )
    
    jumlah_gagal = db.Column(db.Integer, default=0)
    # Tunda dihapus karena diganti DelayedLogin
    # tunda_sampai = db.Column(db.DateTime, nullable=True)
    # tunda_alasan = db.Column(db.String(255), nullable=True)
    
    # Security metadata
    diblokir_pada = db.Column(db.DateTime, nullable=True)
    alasan_blokir = db.Column(db.Text, nullable=True)
    diblokir_oleh = db.Column(db.Enum('system', 'admin'), nullable=True)
    
    dalam_pantauan = db.Column(db.Boolean, default=False)
    pantauan_mulai = db.Column(db.DateTime, nullable=True)
    pantauan_selesai = db.Column(db.DateTime, nullable=True)
    
    terakhir_login = db.Column(db.DateTime, nullable=True)
    terakhir_ip = db.Column(db.String(100), nullable=True)
    
    tanggal_daftar = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # Relationships
    logins = db.relationship(
        'LogLogin',
        backref='mahasiswa',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    delayed_logins = db.relationship(
        'DelayedLogin',
        backref='mahasiswa',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    security_history = db.relationship(
        'UserSecurityHistory',
        backref='mahasiswa',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    # ... (repr dan to_dict tetap sama) ...
    def __repr__(self):
        return f"<Mahasiswa {self.nim} - {self.nama}>"
    
    def to_dict(self):
        return {
            'nim': self.nim,
            'nama': self.nama,
            'email': self.email,
            'status_akun': self.status_akun,
            'tanggal_daftar': self.tanggal_daftar.isoformat() if self.tanggal_daftar else None,
            'jumlah_gagal': self.jumlah_gagal,
            'dalam_pantauan': self.dalam_pantauan,
            'terakhir_login': self.terakhir_login.isoformat() if self.terakhir_login else None,
        }


# ===========
# MODEL ADMIN
# ===========

class Admin(db.Model):
    __tablename__ = 'admin'
    
    # ... (tetap sama) ...
    id_admin = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nama_admin = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(
        db.Enum('superadmin', 'staff', 'admin'),
        default='staff',
        nullable=False
    )

    # Relationships
    keputusan = db.relationship(
        'KeputusanAdmin',
        backref='admin',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    security_actions = db.relationship(
        'UserSecurityHistory',
        backref='admin',
        lazy=True,
        foreign_keys='UserSecurityHistory.admin_id'
    )
    
    def __repr__(self):
        return f"<Admin {self.username} ({self.role})>"
    
    def to_dict(self):
        return {
            'id_admin': self.id_admin,
            'nama_admin': self.nama_admin,
            'username': self.username,
            'email': self.email,
            'role': self.role
        }


# ===============
# MODEL LOG LOGIN (ip_frequency/combo_frequency diubah ke Float)
# ===============

class LogLogin(db.Model):
    __tablename__ = 'log_login'

    id_log = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nim = db.Column(
        db.String(15),
        db.ForeignKey('mahasiswa.nim', ondelete='CASCADE'),
        nullable=False
    )
    waktu_login = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    
    # Raw data (untuk UI)
    ip_address = db.Column(db.String(100))
    lokasi = db.Column(db.String(200))
    device = db.Column(db.String(200))
    os = db.Column(db.String(200))
    browser = db.Column(db.String(200))
    
    # 10 Fitur ML (hidden) - REVISI KE FLOAT
    ip_score = db.Column(db.Float, default=0.0)
    lokasi_score = db.Column(db.Float, default=0.0)
    device_score = db.Column(db.Float, default=0.0)
    os_score = db.Column(db.Float, default=0.0)
    browser_score = db.Column(db.Float, default=0.0)
    jam_login = db.Column(db.Integer, default=0)
    ip_frequency = db.Column(db.Float, default=0.693147) # LOG(1+1)
    combo_frequency = db.Column(db.Float, default=0.693147) # LOG(1+1)
    is_high_risk_country = db.Column(db.Boolean, default=False)
    is_night_login = db.Column(db.Boolean, default=False)
    
    status_login = db.Column(
        db.Enum('berhasil', 'gagal'),
        nullable=False
    )
    percobaan_ke = db.Column(db.Integer, default=1)
    hasil_deteksi = db.Column(
        db.Enum('normal', 'peringatan', 'tunda', 'blokir', 'izinkan'),
        default='normal',
        nullable=False
    )
    skor_anomali = db.Column(db.Float, default=0.0)
    keterangan = db.Column(db.Text)

    # Relationships
    deteksi = db.relationship(
        'DeteksiAnomali',
        backref='log_login',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    # ... (repr dan to_dict tetap sama) ...
    def __repr__(self):
        return f"<LogLogin ID={self.id_log} NIM={self.nim} Status={self.status_login}>"
    
    def to_dict(self):
        return {
            'id_log': self.id_log,
            'nim': self.nim,
            'waktu_login': self.waktu_login.isoformat() if self.waktu_login else None,
            'ip_address': self.ip_address,
            'lokasi': self.lokasi,
            'device': self.device,
            'os': self.os,
            'browser': self.browser,
            'status_login': self.status_login,
            'percobaan_ke': self.percobaan_ke,
            'hasil_deteksi': self.hasil_deteksi,
            'skor_anomali': round(self.skor_anomali, 3) if self.skor_anomali else 0.0,
            'keterangan': self.keterangan
        }


# =====================
# MODEL DETEKSI ANOMALI
# =====================

class DeteksiAnomali(db.Model):
    __tablename__ = 'deteksi_anomali'
    
    # ... (tetap sama) ...
    id_deteksi = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_log = db.Column(
        db.Integer,
        db.ForeignKey('log_login.id_log', ondelete='CASCADE'),
        nullable=False
    )
    waktu_deteksi = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    skor_anomali = db.Column(db.Float, nullable=False)
    
    # 4-level risk
    tingkat_risiko = db.Column(
        db.Enum('rendah', 'sedang', 'tinggi', 'kritis'), 
        nullable=False
    )
    tindakan_otomatis = db.Column(
        db.Enum('izinkan', 'peringatan', 'tunda', 'blokir'),
        nullable=False
    )
    
    # Detail action
    delay_seconds = db.Column(db.Integer, default=0)
    require_admin = db.Column(db.Boolean, default=False)
    auto_block = db.Column(db.Boolean, default=False)
    message_to_user = db.Column(db.Text)
    detail_anomali = db.Column(db.Text)
    
    status_tinjauan = db.Column(
        db.Enum('belum_ditinjau', 'ditinjau'),
        default='belum_ditinjau',
        nullable=False
    )

    # Relationships
    keputusan_admin = db.relationship(
        'KeputusanAdmin',
        backref='deteksi',
        lazy=True,
        cascade="all, delete-orphan"
    )
    
    def __repr__(self):
        return f"<DeteksiAnomali {self.id_deteksi} | Risiko={self.tingkat_risiko}>"
    
    def to_dict(self):
        return {
            'id_deteksi': self.id_deteksi,
            'id_log': self.id_log,
            'waktu_deteksi': self.waktu_deteksi.isoformat() if self.waktu_deteksi else None,
            'skor_anomali': round(self.skor_anomali, 3),
            'tingkat_risiko': self.tingkat_risiko,
            'tindakan_otomatis': self.tindakan_otomatis,
            'delay_seconds': self.delay_seconds,
            'require_admin': self.require_admin,
            'auto_block': self.auto_block,
            'message_to_user': self.message_to_user,
            'status_tinjauan': self.status_tinjauan
        }


# =====================
# MODEL KEPUTUSAN ADMIN
# =====================

class KeputusanAdmin(db.Model):
    __tablename__ = 'keputusan_admin'
    
    # ... (tetap sama) ...
    id_keputusan = db.Column(db.Integer, primary_key=True, autoincrement=True)
    id_deteksi = db.Column(
        db.Integer,
        db.ForeignKey('deteksi_anomali.id_deteksi', ondelete='CASCADE'),
        nullable=False
    )
    id_admin = db.Column(
        db.Integer,
        db.ForeignKey('admin.id_admin', ondelete='CASCADE'),
        nullable=False
    )
    waktu_keputusan = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    
    jenis_tindakan = db.Column(
        db.Enum('reset_password', 'blokir_permanen', 'buka_blokir', 'hapus_pantauan', 'abaikan'),
        nullable=False
    )
    catatan_admin = db.Column(db.Text)
    
    def __repr__(self):
        return f"<KeputusanAdmin {self.id_keputusan} | Tindakan={self.jenis_tindakan}>"
    
    def to_dict(self):
        return {
            'id_keputusan': self.id_keputusan,
            'id_deteksi': self.id_deteksi,
            'id_admin': self.id_admin,
            'waktu_keputusan': self.waktu_keputusan.isoformat() if self.waktu_keputusan else None,
            'jenis_tindakan': self.jenis_tindakan,
            'catatan_admin': self.catatan_admin
        }


# ===================
# MODEL DELAYED LOGIN 
# ===================

class DelayedLogin(db.Model):
    """Model untuk tracking countdown tunda login"""
    __tablename__ = 'delayed_logins'

    id_delayed = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nim = db.Column(
        db.String(15),
        db.ForeignKey('mahasiswa.nim', ondelete='CASCADE'),
        nullable=False
    )
    id_log = db.Column(
        db.Integer,
        db.ForeignKey('log_login.id_log', ondelete='SET NULL'),
        nullable=True
    )
    
    delay_seconds = db.Column(db.Integer, default=60, nullable=False)
    delay_start = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    delay_end = db.Column(db.DateTime, nullable=False)
    
    status_delay = db.Column(
        db.Enum('waiting', 'completed', 'cancelled', 'expired'),
        default='waiting',
        nullable=False
    )
    
    ip_address = db.Column(db.String(100))
    user_agent = db.Column(db.Text)
    
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    
    def __repr__(self):
        return f"<DelayedLogin {self.id_delayed} | NIM={self.nim} Status={self.status_delay}>"
    
    def to_dict(self):
        return {
            'id_delayed': self.id_delayed,
            'nim': self.nim,
            'id_log': self.id_log,
            'delay_seconds': self.delay_seconds,
            'delay_start': self.delay_start.isoformat() if self.delay_start else None,
            'delay_end': self.delay_end.isoformat() if self.delay_end else None,
            'status_delay': self.status_delay,
            'ip_address': self.ip_address,
        }


# ===========================
# MODEL USER SECURITY HISTORY 
# ===========================

class UserSecurityHistory(db.Model):
    __tablename__ = 'user_security_history'
    
    id_history = db.Column(db.Integer, primary_key=True, autoincrement=True)
    nim = db.Column(db.String(15), db.ForeignKey('mahasiswa.nim', ondelete='CASCADE'), nullable=False)
    
    event_type = db.Column(
        db.Enum('blocked', 'unblocked', 'monitoring_start', 'monitoring_end', 'password_reset', name='security_event_type'),
        nullable=False
    )
    event_time = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    
    triggered_by = db.Column(
        db.Enum('system', 'admin', name='triggered_by_type'),
        nullable=False
    )
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id_admin', ondelete='SET NULL'), nullable=True)
    
    reason = db.Column(db.Text, nullable=True)
    
    meta_data = db.Column(db.JSON, nullable=True)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_nim_security', 'nim'),
        db.Index('idx_event_type', 'event_type'),
        db.Index('idx_event_time', 'event_time'),
    )
    
    def to_dict(self):
        return {
            'id_history': self.id_history,
            'nim': self.nim,
            'event_type': self.event_type,
            'event_time': self.event_time.isoformat() if self.event_time else None,
            'triggered_by': self.triggered_by,
            'admin_id': self.admin_id,
            'reason': self.reason,
            'metadata': self.metadata 
        }