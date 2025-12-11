import re
from datetime import datetime, timedelta, timezone
from user_agents import parse
from models.entities import LogLogin, Mahasiswa, DeteksiAnomali, DelayedLogin, UserSecurityHistory
from models import db
from sqlalchemy import func
import pytz
import traceback
import numpy as np 
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from backend.ml.detector import deteksi_anomali as ml_deteksi_anomali

# ==========================
# Feature Extraction & Scoring
# ==========================

def extract_features_from_request(request, nim=None):
    user_agent_string = request.headers.get('User-Agent', '')
    user_agent = parse(user_agent_string)
    
    # IP Address
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
    
    # Geo-location (simulasi - production pakai API GeoIP)
    lokasi = request.headers.get('X-Location', 'Unknown')
    country = request.headers.get('X-Country', 'ID')
    city = request.headers.get('X-City', 'Unknown')
    
    # Device info
    device = user_agent.device.family
    os_name = f"{user_agent.os.family} {user_agent.os.version_string}"
    browser = f"{user_agent.browser.family} {user_agent.browser.version_string}"
    
    import pytz
    jakarta_tz = pytz.timezone('Asia/Jakarta')
    waktu_login = datetime.now(jakarta_tz)  
    jam_login = waktu_login.hour  

    ip_frequency_raw = 1
    combo_frequency_raw = 1
    
    if nim:
        # 1. Ambil frekuensi MENTAH dari database 
        ip_frequency_raw = LogLogin.query.filter_by(nim=nim, ip_address=ip_address).count() + 1
        
        device_os_combo = f"{device}_{os_name}"
        combo_frequency_raw = LogLogin.query.filter_by(nim=nim).filter(
            func.concat(LogLogin.device, '_', LogLogin.os) == device_os_combo
        ).count() + 1
        
        # 2. Terapkan LOGARITMA untuk model ML 
        ip_frequency = np.log1p(ip_frequency_raw)
        combo_frequency = np.log1p(combo_frequency_raw)
    else:
        # Fallback jika nim tidak ada (gunakan nilai log1p(1) = 0.693)
        ip_frequency = np.log1p(1)
        combo_frequency = np.log1p(1)
    
    # Hitung score (0-1)
    ip_score = calculate_ip_score(ip_address)
    lokasi_score = calculate_lokasi_score(lokasi)
    device_score = calculate_device_score(device)
    os_score = calculate_os_score(os_name)
    browser_score = calculate_browser_score(browser)
    
    # Flag
    high_risk_countries = ['RU', 'CN', 'KP', 'IR', 'SY']
    is_high_risk_country = 1 if country in high_risk_countries else 0
    is_night_login = 1 if 0 <= jam_login <= 6 else 0
    
    # RAW DATA (untuk UI dan database - 4 kolom utama)
    raw_data = {
        'waktu_login': waktu_login,
        'ip_address': ip_address,
        'lokasi': f"{city}, {country}" if city != 'Unknown' else country,
        'device': device,
        'os': os_name,
        'browser': browser,
        'ip_frequency_raw': ip_frequency_raw,
        'combo_frequency_raw': combo_frequency_raw,
    }
    
    # ML FEATURES (10 fitur untuk model)
    ml_features = {
        'ip_score': ip_score,
        'lokasi_score': lokasi_score,
        'device_score': device_score,
        'os_score': os_score,
        'browser_score': browser_score,
        'jam_login': jam_login,
        'ip_frequency': ip_frequency,        
        'combo_frequency': combo_frequency, 
        'is_high_risk_country': is_high_risk_country,
        'is_night_login': is_night_login,
    }
    
    return {
        'raw_data': raw_data,
        'ml_features': ml_features
    }

# ==========================
# Scoring Rules (0-1)
# ==========================

def calculate_ip_score(ip_address):
    """0.0 = private/public (normal), 1.0 = unknown"""
    if not ip_address:
        return 1.0
    private_prefixes = ['10.', '172.', '192.168.', '127.']
    if any(ip_address.startswith(prefix) for prefix in private_prefixes):
        return 0.0
    return 0.0 
def calculate_lokasi_score(lokasi):
    """0 = lengkap, 1 = tidak lengkap"""
    if not lokasi or lokasi == 'Unknown':
        return 1.0
    parts = [p.strip() for p in lokasi.split(',') if p.strip()]
    if len(parts) >= 2:  
        return 0.0
    return 1.0

def calculate_device_score(device):
    """0 = Desktop, 0.25 = Mobile/Tablet, 1.0 = Other/Unknown"""
    if not device or device == 'Other' or device == 'Unknown':
        return 1.0

    if 'Desktop' in device or 'PC' in device:
        return 0.0

    if 'Mobile' in device or 'Tablet' in device:
        return 0.25
        
    return 1.0 

def calculate_os_score(os_name):
    """0 = common OS, 0.5 = uncommon"""
    if not os_name:
        return 1.0
    common_os = ['Windows', 'Mac OS', 'Ubuntu', 'Linux', 'Android', 'iOS']
    if any(os in os_name for os in common_os):
        return 0.0
    return 0.5

def calculate_browser_score(browser):
    """0 = common browser, 0.5 = uncommon"""
    if not browser:
        return 1.0
    common_browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera']
    if any(b in browser for b in common_browsers):
        return 0.0
    return 0.5

# ==========================
# ML Detection (4-Level Risk)
# ==========================

def detect_anomaly_with_ml(ml_features):
    try:
        result = ml_deteksi_anomali(ml_features)
        return result
    except Exception as e:
        print(f"ML Detection Error: {e}")
        traceback.print_exc()
        return fallback_rule_based_detection(ml_features)
    
def fallback_rule_based_detection(ml_features):
    score = 0.0
    
    score += ml_features.get('lokasi_score', 0.0) * 0.1
    score += ml_features.get('device_score', 0.0) * 0.05
    score += ml_features.get('os_score', 0.0) * 0.05
    score += ml_features.get('browser_score', 0.0) * 0.05
    
    if ml_features.get('is_high_risk_country') == 1:
        score += 0.2
    if ml_features.get('is_night_login') == 1:
        score += 0.1
    
    # IP baru (frekuensi logaritmik sangat rendah)
    if ml_features.get('ip_frequency', np.log1p(1)) <= np.log1p(2): 
        score += 0.1
        
    # LOGIKA CLASSIFICATION
    if score >= 0.4:
        risk_level = 'kritis'
        action = 'blokir'
        delay_seconds = 0
        require_admin = True
        auto_block = True
        message = 'Login diblokir karena aktivitas sangat mencurigakan.'
    elif score >= 0.2:
        risk_level = 'tinggi'
        action = 'tunda'
        delay_seconds = 60
        require_admin = True
        auto_block = False
        message = 'Login akan ditunda karena aktivitas mencurigakan.'
    elif score >= 0.1:
        risk_level = 'sedang'
        action = 'peringatan'
        delay_seconds = 0
        require_admin = False
        auto_block = False
        message = 'Peringatan: Terdeteksi pola login sedikit tidak biasa.'
    else:
        risk_level = 'rendah'
        action = 'izinkan'
        delay_seconds = 0
        require_admin = False
        auto_block = False
        message = 'Login berhasil. Pola login normal.'
    
    return {
        'score': score,
        'risk_level': risk_level,
        'action': action,
        'delay_seconds': delay_seconds,
        'require_admin': require_admin,
        'auto_block': auto_block,
        'message': message,
        'detail': 'Deteksi menggunakan rule-based (ML model tidak tersedia)'
    }

def map_risk_to_hasil_deteksi(risk_level):
    """Map risk_level ke hasil_deteksi enum"""
    mapping = {
        'rendah': 'normal',
        'sedang': 'peringatan',
        'tinggi': 'tunda',
        'kritis': 'blokir'
    }
    return mapping.get(risk_level, 'normal')

def log_successful_login_with_detection(nim, request):
    try:
        # 1. Ekstrak fitur
        features = extract_features_from_request(request, nim)
        raw_data = features['raw_data']
        ml_features = features['ml_features']
        
        print(f"\n{'='*60}")
        print(f"LOGIN BERHASIL: {nim}")
        print(f"{'='*60}")
        
        # 2. Deteksi anomali dengan ML
        ml_result = detect_anomaly_with_ml(ml_features)
        
        print(f"Skor Anomali    : {ml_result['score']:.4f}")
        print(f"Risk Level      : {ml_result['risk_level'].upper()}")
        print(f"Action          : {ml_result['action'].upper()}")
        print(f"Require Admin   : {'YA' if ml_result['require_admin'] else 'TIDAK'}")
        print(f"Auto Block      : {'YA' if ml_result['auto_block'] else 'TIDAK'}")
        
        # 3. Simpan log login
        log = LogLogin(
            nim=nim,
            waktu_login=raw_data['waktu_login'],
            ip_address=raw_data['ip_address'],
            lokasi=raw_data['lokasi'],
            device=raw_data['device'],
            os=raw_data['os'],
            browser=raw_data['browser'],
            
            # ML Features (hidden)
            ip_score=ml_features['ip_score'],
            lokasi_score=ml_features['lokasi_score'],
            device_score=ml_features['device_score'],
            os_score=ml_features['os_score'],
            browser_score=ml_features['browser_score'],
            jam_login=ml_features['jam_login'],
            ip_frequency=ml_features['ip_frequency'],
            combo_frequency=ml_features['combo_frequency'],
            is_high_risk_country=ml_features['is_high_risk_country'],
            is_night_login=ml_features['is_night_login'],
            
            # Status
            status_login='berhasil',
            hasil_deteksi=map_risk_to_hasil_deteksi(ml_result['risk_level']),
            skor_anomali=ml_result['score'],
            keterangan=ml_result['message']
        )
        db.session.add(log)
        db.session.flush()
        
        print(f"Log disimpan: ID {log.id_log}")
        
        # 4. Simpan deteksi anomali (untuk risk: sedang, tinggi, kritis)
        if ml_result['risk_level'] in ['sedang', 'tinggi', 'kritis']:
            deteksi = DeteksiAnomali(
                id_log=log.id_log,
                waktu_deteksi=datetime.now(timezone.utc),
                skor_anomali=ml_result['score'],
                tingkat_risiko=ml_result['risk_level'],
                tindakan_otomatis=ml_result['action'],
                delay_seconds=ml_result['delay_seconds'],
                require_admin=ml_result['require_admin'],
                auto_block=ml_result['auto_block'],
                message_to_user=ml_result['message'],
                detail_anomali=ml_result.get('detail', ''),
                status_tinjauan='belum_ditinjau' if ml_result['require_admin'] else 'ditinjau'
            )
            db.session.add(deteksi)
            print(f"Deteksi anomali disimpan: {ml_result['risk_level'].upper()}")
        
        # 5. Handle actions
        mahasiswa = Mahasiswa.query.filter_by(nim=nim).first()
        
        if ml_result['action'] == 'blokir':
            # Auto block
            mahasiswa.status_akun = 'diblokir'
            mahasiswa.diblokir_pada = datetime.now(timezone.utc)
            mahasiswa.alasan_blokir = 'Blokir otomatis: Anomali kritis terdeteksi'
            mahasiswa.diblokir_oleh = 'system'
            
            # Log security event
            log_security_event(nim, 'blocked', 'system', ml_result['message'])
            
            print(f"Akun {nim} DIBLOKIR otomatis")
        
        elif ml_result['action'] == 'tunda':
            # Delayed login
            delayed = create_delayed_login(
                nim=nim,
                id_log=log.id_log,
                delay_seconds=ml_result['delay_seconds'],
                ip_address=raw_data['ip_address'],
                user_agent=request.headers.get('User-Agent', '')
            )
            
            # Set monitoring
            mahasiswa.dalam_pantauan = True
            mahasiswa.pantauan_mulai = datetime.now(timezone.utc)
            
            # Log security event
            log_security_event(nim, 'monitoring_start', 'system', 'Login ditunda, masuk pantauan')
            
            print(f"Login ditunda: {ml_result['delay_seconds']} detik")
            print(f"Masuk pantauan admin")
        
        elif ml_result['action'] == 'peringatan':
            # Set monitoring (optional untuk sedang)
            mahasiswa.dalam_pantauan = True
            mahasiswa.pantauan_mulai = datetime.now(timezone.utc)
            print(f"Peringatan diberikan, masuk pantauan ringan")
        
        # Update last login
        mahasiswa.terakhir_login = raw_data['waktu_login']
        mahasiswa.terakhir_ip = raw_data['ip_address']
        
        db.session.commit()
        print(f"Commit berhasil")
        print(f"{'='*60}\n")
        
        return log, ml_result
        
    except Exception as e:
        print(f"Error log successful login: {e}")
        traceback.print_exc()
        db.session.rollback()
        raise

def log_failed_login_with_detection(nim, request, reason):
    """
    Catat login gagal + deteksi brute force.
    """
    try:
        features = extract_features_from_request(request, nim)
        raw_data = features['raw_data']
        ml_features = features['ml_features'] 

        # Hitung percobaan gagal dalam 30 menit terakhir
        time_window = datetime.now(timezone.utc) - timedelta(minutes=30)
        failed_count = LogLogin.query.filter_by(
            nim=nim, status_login='gagal'
        ).filter(LogLogin.waktu_login >= time_window).count()
        
        percobaan_ke = failed_count + 1

        delay_seconds_bf = 0 
        id_delayed = None

        print(f"\n{'='*60}"); print(f"LOGIN GAGAL: {nim}"); print(f"{'='*60}")
        print(f"Percobaan ke    : {percobaan_ke}")
        print(f"Alasan          : {reason}")
        
        # Tentukan skor dan risiko berdasarkan brute force
        if percobaan_ke >= 6:
            skor_anomali = 0.5
            tingkat_risiko = 'kritis'
            hasil_deteksi = 'blokir'
            action_message = 'Akun diblokir karena terlalu banyak percobaan login gagal'
        elif percobaan_ke >= 4:
            skor_anomali = 0.0
            tingkat_risiko = 'tinggi'
            hasil_deteksi = 'tunda'
            delay_seconds_bf = 60 
            action_message = 'Login akan ditunda jika terus gagal'
        elif percobaan_ke >= 3:
            skor_anomali = -0.03
            tingkat_risiko = 'sedang'
            hasil_deteksi = 'peringatan'
            action_message = 'Peringatan: Terlalu banyak percobaan gagal'
        else:
            skor_anomali = -0.1
            tingkat_risiko = 'rendah'
            hasil_deteksi = 'normal'
            action_message = 'Login gagal (percobaan normal)'
        
        # Simpan log login gagal
        log = LogLogin(
            nim=nim, waktu_login=raw_data['waktu_login'], ip_address=raw_data['ip_address'],
            lokasi=raw_data['lokasi'], device=raw_data['device'], os=raw_data['os'],
            browser=raw_data['browser'], status_login='gagal', percobaan_ke=percobaan_ke,
            hasil_deteksi=hasil_deteksi, skor_anomali=skor_anomali,
            keterangan=f"{reason} (Percobaan ke-{percobaan_ke})",
            **{k: ml_features[k] for k in ml_features.keys()}
        )
        db.session.add(log); db.session.flush()
        
        # Simpan deteksi anomali untuk percobaan >= 3
        if percobaan_ke >= 3:
            deteksi = DeteksiAnomali(
                id_log=log.id_log, waktu_deteksi=datetime.now(timezone.utc), skor_anomali=skor_anomali,
                tingkat_risiko=tingkat_risiko, tindakan_otomatis=hasil_deteksi,
                delay_seconds=delay_seconds_bf, # Menggunakan nilai delay yang sudah disetel (0 atau 60)
                message_to_user=action_message, detail_anomali=f"Brute force detection: {percobaan_ke} percobaan gagal dalam 30 menit",
                require_admin=True if hasil_deteksi in ['blokir', 'tunda'] else False,
                auto_block=True if hasil_deteksi == 'blokir' else False,
                status_tinjauan='belum_ditinjau'
            )
            db.session.add(deteksi)

        if hasil_deteksi == 'tunda':
            delayed_record = create_delayed_login(
                nim=nim, id_log=log.id_log, delay_seconds=delay_seconds_bf, 
                ip_address=raw_data['ip_address'], user_agent=request.headers.get('User-Agent', '')
            )
            id_delayed = delayed_record.id_delayed
        
        # Blokir akun jika >= 6 percobaan
        if hasil_deteksi == 'blokir':
            mahasiswa = Mahasiswa.query.filter_by(nim=nim).first()
            if mahasiswa:
                mahasiswa.status_akun = 'diblokir'; mahasiswa.diblokir_pada = datetime.now(timezone.utc)
                mahasiswa.alasan_blokir = f'Blokir otomatis: {percobaan_ke} percobaan login gagal'; mahasiswa.diblokir_oleh = 'system'
                log_security_event(nim, 'blocked', 'system', action_message)
        
        db.session.commit()
        print(f"Commit berhasil"); print(f"{'='*60}\n")
        
        # --- RETURN AKHIR (FIXED TYPO) ---
        return {
            'action': hasil_deteksi,
            'message': action_message,
            'id_delayed': id_delayed,
            'delay_seconds': delay_seconds_bf
        }
        
    except Exception as e:
        print(f"Error log failed login: {e}")
        traceback.print_exc()
        db.session.rollback()
        return {'action': 'normal', 'message': 'System error, login failed.'}

# ==========================
# Delayed Login Operations
# ==========================

def create_delayed_login(nim, id_log, delay_seconds, ip_address, user_agent):
    """Buat entry delayed login"""
    delay_end = datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
    
    delayed = DelayedLogin(
        nim=nim,
        id_log=id_log,
        delay_seconds=delay_seconds,
        delay_start=datetime.now(timezone.utc),
        delay_end=delay_end,
        status_delay='waiting',
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.session.add(delayed)
    db.session.flush()
    
    return delayed

def check_delayed_login_status(id_delayed):
    """Check status delayed login"""
    delayed = DelayedLogin.query.filter_by(id_delayed=id_delayed).first()
    if not delayed:
        return None
    
    now = datetime.now(timezone.utc)
    
    if delayed.status_delay == 'completed':
        return {'status': 'completed', 'can_login': True}
    
    if delayed.status_delay == 'cancelled':
        return {'status': 'cancelled', 'can_login': False}
    
    if now >= delayed.delay_end:
        # Waktu tunda selesai
        delayed.status_delay = 'completed'
        db.session.commit()
        return {'status': 'completed', 'can_login': True}
    else:
        # Masih dalam periode tunda
        remaining = (delayed.delay_end - now).total_seconds()
        return {
            'status': 'waiting',
            'can_login': False,
            'remaining_seconds': int(remaining),
            'delay_end': delayed.delay_end.isoformat()
        }

# ==========================
# Security Event Logging
# ==========================

def log_security_event(nim, event_type, triggered_by, reason, admin_id=None, metadata=None):
    """Log security event ke history"""
    try:
        history = UserSecurityHistory(
            nim=nim,
            event_type=event_type,
            triggered_by=triggered_by,
            admin_id=admin_id,
            reason=reason,
            metadata=metadata
        )
        db.session.add(history)
        db.session.flush()
        return history
    except Exception as e:
        print(f"Error log security event: {e}")
        return None

# ==========
# Validators
# ==========

def validate_nim(nim):
    if not nim:
        return False, "NIM tidak boleh kosong"
    if not re.match(r'^[A-Za-z0-9]{8,15}$', nim):
        return False, "Format NIM tidak valid (8-15 karakter alfanumerik)"
    return True, "Valid"

def validate_email(email):
    if not email:
        return False, "Email tidak boleh kosong"
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Format email tidak valid"
    return True, "Valid"

def validate_password(password):
    if not password:
        return False, "Password tidak boleh kosong"
    if len(password) < 8:
        return False, "Password minimal 8 karakter"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password harus mengandung huruf"
    if not re.search(r'\d', password):
        return False, "Password harus mengandung angka"
    return True, "Valid"

def validate_tindakan(tindakan):
    valid_tindakan = ['reset_password', 'blokir_permanen', 'buka_blokir', 'hapus_pantauan', 'abaikan']
    if tindakan not in valid_tindakan:
        return False, f"Tindakan tidak valid. Pilihan: {', '.join(valid_tindakan)}"
    return True, "Valid"

# ==========================
# Response Formatter
# ==========================

def format_login_response(log, ml_result):
    """Format response untuk API login"""
    status_map = {
        'izinkan': 'success',
        'peringatan': 'success_with_warning',
        'tunda': 'delayed',
        'blokir': 'blocked'
    }
    
    return {
        'status': status_map.get(ml_result['action'], 'success'),
        'message': ml_result['message'],
        'data': {
            'id_log': log.id_log,
            'nim': log.nim,
            'waktu_login': log.waktu_login.isoformat(),
            'skor_anomali': round(ml_result['score'], 3),
            'tingkat_risiko': ml_result['risk_level'],
            'tindakan': ml_result['action'],
            'ip_address': log.ip_address,
            'delay_seconds': ml_result.get('delay_seconds', 0)
        }
    }
