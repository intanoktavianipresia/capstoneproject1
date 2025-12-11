import os
import joblib
import numpy as np

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_DIR = os.path.join(BASE_DIR, "ml", "save_model")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
STATS_PATH = os.path.join(MODEL_DIR, "training_stats.pkl")

FEATURE_COLUMNS = [
    "ip_score", "lokasi_score", "device_score", "os_score",
    "browser_score", "jam_login", "ip_frequency", 
    "is_high_risk_country", "is_night_login", "combo_frequency"
]

# Cache untuk performa
_model_cache = None
_scaler_cache = None
_stats_cache = None


def load_model():
    """Load model, scaler, dan stats (dengan caching)"""
    global _model_cache, _scaler_cache, _stats_cache
    
    if _model_cache is not None:
        return _model_cache, _scaler_cache, _stats_cache
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Model belum dilatih! File tidak ditemukan: {MODEL_PATH}\n"
            "Jalankan: python backend/ml/training.py"
        )
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(f"Scaler tidak ditemukan: {SCALER_PATH}")
    if not os.path.exists(STATS_PATH):
        raise FileNotFoundError(f"Training stats tidak ditemukan: {STATS_PATH}")
    
    _model_cache = joblib.load(MODEL_PATH)
    _scaler_cache = joblib.load(SCALER_PATH)
    _stats_cache = joblib.load(STATS_PATH)
    
    print("Model ML berhasil dimuat")
    return _model_cache, _scaler_cache, _stats_cache


def deteksi_anomali(data_login: dict) -> dict:
    """
    Deteksi anomali login dengan 4-level risk classification (SKOR DIBALIK).
    """
    try:
        model, scaler, stats = load_model()
    except FileNotFoundError as e:
        print(str(e))
        return {
            'score': 0.8, 
            'risk_level': 'rendah',
            'action': 'izinkan',
            'delay_seconds': 0,
            'require_admin': False,
            'auto_block': False,
            'message': 'Model ML belum tersedia. Menggunakan klasifikasi default.',
            'detail': 'Model belum di-training'
        }
    
    missing_features = [col for col in FEATURE_COLUMNS if col not in data_login]
    if missing_features:
        raise ValueError(f"Fitur tidak lengkap! Hilang: {missing_features}")
    
    X = np.array([data_login[col] for col in FEATURE_COLUMNS]).reshape(1, -1)
    X_scaled = scaler.transform(X)
 
    raw_score = model.decision_function(X_scaled)[0]
    
    # REVISI KRUSIAL: BALIKKAN SKOR
    anomaly_score = -raw_score 

    classification = classify_risk(anomaly_score, stats, data_login) 
    
    return {
        'score': float(anomaly_score),
        **classification 
    }


def classify_risk(score: float, stats: dict = None, data_input: dict = None) -> dict:
    
    # Load stats
    if stats is None:
        try:
            _, _, stats = load_model()
        except:
            stats = {
                'threshold_rendah_min': 0.15, 'threshold_sedang_min': 0.05, 'threshold_tinggi_min': -0.05
            }
    
    p75 = stats.get('threshold_rendah_min', 0.15)
    p50 = stats.get('threshold_sedang_min', 0.05)
    p25 = stats.get('threshold_tinggi_min', -0.05)
    
    # === DEBUGGING: CETAK NILAI KRUSIAL ===
    print(f"\n[DEBUG CLASSIFY] Score Masuk: {score:.4f}")
    print(f"[DEBUG CLASSIFY] Thresholds: RENDAH>={p75:.4f}, SEDANG>={p50:.4f}, TINGGI>={p25:.4f}")

    # ========================================
    # HARD RULE: KRITIS MUTLAK (PRIORITAS TERTINGGI)
    # ========================================
    if data_input:
        is_lokasi = data_input.get('lokasi_score', 0.0) == 1.0
        is_country = data_input.get('is_high_risk_country', 0) == 1
        is_night = data_input.get('is_night_login', 0) == 1
        is_ip_baru = data_input.get('ip_frequency', 1.0) <= 1.0
        
        # CETAK KONDISI HARD RULE
        print(f"[DEBUG HARD] Lokasi: {is_lokasi}, Country: {is_country}, Night: {is_night}, IP Baru: {is_ip_baru}")
        
        is_hard_anomaly = is_lokasi and is_country and is_night and is_ip_baru

        if is_hard_anomaly:
            print("[DEBUG HARD] 🟢 KRITIS MUTLAK TERDETEKSI!")
            return {
                'risk_level': 'kritis',
                'action': 'blokir',
                'delay_seconds': 0,
                'require_admin': True,
                'auto_block': True,
                'message': 'Login diblokir karena kombinasi anomali berat terdeteksi (Hard Rule).',
                'detail': 'Deteksi Kritis Mutlak: Lokasi Hilang/Berisiko + Negara Berisiko Tinggi + Jam Malam + IP Baru.'
            }
        else:
            print("[DEBUG HARD] Hard Rule tidak terpenuhi.")
    
    # ========================================
    # LOGIKA ML KLASIFIKASI 4-LEVEL (DIBALIKKAN)
    # ========================================
    
    if score >= p75:
        print(f"[DEBUG ML] Score {score:.4f} >= {p75:.4f}. Klasifikasi: RENDAH")
        return {
            'risk_level': 'rendah',
            'action': 'izinkan',
            'delay_seconds': 0,
            'require_admin': False,
            'auto_block': False,
            'message': 'Login berhasil. Pola login sesuai dengan histori normal Anda.',
            'detail': 'Tidak ada anomali terdeteksi. Semua atribut login sesuai pola biasa.'
        }
    
    elif score >= p50:
        print(f"[DEBUG ML] Score {score:.4f} >= {p50:.4f}. Klasifikasi: SEDANG")
        return {
            'risk_level': 'sedang',
            'action': 'peringatan',
            'delay_seconds': 0,
            'require_admin': False,
            'auto_block': False,
            'message': ('Peringatan: Terdeteksi pola login sedikit tidak biasa (misalnya IP atau perangkat baru). Login tetap diizinkan.'),
            'detail': ('Beberapa atribut login berbeda dari biasanya, namun masih dalam batas wajar. Sistem akan memantau aktivitas Anda.')
        }
    
    elif score >= p25:
        print(f"[DEBUG ML] Score {score:.4f} >= {p25:.4f}. Klasifikasi: TINGGI")
        return {
            'risk_level': 'tinggi',
            'action': 'tunda',
            'delay_seconds': 60,
            'require_admin': True,
            'auto_block': False,
            'message': ('Login ditunda 1 menit karena aktivitas tidak biasa terdeteksi. Akun Anda akan masuk dalam sistem pantauan admin.'),
            'detail': ('Pola login mencurigakan: IP atau perangkat baru dengan waktu login tidak biasa. Sistem perlu verifikasi tambahan.')
        }
    
    else:
        print(f"[DEBUG ML] Score {score:.4f} < {p25:.4f}. Klasifikasi: KRITIS")
        return {
            'risk_level': 'kritis',
            'action': 'blokir',
            'delay_seconds': 0,
            'require_admin': True,
            'auto_block': True,
            'message': ('Login diblokir karena terdeteksi aktivitas sangat mencurigakan. Hubungi admin untuk membuka blokir.'),
            'detail': ('Anomali berat terdeteksi: kombinasi IP, perangkat, dan pola waktu tidak sesuai dengan histori normal Anda.')
        }


def get_model_info():
    """Informasi model untuk debugging / admin dashboard"""
    try:
        model, scaler, stats = load_model()
        return {
            'status': 'loaded',
            'model_type': str(type(model).__name__),
            'n_estimators': getattr(model, 'n_estimators', 'N/A'),
            'contamination': getattr(model, 'contamination', 'N/A'),
            'thresholds': {
                'rendah': stats.get('threshold_rendah_min'), 
                'sedang': stats.get('threshold_sedang_min'), 
                'tinggi': stats.get('threshold_tinggi_min'), 
                'kritis': f"<{stats.get('threshold_tinggi_min')}"
            },
            'score_range': {
                'min': stats.get('score_min'),
                'max': stats.get('score_max'),
                'mean': stats.get('score_mean'),
                'std': stats.get('score_std'),
            },
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def hitung_skor_anomali(data_login: dict) -> float:
    """Alias untuk compatibility - hanya return skor"""
    result = deteksi_anomali(data_login)
    return result['score']