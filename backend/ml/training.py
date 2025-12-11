import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
PROCESSED_PATH = os.path.join(BASE_DIR, "data", "processed", "dataset_processed.csv")
HYBRID_DIR = os.path.join(BASE_DIR, "data", "processed")
HYBRID_PATH = os.path.join(HYBRID_DIR, "dataset_hybrid.csv")
MODEL_DIR = os.path.join(BASE_DIR, "backend", "ml", "save_model")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
STATS_PATH = os.path.join(MODEL_DIR, "training_stats.pkl")

FEATURE_COLUMNS = [
    "ip_score", "lokasi_score", "device_score", "os_score",
    "browser_score", "jam_login", "ip_frequency", 
    "is_high_risk_country", "is_night_login", "combo_frequency"
]

def train_isolation_forest(dataset_path=PROCESSED_PATH):
    print("=" * 70)
    print("TRAINING ISOLATION FOREST MODEL (KONVENSI LAPORAN)")
    print("=" * 70)
    print(f"Dataset: {dataset_path}\n")
    
    # 1. VALIDASI FILE
    if not os.path.exists(dataset_path):
        print(f"Dataset tidak ditemukan!")
        print(f"Jalankan dulu: python backend/ml/preprocessing.py")
        return

    # 2. LOAD DATA
    df = pd.read_csv(dataset_path)
    X = df[FEATURE_COLUMNS].values
    
    # 3. STANDARISASI
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # 4. TRAINING MODEL 
    print("Training Isolation Forest...")
    model = IsolationForest(
        n_estimators=250,
        contamination=0.15, 
        random_state=42,
        max_samples='auto',
        n_jobs=-1
    )
    model.fit(X_scaled)
    print("Training selesai!\n")
    
    # 5. HITUNG ANOMALY SCORES 
    print("Menghitung anomaly scores (DIBALIKKAN)...")
    anomaly_scores_raw = model.decision_function(X_scaled)
    anomaly_scores = -anomaly_scores_raw
    
    
    # 6. HITUNG THRESHOLD OPTIMAL 
    print("Menghitung threshold optimal (P75, P50, P25)...\n")
    
    # Menemukan batas percentile untuk 4 level risiko:
    p25 = np.percentile(anomaly_scores, 25) 
    p50 = np.percentile(anomaly_scores, 50) 
    p75 = np.percentile(anomaly_scores, 75) 
    
    # 7. SIAPKAN TRAINING STATS
    print("=" * 70)
    print("STATISTIK ANOMALY SCORES (DIBALIKKAN)")
    print("=" * 70)
    
    training_stats = {
        'score_min': float(np.min(anomaly_scores)),
        'score_max': float(np.max(anomaly_scores)),
        'threshold_rendah_min': float(p75),
        'threshold_sedang_min': float(p50), 
        'threshold_tinggi_min': float(p25), 
    }

    for key, value in training_stats.items():
        if key.startswith('score_') or key.startswith('threshold'):
            print(f"   {key:25s}: {value:8.4f}")

    # 8. KLASIFIKASI RISK LEVEL DENGAN THRESHOLD 
    print("\nMelakukan pelabelan dataset (Hybrid)...")
    risk_levels = []
    for score in anomaly_scores:
        if score >= p75:
            risk_level = 'rendah'
        elif score >= p50:
            risk_level = 'sedang'
        elif score >= p25:
            risk_level = 'tinggi'
        else: # Score < p25
            risk_level = 'kritis'
        risk_levels.append(risk_level)
    
    # 9. DISTRIBUSI RISK LEVEL
    print("\n" + "=" * 70)
    print("DISTRIBUSI RISK LEVEL")
    print("=" * 70)
    
    risk_counts = pd.Series(risk_levels).value_counts()
    total = len(risk_levels)
    
    for level in ['rendah', 'sedang', 'tinggi', 'kritis']:
        count = risk_counts.get(level, 0)
        pct = count / total * 100
        print(f" {level.upper():10s}: {count:6,d} ({pct:5.1f}%) [Target: ~25%]")
    
    # 11. SAVE MODEL
    print("\n" + "=" * 70)
    print("MENYIMPAN MODEL & STATS")
    print("=" * 70)
    
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(training_stats, STATS_PATH)
    
    print(f"Model : {MODEL_PATH}")
    print(f"Scaler: {SCALER_PATH}")
    print(f"Stats : {STATS_PATH}")
    
    # 12. BUAT HYBRID CSV
    df_hybrid = df.copy()
    df_hybrid['anomaly_score'] = anomaly_scores
    df_hybrid['risk_level'] = risk_levels
    df_hybrid.to_csv(HYBRID_PATH, index=False)

    print("\n" + "=" * 70)
    print("TRAINING SELESAI!")
    print("=" * 70)
    print("   Skor yang lebih BESAR berarti Risiko lebih RENDAH (Normal).")
    print(f" RENDAH (Normal) ≥ {p75:.4f}")
    print(f" SEDANG: {p50:.4f} - {p75:.4f}")
    print(f" TINGGI: {p25:.4f} - {p50:.4f}")
    print(f" KRITIS (Blokir) < {p25:.4f}")
    
    print("\nLangkah selanjutnya:")
    print("   1. Test model: python backend/ml/deteksi.py --test")
    print("   2. Integrasi ke API backend siap!")
    print("=" * 70)

if __name__ == "__main__":
    train_isolation_forest()