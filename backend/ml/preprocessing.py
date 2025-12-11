import os
import pandas as pd
import numpy as np

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
RAW_PATH = os.path.join(BASE_DIR, "data", "raw", "rba-dataset.csv")
PROCESSED_PATH = os.path.join(BASE_DIR, "data", "processed", "dataset_processed.csv")


def extract_advanced_features(df):
    """
    Ekstraksi fitur lanjutan dengan NORMALISASI LOGARITMIK
    untuk mencegah dominasi frekuensi tinggi
    """
    
    # 1. Frekuensi IP dengan NORMALISASI
    df["ip_frequency_raw"] = df.groupby("IP Address")["IP Address"].transform("count")
    df["ip_frequency"] = np.log1p(df["ip_frequency_raw"])
    
    # 2. Negara berisiko tinggi
    high_risk_countries = ["RU", "CN", "KP", "IR", "SY"]
    df["is_high_risk_country"] = df["Country"].apply(
        lambda x: 1.0 if x in high_risk_countries else 0.0
    )
    
    # 3. Login malam (00:00 - 06:00)
    df["is_night_login"] = df["jam_login"].apply(
        lambda x: 1.0 if 0 <= x <= 6 else 0.0
    )
    
    # 4. Kombinasi device + OS dengan NORMALISASI
    df["device_os_combo"] = (
        df["Device Type"].astype(str) + "_" + df["OS Name and Version"].astype(str)
    )
    # PERBAIKAN: Gunakan np.log1p untuk menormalkan frekuensi Combo
    df["combo_frequency_raw"] = df.groupby("device_os_combo")["device_os_combo"].transform("count")
    df["combo_frequency"] = np.log1p(df["combo_frequency_raw"])
    
    return df


def preprocessing_rba(limit_data=15000):
    print("=" * 70)
    print("PREPROCESSING DATASET RBA (4-LEVEL RISK CLASSIFICATION)")
    print("=" * 70)
    print(f"Input : {RAW_PATH}")
    print(f"Output: {PROCESSED_PATH}\n")
    
    # 1. VALIDASI FILE
    if not os.path.exists(RAW_PATH):
        print(f"File tidak ditemukan: {RAW_PATH}")
        print(" Pastikan dataset sudah ada di folder data/raw/")
        return

    # 2. LOAD DATA
    print(f"Membaca {limit_data:,} baris dataset...")
    df = pd.read_csv(RAW_PATH, nrows=limit_data, low_memory=False, on_bad_lines='skip')
    
    # Menghapus duplikat
    before_drop = len(df)
    df = df.drop_duplicates(subset=["IP Address", "Login Timestamp", "Device Type"], keep='first')
    dropped = before_drop - len(df)
    
    print(f"Berhasil membaca {before_drop:,} baris")
    if dropped > 0:
        print(f"Menghapus {dropped:,} duplikat")
    print(f"Total data bersih: {len(df):,} baris\n")

    # 3. VALIDASI KOLOM
    required_cols = [
        "IP Address", "Country", "Region", "City",
        "Device Type", "OS Name and Version",
        "Browser Name and Version", "Login Timestamp"
    ]
    
    missing = [col for col in required_cols if col not in df.columns]
    if missing:
        print(f"Kolom hilang: {missing}")
        return

    print("🔧 Membuat fitur basic (Skor Risiko)...")
    
    # ==========================================
    # FITUR BASIC (Binary/Categorical Scores)
    # ==========================================
    
    # 1. IP Score
    df["ip_score"] = df["IP Address"].apply(
        lambda x: 0.0 if isinstance(x, str) and any(
            x.startswith(p) for p in ["10.", "172.", "192.168.", "127."]
        ) else 0.0
    )
    
    # 2. Lokasi Score (0 = lengkap, 1 = tidak lengkap)
    df["lokasi_score"] = df.apply(
        lambda r: 0.0 if all(pd.notna([r["City"], r["Region"], r["Country"]])) else 1.0,
        axis=1
    )
    
    # 3. Device Score (PERBAIKAN: Menurunkan bobot risiko Mobile/Other)
    print("Device Score: Mobile/Tablet diturunkan menjadi risiko rendah (0.25).")
    df["device_score"] = df["Device Type"].apply(
        # Desktop tetap 0.0 (Normal)
        lambda x: 0.0 if isinstance(x, str) and "Desktop" in x 
        # Mobile/Tablet diberi bobot risiko yang lebih rendah
        else 0.25 if isinstance(x, str) and any(d in x for d in ["Mobile", "Tablet"])
        # Sisanya 1.0 (Anomali signifikan)
        else 1.0 
    )
    
    # 4. OS Score (0 = common OS, 0.5 = uncommon)
    common_os = ["Windows", "Mac", "Ubuntu", "Linux", "iOS", "Android"]
    df["os_score"] = df["OS Name and Version"].apply(
        lambda x: 0.0 if isinstance(x, str) and any(o in x for o in common_os) else 0.5
    )
    
    # 5. Browser Score (0 = common, 0.5 = uncommon)
    common_browsers = ["Chrome", "Edge", "Firefox", "Safari"]
    df["browser_score"] = df["Browser Name and Version"].apply(
        lambda x: 0.0 if isinstance(x, str) and any(b in x for b in common_browsers) else 0.5
    )
    
    # 6. Jam Login (0-23)
    df["jam_login"] = pd.to_datetime(df["Login Timestamp"], errors="coerce").dt.hour
    df["jam_login"] = df["jam_login"].fillna(12).astype(int)

    # ==========================================
    # FITUR ADVANCED (Frequency & Pattern)
    # ==========================================
    print("Membuat fitur advanced (Frekuensi & Pola)...")
    df = extract_advanced_features(df)
 
    # ==========================================
    # OUTPUT COLUMNS
    # ==========================================
    output_cols = [
        "ip_score", "lokasi_score", "device_score", "os_score",
        "browser_score", "jam_login", "ip_frequency",
        "is_high_risk_country", "is_night_login", "combo_frequency"
    ]
    
    # ==========================================
    # SAVE HASIL
    # ==========================================
    os.makedirs(os.path.dirname(PROCESSED_PATH), exist_ok=True)
    df[output_cols].to_csv(PROCESSED_PATH, index=False)
    
    # ... (Bagian print output, preview, dan statistik tetap sama) ...
    print("\n" + "=" * 70)
    print("PREPROCESSING SELESAI!")
    print("=" * 70)
    print(f"File tersimpan: {PROCESSED_PATH}")
    print(f"Total baris : {len(df):,}")
    print(f"Total fitur : {len(output_cols)}")
    
    print("\nFitur yang dibuat:")
    for i, col in enumerate(output_cols, 1):
        print(f" {i:2d}. {col}")
        
    print("\n" + "=" * 70)
    print("PREVIEW 5 BARIS PERTAMA")
    print("=" * 70)
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width", None)
    print(df[output_cols].head().to_string(index=False))

    print("\n" + "=" * 70)
    print("STATISTIK FITUR (setelah normalisasi logaritmik)")
    print("=" * 70)
    stats = df[output_cols].describe().round(3)
    print(stats)
    
    print("\n" + "=" * 70)
    print("ℹINFORMASI PENTING")
    print("=" * 70)
    print(f"ip_frequency sudah dinormalisasi dengan log1p()")
    print(f" Range: {df['ip_frequency'].min():.2f} - {df['ip_frequency'].max():.2f}")
    print(f" (Nilai mentah: {df['ip_frequency_raw'].min():.0f} - {df['ip_frequency_raw'].max():.0f})")
    
    print(f"\ncombo_frequency sudah dinormalisasi dengan log1p()")
    print(f"Range: {df['combo_frequency'].min():.2f} - {df['combo_frequency'].max():.2f}")
    print(f"(Nilai mentah: {df['combo_frequency_raw'].min():.0f} - {df['combo_frequency_raw'].max():.0f})")
    
    print(f"\nIP Score: Semua IP (public/private) = 0.0 (normal)")
    print(f"IP private count: {(df['ip_score'] == 0.0).sum():,}")
    
    print("LANGKAH SELANJUTNYA")
    print("1. Training model: python backend/ml/training.py")


if __name__ == "__main__":
    preprocessing_rba(limit_data=15000)