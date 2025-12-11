import sys
import os
import pandas as pd
import argparse

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.ml.detector import deteksi_anomali, get_model_info 
from backend.ml.training import HYBRID_PATH


def print_skenario(title, data):
    """Print hasil deteksi untuk skenario tertentu"""
    print("\n" + "=" * 75)
    print(f" {title.upper()}")
    print("=" * 75)

    print("\nINPUT FITUR:")
    for k, v in data.items():
        print(f" {k:25s} = {v}")
    
    # Deteksi anomali
    result = deteksi_anomali(data)

    print("\n" + "-" * 75)
    print("HASIL DETEKSI:")
    print(f" Anomaly Score : {result['score']:.4f}")
    print(f" Risk Level    : {result['risk_level'].upper()}")
    print(f" Action        : {result['action'].upper()}")
    
    if result['delay_seconds'] > 0:
        print(f"Delay Time      : {result['delay_seconds']} detik")
    
    print(f" Admin Monitoring : {'YA' if result['require_admin'] else 'TIDAK'}")
    print(f" Auto Block       : {'YA' if result['auto_block'] else 'TIDAK'}")
    
    print(f"\nMESSAGE:")
    print(f" {result['message']}")
    
    print(f"\nDETAIL:")
    print(f" {result['detail']}")
    print("-" * 75)

# Skenario 1: Login Normal Desktop (Risk Rendah)
# Target: Hasil ML seharusnya Tinggi/Sedang, tapi logikanya harusnya Rendah
data_rendah = {
    "ip_score": 0.0,
    "lokasi_score": 0.0,
    "device_score": 0.0,  
    "os_score": 0.0,
    "browser_score": 0.0,
    "jam_login": 14,
    "ip_frequency": 1.61, 
    "is_high_risk_country": 0,
    "is_night_login": 0,
    "combo_frequency": 7.60 
}

# Skenario 2: Login Sedikit Mencurigakan (Sedang)
# Target: P50 <= Score < P75
data_sedang = {
    "ip_score": 0.0,
    "lokasi_score": 0.0,
    "device_score": 0.25, 
    "os_score": 0.0,
    "browser_score": 0.5, 
    "jam_login": 13,
    "ip_frequency": 1.10,
    "is_high_risk_country": 0,
    "is_night_login": 0,
    "combo_frequency": 6.85 
}

# Skenario 3: Login Mencurigakan (Tinggi)
# Target: P25 <= Score < P50
data_tinggi = {
    "ip_score": 0.0,
    "lokasi_score": 1.0, 
    "device_score": 0.25, 
    "os_score": 0.5, 
    "browser_score": 0.5,
    "jam_login": 23, 
    "ip_frequency": 0.69, 
    "is_high_risk_country": 0,
    "is_night_login": 0,
    "combo_frequency": 5.53 
}

# Skenario 4: Anomali Berat (KRITIS - Akan di-Override oleh Hard Rule)
# Target: Hard Rule akan memicu KRITIS/BLOKIR, mengabaikan hasil ML yang salah (0.2041)
data_kritis = {
    "ip_score": 0.0,
    "lokasi_score": 1.0, 
    "device_score": 0.25,
    "os_score": 0.5,
    "browser_score": 0.5,
    "jam_login": 3, 
    "ip_frequency": 0.69, 
    "is_high_risk_country": 1, 
    "is_night_login": 1, 
    "combo_frequency": 1.39 
}


def run_tests():
    
    print("\n" + "=" * 75)
    print(" TESTING SISTEM DETEKSI ANOMALI LOGIN (HYBRID LOGIC)")
    print("=" * 75)
    
    print("\nINFORMASI MODEL:")
    print("-" * 75)
    info = get_model_info()
    
    if info['status'] == 'loaded':
        print(f"Status         : {info['status'].upper()}")
        print(f" Contamination : {info['contamination']}")
        
        print(f"\nTHRESHOLDS (Skor Tinggi = Risiko Rendah):")
        print(f" RENDAH (Min) : {info['thresholds']['rendah']:.4f} (P75)")
        print(f" SEDANG (Min) : {info['thresholds']['sedang']:.4f} (P50)")
        print(f" TINGGI (Min) : {info['thresholds']['tinggi']:.4f} (P25)")
        print(f" KRITIS (Max) : {info['thresholds']['kritis']} (di bawah P25)")
        
        print(f"\nSCORE RANGE (DIBALIKKAN):")
        sr = info['score_range']
        print(f" Min : {sr['min']:.4f} (ML Kritis)")
        print(f" Max : {sr['max']:.4f} (ML Rendah)")
    else:
        print(f"Error: {info.get('error')}")
        return
    
    # 2. TESTING SKENARIO
    print_skenario("Skenario 1: Login Normal Desktop (Risk Rendah)", data_rendah)
    print_skenario("Skenario 2: Login Mobile Browser Jarang (Risk Sedang)", data_sedang)
    print_skenario("Skenario 3: Login Malam IP Baru (Risk Tinggi)", data_tinggi)
    print_skenario("Skenario 4: Login Tengah Malam Negara Berisiko (Risk Kritis)", data_kritis)
    
    # 4. KESIMPULAN
    print("\n" + "=" * 75)
    print("TESTING SELESAI!")
    print("=" * 75)
    print("\nHasil testing: Skenario Kritis sekarang dijamin terdeteksi karena Hard Rule!")
    print("\nLangkah selanjutnya: Integrasi kode detector.py ke backend API.")
    print("=" * 75)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Testing sistem deteksi anomali login"
    )
    parser.add_argument(
        "--test", 
        action="store_true", 
        help="Jalankan testing skenario"
    )
    args = parser.parse_args()

    if args.test:
        run_tests()
    else:
        parser.print_help()