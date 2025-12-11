import sys
import os
import pandas as pd
from werkzeug.security import generate_password_hash
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db
from models.entities import Mahasiswa

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CSV_PATH = os.path.join(BASE_DIR, "data", "dummy", "mahasiswa_dummy.csv")

def import_mahasiswa():
    
    print("IMPORT DATA MAHASISWA")
    if not os.path.exists(CSV_PATH):
        print(f"File tidak ditemukan: {CSV_PATH}")
        print("\nBuat file CSV dengan kolom:")
        print("nim,nama,email,password,status_akun,tanggal_daftar")
        return
    
    app = create_app()
    
    with app.app_context():
        try:
            print(f"Membaca file: {CSV_PATH}")
            df = pd.read_csv(CSV_PATH)
            print(f"Total data: {len(df)} baris\n")
            
            inserted = 0
            skipped = 0
            errors = 0
            
            for idx, row in df.iterrows():
                try:
                    nim = str(row["nim"]).strip()
                    
                    existing = Mahasiswa.query.filter_by(nim=nim).first()
                    if existing:
                        skipped += 1
                        continue
        
                    password_hash = generate_password_hash(str(row["password"]))
                    
                    mhs = Mahasiswa(
                        nim=nim,
                        nama=str(row["nama"]).strip(),
                        password_hash=password_hash,
                        email=str(row["email"]).strip(),
                        status_akun=str(row.get("status_akun", "aktif")).strip()
                    )
                    
                    if "tanggal_daftar" in row and pd.notna(row["tanggal_daftar"]):
                        try:
                            mhs.tanggal_daftar = pd.to_datetime(row["tanggal_daftar"])
                        except:
                            pass
        
                    db.session.add(mhs)
                    inserted += 1
                    
                    if (idx + 1) % 100 == 0:
                        print(f"Progress: {idx+1}/{len(df)} selesai...")

                except Exception as e:
                    errors += 1
                    continue
        
            db.session.commit()
            
        except FileNotFoundError:
            print(f"File tidak ditemukan: {CSV_PATH}")
        except Exception as e:
            print(f"Gagal import: {e}")
            db.session.rollback()

if __name__ == "__main__":
    import_mahasiswa()