from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone, timedelta

from models import db
from models.entities import Mahasiswa, LogLogin, DelayedLogin
from utils.auth import generate_token, mahasiswa_required
from utils.helpers import (
    validate_nim,
    validate_password,
    log_successful_login_with_detection,
    log_failed_login_with_detection,
    check_delayed_login_status,
    log_security_event
)

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        nim = data.get("nim", "").strip()
        password = data.get("password", "")

        if not nim or not password:
            return jsonify({
                "status": "error",
                "message": "NIM dan password wajib diisi"
            }), 400
        
        is_valid, msg = validate_nim(nim)
        if not is_valid:
            return jsonify({"status": "error", "message": msg}), 400
        
        mahasiswa = Mahasiswa.query.filter_by(nim=nim).first()

        if not mahasiswa:
            log_failed_login_with_detection(nim, request, "Mahasiswa tidak ditemukan")
            return jsonify({
                "status": "error",
                "message": "NIM atau password salah"
            }), 401
        
        now = datetime.now(timezone.utc)

        # A. Jika DIBLOKIR = hanya admin bisa buka
        if mahasiswa.status_akun == "diblokir":
            log_failed_login_with_detection(nim, request, "Akun diblokir")
            
            return jsonify({
                "status": "blocked",
                "message": f"Akun Anda diblokir. Alasan: {mahasiswa.alasan_blokir or 'Aktivitas mencurigakan'}. Hubungi admin untuk membuka blokir.",
                "data": {
                    "diblokir_pada": mahasiswa.diblokir_pada.isoformat() if mahasiswa.diblokir_pada else None,
                    "diblokir_oleh": mahasiswa.diblokir_oleh
                }
            }), 403

        # B. Jika DITUNDA = (Menggunakan DelayedLogin)
        active_delay = DelayedLogin.query.filter_by(
            nim=nim, 
            status_delay='waiting'
        ).order_by(DelayedLogin.delay_end.desc()).first()

        if active_delay:
            delay_result = check_delayed_login_status(active_delay.id_delayed)

            if delay_result and delay_result['status'] == 'waiting':
                remaining = delay_result['remaining_seconds']
                
                # Pastikan status Mahasiswa ter-update ke 'ditunda'
                if mahasiswa.status_akun != "ditunda":
                    mahasiswa.status_akun = "ditunda"
                    db.session.commit()
                
                return jsonify({
                    "status": "delayed",
                    "message": f"Akun Anda ditunda. Mohon tunggu {remaining} detik lagi.",
                    "data": {
                        "id_delayed": active_delay.id_delayed,
                        "delay_end": delay_result['delay_end'],
                        "remaining_seconds": remaining
                    }
                }), 429
            
            elif delay_result and delay_result['status'] == 'completed':
                
                if mahasiswa.status_akun == "ditunda":
                    mahasiswa.status_akun = "aktif"
                    db.session.commit()
                
        # =======================
        # 4. CEK PASSWORD
        # =======================
        if not check_password_hash(mahasiswa.password_hash, password):
            bf_result = log_failed_login_with_detection(nim, request, "Password salah") 
            bf_action = bf_result.get('action') 
            bf_message = bf_result.get('message') 
            if bf_action == 'blokir': 
                return jsonify({"status": "blocked", "message": bf_message}), 403 
            elif bf_action == 'tunda': 
                return jsonify({"status": "delayed", "message": bf_message}), 429
            
            return jsonify({
                "status": "error",
                "message": "NIM atau password salah"
            }), 401
            
        log, ml_result = log_successful_login_with_detection(nim, request)
        
        if ml_result['action'] == 'blokir':
            return jsonify({
                'status': 'blocked',
                'message': ml_result['message'],
                'data': {
                    'id_log': log.id_log,
                    'skor_anomali': round(ml_result['score'], 3),
                    'risk_level': ml_result['risk_level'],
                    'detail': ml_result.get('detail', '')
                }
            }), 403
        
        elif ml_result['action'] == 'tunda':
            delayed = DelayedLogin.query.filter_by(
                id_log=log.id_log, 
                status_delay='waiting'
            ).order_by(DelayedLogin.created_at.desc()).first()
            
            if delayed:
                return jsonify({
                    'status': 'delayed',
                    'message': ml_result['message'],
                    'data': {
                        'id_delayed': delayed.id_delayed,
                        'delay_seconds': delayed.delay_seconds,
                        'delay_end': delayed.delay_end.isoformat(),
                        'skor_anomali': round(ml_result['score'], 3),
                        'risk_level': ml_result['risk_level']
                    }
                }), 429 
            else:
                return jsonify({
                    'status': 'delayed',
                    'message': ml_result['message'],
                    'data': {
                        'delay_seconds': ml_result['delay_seconds'],
                        'skor_anomali': round(ml_result['score'], 3),
                        'risk_level': ml_result['risk_level']
                    }  
                }), 429

        else: 
            token = generate_token(mahasiswa.nim, role="mahasiswa")
            
            return jsonify({
                'status': 'success_with_warning' if ml_result['action'] == 'peringatan' else 'success',
                'message': ml_result['message'],
                'token': token,
                'data': {
                    'nim': mahasiswa.nim,
                    'nama': mahasiswa.nama,
                    'email': mahasiswa.email,
                    'id_log': log.id_log,
                    'skor_anomali': round(ml_result['score'], 3),
                    'risk_level': ml_result['risk_level'],
                    'dalam_pantauan': mahasiswa.dalam_pantauan
                }
            }), 200

    except Exception as e:
        db.session.rollback()
        print(f"Login Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": "Terjadi kesalahan pada server"
        }), 500


# =========================================
#  CHECK DELAYED LOGIN STATUS
# =========================================

@auth_bp.route("/login/check-delay/<int:id_delayed>", methods=["GET"])
def check_delay(id_delayed):
   
    try:
        result = check_delayed_login_status(id_delayed)
        
        if not result:
            return jsonify({
                'status': 'error',
                'message': 'Delayed login tidak ditemukan'
            }), 404
        
        if result['status'] == 'completed' and result['can_login']:
            delayed = DelayedLogin.query.get(id_delayed)
            mahasiswa = Mahasiswa.query.filter_by(nim=delayed.nim).first()
            
            if mahasiswa:
                token = generate_token(mahasiswa.nim, role="mahasiswa")
                
                return jsonify({
                    'status': 'completed',
                    'message': 'Waktu tunda selesai. Anda dapat login sekarang.',
                    'token': token,
                    'data': {
                        'nim': mahasiswa.nim,
                        'nama': mahasiswa.nama,
                        'email': mahasiswa.email
                    }
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Mahasiswa tidak ditemukan'
                }), 404
        
        elif result['status'] == 'waiting':
            return jsonify({
                'status': 'waiting',
                'message': 'Masih dalam periode tunda',
                'data': {
                    'remaining_seconds': result['remaining_seconds'],
                    'delay_end': result['delay_end']
                }
            }), 202
        
        else:
            return jsonify({
                'status': 'error',
                'message': f"Delayed login sudah {result['status']}"
            }), 403
            
    except Exception as e:
        print(f"Error check delay: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


# =========================================
#  PROFILE MAHASISWA (Kolom lama dihapus)
# =========================================

@auth_bp.route('/profile', methods=['GET'])
@mahasiswa_required
def get_profile(current_user):
    """Get profile mahasiswa yang sedang login"""
    try:
        nim = current_user["user_id"]
        mahasiswa = Mahasiswa.query.filter_by(nim=nim).first()

        if not mahasiswa:
            return jsonify({
                "status": "error",
                "message": "Mahasiswa tidak ditemukan"
            }), 404

        return jsonify({
            "status": "success",
            "data": {
                "nim": mahasiswa.nim,
                "nama": mahasiswa.nama,
                "email": mahasiswa.email,
                "status_akun": mahasiswa.status_akun,
                "dalam_pantauan": mahasiswa.dalam_pantauan,
                "pantauan_mulai": mahasiswa.pantauan_mulai.isoformat() if mahasiswa.pantauan_mulai else None,
                # Kolom lama tunda_sampai dan tunda_alasan DIHAPUS DARI RESPONSE
                "terakhir_login": mahasiswa.terakhir_login.isoformat() if mahasiswa.terakhir_login else None,
                "tanggal_daftar": mahasiswa.tanggal_daftar.isoformat() if mahasiswa.tanggal_daftar else None
            }
        }), 200

    except Exception as e:
        print(f"Error get_profile: {e}")
        return jsonify({
            "status": "error",
            "message": "Terjadi kesalahan pada server"
        }), 500


# =========================================
#  RESET PASSWORD
# =========================================

@auth_bp.route('/reset-password', methods=['POST'])
@mahasiswa_required
def reset_password(current_user):
    try:
        data = request.get_json()
        old_pass = data.get("old_password")
        new_pass = data.get("new_password")

        if not old_pass or not new_pass:
            return jsonify({
                "status": "error",
                "message": "Password lama dan baru wajib diisi"
            }), 400

        is_valid, msg = validate_password(new_pass)
        if not is_valid:
            return jsonify({"status": "error", "message": msg}), 400

        mahasiswa = Mahasiswa.query.filter_by(nim=current_user["user_id"]).first()

        if not check_password_hash(mahasiswa.password_hash, old_pass):
            return jsonify({
                "status": "error",
                "message": "Password lama salah"
            }), 400

        mahasiswa.password_hash = generate_password_hash(new_pass)
        
        log_security_event(
            nim=mahasiswa.nim,
            event_type='password_reset',
            triggered_by='mahasiswa',
            reason='Self-service password reset'
        )
        
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Password berhasil diubah"
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error reset password: {e}")
        return jsonify({
            "status": "error",
            "message": "Terjadi kesalahan pada server"
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@mahasiswa_required
def logout(current_user):
    """Logout mahasiswa (token dihapus di client side)"""
    return jsonify({
        "status": "success",
        "message": "Logout berhasil. Token dihapus di client."
    }), 200
