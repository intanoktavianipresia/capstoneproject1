from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import csv  
from io import StringIO
from models import db
from models.entities import (
    Mahasiswa, Admin, LogLogin, DeteksiAnomali, 
    DelayedLogin, UserSecurityHistory
)
from utils.auth import admin_required, superadmin_required
from utils.helpers import (
    validate_nim, validate_email, validate_password,
    log_security_event
)
from typing import List, Dict, Any, Union

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/mahasiswa', methods=['GET'])
@admin_required
def get_all_mahasiswa(current_user):
    try:
        # Parse query params
        status_filter = request.args.get('status', 'all')
        pantauan_filter = request.args.get('dalam_pantauan', 'all')
        search = request.args.get('search', '').strip()
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = Mahasiswa.query
        
        if status_filter != 'all':
            query = query.filter_by(status_akun=status_filter)
        
        if pantauan_filter == '1':
            query = query.filter_by(dalam_pantauan=True)
        elif pantauan_filter == '0':
            query = query.filter_by(dalam_pantauan=False)
        
        if search:
            query = query.filter(
                db.or_(
                    Mahasiswa.nim.like(f'%{search}%'),
                    Mahasiswa.nama.like(f'%{search}%'),
                    Mahasiswa.email.like(f'%{search}%')
                )
            )
        
        # Count total
        total = query.count()
        
        # Get data
        mahasiswa_list: List[Mahasiswa] = query.order_by(
            Mahasiswa.nim.asc()
        ).limit(limit).offset(offset).all()
        
        # Format response
        data: List[Dict[str, Any]] = []
        for mhs in mahasiswa_list:
            # Hitung total login
            total_login = LogLogin.query.filter_by(nim=mhs.nim).count()
            
            # Login terakhir
            last_login: LogLogin | None = LogLogin.query.filter_by(nim=mhs.nim).order_by(
                LogLogin.waktu_login.desc()
            ).first()
            
            data.append({
                'nim': mhs.nim,
                'nama': mhs.nama,
                'email': mhs.email,
                'status_akun': mhs.status_akun,
                'dalam_pantauan': mhs.dalam_pantauan,
                'pantauan_mulai': mhs.pantauan_mulai.isoformat() if mhs.pantauan_mulai else None,
                'diblokir_pada': mhs.diblokir_pada.isoformat() if mhs.diblokir_pada else None,
                'alasan_blokir': mhs.alasan_blokir,
                'tanggal_daftar': mhs.tanggal_daftar.isoformat() if mhs.tanggal_daftar else None,
                'total_login': total_login,
                'login_terakhir': last_login.waktu_login.isoformat() if last_login else None
                # Catatan: Kolom tunda_sampai dan tunda_alasan dihapus dari response
            })
        
        return jsonify({
            'status': 'success',
            'data': data,
            'pagination': {
                'total': total,
                'limit': limit,
                'offset': offset,
                'has_more': (offset + limit) < total
            }
        }), 200
        
    except Exception as e:
        print(f"Error get mahasiswa: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500

@admin_bp.route('/mahasiswa/<nim>', methods=['GET'])
@admin_required
def get_mahasiswa_detail(current_user, nim):
    try:
        mahasiswa: Mahasiswa | None = Mahasiswa.query.filter_by(nim=nim).first()
        
        if not mahasiswa:
            return jsonify({'status': 'error', 'message': 'Mahasiswa tidak ditemukan'}), 404
        
        # Statistics (Logika ini sudah benar)
        all_logs: List[LogLogin] = LogLogin.query.filter_by(nim=nim).all()
        total_login = len(all_logs)
        login_berhasil = sum(1 for log in all_logs if log.status_login == 'berhasil')
        login_gagal = sum(1 for log in all_logs if log.status_login == 'gagal')
        
        deteksi_rendah = DeteksiAnomali.query.join(LogLogin).filter(LogLogin.nim == nim, DeteksiAnomali.tingkat_risiko == 'rendah').count()
        deteksi_sedang = DeteksiAnomali.query.join(LogLogin).filter(LogLogin.nim == nim, DeteksiAnomali.tingkat_risiko == 'sedang').count()
        deteksi_tinggi = DeteksiAnomali.query.join(LogLogin).filter(LogLogin.nim == nim, DeteksiAnomali.tingkat_risiko == 'tinggi').count()
        deteksi_kritis = DeteksiAnomali.query.join(LogLogin).filter(LogLogin.nim == nim, DeteksiAnomali.tingkat_risiko == 'kritis').count()
        
        # Recent logins (5 terakhir)
        recent_logs: List[LogLogin] = LogLogin.query.filter_by(nim=nim).order_by(LogLogin.waktu_login.desc()).limit(5).all()
        
        recent_logins: List[Dict[str, Any]] = []
        for log in recent_logs:
            score: float = float(log.skor_anomali) if log.skor_anomali is not None else 0.0
            deteksi_terkait: DeteksiAnomali | None = DeteksiAnomali.query.filter_by(id_log=log.id_log).first()
            risk_level: Union[str, None] = deteksi_terkait.tingkat_risiko if deteksi_terkait else 'n/a'
            
            recent_logins.append({
                'id_log': log.id_log, 'waktu_login': log.waktu_login.isoformat(), 'ip_address': log.ip_address,
                'lokasi': log.lokasi, 'device': log.device, 'status_login': log.status_login,
                'hasil_deteksi': log.hasil_deteksi, 'skor_anomali': round(score, 3),
                'risk_level_deteksi': risk_level
            })
        security_history_query = db.session.query(
            UserSecurityHistory.id_history,
            UserSecurityHistory.event_type,
            UserSecurityHistory.event_time,
            UserSecurityHistory.triggered_by,
            UserSecurityHistory.reason
        ).filter(
            UserSecurityHistory.nim == nim
        ).order_by(
            UserSecurityHistory.event_time.desc()
        ).limit(5)
        
        security_events: List[Dict[str, Any]] = []
        for event in security_history_query.all():
            security_events.append({
                'id_history': event[0],
                'event_type': event[1],
                'event_time': event[2].isoformat(),
                'triggered_by': event[3],
                'reason': event[4]
            })
        
        return jsonify({
            'status': 'success',
            'data': {
                'mahasiswa': {
                    'nim': mahasiswa.nim, 'nama': mahasiswa.nama, 'email': mahasiswa.email,
                    'status_akun': mahasiswa.status_akun, 'dalam_pantauan': mahasiswa.dalam_pantauan,
                    'pantauan_mulai': mahasiswa.pantauan_mulai.isoformat() if mahasiswa.pantauan_mulai else None,
                    'diblokir_pada': mahasiswa.diblokir_pada.isoformat() if mahasiswa.diblokir_pada else None,
                    'alasan_blokir': mahasiswa.alasan_blokir, 'diblokir_oleh': mahasiswa.diblokir_oleh,
                    'terakhir_login': mahasiswa.terakhir_login.isoformat() if mahasiswa.terakhir_login else None,
                    'terakhir_ip': mahasiswa.terakhir_ip,
                    'tanggal_daftar': mahasiswa.tanggal_daftar.isoformat() if mahasiswa.tanggal_daftar else None
                },
                'statistics': {
                    'total_login': total_login, 'login_berhasil': login_berhasil, 'login_gagal': login_gagal,
                    'deteksi_anomali': {'rendah': deteksi_rendah, 'sedang': deteksi_sedang, 'tinggi': deteksi_tinggi, 'kritis': deteksi_kritis, 'total': deteksi_rendah + deteksi_sedang + deteksi_tinggi + deteksi_kritis}
                },
                'recent_logins': recent_logins,
                'security_history': security_events 
            }
        }), 200
        
    except Exception as e:
        print(f"Error get mahasiswa detail: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'message': 'Terjadi kesalahan pada server'}), 500


@admin_bp.route('/mahasiswa', methods=['POST'])
@admin_required
def create_mahasiswa(current_user):
    try:
        data = request.get_json()
        
        nim = data.get('nim', '').strip()
        nama = data.get('nama', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        # Validasi
        if not all([nim, nama, email, password]):
            return jsonify({
                'status': 'error',
                'message': 'Semua field wajib diisi'
            }), 400
        
        # Validasi NIM
        is_valid, msg = validate_nim(nim)
        if not is_valid:
            return jsonify({'status': 'error', 'message': msg}), 400
        
        # Validasi email
        is_valid, msg = validate_email(email)
        if not is_valid:
            return jsonify({'status': 'error', 'message': msg}), 400
        
        # Validasi password
        is_valid, msg = validate_password(password)
        if not is_valid:
            return jsonify({'status': 'error', 'message': msg}), 400
        
        # Cek duplikat NIM
        existing: Mahasiswa | None = Mahasiswa.query.filter_by(nim=nim).first()
        if existing:
            return jsonify({
                'status': 'error',
                'message': 'NIM sudah terdaftar'
            }), 400
        
        # Cek duplikat email
        existing = Mahasiswa.query.filter_by(email=email).first()
        if existing:
            return jsonify({
                'status': 'error',
                'message': 'Email sudah terdaftar'
            }), 400
        
        # Buat mahasiswa baru
        mahasiswa = Mahasiswa(
            nim=nim,
            nama=nama,
            email=email,
            password_hash=generate_password_hash(password),
            status_akun='aktif'
        )
        
        db.session.add(mahasiswa)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Mahasiswa berhasil ditambahkan',
            'data': {
                'nim': mahasiswa.nim,
                'nama': mahasiswa.nama,
                'email': mahasiswa.email,
                'status_akun': mahasiswa.status_akun
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Error create mahasiswa: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


@admin_bp.route('/mahasiswa/<nim>', methods=['PUT'])
@admin_required
def update_mahasiswa(current_user, nim):
    try:
        mahasiswa: Mahasiswa | None = Mahasiswa.query.filter_by(nim=nim).first()
        
        if not mahasiswa:
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak ditemukan'
            }), 404
        
        data = request.get_json()
        
        # Update fields jika ada
        if 'nama' in data:
            mahasiswa.nama = data['nama'].strip()
        
        if 'email' in data:
            new_email = data['email'].strip()
            # Cek duplikat email
            existing: Mahasiswa | None = Mahasiswa.query.filter(
                Mahasiswa.email == new_email,
                Mahasiswa.nim != nim
            ).first()
            if existing:
                return jsonify({
                    'status': 'error',
                    'message': 'Email sudah digunakan mahasiswa lain'
                }), 400
            mahasiswa.email = new_email
        
        if 'status_akun' in data:
            status = data['status_akun']
            if status not in ['aktif', 'diblokir', 'ditunda']:
                return jsonify({
                    'status': 'error',
                    'message': 'Status akun tidak valid'
                }), 400
            mahasiswa.status_akun = status
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Data mahasiswa berhasil diupdate',
            'data': {
                'nim': mahasiswa.nim,
                'nama': mahasiswa.nama,
                'email': mahasiswa.email,
                'status_akun': mahasiswa.status_akun
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error update mahasiswa: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


@admin_bp.route('/mahasiswa/<nim>/unblock', methods=['POST'])
@admin_required
def unblock_mahasiswa(current_user, nim):
    try:
        mahasiswa: Mahasiswa | None = Mahasiswa.query.filter_by(nim=nim).first()
        
        if not mahasiswa:
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak ditemukan'
            }), 404
        
        if mahasiswa.status_akun != 'diblokir':
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak dalam status diblokir'
            }), 400
        
        data = request.get_json() or {}
        reset_password = data.get('reset_password', True)
        catatan = data.get('catatan', 'Unblock oleh admin')
        
        # Unblock akun
        mahasiswa.status_akun = 'aktif'
        mahasiswa.diblokir_pada = None
        mahasiswa.alasan_blokir = None
        mahasiswa.diblokir_oleh = None
        
        new_password = None
        if reset_password:
            # Generate password baru
            new_password = f"Reset{nim[:4]}!"
            mahasiswa.password_hash = generate_password_hash(new_password)
        
        # Log security event
        admin_id = int(current_user['user_id'])
        log_security_event(
            nim=nim,
            event_type='unblocked',
            triggered_by='admin',
            reason=catatan,
            admin_id=admin_id
        )
        
        db.session.commit()
        
        response_data = {
            'nim': mahasiswa.nim,
            'nama': mahasiswa.nama,
            'status_akun': mahasiswa.status_akun
        }
        
        if new_password:
            response_data['new_password'] = new_password
        
        message = 'Akun berhasil di-unblock.'
        if reset_password:
            message += f' Password telah direset.'
        
        return jsonify({
            'status': 'success',
            'message': message,
            'data': response_data
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error unblock mahasiswa: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


@admin_bp.route('/mahasiswa/<nim>/stop-monitoring', methods=['POST'])
@admin_required
def stop_monitoring(current_user, nim):
    try:
        mahasiswa: Mahasiswa | None = Mahasiswa.query.filter_by(nim=nim).first()
        
        if not mahasiswa:
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak ditemukan'
            }), 404
        
        if not mahasiswa.dalam_pantauan:
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak sedang dalam pantauan'
            }), 400
        
        data = request.get_json() or {}
        catatan = data.get('catatan', 'Monitoring dihentikan oleh admin')
        
        # Stop monitoring
        mahasiswa.dalam_pantauan = False
        mahasiswa.pantauan_selesai = datetime.now(timezone.utc)
        
        # Log security event
        admin_id = int(current_user['user_id'])
        log_security_event(
            nim=nim,
            event_type='monitoring_end',
            triggered_by='admin',
            reason=catatan,
            admin_id=admin_id
        )
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Monitoring berhasil dihentikan',
            'data': {
                'nim': mahasiswa.nim,
                'dalam_pantauan': mahasiswa.dalam_pantauan,
                'pantauan_selesai': mahasiswa.pantauan_selesai.isoformat()
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error stop monitoring: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


@admin_bp.route('/mahasiswa/<nim>/reset-password', methods=['POST'])
@admin_required
def reset_mahasiswa_password(current_user, nim):
    try:
        mahasiswa: Mahasiswa | None = Mahasiswa.query.filter_by(nim=nim).first()
        
        if not mahasiswa:
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak ditemukan'
            }), 404
        
        data = request.get_json() or {}
        new_password = data.get('new_password', '')
        
        if not new_password:
            # Generate password otomatis
            new_password = f"Reset{nim[:4]}!"
        
        # Validasi password
        from utils.helpers import validate_password # Dipastikan diimport jika belum
        is_valid, msg = validate_password(new_password)
        if not is_valid:
            return jsonify({'status': 'error', 'message': msg}), 400
        
        # Update password
        mahasiswa.password_hash = generate_password_hash(new_password)
        
        # Jika diblokir, aktifkan kembali
        if mahasiswa.status_akun == 'diblokir':
            mahasiswa.status_akun = 'aktif'
            mahasiswa.diblokir_pada = None
            mahasiswa.alasan_blokir = None
            mahasiswa.diblokir_oleh = None
        
        # Log security event
        admin_id = int(current_user['user_id'])
        log_security_event(
            nim=nim,
            event_type='password_reset',
            triggered_by='admin',
            reason='Password direset oleh admin',
            admin_id=admin_id
        )
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Password berhasil direset',
            'data': {
                'nim': mahasiswa.nim,
                'new_password': new_password,
                'status_akun': mahasiswa.status_akun
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error reset password: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


@admin_bp.route('/mahasiswa/<nim>', methods=['DELETE'])
@superadmin_required
def delete_mahasiswa(current_user, nim):
    try:
        mahasiswa: Mahasiswa | None = Mahasiswa.query.filter_by(nim=nim).first()
        
        if not mahasiswa:
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak ditemukan'
            }), 404
        
        db.session.delete(mahasiswa)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Mahasiswa {nim} berhasil dihapus'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error delete mahasiswa: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500

@admin_bp.route('/monitoring', methods=['GET'])
@admin_required
def get_monitored_users(current_user):
    try:
        from sqlalchemy import func
        
        # Get mahasiswa dalam pantauan
        monitored: List[Mahasiswa] = Mahasiswa.query.filter_by(dalam_pantauan=True).all()
        
        data: List[Dict[str, Any]] = []
        for mhs in monitored:
            # Hitung login sejak pantauan
            total_login = 0
            avg_score = 0.0
            highest_risk: str = 'rendah'
            
            if mhs.pantauan_mulai:
                logs_since: List[LogLogin] = LogLogin.query.filter(
                    LogLogin.nim == mhs.nim,
                    LogLogin.waktu_login >= mhs.pantauan_mulai
                ).all()
                
                total_login = len(logs_since)
                
                if total_login > 0:
                    # Rata-rata skor anomali
                    # Perhatian: Skor anomali DIBALIKKAN (skor lebih besar = risiko rendah)
                    # Jadi, kita harus hati-hati menginterpretasi 'rata-rata'
                    avg_score = sum(float(log.skor_anomali) for log in logs_since) / total_login
                    
                    # Cari risk level tertinggi
                    risk_levels = []
                    for log in logs_since:
                        if log.deteksi:
                            # Ambil semua deteksi yang terkait dengan log ini
                            risk_levels.extend([det.tingkat_risiko for det in log.deteksi])
                    
                    risk_priority = {'kritis': 4, 'tinggi': 3, 'sedang': 2, 'rendah': 1}
                    highest_risk = max(risk_levels, key=lambda r: risk_priority.get(r, 0)) if risk_levels else 'rendah'
            
            data.append({
                'nim': mhs.nim,
                'nama': mhs.nama,
                'email': mhs.email,
                'status_akun': mhs.status_akun,
                'pantauan_mulai': mhs.pantauan_mulai.isoformat() if mhs.pantauan_mulai else None,
                'total_login_sejak_pantauan': total_login,
                'rata_rata_skor_anomali': round(avg_score, 3),
                'risk_level_tertinggi': highest_risk
            })
        
        return jsonify({
            'status': 'success',
            'total': len(data),
            'data': data
        }), 200
        
    except Exception as e:
        print(f"Error get monitored users: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500

@admin_bp.route('/dashboard', methods=['GET'])
@admin_required
def get_dashboard_stats(current_user):
    try:
        from sqlalchemy import func
        
        # Statistik mahasiswa
        total_mhs = Mahasiswa.query.count()
        aktif = Mahasiswa.query.filter_by(status_akun='aktif').count()
        diblokir = Mahasiswa.query.filter_by(status_akun='diblokir').count()
        ditunda = Mahasiswa.query.filter_by(status_akun='ditunda').count()
        dalam_pantauan = Mahasiswa.query.filter_by(dalam_pantauan=True).count()
        
        # Login hari ini
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        login_hari_ini = LogLogin.query.filter(LogLogin.waktu_login >= today_start).count()
        
        # Deteksi (4-level risk)
        total_deteksi = DeteksiAnomali.query.count()
        belum_ditinjau = DeteksiAnomali.query.filter_by(status_tinjauan='belum_ditinjau').count()
        deteksi_rendah = DeteksiAnomali.query.filter_by(tingkat_risiko='rendah').count()
        deteksi_sedang = DeteksiAnomali.query.filter_by(tingkat_risiko='sedang').count()
        deteksi_tinggi = DeteksiAnomali.query.filter_by(tingkat_risiko='tinggi').count()
        deteksi_kritis = DeteksiAnomali.query.filter_by(tingkat_risiko='kritis').count()
        
        recent: List[DeteksiAnomali] = DeteksiAnomali.query.filter_by(status_tinjauan='belum_ditinjau').order_by( DeteksiAnomali.waktu_deteksi.desc()).limit(5).all()
    
        recent_anomalies: List[Dict[str, Any]] = []
        for det in recent:
            log: LogLogin | None = det.log_login
            mhs: Mahasiswa | None = log.mahasiswa if log else None
            recent_anomalies.append({
                'id_deteksi': det.id_deteksi,
                'nim': log.nim if log else None,
                'nama_mahasiswa': mhs.nama if mhs else 'Unknown',
                'skor_anomali': round(float(det.skor_anomali), 3),
                'tingkat_risiko': det.tingkat_risiko,
                'tindakan_otomatis': det.tindakan_otomatis,
                'waktu_deteksi': det.waktu_deteksi.isoformat()
            })
        
        return jsonify({
            'status': 'success',
            'data': {
                'mahasiswa': {
                    'total': total_mhs,
                    'aktif': aktif,
                    'diblokir': diblokir,
                    'ditunda': ditunda,
                    'dalam_pantauan': dalam_pantauan
                },
                'login_hari_ini': login_hari_ini,
                'deteksi': {
                    'total': total_deteksi,
                    'belum_ditinjau': belum_ditinjau,
                    'rendah': deteksi_rendah,
                    'sedang': deteksi_sedang,
                    'tinggi': deteksi_tinggi,
                    'kritis': deteksi_kritis
                },
                'recent_anomalies': recent_anomalies
            }
        }), 200
        
    except Exception as e:
        print(f"Error get dashboard stats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500

@admin_bp.route('/mahasiswa/import-csv', methods=['POST'])
@admin_required
def import_mahasiswa_csv(current_user):
    # Pastikan file ada di request
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'Tidak ada file di request'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'Nama file kosong'}), 400
    
    from utils.helpers import validate_nim
        
    if file and file.filename.endswith('.csv'):
        try:
            # Gunakan StringIO atau simpan sementara untuk diproses Pandas
            stream = file.stream.read().decode("utf-8")
            from io import StringIO
            csv_data = StringIO(stream)
            
            # Asumsi format CSV: nim,nama,email,password
            reader = csv.reader(csv_data)
            next(reader) # Lewati header jika ada
            
            new_mahasiswa_list: List[Mahasiswa] = []
            
            # Proses setiap baris
            for row in reader:
                # Pastikan baris memiliki minimal 4 kolom
                if len(row) < 4: continue
                
                nim, nama, email, password = [r.strip() for r in row[:4]]
                
                # Cek duplikat dan validasi nim
                if Mahasiswa.query.filter_by(nim=nim).first() or not validate_nim(nim)[0]:
                    continue 
                
                # Cek duplikat email
                if Mahasiswa.query.filter_by(email=email).first():
                    continue

                new_mahasiswa = Mahasiswa(
                    nim=nim,
                    nama=nama,
                    email=email,
                    password_hash=generate_password_hash(password),
                    status_akun='aktif'
                )
                new_mahasiswa_list.append(new_mahasiswa)

            db.session.bulk_save_objects(new_mahasiswa_list)
            db.session.commit()
            
            return jsonify({
                'status': 'success',
                'message': f'Berhasil mengimpor {len(new_mahasiswa_list)} mahasiswa.',
                'imported_count': len(new_mahasiswa_list)
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': f'Gagal memproses CSV: {e}'}), 500
