from flask import Blueprint, request, jsonify
from datetime import datetime, timezone

from models import db
from models.entities import (
    DeteksiAnomali, KeputusanAdmin, LogLogin, Mahasiswa,
    UserSecurityHistory, DelayedLogin, Admin # Import Admin
)
from utils.auth import admin_required
from utils.helpers import log_security_event
from werkzeug.security import generate_password_hash
from typing import List, Dict, Any

deteksi_bp = Blueprint('detection', __name__)

@deteksi_bp.route('/anomalies', methods=['GET'])
@admin_required
def get_anomalies(current_user):
    try:
        # Parse query parameters
        status_filter = request.args.get('status', 'all')
        risiko_filter = request.args.get('risiko', 'all')
        tindakan_filter = request.args.get('tindakan', 'all')
        require_admin_filter = request.args.get('require_admin', 'all')
        nim_filter = request.args.get('nim')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = DeteksiAnomali.query
        
        if status_filter != 'all':
            query = query.filter_by(status_tinjauan=status_filter)
        
        if risiko_filter != 'all':
            query = query.filter_by(tingkat_risiko=risiko_filter)
        
        if tindakan_filter != 'all':
            query = query.filter_by(tindakan_otomatis=tindakan_filter)
        
        if require_admin_filter == '1':
            query = query.filter_by(require_admin=True)
        elif require_admin_filter == '0':
            query = query.filter_by(require_admin=False)
        
        if nim_filter:
            query = query.join(LogLogin).filter(LogLogin.nim == nim_filter)
        
        # Count total
        total = query.count()
        
        # Get data with pagination
        deteksi_list: List[DeteksiAnomali] = query.order_by(
            DeteksiAnomali.waktu_deteksi.desc()
        ).limit(limit).offset(offset).all()
        
        # Format response dengan join data
        data: List[Dict[str, Any]] = []
        for deteksi in deteksi_list:
            log: LogLogin | None = deteksi.log_login
            mahasiswa: Mahasiswa | None = log.mahasiswa if log else None
            
            item = {
                'id_deteksi': deteksi.id_deteksi,
                'id_log': deteksi.id_log,
                'nim': log.nim if log else None,
                'nama_mahasiswa': mahasiswa.nama if mahasiswa else 'Unknown',
                'waktu_deteksi': deteksi.waktu_deteksi.isoformat(),
                'waktu_login': log.waktu_login.isoformat() if log else None,
                'skor_anomali': round(deteksi.skor_anomali, 3),
                'tingkat_risiko': deteksi.tingkat_risiko,
                'tindakan_otomatis': deteksi.tindakan_otomatis,
                'delay_seconds': deteksi.delay_seconds,
                'require_admin': deteksi.require_admin,
                'auto_block': deteksi.auto_block,
                'message_to_user': deteksi.message_to_user,
                'status_tinjauan': deteksi.status_tinjauan,
                'ip_address': log.ip_address if log else None,
                'lokasi': log.lokasi if log else None,
                'device': log.device if log else None,
                'os': log.os if log else None,
                'browser': log.browser if log else None
            }
            data.append(item)
        
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
        print(f"Error get anomalies: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500

@deteksi_bp.route('/anomalies/<int:id_deteksi>', methods=['GET'])
@admin_required
def get_anomaly_detail(current_user, id_deteksi):
    try:
        deteksi = DeteksiAnomali.query.get(id_deteksi)
        
        if not deteksi:
            return jsonify({
                'status': 'error',
                'message': 'Deteksi tidak ditemukan'
            }), 404
        
        log: LogLogin | None = deteksi.log_login
        mahasiswa: Mahasiswa | None = log.mahasiswa if log else None
        # Mengambil keputusan admin terbaru jika ada
        keputusan: KeputusanAdmin | None = deteksi.keputusan_admin[0] if deteksi.keputusan_admin else None
        
        response_data: Dict[str, Any] = {
            'deteksi': {
                'id_deteksi': deteksi.id_deteksi,
                'id_log': deteksi.id_log,
                'waktu_deteksi': deteksi.waktu_deteksi.isoformat(),
                'skor_anomali': round(deteksi.skor_anomali, 3),
                'tingkat_risiko': deteksi.tingkat_risiko,
                'tindakan_otomatis': deteksi.tindakan_otomatis,
                'delay_seconds': deteksi.delay_seconds,
                'require_admin': deteksi.require_admin,
                'auto_block': deteksi.auto_block,
                'message_to_user': deteksi.message_to_user,
                'detail_anomali': deteksi.detail_anomali,
                'status_tinjauan': deteksi.status_tinjauan
            }
        }
        
        if log:
            response_data['log'] = {
                'id_log': log.id_log,
                'nim': log.nim,
                'waktu_login': log.waktu_login.isoformat(),
                'ip_address': log.ip_address,
                'lokasi': log.lokasi,
                'device': log.device,
                'os': log.os,
                'browser': log.browser,
                'status_login': log.status_login,
                'hasil_deteksi': log.hasil_deteksi,
                'keterangan': log.keterangan,
                # ML Features: Menggunakan float() untuk memastikan output JSON akurat
                'ml_features': {
                    'ip_score': float(log.ip_score),
                    'lokasi_score': float(log.lokasi_score),
                    'device_score': float(log.device_score),
                    'os_score': float(log.os_score),
                    'browser_score': float(log.browser_score),
                    'jam_login': log.jam_login,
                    'ip_frequency': float(log.ip_frequency),
                    'combo_frequency': float(log.combo_frequency),
                    'is_high_risk_country': log.is_high_risk_country,
                    'is_night_login': log.is_night_login
                }
            }
        
        if mahasiswa:
            response_data['mahasiswa'] = {
                'nim': mahasiswa.nim,
                'nama': mahasiswa.nama,
                'email': mahasiswa.email,
                'status_akun': mahasiswa.status_akun,
                'dalam_pantauan': mahasiswa.dalam_pantauan,
                'tanggal_daftar': mahasiswa.tanggal_daftar.isoformat() if mahasiswa.tanggal_daftar else None
            }
        
        if keputusan:
            admin: Admin | None = keputusan.admin
            response_data['keputusan'] = {
                'id_keputusan': keputusan.id_keputusan,
                'id_admin': keputusan.id_admin,
                'nama_admin': admin.nama_admin if admin else 'Unknown',
                'waktu_keputusan': keputusan.waktu_keputusan.isoformat(),
                'jenis_tindakan': keputusan.jenis_tindakan,
                'catatan_admin': keputusan.catatan_admin
            }
        else:
            response_data['keputusan'] = None
        
        return jsonify({
            'status': 'success',
            'data': response_data
        }), 200
        
    except Exception as e:
        print(f"Error get anomaly detail: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500

@deteksi_bp.route('/action', methods=['POST'])
@admin_required
def take_action(current_user):
    try:
        data = request.get_json()
        
        id_deteksi = data.get('id_deteksi')
        jenis_tindakan = data.get('jenis_tindakan')
        catatan_admin = data.get('catatan_admin', '')
        
        # Validasi input
        if not id_deteksi or not jenis_tindakan:
            return jsonify({
                'status': 'error',
                'message': 'id_deteksi dan jenis_tindakan wajib diisi'
            }), 400
        
        valid_tindakan = ['reset_password', 'blokir_permanen', 'buka_blokir', 'hapus_pantauan', 'abaikan']
        if jenis_tindakan not in valid_tindakan:
            return jsonify({
                'status': 'error',
                'message': f'jenis_tindakan tidak valid. Pilihan: {", ".join(valid_tindakan)}'
            }), 400
        
        # Cari deteksi
        deteksi: DeteksiAnomali | None = DeteksiAnomali.query.get(id_deteksi)
        if not deteksi:
            return jsonify({
                'status': 'error',
                'message': 'Deteksi tidak ditemukan'
            }), 404
        
        # Cek apakah sudah ada keputusan
        if deteksi.keputusan_admin:
            return jsonify({
                'status': 'error',
                'message': 'Deteksi ini sudah ditinjau sebelumnya'
            }), 400
        
        # Get mahasiswa
        log: LogLogin | None = deteksi.log_login
        mahasiswa: Mahasiswa | None = log.mahasiswa if log else None
        
        if not mahasiswa:
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak ditemukan'
            }), 404
        
        # Simpan keputusan
        admin_id = int(current_user['user_id'])
        keputusan = KeputusanAdmin(
            id_deteksi=id_deteksi,
            id_admin=admin_id,
            waktu_keputusan=datetime.now(timezone.utc),
            jenis_tindakan=jenis_tindakan,
            catatan_admin=catatan_admin
        )
        db.session.add(keputusan)
        
        # Update status tinjauan
        deteksi.status_tinjauan = 'ditinjau'
        
        # Eksekusi tindakan
        response_message = ""
        new_password = None
        
        if jenis_tindakan == 'reset_password':
            # Generate password baru
            new_password = f"Reset{mahasiswa.nim[:4]}!"
            mahasiswa.password_hash = generate_password_hash(new_password)
            
            # Aktifkan akun jika diblokir
            if mahasiswa.status_akun == 'diblokir':
                mahasiswa.status_akun = 'aktif'
                mahasiswa.diblokir_pada = None
                mahasiswa.alasan_blokir = None
                mahasiswa.diblokir_oleh = None
            
            # Log security event
            log_security_event(
                nim=mahasiswa.nim,
                event_type='password_reset',
                triggered_by='admin',
                reason=catatan_admin or 'Password direset oleh admin',
                admin_id=admin_id
            )
            
            response_message = f"Password berhasil direset. Password baru: {new_password}"
            
        elif jenis_tindakan == 'blokir_permanen':
            mahasiswa.status_akun = 'diblokir'
            mahasiswa.diblokir_pada = datetime.now(timezone.utc)
            mahasiswa.alasan_blokir = catatan_admin or 'Diblokir oleh admin'
            mahasiswa.diblokir_oleh = 'admin'
            
            # Log security event
            log_security_event(
                nim=mahasiswa.nim,
                event_type='blocked',
                triggered_by='admin',
                reason=catatan_admin or 'Diblokir permanen oleh admin',
                admin_id=admin_id
            )
            
            response_message = "Akun mahasiswa berhasil diblokir permanen"
            
        elif jenis_tindakan == 'buka_blokir':
            if mahasiswa.status_akun != 'diblokir':
                return jsonify({
                    'status': 'error',
                    'message': 'Akun mahasiswa tidak dalam status diblokir'
                }), 400
            
            mahasiswa.status_akun = 'aktif'
            mahasiswa.diblokir_pada = None
            mahasiswa.alasan_blokir = None
            mahasiswa.diblokir_oleh = None
            
            # Log security event
            log_security_event(
                nim=mahasiswa.nim,
                event_type='unblocked',
                triggered_by='admin',
                reason=catatan_admin or 'Dibuka oleh admin',
                admin_id=admin_id
            )
            
            response_message = "Blokir akun berhasil dibuka. Status dikembalikan aktif."
            
        elif jenis_tindakan == 'hapus_pantauan':
            if not mahasiswa.dalam_pantauan:
                return jsonify({
                    'status': 'error',
                    'message': 'Mahasiswa tidak sedang dalam pantauan'
                }), 400
            
            mahasiswa.dalam_pantauan = False
            mahasiswa.pantauan_selesai = datetime.now(timezone.utc)
            
            # Log security event
            log_security_event(
                nim=mahasiswa.nim,
                event_type='monitoring_end',
                triggered_by='admin',
                reason=catatan_admin or 'Pantauan dihentikan oleh admin',
                admin_id=admin_id
            )
            
            response_message = "Pantauan berhasil dihentikan. Mahasiswa tidak lagi dalam monitoring."
            
        elif jenis_tindakan == 'abaikan':
            # Jika ditunda, kembalikan ke aktif
            if mahasiswa.status_akun == 'ditunda':
                # Hapus entry delayed_logins yang aktif
                DelayedLogin.query.filter_by(nim=mahasiswa.nim, status_delay='waiting').update(
                    {'status_delay': 'cancelled'}
                )
                mahasiswa.status_akun = 'aktif'
            
            # Jika dalam pantauan, hentikan
            if mahasiswa.dalam_pantauan:
                mahasiswa.dalam_pantauan = False
                mahasiswa.pantauan_selesai = datetime.now(timezone.utc)
            
            response_message = "Deteksi diabaikan. Status akun dikembalikan normal."
        
        db.session.commit()
        
        response_data = {
            'id_keputusan': keputusan.id_keputusan,
            'jenis_tindakan': jenis_tindakan,
            'status_akun_mahasiswa': mahasiswa.status_akun,
            'dalam_pantauan': mahasiswa.dalam_pantauan,
            'nim': mahasiswa.nim
        }
        
        if new_password:
            response_data['new_password'] = new_password
        
        return jsonify({
            'status': 'success',
            'message': response_message,
            'data': response_data
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error take action: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500

# STATISTICS

@deteksi_bp.route('/statistics', methods=['GET'])
@admin_required
def get_statistics(current_user):
    try:
        from sqlalchemy import func
        
        # Deteksi statistics
        total_deteksi = DeteksiAnomali.query.count()
        belum_ditinjau = DeteksiAnomali.query.filter_by(status_tinjauan='belum_ditinjau').count()
        
        # By risk level (4-level)
        deteksi_rendah = DeteksiAnomali.query.filter_by(tingkat_risiko='rendah').count()
        deteksi_sedang = DeteksiAnomali.query.filter_by(tingkat_risiko='sedang').count()
        deteksi_tinggi = DeteksiAnomali.query.filter_by(tingkat_risiko='tinggi').count()
        deteksi_kritis = DeteksiAnomali.query.filter_by(tingkat_risiko='kritis').count()
        
        # By action
        action_izinkan = DeteksiAnomali.query.filter_by(tindakan_otomatis='izinkan').count()
        action_peringatan = DeteksiAnomali.query.filter_by(tindakan_otomatis='peringatan').count()
        action_tunda = DeteksiAnomali.query.filter_by(tindakan_otomatis='tunda').count()
        action_blokir = DeteksiAnomali.query.filter_by(tindakan_otomatis='blokir').count()
        
        # Require admin review & auto blocked
        require_admin = DeteksiAnomali.query.filter_by(require_admin=True).count()
        auto_blocked = DeteksiAnomali.query.filter_by(auto_block=True).count()
        
        # Mahasiswa statistics
        total_mahasiswa = Mahasiswa.query.count()
        akun_diblokir = Mahasiswa.query.filter_by(status_akun='diblokir').count()
        akun_ditunda = Mahasiswa.query.filter_by(status_akun='ditunda').count()
        dalam_pantauan = Mahasiswa.query.filter_by(dalam_pantauan=True).count()
        
        # Login hari ini
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        total_login_hari_ini = LogLogin.query.filter(LogLogin.waktu_login >= today_start).count()
        
        stats = {
            'total_deteksi': total_deteksi,
            'belum_ditinjau': belum_ditinjau,
            'by_risk_level': {
                'rendah': deteksi_rendah,
                'sedang': deteksi_sedang,
                'tinggi': deteksi_tinggi,
                'kritis': deteksi_kritis
            },
            'by_action': {
                'izinkan': action_izinkan,
                'peringatan': action_peringatan,
                'tunda': action_tunda,
                'blokir': action_blokir
            },
            'require_admin_review': require_admin,
            'auto_blocked': auto_blocked,
            'total_mahasiswa': total_mahasiswa,
            'akun_diblokir': akun_diblokir,
            'akun_ditunda': akun_ditunda,
            'dalam_pantauan': dalam_pantauan,
            'total_login_hari_ini': total_login_hari_ini
        }
        
        return jsonify({
            'status': 'success',
            'data': stats
        }), 200
        
    except Exception as e:
        print(f"Error get statistics: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500
