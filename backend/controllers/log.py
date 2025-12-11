from flask import Blueprint, request, jsonify
from datetime import datetime, timezone, timedelta

from models import db
from models.entities import LogLogin, Mahasiswa, DeteksiAnomali
from utils.auth import admin_required, mahasiswa_required
from sqlalchemy import func # Import func untuk statistik
from typing import List, Dict, Any, Union

log_bp = Blueprint('log', __name__)


# ========================================
# GET ALL LOGIN HISTORY (ADMIN)
# ========================================

@log_bp.route('/history', methods=['GET'])
@admin_required
def get_all_history(current_user):
    try:
        # Parse query parameters
        nim_filter = request.args.get('nim')
        status_filter = request.args.get('status', 'all')
        hasil_filter = request.args.get('hasil', 'all')
        risk_filter = request.args.get('risk_level', 'all')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build query
        query = LogLogin.query
        
        if nim_filter:
            query = query.filter_by(nim=nim_filter)
        
        if status_filter != 'all':
            query = query.filter_by(status_login=status_filter)
        
        if hasil_filter != 'all':
            query = query.filter_by(hasil_deteksi=hasil_filter)
        
        # Filter by risk level (join dengan DeteksiAnomali)
        if risk_filter != 'all':
            query = query.join(DeteksiAnomali).filter(
                DeteksiAnomali.tingkat_risiko == risk_filter
            )
        
        # Date range filter
        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                query = query.filter(LogLogin.waktu_login >= date_from_obj)
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'message': 'Format date_from salah. Gunakan: YYYY-MM-DD'
                }), 400
        
        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
                query = query.filter(LogLogin.waktu_login <= date_to_obj)
            except ValueError:
                return jsonify({
                    'status': 'error',
                    'message': 'Format date_to salah. Gunakan: YYYY-MM-DD'
                }), 400
        
        # Count total
        total = query.count()
        
        # Get data with pagination
        logs: List[LogLogin] = query.order_by(
            LogLogin.waktu_login.desc()
        ).limit(limit).offset(offset).all()
        
        # Format response
        data: List[Dict[str, Any]] = []
        for log in logs:
            mahasiswa: Mahasiswa | None = log.mahasiswa
            
            # Get risk level dari DeteksiAnomali (jika ada)
            deteksi: DeteksiAnomali | None = DeteksiAnomali.query.filter_by(id_log=log.id_log).first()
            risk_level: Union[str, None] = deteksi.tingkat_risiko if deteksi else None
            
            item = {
                'id_log': log.id_log,
                'nim': log.nim,
                'nama_mahasiswa': mahasiswa.nama if mahasiswa else 'Unknown',
                'waktu_login': log.waktu_login.isoformat(),
                'ip_address': log.ip_address,
                'lokasi': log.lokasi,
                'device': log.device,
                'os': log.os,
                'browser': log.browser,
                'status_login': log.status_login,
                'percobaan_ke': log.percobaan_ke,
                'hasil_deteksi': log.hasil_deteksi,
                'skor_anomali': round(float(log.skor_anomali), 3) if log.skor_anomali else 0.0,
                'risk_level': risk_level,
                'keterangan': log.keterangan
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
        print(f"Error get all history: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


# ========================================
# GET USER LOGIN HISTORY (ADMIN)
# ========================================

@log_bp.route('/user/<nim>', methods=['GET'])
@admin_required
def get_user_history(current_user, nim):
    try:
        mahasiswa: Mahasiswa | None = Mahasiswa.query.filter_by(nim=nim).first()
        
        if not mahasiswa:
            return jsonify({
                'status': 'error',
                'message': 'Mahasiswa tidak ditemukan'
            }), 404
        
        # Parse query params
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        status_filter = request.args.get('status', 'all')
        hasil_filter = request.args.get('hasil', 'all')
        
        # Build query
        query = LogLogin.query.filter_by(nim=nim)
        
        if status_filter != 'all':
            query = query.filter_by(status_login=status_filter)
        
        if hasil_filter != 'all':
            query = query.filter_by(hasil_deteksi=hasil_filter)
        
        total = query.count()
        
        logs: List[LogLogin] = query.order_by(
            LogLogin.waktu_login.desc()
        ).limit(limit).offset(offset).all()
        
        # Format logs
        logs_data: List[Dict[str, Any]] = []
        for log in logs:
            # Get risk level dari DeteksiAnomali (jika ada)
            deteksi: DeteksiAnomali | None = DeteksiAnomali.query.filter_by(id_log=log.id_log).first()
            risk_level: Union[str, None] = deteksi.tingkat_risiko if deteksi else None
            
            logs_data.append({
                'id_log': log.id_log,
                'waktu_login': log.waktu_login.isoformat(),
                'ip_address': log.ip_address,
                'lokasi': log.lokasi,
                'device': log.device,
                'os': log.os,
                'browser': log.browser,
                'status_login': log.status_login,
                'hasil_deteksi': log.hasil_deteksi,
                'skor_anomali': round(float(log.skor_anomali), 3) if log.skor_anomali else 0.0,
                'risk_level': risk_level,
                'keterangan': log.keterangan
            })
        
        # Hitung statistik
        total_berhasil = LogLogin.query.filter_by(nim=nim, status_login='berhasil').count()
        total_gagal = LogLogin.query.filter_by(nim=nim, status_login='gagal').count()
        
        # Deteksi anomali per risk level (4-level)
        deteksi_rendah = DeteksiAnomali.query.join(LogLogin).filter(
            LogLogin.nim == nim,
            DeteksiAnomali.tingkat_risiko == 'rendah'
        ).count()
        deteksi_sedang = DeteksiAnomali.query.join(LogLogin).filter(
            LogLogin.nim == nim,
            DeteksiAnomali.tingkat_risiko == 'sedang'
        ).count()
        deteksi_tinggi = DeteksiAnomali.query.join(LogLogin).filter(
            LogLogin.nim == nim,
            DeteksiAnomali.tingkat_risiko == 'tinggi'
        ).count()
        deteksi_kritis = DeteksiAnomali.query.join(LogLogin).filter(
            LogLogin.nim == nim,
            DeteksiAnomali.tingkat_risiko == 'kritis'
        ).count()
        
        total_anomali = deteksi_rendah + deteksi_sedang + deteksi_tinggi + deteksi_kritis
        
        return jsonify({
            'status': 'success',
            'data': {
                'mahasiswa': {
                    'nim': mahasiswa.nim,
                    'nama': mahasiswa.nama,
                    'email': mahasiswa.email,
                    'status_akun': mahasiswa.status_akun,
                    'dalam_pantauan': mahasiswa.dalam_pantauan,
                    'pantauan_mulai': mahasiswa.pantauan_mulai.isoformat() if mahasiswa.pantauan_mulai else None
                },
                'logs': logs_data,
                'statistics': {
                    'total_login': total,
                    'login_berhasil': total_berhasil,
                    'login_gagal': total_gagal,
                    'deteksi_anomali': {
                        'rendah': deteksi_rendah,
                        'sedang': deteksi_sedang,
                        'tinggi': deteksi_tinggi,
                        'kritis': deteksi_kritis,
                        'total': total_anomali
                    }
                }
            },
            'pagination': {
                'total': total,
                'limit': limit,
                'offset': offset,
                'has_more': (offset + limit) < total
            }
        }), 200
        
    except Exception as e:
        print(f"Error get user history: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


# ========================================
# GET MY LOGIN HISTORY (MAHASISWA)
# ========================================

@log_bp.route('/my-history', methods=['GET'])
@mahasiswa_required
def get_my_history(current_user):
    try:
        nim = current_user['user_id']
        limit = int(request.args.get('limit', 20))
        offset = int(request.args.get('offset', 0))
        
        query = LogLogin.query.filter_by(nim=nim)
        total = query.count()
        
        logs: List[LogLogin] = query.order_by(
            LogLogin.waktu_login.desc()
        ).limit(limit).offset(offset).all()
        
        data: List[Dict[str, Any]] = []
        for log in logs:
            data.append({
                'id_log': log.id_log,
                'waktu_login': log.waktu_login.isoformat(),
                'ip_address': log.ip_address,
                'lokasi': log.lokasi,
                'device': log.device,
                'os': log.os,
                'browser': log.browser,
                'status_login': log.status_login,
                'hasil_deteksi': log.hasil_deteksi,
                'skor_anomali': round(float(log.skor_anomali), 3) if log.skor_anomali else 0.0
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
        print(f"Error get my history: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


# ========================================
# GET LOG DETAIL (ADMIN)
# ========================================

@log_bp.route('/detail/<int:id_log>', methods=['GET'])
@admin_required
def get_log_detail(current_user, id_log):
    try:
        log: LogLogin | None = LogLogin.query.get(id_log)
        
        if not log:
            return jsonify({
                'status': 'error',
                'message': 'Log tidak ditemukan'
            }), 404
        
        mahasiswa: Mahasiswa | None = log.mahasiswa
        deteksi: DeteksiAnomali | None = DeteksiAnomali.query.filter_by(id_log=id_log).first()
        
        response_data: Dict[str, Any] = {
            'log': {
                'id_log': log.id_log,
                'nim': log.nim,
                'waktu_login': log.waktu_login.isoformat(),
                'ip_address': log.ip_address,
                'lokasi': log.lokasi,
                'device': log.device,
                'os': log.os,
                'browser': log.browser,
                'status_login': log.status_login,
                'percobaan_ke': log.percobaan_ke,
                'hasil_deteksi': log.hasil_deteksi,
                'skor_anomali': round(float(log.skor_anomali), 3) if log.skor_anomali else 0.0,
                'keterangan': log.keterangan,
                # ML Features (untuk admin debugging)
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
        }
        
        if mahasiswa:
            response_data['mahasiswa'] = {
                'nim': mahasiswa.nim,
                'nama': mahasiswa.nama,
                'email': mahasiswa.email,
                'status_akun': mahasiswa.status_akun,
                'dalam_pantauan': mahasiswa.dalam_pantauan
            }
        
        if deteksi:
            response_data['deteksi'] = {
                'id_deteksi': deteksi.id_deteksi,
                'waktu_deteksi': deteksi.waktu_deteksi.isoformat(),
                'skor_anomali': round(float(deteksi.skor_anomali), 3),
                'tingkat_risiko': deteksi.tingkat_risiko,
                'tindakan_otomatis': deteksi.tindakan_otomatis,
                'delay_seconds': deteksi.delay_seconds,
                'require_admin': deteksi.require_admin,
                'auto_block': deteksi.auto_block,
                'message_to_user': deteksi.message_to_user,
                'detail_anomali': deteksi.detail_anomali,
                'status_tinjauan': deteksi.status_tinjauan
            }
        else:
            response_data['deteksi'] = None
        
        return jsonify({
            'status': 'success',
            'data': response_data
        }), 200
        
    except Exception as e:
        print(f"error get log detail: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


# ========================================
# GET LOGIN STATISTICS (ADMIN)
# ========================================

@log_bp.route('/statistics', methods=['GET'])
@admin_required
def get_login_statistics(current_user):
    try:
        from sqlalchemy import func
        
        period = request.args.get('period', 'today')
        
        # Tentukan time range
        now = datetime.now(timezone.utc)
        
        if period == 'today':
            start_time = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == 'week':
            start_time = now - timedelta(days=7)
        elif period == 'month':
            start_time = now - timedelta(days=30)
        else:  # all
            start_time = None
        
        # Build query
        query = LogLogin.query
        if start_time:
            query = query.filter(LogLogin.waktu_login >= start_time)
        
        # Total login
        total_login = query.count()
        login_berhasil = query.filter_by(status_login='berhasil').count()
        login_gagal = query.filter_by(status_login='gagal').count()
        
        # By hasil deteksi
        hasil_counts = db.session.query(
            LogLogin.hasil_deteksi,
            func.count(LogLogin.id_log)
        ).filter(
            LogLogin.waktu_login >= start_time if start_time else True
        ).group_by(LogLogin.hasil_deteksi).all()
        
        by_hasil = {hasil: count for hasil, count in hasil_counts}
        
        # Unique users
        unique_users = db.session.query(
            func.count(func.distinct(LogLogin.nim))
        ).filter(
            LogLogin.waktu_login >= start_time if start_time else True
        ).scalar()
        
        # Peak hour (jam dengan login terbanyak)
        if start_time:
            peak_hour_result = db.session.query(
                LogLogin.jam_login,
                func.count(LogLogin.id_log).label('count')
            ).filter(
                LogLogin.waktu_login >= start_time
            ).group_by(LogLogin.jam_login).order_by(
                func.count(LogLogin.id_log).desc()
            ).first()
            
            peak_hour = peak_hour_result[0] if peak_hour_result else None
        else:
            peak_hour = None
        
        return jsonify({
            'status': 'success',
            'data': {
                'period': period,
                'total_login': total_login,
                'login_berhasil': login_berhasil,
                'login_gagal': login_gagal,
                'by_hasil_deteksi': by_hasil,
                'unique_users': unique_users,
                'peak_hour': peak_hour
            }
        }), 200
        
    except Exception as e:
        print(f"Error get login statistics: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500
