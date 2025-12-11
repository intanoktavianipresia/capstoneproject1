from flask import Flask, jsonify
from flask_cors import CORS
from config import Config
from extensions import db  
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
from werkzeug.security import generate_password_hash # Import untuk hashing password admin
from models.entities import Admin, Mahasiswa # Import model yang dibutuhkan
import sys
import os
from datetime import datetime, timezone

# ============================================
# UTILITY FUNCTION: CREATE INITIAL ADMIN
# ============================================

def create_initial_admin(app):
    """Membuat admin superadmin default jika belum ada."""
    with app.app_context():
        try:
            # Cek apakah ada admin dengan username 'superadmin'
            if Admin.query.filter_by(username='superadmin').first() is None:
                admin = Admin(
                    nama_admin='Super Admin',
                    username='superadmin',
                    password_hash=generate_password_hash('admin123!'), # Gunakan password kuat
                    email='admin@rba.com',
                    role='superadmin'
                )
                db.session.add(admin)
                db.session.commit()
                print("==================================================")
                print("✅ Super Admin berhasil dibuat:")
                print("   Username: superadmin")
                print("   Password: admin123!")
                print("   Akses Admin Dashboard sekarang sudah tersedia.")
                print("==================================================")
            else:
                print("ℹ️ Admin superadmin sudah ada.")
        except Exception as e:
            db.session.rollback()
            print(f"❌ Gagal membuat admin awal: {e}")


def create_app():
    
    app = Flask(__name__)
    
    app.config.from_object(Config)
    
    CORS(app, resources={
        r"/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "expose_headers": ["Content-Type", "Authorization"]
        }
    })
    
    db.init_app(app)
    
    with app.app_context():
        try:
            db.session.execute(text("SELECT 1"))
            print("Koneksi database berhasil")

            # Import semua model entitas agar db.create_all() berfungsi
            from models.entities import (
                Mahasiswa, Admin, LogLogin, DeteksiAnomali, 
                KeputusanAdmin, DelayedLogin, UserSecurityHistory 
            )
            
            # Membuat tabel jika belum ada
            db.create_all()
            print("Database tables ready")
            
        except OperationalError as e:
            print(f"Koneksi database gagal: {e}")
    
    # Register blueprints (controllers)
    register_blueprints(app)
    register_error_handlers(app)
    register_routes(app)
    
    return app


def register_blueprints(app):
    """Register semua blueprint controllers"""
    try:
        # PENTING: Semua controller harus ada di sini
        from controllers.auth_controller import auth_bp
        from controllers.auth_admin import auth_admin_bp  
        from controllers.admin_controller import admin_bp
        from controllers.detection import deteksi_bp  
        from controllers.log import log_bp  
        
        app.register_blueprint(auth_bp, url_prefix='/api/auth')
        app.register_blueprint(auth_admin_bp, url_prefix='/api/auth-admin')
        app.register_blueprint(admin_bp, url_prefix='/api/admin')
        app.register_blueprint(deteksi_bp, url_prefix='/api/detection')
        app.register_blueprint(log_bp, url_prefix='/api/log')
        
        print("All blueprints registered:")
        print("   • /api/auth             - Mahasiswa authentication")
        print("   • /api/auth-admin       - Admin authentication")
        print("   • /api/admin            - Admin management")
        print("   • /api/detection        - Detection & anomaly management")
        print("   • /api/log              - Login history & logs")
        
    except ImportError as e:
        print(f"Error importing blueprints: {e}")
        # Tambahkan solusi untuk ImportError
        if "No module named 'controllers'" in str(e):
             print("\n⚠️ SOLUSI: Pastikan folder 'controllers' ada di direktori backend dan mengandung file-file yang benar.")
        sys.exit(1)


def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'status': 'error',
            'message': 'Endpoint tidak ditemukan',
            'code': 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server',
            'code': 500
        }), 500
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'status': 'error',
            'message': 'Akses ditolak',
            'code': 403
        }), 403
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized. Token tidak valid atau expired.',
            'code': 401
        }), 401


def register_routes(app):
    """Register custom routes"""
    
    # ... (API Docs dan Error Handlers tetap sama) ...
    @app.route('/')
    def index():
        """API Documentation / Welcome page"""
        return jsonify({
            'status': 'success',
            'message': 'Backend Sistem Deteksi Anomali Login Portal Akademik',
            'version': '2.0.0',  
            'description': 'API untuk deteksi anomali login menggunakan Machine Learning (Isolation Forest) dengan klasifikasi 4-level risk',
            'features': [
                '4-Level Risk Classification (Rendah, Sedang, Tinggi, Kritis)',
                'Delayed Login dengan Countdown',
                'Auto Block untuk Anomali Kritis',
                'User Monitoring System',
                'Security Event Logging',
                'Admin Management Dashboard'
            ],
            'endpoints': {
                'general': {
                    'health_check': 'GET /',
                    'model_info': 'GET /api/model-info'
                },
                'auth_mahasiswa': {
                    'login': 'POST /api/auth/login',
                    'check_delay': 'GET /api/auth/login/check-delay/:id',  
                    'profile': 'GET /api/auth/profile',
                    'reset_password': 'POST /api/auth/reset-password',
                    'logout': 'POST /api/auth/logout',
                    'my_history': 'GET /api/log/my-history'
                },
                'auth_admin': {
                    'login': 'POST /api/auth-admin/login',
                    'profile': 'GET /api/auth-admin/profile',
                    'logout': 'POST /api/auth-admin/logout'
                },
                'admin_management': {
                    'get_mahasiswa': 'GET /api/admin/mahasiswa',
                    'get_mahasiswa_detail': 'GET /api/admin/mahasiswa/:nim',
                    'create_mahasiswa': 'POST /api/admin/mahasiswa',
                    'update_mahasiswa': 'PUT /api/admin/mahasiswa/:nim',
                    'unblock_mahasiswa': 'POST /api/admin/mahasiswa/:nim/unblock',  
                    'stop_monitoring': 'POST /api/admin/mahasiswa/:nim/stop-monitoring',  
                    'reset_password': 'POST /api/admin/mahasiswa/:nim/reset-password',
                    'delete_mahasiswa': 'DELETE /api/admin/mahasiswa/:nim',
                    'get_monitoring': 'GET /api/admin/monitoring',  
                    'dashboard': 'GET /api/admin/dashboard'
                },
                'detection_admin': {
                    'get_anomalies': 'GET /api/detection/anomalies',
                    'get_detail': 'GET /api/detection/anomalies/:id',
                    'take_action': 'POST /api/detection/action',
                    'statistics': 'GET /api/detection/statistics'
                },
                'log_admin': {
                    'get_all_history': 'GET /api/log/history',
                    'get_user_history': 'GET /api/log/user/:nim',
                    'get_log_detail': 'GET /api/log/detail/:id',  
                    'get_statistics': 'GET /api/log/statistics'  
                }
            },
            'risk_levels': {
                'rendah': {'description': 'Login normal', 'action': 'Izinkan langsung', 'threshold': 'Score >= P75'},
                'sedang': {'description': 'Sedikit anomali', 'action': 'Login + Peringatan', 'threshold': 'P50 <= Score < P75'},
                'tinggi': {'description': 'Anomali signifikan', 'action': 'Tunda 1 menit + Pantau Admin', 'threshold': 'P25 <= Score < P50'},
                'kritis': {'description': 'Anomali berat', 'action': 'Blokir Otomatis', 'threshold': 'Score < P25'}
            },
            'quick_test': {
                'health': 'GET /health',
                'model_info': 'GET /api/model-info',
                'login_mahasiswa': 'POST /api/auth/login with {"nim":"12345678","password":"Password123!"}',
                'login_admin': 'POST /api/auth-admin/login with {"username":"superadmin","password":"admin123!"}'
            }
        }), 200
    
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        try:
            # Test database connection
            db.session.execute(text("SELECT 1"))
            db_status = 'connected'
            db_message = 'Database connection OK'
            
            # Test ML model
            try:
                from backend.ml.detector import get_model_info
                model_info = get_model_info()
                ml_status = 'loaded'
                ml_message = 'ML model ready'
            except Exception as e:
                ml_status = 'not_loaded'
                ml_message = f'ML model error: {str(e)}'
                
        except Exception as e:
            db_status = 'disconnected'
            db_message = f'Database error: {str(e)}'
            ml_status = 'unknown'
            ml_message = 'Cannot check ML model'
        
        overall_status = 'healthy' if db_status == 'connected' else 'unhealthy'
        
        return jsonify({
            'status': overall_status,
            'message': 'Server berjalan normal' if overall_status == 'healthy' else 'Ada masalah dengan server',
            'checks': {
                'database': {
                    'status': db_status,
                    'message': db_message
                },
                'ml_model': {
                    'status': ml_status,
                    'message': ml_message
                }
            },
            'timestamp': str(datetime.now(timezone.utc).isoformat()) if db_status == 'connected' else None,
            'version': '2.0.0'
        }), 200 if overall_status == 'healthy' else 503
    
    @app.route('/api/model-info')
    def model_info():
        try:
            from backend.ml.detector import get_model_info
            info = get_model_info()
            
            if info.get('status') == 'error':
                return jsonify({
                    'status': 'error',
                    'message': 'Model belum dilatih atau error',
                    'detail': info.get('error'),
                    'solution': 'Jalankan: python backend/ml/training.py'
                }), 404
            
            return jsonify({
                'status': 'success',
                'data': info
            }), 200
            
        except FileNotFoundError as e:
            return jsonify({
                'status': 'error',
                'message': 'Model belum dilatih',
                'detail': str(e),
                'solution': 'Jalankan: python backend/ml/training.py'
            }), 404
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': 'Terjadi kesalahan saat load model',
                'detail': str(e)
            }), 500


if __name__ == '__main__':
    app = create_app()
    
    create_initial_admin(app) 
    
    print("\n" + "="*60)
    print("BACKEND DETEKSI ANOMALI LOGIN PORTAL AKADEMIK")
    print("Version: 2.0.0 (4-Level Risk Classification)")
    print("="*60)
    print("\nServer Endpoints:")
    print("   • Main        : http://localhost:5000")
    print("   • Health      : http://localhost:5000/health")
    print("   • API Docs    : http://localhost:5000/")
    print("   • Model Info  : http://localhost:5000/api/model-info")
    print("   • Auth        : http://localhost:5000/api/auth/login")
    print("\nStarting server...")
    print("="*60 + "\n")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=True
    )
