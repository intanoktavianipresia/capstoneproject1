from flask import Blueprint, request, jsonify
from werkzeug.security import check_password_hash

from models import db
from models.entities import Admin
from utils.auth import generate_token, admin_required

auth_admin_bp = Blueprint('auth_admin', __name__)


@auth_admin_bp.route('/login', methods=['POST'])
def login_admin():

    try:
        data = request.get_json()
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({
                'status': 'error',
                'message': 'Username dan password wajib diisi'
            }), 400
        
        # Cari admin
        admin = Admin.query.filter_by(username=username).first()
        
        if not admin:
            return jsonify({
                'status': 'error',
                'message': 'Username atau password salah'
            }), 401
        
        # Verifikasi password
        if not check_password_hash(admin.password_hash, password):
            return jsonify({
                'status': 'error',
                'message': 'Username atau password salah'
            }), 401
        
        # Generate token
        token = generate_token(
            user_id=str(admin.id_admin),
            role='admin',
            expiration_hours=24
        )
        
        return jsonify({
            'status': 'success',
            'message': 'Login admin berhasil',
            'token': token,
            'data': {
                'id_admin': admin.id_admin,
                'nama_admin': admin.nama_admin,
                'username': admin.username,
                'email': admin.email,
                'role': admin.role
            }
        }), 200
        
    except Exception as e:
        print(f"Error login admin: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


@auth_admin_bp.route('/profile', methods=['GET'])
@admin_required
def get_admin_profile(current_user):
    try:
        admin_id = int(current_user['user_id'])
        admin = Admin.query.get(admin_id)
        
        if not admin:
            return jsonify({
                'status': 'error',
                'message': 'Admin tidak ditemukan'
            }), 404
        
        return jsonify({
            'status': 'success',
            'data': {
                'id_admin': admin.id_admin,
                'nama_admin': admin.nama_admin,
                'username': admin.username,
                'email': admin.email,
                'role': admin.role
            }
        }), 200
        
    except Exception as e:
        print(f"Error get admin profile: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Terjadi kesalahan pada server'
        }), 500


@auth_admin_bp.route('/logout', methods=['POST'])
@admin_required
def logout_admin(current_user):
    return jsonify({
        'status': 'success',
        'message': 'Logout admin berhasil. Token akan dihapus di client.'
    }), 200