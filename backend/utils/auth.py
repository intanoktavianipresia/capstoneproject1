import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify
from config import Config

def generate_token(user_id, role='mahasiswa', expiration_hours=None, **extra_payload):
    if expiration_hours is None:
        expiration_hours = Config.JWT_EXPIRATION_HOURS
    
    payload = {
        'user_id': user_id,
        'role': role,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=expiration_hours),
        **extra_payload
    }
    
    token = jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm='HS256')
    return token


def decode_token(token):
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(roles=None):
    if roles is not None and not isinstance(roles, (list, tuple)):
        roles = [roles]

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = None
            
            if 'Authorization' in request.headers:
                auth_header = request.headers['Authorization']
                try:
                    token = auth_header.split(' ')[1]
                except IndexError:
                    return jsonify({
                        'status': 'error',
                        'message': 'Format token tidak valid. Gunakan: Bearer <token>'
                    }), 401
            
            if not token:
                return jsonify({
                    'status': 'error',
                    'message': 'Token tidak ditemukan. Silakan login terlebih dahulu.'
                }), 401
            
            payload = decode_token(token)
            
            if not payload:
                return jsonify({
                    'status': 'error',
                    'message': 'Token tidak valid atau telah kedaluwarsa.'
                }), 401

            # Check multiple roles
            if roles and payload.get('role') not in roles:
                return jsonify({
                    'status': 'error',
                    'message': f"Akses ditolak. Endpoint ini hanya untuk role: {', '.join(roles)}"
                }), 403
            
            kwargs['current_user'] = payload
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator untuk endpoint admin/superadmin"""
    return token_required(roles=['admin', 'superadmin'])(f)


def mahasiswa_required(f):
    """Decorator untuk endpoint mahasiswa"""
    return token_required(roles=['mahasiswa'])(f)


def superadmin_required(f):
    """Decorator untuk endpoint superadmin only"""
    return token_required(roles=['superadmin'])(f)
